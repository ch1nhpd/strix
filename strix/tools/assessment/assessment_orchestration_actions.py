import contextlib
import json
import re
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from strix.tools.agents_graph.agents_graph_actions import (
    _agent_graph,
    _agent_instances,
    _agent_states,
    create_agent,
)
from strix.tools.registry import register_tool

from .assessment_actions import (
    VALID_PRIORITIES,
    _normalize_non_empty,
    _resolve_root_agent_id,
    list_assessment_state,
)
from .assessment_surface_review_actions import list_attack_surface_reviews

SUPPORTED_SWARM_STRATEGIES = {"balanced", "coverage_first", "depth_first"}
SUPPORTED_SIGNAL_STATUSES = {"open", "in_progress", "validated"}
PHASE_RECON = "phase-1-recon"
PHASE_VALIDATION = "phase-2-validation"
PHASE_CHAINING = "phase-3-chaining"
PHASE_GAP_CLOSURE = "phase-gap-closure"
PHASE_SEQUENCE = [PHASE_RECON, PHASE_VALIDATION, PHASE_CHAINING, PHASE_GAP_CLOSURE]
URL_PATTERN = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
STRONG_SIGNAL_HINTS = (
    "browser confirmed",
    "confirmed execution",
    "correlated",
    "cross-tenant",
    "dangerous",
    "exploit",
    "high-signal",
    "oob",
    "out-of-band",
    "stored xss",
    "unauthorized",
    "validated",
)
IMPACT_CHAIN_HINTS = (
    "admin",
    "another tenant",
    "browser confirmed",
    "confirmed execution",
    "cross-tenant",
    "duplicate",
    "exfil",
    "leaked",
    "oob",
    "privilege",
    "replay",
    "stored xss",
    "unauthorized",
)
CHAINABLE_VULNERABILITY_TYPES = {
    "authentication",
    "authorization",
    "business_logic",
    "file_upload",
    "idor",
    "jwt",
    "open_redirect",
    "path_traversal",
    "race_condition",
    "rce",
    "sqli",
    "ssrf",
    "ssti",
    "xxe",
    "xss",
}
_orchestration_round_storage: dict[str, dict[str, dict[str, Any]]] = {}
_orchestration_autorun_locks: dict[str, threading.Lock] = {}
_orchestration_autorun_queue_lock = threading.Lock()
_orchestration_autorun_queue: dict[str, dict[str, Any]] = {}
_orchestration_autorun_queue_loaded = False
SUPPRESSED_DELEGATION_KEYS_CONTEXT_KEY = "_orchestration_suppressed_delegation_keys"
BLOCKED_TERMINAL_DELEGATION_KEYS_CONTEXT_KEY = "_orchestration_blocked_terminal_delegation_keys"
TERMINAL_DELEGATION_STATUSES = {"completed", "finished", "failed", "stopped", "error"}
ROUND_TARGET_PATTERN = re.compile(
    r"run_attack_surface_orchestration_round\(target=(?:'([^']+)'|\"([^\"]+)\")",
    re.IGNORECASE,
)
DEFAULT_AUTORUN_DEBOUNCE_SECONDS = 0.2
AUTORUN_QUEUE_RETRY_SECONDS = 1.0
AUTORUN_QUEUE_MAX_RETRIES = 30
AUTORUN_QUEUE_STORAGE_FILENAME = "assessment_orchestration_autorun_queue.json"


def clear_orchestration_round_storage() -> None:
    with _orchestration_autorun_queue_lock:
        for entry in _orchestration_autorun_queue.values():
            timer = entry.get("timer")
            if isinstance(timer, threading.Timer):
                timer.cancel()
        _orchestration_autorun_queue.clear()
        global _orchestration_autorun_queue_loaded
        _orchestration_autorun_queue_loaded = True
        with contextlib.suppress(OSError):
            _autorun_queue_storage_path().unlink()
    _orchestration_round_storage.clear()
    _orchestration_autorun_locks.clear()


def _priority_rank(priority: str) -> int:
    return {"low": 0, "normal": 1, "high": 2, "critical": 3}.get(str(priority), 1)


def _normalize_swarm_strategy(strategy: str) -> str:
    normalized = str(strategy).strip().lower()
    if normalized not in SUPPORTED_SWARM_STRATEGIES:
        raise ValueError(
            f"strategy must be one of: {', '.join(sorted(SUPPORTED_SWARM_STRATEGIES))}"
        )
    return normalized


def _skills_csv(values: list[str]) -> str | None:
    normalized: list[str] = []
    for value in values:
        candidate = str(value).strip()
        if candidate and candidate not in normalized:
            normalized.append(candidate)
        if len(normalized) >= 5:
            break
    return ",".join(normalized) if normalized else None


def _unique_strings(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        candidate = str(value).strip()
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return normalized


def _json_safe_copy(value: Any, *, depth: int = 0) -> Any:
    if depth >= 6:
        return str(value)
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            normalized[str(key)] = _json_safe_copy(item, depth=depth + 1)
        return normalized
    if isinstance(value, (list, tuple, set)):
        return [_json_safe_copy(item, depth=depth + 1) for item in list(value)]
    return str(value)


class _AgentStateProxy:
    def __init__(self, base_state: Any, *, agent_id: str, parent_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.parent_id = parent_id
        self._base_state = base_state
        self.context = getattr(base_state, "context", {})

    def update_context(self, key: str, value: Any) -> None:
        if hasattr(self._base_state, "update_context"):
            self._base_state.update_context(key, value)
        else:
            self.context[key] = value

    def get_conversation_history(self) -> list[dict[str, Any]]:
        getter = getattr(self._base_state, "get_conversation_history", None)
        if callable(getter):
            history = getter()
            return history if isinstance(history, list) else []
        return []


class _PersistedAutorunState:
    def __init__(
        self,
        *,
        agent_id: str,
        parent_id: str | None = None,
        agent_name: str | None = None,
        task: str | None = None,
        context: dict[str, Any] | None = None,
        created_at: str | None = None,
        runtime_snapshot: dict[str, Any] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.parent_id = parent_id
        self.agent_name = agent_name or "Recovered Root Orchestrator"
        self.task = task or "Recovered attack-surface orchestration root"
        self.start_time = created_at or _utc_now()
        self.last_updated = self.start_time
        self.runtime_snapshot = (
            _json_safe_copy(runtime_snapshot)
            if isinstance(runtime_snapshot, dict)
            else {}
        )
        restored_context = context if isinstance(context, dict) else {}
        if not restored_context and isinstance(self.runtime_snapshot.get("context"), dict):
            restored_context = self.runtime_snapshot.get("context") or {}
        self.context: dict[str, Any] = (
            _json_safe_copy(restored_context)
            if isinstance(restored_context, dict)
            else {}
        )
        if self.runtime_snapshot:
            self.context.setdefault(
                "_recovered_root_runtime_snapshot",
                _json_safe_copy(self.runtime_snapshot),
            )

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value
        self.last_updated = _utc_now()

    def get_conversation_history(self) -> list[dict[str, Any]]:
        return []

    def model_dump(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "parent_id": self.parent_id,
            "task": self.task,
            "context": _json_safe_copy(self.context),
            "start_time": self.start_time,
            "last_updated": self.last_updated,
            "runtime_snapshot": _json_safe_copy(self.runtime_snapshot),
            "recovered_from_snapshot": True,
        }


def _state_context_snapshot(state: Any) -> dict[str, Any]:
    context = getattr(state, "context", None)
    if isinstance(context, dict):
        return _json_safe_copy(context)
    return {}


def _state_runtime_snapshot(state: Any) -> dict[str, Any]:
    runtime_snapshot = getattr(state, "runtime_snapshot", None)
    return _json_safe_copy(runtime_snapshot) if isinstance(runtime_snapshot, dict) else {}


def _subtree_contains(node_id: str, ancestor_id: str) -> bool:
    current_id: str | None = node_id
    while current_id:
        if current_id == ancestor_id:
            return True
        current = _agent_graph["nodes"].get(current_id) or {}
        parent_id = current.get("parent_id")
        current_id = str(parent_id) if parent_id else None
    return False


def _delegation_key_from_task(task: str) -> str | None:
    for line in str(task).splitlines():
        if line.lower().startswith("delegation key:"):
            _, value = line.split(":", 1)
            candidate = value.strip()
            return candidate or None
    return None


def _active_delegation_keys(agent_id: str) -> set[str]:
    keys: set[str] = set()
    for node_id, node in _agent_graph["nodes"].items():
        if not _subtree_contains(node_id, agent_id):
            continue
        if str(node.get("status") or "") not in {"running", "waiting", "stopping"}:
            continue
        key = _delegation_key_from_task(str(node.get("task") or ""))
        if key:
            keys.add(key)
    return keys


def _completed_delegation_keys_since(
    agent_id: str,
    *,
    after_finished_at: str | None = None,
) -> set[str]:
    keys: set[str] = set()
    for node_id, node in _agent_graph["nodes"].items():
        if not _subtree_contains(node_id, agent_id):
            continue
        status = str(node.get("status") or "").strip().lower()
        if status not in {"completed", "finished"}:
            continue
        finished_at = str(node.get("finished_at") or "").strip() or None
        if after_finished_at and finished_at and finished_at <= after_finished_at:
            continue
        key = _delegation_key_from_task(str(node.get("task") or ""))
        if key:
            keys.add(key)
    return keys


def _terminal_delegation_keys(agent_id: str) -> set[str]:
    keys: set[str] = set()
    for node_id, node in _agent_graph["nodes"].items():
        if not _subtree_contains(node_id, agent_id):
            continue
        status = str(node.get("status") or "").strip().lower()
        if status not in TERMINAL_DELEGATION_STATUSES:
            continue
        key = _delegation_key_from_task(str(node.get("task") or ""))
        if key:
            keys.add(key)
    return keys


def _suppressed_delegation_keys(agent_state: Any) -> set[str]:
    context = getattr(agent_state, "context", None)
    if not isinstance(context, dict):
        return set()
    values = context.get(SUPPRESSED_DELEGATION_KEYS_CONTEXT_KEY)
    if not isinstance(values, list):
        return set()
    return {
        str(item).strip()
        for item in values
        if str(item).strip()
    }


def _set_suppressed_delegation_keys(agent_state: Any, keys: set[str]) -> None:
    normalized = sorted(
        {
            str(item).strip()
            for item in keys
            if str(item).strip()
        }
    )
    if hasattr(agent_state, "update_context"):
        agent_state.update_context(SUPPRESSED_DELEGATION_KEYS_CONTEXT_KEY, normalized)
        return
    context = getattr(agent_state, "context", None)
    if isinstance(context, dict):
        context[SUPPRESSED_DELEGATION_KEYS_CONTEXT_KEY] = normalized


def _blocked_terminal_delegation_keys(agent_state: Any) -> set[str]:
    context = getattr(agent_state, "context", None)
    if not isinstance(context, dict):
        return set()
    values = context.get(BLOCKED_TERMINAL_DELEGATION_KEYS_CONTEXT_KEY)
    if not isinstance(values, list):
        return set()
    return {
        str(item).strip()
        for item in values
        if str(item).strip()
    }


def _set_blocked_terminal_delegation_keys(agent_state: Any, keys: set[str]) -> None:
    normalized = sorted(
        {
            str(item).strip()
            for item in keys
            if str(item).strip()
        }
    )
    if hasattr(agent_state, "update_context"):
        agent_state.update_context(BLOCKED_TERMINAL_DELEGATION_KEYS_CONTEXT_KEY, normalized)
        return
    context = getattr(agent_state, "context", None)
    if isinstance(context, dict):
        context[BLOCKED_TERMINAL_DELEGATION_KEYS_CONTEXT_KEY] = normalized


def _orchestrator_agent_state(agent_state: Any) -> Any:
    root_agent_id = _resolve_root_agent_id(agent_state)
    root_node = _agent_graph.get("nodes", {}).get(root_agent_id, {})
    parent_id = root_node.get("parent_id")
    return _AgentStateProxy(
        agent_state,
        agent_id=root_agent_id,
        parent_id=str(parent_id) if parent_id else None,
    )


def _round_store(agent_state: Any) -> tuple[str, dict[str, dict[str, Any]]]:
    root_agent_id = _resolve_root_agent_id(agent_state)
    if root_agent_id not in _orchestration_round_storage:
        _orchestration_round_storage[root_agent_id] = {}
    return root_agent_id, _orchestration_round_storage[root_agent_id]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _root_runtime_snapshot(root_agent_id: str, fallback_state: Any | None = None) -> dict[str, Any]:
    root_node = _agent_graph.get("nodes", {}).get(root_agent_id, {})
    root_node_state = root_node.get("state") if isinstance(root_node.get("state"), dict) else {}
    root_state = _agent_states.get(root_agent_id)
    if root_state is None and getattr(fallback_state, "agent_id", None) == root_agent_id:
        root_state = fallback_state

    snapshot = _state_runtime_snapshot(root_state)
    if not snapshot and isinstance(root_node_state.get("runtime_snapshot"), dict):
        snapshot = _json_safe_copy(root_node_state.get("runtime_snapshot"))

    state_context = _state_context_snapshot(root_state)
    if not state_context and isinstance(root_node_state.get("context"), dict):
        state_context = _json_safe_copy(root_node_state.get("context"))
    if not state_context and isinstance(snapshot.get("context"), dict):
        state_context = _json_safe_copy(snapshot.get("context"))

    runtime = (
        _json_safe_copy(snapshot.get("runtime"))
        if isinstance(snapshot.get("runtime"), dict)
        else {}
    )
    root_agent = _agent_instances.get(root_agent_id)
    if root_agent and hasattr(root_agent, "llm_config"):
        timeout = getattr(root_agent.llm_config, "timeout", None)
        if timeout is not None:
            runtime["timeout"] = timeout
        runtime["scan_mode"] = getattr(
            root_agent.llm_config,
            "scan_mode",
            runtime.get("scan_mode", "deep"),
        )
        runtime["assessment_objective"] = getattr(
            root_agent.llm_config,
            "assessment_objective",
            runtime.get("assessment_objective", "discovery"),
        )
        runtime["interactive"] = getattr(
            root_agent.llm_config,
            "interactive",
            runtime.get("interactive", False),
        )
        if hasattr(root_agent, "llm") and hasattr(root_agent.llm, "_system_prompt_context"):
            runtime["system_prompt_context"] = _json_safe_copy(
                getattr(root_agent.llm, "_system_prompt_context", {})
            )

    if "system_prompt_context" not in runtime or not isinstance(
        runtime.get("system_prompt_context"),
        dict,
    ):
        runtime["system_prompt_context"] = {}
    runtime.setdefault("scan_mode", "deep")
    runtime.setdefault("assessment_objective", "discovery")
    runtime["interactive"] = bool(runtime.get("interactive", False))

    agent_name = str(
        root_node.get("name")
        or getattr(root_state, "agent_name", "")
        or root_node_state.get("agent_name")
        or snapshot.get("agent_name")
        or "Recovered Root Orchestrator"
    )
    task = str(
        root_node.get("task")
        or getattr(root_state, "task", "")
        or root_node_state.get("task")
        or snapshot.get("task")
        or "Recovered attack-surface orchestration root"
    )
    parent_id = str(
        root_node.get("parent_id")
        or getattr(root_state, "parent_id", "")
        or root_node_state.get("parent_id")
        or snapshot.get("parent_id")
        or ""
    ).strip() or None
    created_at = str(
        root_node.get("created_at")
        or getattr(root_state, "start_time", "")
        or root_node_state.get("start_time")
        or snapshot.get("created_at")
        or _utc_now()
    )

    known_targets = [
        str(item).strip()
        for item in list(snapshot.get("known_targets") or [])
        if str(item).strip()
    ]
    target_state = root_state if root_state is not None else None
    if target_state is None and getattr(fallback_state, "agent_id", None) == root_agent_id:
        target_state = fallback_state
    if target_state is not None:
        known_targets = _unique_strings([*known_targets, *_known_orchestration_targets(target_state)])

    return {
        "agent_id": root_agent_id,
        "agent_name": agent_name,
        "parent_id": parent_id,
        "task": task,
        "context": state_context,
        "created_at": created_at,
        "runtime": _json_safe_copy(runtime),
        "known_targets": known_targets,
    }


def _restore_root_state_from_snapshot(root_agent_id: str, entry: dict[str, Any]) -> bool:
    snapshot = entry.get("root_runtime_snapshot")
    if not isinstance(snapshot, dict):
        snapshot = _state_runtime_snapshot(entry.get("base_state"))
    if not isinstance(snapshot, dict) or not snapshot:
        return False

    base_state = entry.get("base_state")
    if not isinstance(base_state, _PersistedAutorunState):
        base_state = _PersistedAutorunState(
            agent_id=root_agent_id,
            parent_id=str(snapshot.get("parent_id") or "").strip() or None,
            agent_name=str(snapshot.get("agent_name") or "").strip() or None,
            task=str(snapshot.get("task") or "").strip() or None,
            context=(
                snapshot.get("context")
                if isinstance(snapshot.get("context"), dict)
                else {}
            ),
            created_at=str(snapshot.get("created_at") or "").strip() or None,
            runtime_snapshot=snapshot,
        )
        entry["base_state"] = base_state

    if root_agent_id not in _agent_states:
        _agent_states[root_agent_id] = base_state

    node = _agent_graph.get("nodes", {}).get(root_agent_id)
    if not isinstance(node, dict):
        _agent_graph.setdefault("nodes", {})[root_agent_id] = {
            "id": root_agent_id,
            "name": base_state.agent_name,
            "task": base_state.task,
            "status": "recovered",
            "parent_id": base_state.parent_id,
            "created_at": str(snapshot.get("created_at") or base_state.start_time),
            "finished_at": None,
            "result": None,
            "state": base_state.model_dump(),
            "recovered_from_snapshot": True,
        }
    else:
        node.setdefault("id", root_agent_id)
        node.setdefault("name", base_state.agent_name)
        node.setdefault("task", base_state.task)
        node.setdefault("parent_id", base_state.parent_id)
        node.setdefault("created_at", str(snapshot.get("created_at") or base_state.start_time))
        node.setdefault("finished_at", None)
        node.setdefault("result", None)
        node["state"] = base_state.model_dump()
        node["recovered_from_snapshot"] = True
        if str(node.get("status") or "").strip().lower() in {"", "unknown"}:
            node["status"] = "recovered"

    entry["root_runtime_snapshot"] = _json_safe_copy(snapshot)
    return True


def _autorun_queue_storage_path() -> Path:
    from strix.config.config import Config

    return Config.config_dir() / "state" / AUTORUN_QUEUE_STORAGE_FILENAME


def _schedule_autorun_timer_unlocked(root_agent_id: str, delay_seconds: float) -> threading.Timer:
    timer = threading.Timer(
        max(delay_seconds, 0),
        _flush_orchestration_autorun_queue,
        args=(root_agent_id,),
    )
    timer.daemon = True
    timer.start()
    return timer


def _persistable_autorun_entry(root_agent_id: str, entry: dict[str, Any]) -> dict[str, Any]:
    root_node = _agent_graph.get("nodes", {}).get(root_agent_id, {})
    root_runtime_snapshot = _root_runtime_snapshot(root_agent_id, entry.get("base_state"))
    return {
        "root_agent_id": root_agent_id,
        "root_parent_id": (
            str(root_node.get("parent_id") or "").strip() or None
            if isinstance(root_node, dict)
            else None
        ),
        "events": [dict(item) for item in list(entry.get("events") or []) if isinstance(item, dict)],
        "root_runtime_snapshot": root_runtime_snapshot,
        "dry_run": bool(entry.get("dry_run")),
        "retry_count": int(entry.get("retry_count") or 0),
        "persisted_created_at": str(entry.get("persisted_created_at") or _utc_now()),
        "execute_after_epoch": float(entry.get("execute_after_epoch") or time.time()),
        "updated_at": _utc_now(),
    }


def _persist_orchestration_autorun_queue_locked() -> None:
    path = _autorun_queue_storage_path()
    payload = {
        root_agent_id: _persistable_autorun_entry(root_agent_id, entry)
        for root_agent_id, entry in _orchestration_autorun_queue.items()
        if isinstance(entry, dict)
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    if not payload:
        with contextlib.suppress(OSError):
            path.unlink()
        return
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    with contextlib.suppress(OSError):
        temp_path.chmod(0o600)
    temp_path.replace(path)
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def _load_persisted_orchestration_autorun_queue_locked() -> None:
    path = _autorun_queue_storage_path()
    if not path.exists():
        return
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict):
        return

    now_epoch = time.time()
    for root_agent_id, raw_entry in payload.items():
        if not isinstance(raw_entry, dict):
            continue
        normalized_root_agent_id = str(root_agent_id).strip()
        if not normalized_root_agent_id:
            continue
        events = [dict(item) for item in list(raw_entry.get("events") or []) if isinstance(item, dict)]
        if not events:
            continue
        root_parent_id = str(raw_entry.get("root_parent_id") or "").strip() or None
        root_runtime_snapshot = (
            _json_safe_copy(raw_entry.get("root_runtime_snapshot"))
            if isinstance(raw_entry.get("root_runtime_snapshot"), dict)
            else {}
        )
        execute_after_epoch = float(raw_entry.get("execute_after_epoch") or now_epoch)
        entry = {
            "events": events,
            "timer": None,
            "base_state": _PersistedAutorunState(
                agent_id=normalized_root_agent_id,
                parent_id=root_parent_id,
                agent_name=str(root_runtime_snapshot.get("agent_name") or "").strip() or None,
                task=str(root_runtime_snapshot.get("task") or "").strip() or None,
                context=(
                    root_runtime_snapshot.get("context")
                    if isinstance(root_runtime_snapshot.get("context"), dict)
                    else {}
                ),
                created_at=str(root_runtime_snapshot.get("created_at") or "").strip() or None,
                runtime_snapshot=root_runtime_snapshot,
            ),
            "root_runtime_snapshot": root_runtime_snapshot,
            "dry_run": bool(raw_entry.get("dry_run")),
            "retry_count": int(raw_entry.get("retry_count") or 0),
            "persisted_created_at": str(raw_entry.get("persisted_created_at") or _utc_now()),
            "execute_after_epoch": execute_after_epoch,
        }
        delay_seconds = max(execute_after_epoch - now_epoch, 0)
        entry["timer"] = _schedule_autorun_timer_unlocked(normalized_root_agent_id, delay_seconds)
        _orchestration_autorun_queue[normalized_root_agent_id] = entry


def _ensure_persisted_orchestration_autorun_queue_loaded() -> None:
    global _orchestration_autorun_queue_loaded
    if _orchestration_autorun_queue_loaded:
        return
    with _orchestration_autorun_queue_lock:
        if _orchestration_autorun_queue_loaded:
            return
        _load_persisted_orchestration_autorun_queue_locked()
        _orchestration_autorun_queue_loaded = True


def _bug_skills(bug_classes: list[str], module_name: str = "") -> list[str]:
    lowered = " ".join([*bug_classes, module_name]).lower()
    skills: list[str] = []
    if any(keyword in lowered for keyword in ["authorization", "idor", "tenant", "bola"]):
        skills.extend(["idor", "broken_function_level_authorization"])
    if any(keyword in lowered for keyword in ["authentication", "jwt", "session", "login", "mfa"]):
        skills.append("authentication_jwt")
    if any(keyword in lowered for keyword in ["business", "workflow", "replay", "race"]):
        skills.extend(["business_logic", "race_conditions"])
    if "sql" in lowered:
        skills.append("sql_injection")
    if "xss" in lowered or "html injection" in lowered:
        skills.append("xss")
    if "ssrf" in lowered:
        skills.append("ssrf")
    if "graphql" in lowered:
        skills.append("graphql")
    if "open redirect" in lowered:
        skills.append("open_redirect")
    if "path traversal" in lowered or "file access" in lowered:
        skills.append("path_traversal_lfi_rfi")
    if "file upload" in lowered:
        skills.append("insecure_file_uploads")
    if "xxe" in lowered:
        skills.append("xxe")
    if "rce" in lowered or "command injection" in lowered:
        skills.append("rce")
    return skills[:5]


def _host_recon_skills(
    host_type: str,
    *,
    signal_classification: str = "",
    resolve_status: str = "",
) -> list[str]:
    normalized_signal = str(signal_classification).strip().lower()
    normalized_resolve_status = str(resolve_status).strip().lower()
    if normalized_signal == "weak-signal" and normalized_resolve_status != "resolved":
        return ["subfinder", "httpx", "naabu", "ffuf", "nuclei"]
    skills = ["httpx", "katana", "ffuf", "nmap", "nuclei"]
    if host_type == "auth":
        skills = ["httpx", "katana", "ffuf", "authentication_jwt", "nuclei"]
    elif host_type == "api":
        skills = ["httpx", "katana", "graphql", "nuclei", "ffuf"]
    return skills[:5]


def _host_recon_objective(host_row: dict[str, Any]) -> str:
    signal_classification = str(host_row.get("signal_classification") or "").strip().lower()
    resolve_status = str(host_row.get("resolve_status") or "").strip().lower()
    objective_lines = [
        "- Expand host -> service -> web/app -> path -> file -> endpoint coverage for this host.",
        "- Execute the full applicable ladder: DNS/TLS/provider clues -> port/service scan -> HTTP fingerprint -> crawl/path fuzz -> JS/docs/data-leak mining.",
        "- Reconcile current wrapped-tool output with missing attack surface and hidden routes.",
        "- Push coverage ledger updates instead of broad narration.",
        "- If you find a real vulnerability signal, create a dedicated child validation agent for that specific bug and location.",
        "- Prioritize reducing blind spots over repeating already-covered scans.",
    ]
    if signal_classification == "weak-signal":
        objective_lines.append(
            "- First validate whether this host is real by corroborating it through subdomain discovery, cert/SAN or provider clues, proxy/runtime history, and sibling asset references."
        )
    if resolve_status and resolve_status != "resolved":
        objective_lines.extend(
            [
                "- If the host does not resolve or does not expose a live listener, do not stop after a single failed request.",
                "- Exhaust passive/off-host recon before concluding blocked: inspect prior tool runs, runtime inventory, proxy history, JS/docs/OpenAPI/source-map references, callback/base-URL mentions, and DNS/CNAME/TLS/provider hints from sibling assets.",
                "- Only attempt port scanning or directory fuzzing when you have a resolvable host, IP, or live service to test; otherwise record that those active checks were blocked and what passive coverage was still completed.",
            ]
        )
    else:
        objective_lines.extend(
            [
                "- If the host is reachable, verify services/ports, then run path discovery, crawl/JS route mining, and exposed-file/data-leak checks before closing the recon task.",
                "- Do not end after the first live page; keep digging until path/file/endpoint coverage materially improves or is explicitly blocked.",
            ]
        )
    return "\n".join(objective_lines)


def _blind_spot_skills(area: str) -> list[str]:
    lowered = str(area).lower()
    if lowered in {"runtime inventory", "surface mining", "blackbox recon", "dns", "tool runs"}:
        return ["subfinder", "httpx", "naabu", "nmap", "ffuf"]
    if lowered == "workflow coverage":
        return ["business_logic", "race_conditions", "katana"]
    if lowered in {"role boundary", "session profiles"}:
        return ["idor", "broken_function_level_authorization", "authentication_jwt"]
    return ["httpx", "katana", "nuclei"]


def _service_recon_skills(service_row: dict[str, Any]) -> list[str]:
    app_family = " ".join(str(item) for item in list(service_row.get("app_family") or []))
    auth_wall = str(service_row.get("auth_wall") or "").strip().lower()
    skills = ["httpx", "nmap", "katana", "nuclei"]
    if "api" in app_family.lower():
        skills.insert(2, "ffuf")
    if "graphql" in app_family.lower():
        skills.insert(2, "graphql")
    if auth_wall in {"protected", "mixed", "likely protected"}:
        skills.insert(2, "authentication_jwt")
    deduped: list[str] = []
    for skill in skills:
        if skill not in deduped:
            deduped.append(skill)
        if len(deduped) >= 5:
            break
    return deduped


def _module_review_skills(module_row: dict[str, Any]) -> list[str]:
    module_name = str(module_row.get("application_module") or "")
    bug_classes = [str(item) for item in list(module_row.get("bug_classes") or [])]
    skills = _bug_skills(bug_classes, module_name)
    if list(module_row.get("hidden_routes") or []):
        skills.extend(["katana", "ffuf"])
    if list(module_row.get("docs_endpoints") or []):
        skills.append("graphql")
    if list(module_row.get("upload_surfaces") or []):
        skills.append("insecure_file_uploads")
    if list(module_row.get("auth_surfaces") or []):
        skills.append("authentication_jwt")
    if not skills:
        skills = ["httpx", "katana", "ffuf", "nuclei"]
    deduped: list[str] = []
    for skill in skills:
        if skill not in deduped:
            deduped.append(skill)
        if len(deduped) >= 5:
            break
    return deduped


def _boundary_skills(boundary: str) -> list[str]:
    lowered = str(boundary).strip().lower()
    skills = ["idor", "broken_function_level_authorization"]
    if any(marker in lowered for marker in ["guest", "user", "privileged", "tenant"]):
        skills.append("authentication_jwt")
    if any(marker in lowered for marker in ["invited", "verified", "suspended", "deleted"]):
        skills.append("business_logic")
    deduped: list[str] = []
    for skill in skills:
        if skill not in deduped:
            deduped.append(skill)
        if len(deduped) >= 5:
            break
    return deduped


def _focus_for_vulnerability(vulnerability_type: str, text: str = "") -> str | None:
    normalized = str(vulnerability_type).strip().lower()
    lowered_text = str(text).strip().lower()
    if normalized in {"authorization", "idor"}:
        return "authz"
    if normalized == "ssrf":
        return "ssrf_oob"
    if normalized == "sqli":
        return "sqli"
    if normalized == "xss":
        return "xss"
    if normalized == "open_redirect":
        return "open_redirect"
    if normalized == "ssti":
        return "ssti"
    if normalized in {"path_traversal", "lfi"}:
        return "path_traversal"
    if normalized == "xxe":
        return "xxe"
    if normalized == "file_upload":
        return "file_upload"
    if normalized in {"jwt", "authentication"} and any(
        marker in lowered_text for marker in ("jwt", "token", "bearer", "jwks", "alg:none")
    ):
        return "auth_jwt"
    if normalized in {"business_logic", "race_condition"}:
        return "workflow_race"
    return None


def _extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    for match in URL_PATTERN.findall(str(text)):
        candidate = str(match).rstrip(".,);]")
        if candidate and candidate not in urls:
            urls.append(candidate)
    return urls


def _component_asset_hints(component: str) -> dict[str, Any]:
    normalized = str(component).strip()
    if not normalized or normalized == "general":
        return {"host": None, "path": None, "candidate_urls": []}
    candidate_urls = _extract_urls(normalized)
    host: str | None = None
    path: str | None = None
    if candidate_urls:
        parsed = urlparse(candidate_urls[0])
        host = parsed.netloc or parsed.hostname
        path = parsed.path or "/"
    else:
        tail = normalized.split(":")[-1].strip()
        if "/" in tail:
            host_candidate, raw_path = tail.split("/", 1)
            if "." in host_candidate:
                host = host_candidate.strip()
                path = f"/{raw_path.strip()}" if raw_path.strip() else "/"
        elif "." in tail and " " not in tail:
            host = tail
        if host:
            candidate_urls.append(f"https://{host}{path or '/'}")
    return {
        "host": host,
        "path": path or "/",
        "candidate_urls": candidate_urls,
    }


def _evidence_for_hypothesis(
    evidence_records: list[dict[str, Any]],
    *,
    hypothesis_id: str,
    component: str,
    target: str,
) -> list[dict[str, Any]]:
    related: list[dict[str, Any]] = []
    for record in evidence_records:
        if not isinstance(record, dict):
            continue
        if str(record.get("target") or "").strip() not in {"", target}:
            continue
        if str(record.get("related_hypothesis_id") or "").strip() == hypothesis_id:
            related.append(record)
            continue
        evidence_component = str(record.get("component") or "").strip()
        if component and evidence_component and evidence_component == component:
            related.append(record)
    return related


def _signal_score(hypothesis: dict[str, Any], related_evidence: list[dict[str, Any]]) -> int:
    priority = str(hypothesis.get("priority") or "normal")
    status = str(hypothesis.get("status") or "open")
    vulnerability_type = str(hypothesis.get("vulnerability_type") or "").strip().lower()
    rationale = str(hypothesis.get("rationale") or "")
    summary_text = " ".join(
        [
            str(hypothesis.get("hypothesis") or ""),
            rationale,
            " ".join(
                f"{item.get('title') or ''} {item.get('details') or ''}" for item in related_evidence[:3]
            ),
        ]
    ).lower()

    score = _priority_rank(priority) + 1
    if status == "validated":
        score += 2
    elif status == "in_progress":
        score += 1
    if related_evidence:
        score += 1
    if any(str(item.get("source") or "") in {"runtime", "tool", "traffic"} for item in related_evidence):
        score += 1
    if vulnerability_type not in {"", "general", "misconfiguration", "scanner_finding"}:
        score += 1
    if any(keyword in summary_text for keyword in STRONG_SIGNAL_HINTS):
        score += 1
    return score


def _signal_candidate_urls(
    hypothesis: dict[str, Any],
    related_evidence: list[dict[str, Any]],
) -> list[str]:
    urls: list[str] = []
    component_hints = _component_asset_hints(str(hypothesis.get("component") or ""))
    for candidate in list(component_hints.get("candidate_urls") or []):
        if candidate not in urls:
            urls.append(candidate)
    for record in related_evidence:
        for field_name in ("title", "details"):
            for candidate in _extract_urls(str(record.get(field_name) or "")):
                if candidate not in urls:
                    urls.append(candidate)
        if len(urls) >= 3:
            break
    return urls[:3]


def _evidence_highlights(related_evidence: list[dict[str, Any]], *, limit: int = 3) -> list[str]:
    highlights: list[str] = []
    for record in related_evidence[:limit]:
        title = str(record.get("title") or "").strip()
        details = " ".join(str(record.get("details") or "").strip().split())
        snippet = details[:180] + ("..." if len(details) > 180 else "")
        line = title or snippet
        if title and snippet:
            line = f"{title}: {snippet}"
        if line:
            highlights.append(line)
    return highlights


def _latest_timestamp(records: list[dict[str, Any]], *field_names: str) -> str | None:
    timestamps: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for field_name in field_names:
            candidate = str(record.get(field_name) or "").strip()
            if candidate:
                timestamps.append(candidate)
    return max(timestamps) if timestamps else None


def _subtree_progress_snapshot(agent_id: str) -> dict[str, Any]:
    active_statuses = {"running", "waiting", "stopping"}
    finished_statuses = {"completed", "finished", "failed", "stopped", "error"}
    active_count = 0
    finished_count = 0
    latest_finished_at: str | None = None
    for node_id, node in _agent_graph.get("nodes", {}).items():
        if node_id == agent_id or not _subtree_contains(node_id, agent_id):
            continue
        status = str(node.get("status") or "").strip().lower()
        if status in active_statuses:
            active_count += 1
        if status in finished_statuses:
            finished_count += 1
            finished_at = str(node.get("finished_at") or "").strip()
            if finished_at and (latest_finished_at is None or finished_at > latest_finished_at):
                latest_finished_at = finished_at
    return {
        "root_agent_id": agent_id,
        "active_descendant_count": active_count,
        "finished_descendant_count": finished_count,
        "latest_finished_at": latest_finished_at,
    }


def _scope_targets_from_review(report: dict[str, Any] | None) -> list[str]:
    if not isinstance(report, dict):
        return []
    scope_map = report.get("scope_map_v1") if isinstance(report.get("scope_map_v1"), dict) else {}
    targets: list[str] = []
    for key in ("root_domains", "fixed_hosts"):
        targets.extend(str(item).strip() for item in list(scope_map.get(key) or []))
    for wildcard_domain in list(scope_map.get("wildcard_domains") or []):
        domain = str(wildcard_domain).strip()
        if domain:
            targets.append(f"*.{domain}")
    for item in list(scope_map.get("path_based_scope") or []):
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or "").strip()
        path = str(item.get("path") or "").strip()
        if host and path:
            targets.append(f"https://{host}{path}")
    return _unique_strings(targets)


def _scope_targets_from_runtime_entries(entries: list[dict[str, Any]]) -> list[str]:
    targets: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for sample_url in list(entry.get("sample_urls") or []):
            candidate = str(sample_url).strip()
            if candidate:
                targets.append(candidate)
        host = str(entry.get("host") or "").strip()
        path = str(entry.get("normalized_path") or "/").strip() or "/"
        if host:
            targets.append(host)
            targets.append(f"https://{host}{path}")
    return _unique_strings(targets)


def _scope_targets_from_surface_artifacts(artifacts: list[dict[str, Any]]) -> list[str]:
    targets: list[str] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        host = str(artifact.get("host") or "").strip()
        path = str(artifact.get("path") or "").strip()
        if host:
            targets.append(host)
            if path:
                targets.append(f"https://{host}{path}")
    return _unique_strings(targets)


def _scope_targets_from_workflows(workflows: list[dict[str, Any]]) -> list[str]:
    targets: list[str] = []
    for workflow in workflows:
        if not isinstance(workflow, dict):
            continue
        host = str(workflow.get("host") or "").strip()
        if host:
            targets.append(host)
        for step in list(workflow.get("sequence") or []):
            if not isinstance(step, dict):
                continue
            step_host = str(step.get("host") or workflow.get("host") or "").strip()
            path = str(step.get("normalized_path") or step.get("path") or "").strip()
            if step_host:
                targets.append(step_host)
                if path:
                    targets.append(f"https://{step_host}{path}")
    return _unique_strings(targets)


def _orchestration_scope_targets(
    agent_state: Any,
    *,
    target: str,
    explicit_scope_targets: list[str] | None,
    review_report: dict[str, Any] | None,
) -> list[str]:
    try:
        from .assessment_toolchain_actions import (
            _attack_surface_review_scope_targets,
            _load_discovered_workflows,
            _load_mined_surface_artifacts,
            _load_runtime_inventory_entries,
        )
    except Exception:  # noqa: BLE001
        explicit = [str(item).strip() for item in list(explicit_scope_targets or []) if str(item).strip()]
        return _unique_strings([*explicit, *_scope_targets_from_review(review_report)])

    runtime_entries = _load_runtime_inventory_entries(agent_state, target)
    surface_artifacts = _load_mined_surface_artifacts(agent_state, target)
    workflows = _load_discovered_workflows(agent_state, target)
    explicit = [str(item).strip() for item in list(explicit_scope_targets or []) if str(item).strip()]
    return _attack_surface_review_scope_targets(
        explicit,
        _scope_targets_from_review(review_report),
        _scope_targets_from_runtime_entries(runtime_entries),
        _scope_targets_from_surface_artifacts(surface_artifacts),
        _scope_targets_from_workflows(workflows),
    )


def _signal_candidate_sort_key(candidate: dict[str, Any]) -> tuple[int, int, str]:
    return (
        -int(candidate.get("signal_score") or 0),
        -_priority_rank(str(candidate.get("priority") or "normal")),
        str(candidate.get("name") or ""),
    )


def _load_review_report(agent_state: Any, target: str) -> dict[str, Any] | None:
    review_result = list_attack_surface_reviews(
        agent_state=agent_state,
        target=target,
        include_report=True,
        max_items=1,
    )
    if not review_result.get("success"):
        return None
    records = [item for item in list(review_result.get("records") or []) if isinstance(item, dict)]
    if not records:
        return None
    report = records[0].get("report")
    return report if isinstance(report, dict) else None


def _known_orchestration_targets(agent_state: Any) -> list[str]:
    targets: list[str] = []
    _, round_store = _round_store(agent_state)
    targets.extend(str(item).strip() for item in round_store.keys())

    review_result = list_attack_surface_reviews(
        agent_state=agent_state,
        include_report=False,
        max_items=50,
    )
    if review_result.get("success"):
        for record in list(review_result.get("records") or []):
            if not isinstance(record, dict):
                continue
            candidate = str(record.get("target") or "").strip()
            if candidate:
                targets.append(candidate)

    assessment_result = list_assessment_state(
        agent_state=agent_state,
        include_resolved_coverage=True,
        include_evidence=True,
        max_items=250,
    )
    if assessment_result.get("success"):
        for key in ("coverage", "hypotheses", "evidence"):
            for record in list(assessment_result.get(key) or []):
                if not isinstance(record, dict):
                    continue
                candidate = str(record.get("target") or "").strip()
                if candidate:
                    targets.append(candidate)

    return _unique_strings(targets)


def _task_target_candidates(task: str, known_targets: list[str]) -> list[str]:
    prioritized: list[str] = []
    text = str(task)
    for match in ROUND_TARGET_PATTERN.findall(text):
        for candidate in match:
            normalized = str(candidate).strip()
            if normalized:
                prioritized.append(normalized)

    for line in text.splitlines():
        lowered = line.lower()
        if lowered.startswith("target label:") or lowered.startswith("target:"):
            _, value = line.split(":", 1)
            candidate = value.strip()
            if candidate:
                prioritized.append(candidate)

    for known_target in known_targets:
        if known_target and known_target in text:
            prioritized.append(known_target)

    prioritized = _unique_strings(prioritized)
    remaining = [target for target in known_targets if target not in prioritized]
    return [*prioritized, *remaining]


def _matching_review_chain_context(
    report: dict[str, Any] | None,
    *,
    host: str,
    path: str,
) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(report, dict):
        return {"chain_matches": [], "exposure_matches": []}
    priorities = report.get("priorities") if isinstance(report.get("priorities"), dict) else {}
    chain_matches: list[dict[str, Any]] = []
    for item in list(priorities.get("top_chain_opportunities") or report.get("chain_analysis") or []):
        if not isinstance(item, dict):
            continue
        assets = [str(asset).strip() for asset in list(item.get("assets") or []) if str(asset).strip()]
        summary = str(item.get("summary") or "").strip()
        searchable = " ".join([summary, *assets]).lower()
        if host and host.lower() in searchable:
            chain_matches.append(item)
            continue
        if path and path != "/" and path.lower() in searchable:
            chain_matches.append(item)

    exposure_matches: list[dict[str, Any]] = []
    for item in list(priorities.get("top_recon_value_exposures") or []):
        if not isinstance(item, dict):
            continue
        exposure_host = str(item.get("host") or "").strip().lower()
        exposure_path = str(item.get("path") or "").strip() or "/"
        if host and exposure_host and exposure_host == host.lower():
            exposure_matches.append(item)
            continue
        if path and path != "/" and exposure_path == path:
            exposure_matches.append(item)

    return {
        "chain_matches": chain_matches[:3],
        "exposure_matches": exposure_matches[:3],
    }


def _impact_ready_text(*parts: str) -> str:
    return " ".join(part for part in [str(item).strip() for item in parts] if part).lower()


def _impact_score(
    *,
    hypothesis: dict[str, Any],
    related_evidence: list[dict[str, Any]],
    signal_score: int,
    chain_matches: list[dict[str, Any]],
    exposure_matches: list[dict[str, Any]],
) -> int:
    vulnerability_type = str(hypothesis.get("vulnerability_type") or "").strip().lower()
    status = str(hypothesis.get("status") or "").strip().lower()
    evidence_text = _impact_ready_text(
        str(hypothesis.get("hypothesis") or ""),
        str(hypothesis.get("rationale") or ""),
        " ".join(_evidence_highlights(related_evidence, limit=3)),
    )
    score = signal_score
    if status == "validated":
        score += 2
    elif status == "in_progress":
        score += 1
    if vulnerability_type in CHAINABLE_VULNERABILITY_TYPES:
        score += 1
    if related_evidence:
        score += 1
    if len(related_evidence) >= 2:
        score += 1
    if chain_matches:
        score += 1
    if exposure_matches:
        score += 1
    if any(keyword in evidence_text for keyword in IMPACT_CHAIN_HINTS):
        score += 1
    return score


def _candidate_sort_key(candidate: dict[str, Any]) -> tuple[int, str, str]:
    return (
        -_priority_rank(str(candidate.get("priority") or "normal")),
        str(candidate.get("phase") or ""),
        str(candidate.get("name") or ""),
    )


def _with_round_followup(task: str, *, target: str) -> str:
    normalized_target = str(target).strip()
    if not normalized_target:
        return task
    return (
        f"{task}\n"
        "Continuation:\n"
        f"- The root orchestrator already tracks target '{normalized_target}' and auto-refreshes follow-up when this child finishes.\n"
        "- Do not manually launch another orchestration round from this child.\n"
        "- Focus on producing durable coverage, evidence, hypotheses, or explicit blocked/needs-more-data outcomes."
    )


def _coalesced_completion_status(events: list[dict[str, Any]]) -> str:
    statuses = {str(item.get("completion_status") or "").strip().lower() for item in events}
    if "error" in statuses or "failed" in statuses:
        return "failed"
    if "stopped" in statuses:
        return "stopped"
    if "finished" in statuses:
        return "finished"
    return "completed"


def _merge_autorun_events(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = [dict(item) for item in existing if isinstance(item, dict)]
    seen = {
        (
            str(item.get("agent_id") or "").strip(),
            str(item.get("completion_status") or "").strip().lower(),
            str(item.get("task") or "").strip(),
        )
        for item in merged
    }
    for item in incoming:
        if not isinstance(item, dict):
            continue
        key = (
            str(item.get("agent_id") or "").strip(),
            str(item.get("completion_status") or "").strip().lower(),
            str(item.get("task") or "").strip(),
        )
        if key in seen:
            continue
        merged.append(dict(item))
        seen.add(key)
    return merged


def _root_base_state(root_agent_id: str, fallback_state: Any) -> Any:
    root_state = _agent_states.get(root_agent_id)
    return root_state if root_state is not None else fallback_state


def _store_autorun_result_on_event_nodes(events: list[dict[str, Any]], result: dict[str, Any]) -> None:
    for event in events:
        if not isinstance(event, dict):
            continue
        event_agent_id = str(event.get("agent_id") or "").strip()
        if not event_agent_id:
            continue
        node = _agent_graph.get("nodes", {}).get(event_agent_id)
        if isinstance(node, dict):
            node["orchestration_autorun"] = dict(result)


def _requeue_orchestration_autorun_entry(
    root_agent_id: str,
    *,
    entry: dict[str, Any],
    delay_seconds: float,
    retry_count: int,
    skip_reason: str,
) -> dict[str, Any]:
    with _orchestration_autorun_queue_lock:
        queue_entry = {
            "events": [dict(item) for item in list(entry.get("events") or []) if isinstance(item, dict)],
            "timer": None,
            "base_state": entry.get("base_state"),
            "root_runtime_snapshot": _root_runtime_snapshot(root_agent_id, entry.get("base_state")),
            "dry_run": bool(entry.get("dry_run")),
            "retry_count": retry_count,
            "persisted_created_at": str(entry.get("persisted_created_at") or _utc_now()),
            "execute_after_epoch": time.time() + max(delay_seconds, 0),
        }
        queue_entry["timer"] = _schedule_autorun_timer_unlocked(root_agent_id, delay_seconds)
        _orchestration_autorun_queue[root_agent_id] = queue_entry
        _persist_orchestration_autorun_queue_locked()
        queued_result = {
            "success": True,
            "queued": True,
            "triggered": False,
            "root_agent_id": root_agent_id,
            "batch_event_count": len(queue_entry["events"]),
            "retry_count": retry_count,
            "scheduled_delay_seconds": delay_seconds,
            "coalesced_agent_ids": [
                str(item.get("agent_id") or "").strip()
                for item in queue_entry["events"]
                if str(item.get("agent_id") or "").strip()
            ],
            "skip_reason": skip_reason,
        }
    _store_autorun_result_on_event_nodes(queue_entry["events"], queued_result)
    return queued_result


def _flush_orchestration_autorun_queue(
    root_agent_id: str,
    *,
    dry_run_override: bool | None = None,
) -> dict[str, Any]:
    _ensure_persisted_orchestration_autorun_queue_loaded()
    with _orchestration_autorun_queue_lock:
        entry = _orchestration_autorun_queue.get(root_agent_id)
        if not isinstance(entry, dict):
            return {
                "success": True,
                "queued": False,
                "triggered": False,
                "root_agent_id": root_agent_id,
                "skip_reason": "No queued orchestration follow-up was pending for this root subtree.",
            }
        timer = entry.get("timer")
        if isinstance(timer, threading.Timer):
            timer.cancel()
        _orchestration_autorun_queue.pop(root_agent_id, None)
        _persist_orchestration_autorun_queue_locked()

    lock = _orchestration_autorun_locks.setdefault(root_agent_id, threading.Lock())
    if not lock.acquire(blocking=False):
        return _requeue_orchestration_autorun_entry(
            root_agent_id,
            entry={
                **entry,
                "dry_run": bool(
                    dry_run_override if dry_run_override is not None else entry.get("dry_run")
                ),
            },
            delay_seconds=DEFAULT_AUTORUN_DEBOUNCE_SECONDS,
            retry_count=int(entry.get("retry_count") or 0),
            skip_reason="Another orchestration follow-up is already running for this root subtree.",
        )

    try:
        events = [dict(item) for item in list(entry.get("events") or []) if isinstance(item, dict)]
        fallback_state = entry.get("base_state")
        if fallback_state is None:
            return {
                "success": False,
                "queued": False,
                "triggered": False,
                "root_agent_id": root_agent_id,
                "error": "Queued orchestration follow-up lost its base agent state.",
            }

        base_state = _root_base_state(root_agent_id, fallback_state)
        restored_from_snapshot = _restore_root_state_from_snapshot(root_agent_id, entry)
        if restored_from_snapshot:
            base_state = _root_base_state(root_agent_id, entry.get("base_state") or fallback_state)
        root_node_present = root_agent_id in _agent_graph.get("nodes", {})
        retry_count = int(entry.get("retry_count") or 0)
        if not root_node_present and retry_count < AUTORUN_QUEUE_MAX_RETRIES:
            return _requeue_orchestration_autorun_entry(
                root_agent_id,
                entry=entry,
                delay_seconds=AUTORUN_QUEUE_RETRY_SECONDS,
                retry_count=retry_count + 1,
                skip_reason="Root subtree state is not available yet after restart; queued for retry.",
            )
        orchestrator_state = _orchestrator_agent_state(base_state)
        root_node = _agent_graph.get("nodes", {}).get(root_agent_id, {})
        root_status = str(root_node.get("status") or "").strip().lower()
        if root_status in {"completed", "finished", "failed", "stopped", "error"}:
            result = {
                "success": True,
                "queued": False,
                "triggered": False,
                "root_agent_id": root_agent_id,
                "completion_status": _coalesced_completion_status(events),
                "coalesced_agent_ids": [
                    str(item.get("agent_id") or "").strip()
                    for item in events
                    if str(item.get("agent_id") or "").strip()
                ],
                "batch_event_count": len(events),
                "skip_reason": f"Root subtree is already terminal ({root_status}).",
            }
        else:
            known_targets = _known_orchestration_targets(orchestrator_state)
            if not known_targets:
                snapshot = entry.get("root_runtime_snapshot")
                if isinstance(snapshot, dict):
                    known_targets = [
                        str(item).strip()
                        for item in list(snapshot.get("known_targets") or [])
                        if str(item).strip()
                    ]
            if not known_targets:
                result = {
                    "success": True,
                    "queued": False,
                    "triggered": False,
                    "root_agent_id": root_agent_id,
                    "completion_status": _coalesced_completion_status(events),
                    "coalesced_agent_ids": [
                        str(item.get("agent_id") or "").strip()
                        for item in events
                        if str(item.get("agent_id") or "").strip()
                    ],
                    "batch_event_count": len(events),
                    "skip_reason": "No assessment targets were available for orchestration follow-up.",
                }
            else:
                ordered_targets: list[str] = []
                for event in events:
                    ordered_targets.extend(
                        _task_target_candidates(
                            str(event.get("task") or ""),
                            known_targets,
                        )
                    )
                ordered_targets = _unique_strings([*ordered_targets, *known_targets])
                dry_run = bool(dry_run_override if dry_run_override is not None else entry.get("dry_run"))
                round_results: list[dict[str, Any]] = []
                triggered_targets: list[str] = []
                for target in ordered_targets:
                    round_result = run_attack_surface_orchestration_round(
                        agent_state=orchestrator_state,
                        target=target,
                        dry_run=dry_run,
                        inherit_context=True,
                        require_new_data=True,
                    )
                    round_results.append(
                        {
                            "target": target,
                            "success": bool(round_result.get("success")),
                            "skipped": bool(round_result.get("skipped")),
                            "round_number": round_result.get("round_number"),
                            "error": round_result.get("error"),
                        }
                    )
                    if round_result.get("success") and not round_result.get("skipped"):
                        triggered_targets.append(target)
                result = {
                    "success": True,
                    "queued": False,
                    "triggered": bool(triggered_targets),
                    "root_agent_id": root_agent_id,
                    "completion_status": _coalesced_completion_status(events),
                    "coalesced_agent_ids": [
                        str(item.get("agent_id") or "").strip()
                        for item in events
                        if str(item.get("agent_id") or "").strip()
                    ],
                    "batch_event_count": len(events),
                    "evaluated_targets": ordered_targets,
                    "triggered_targets": triggered_targets,
                    "round_results": round_results,
                    "skip_reason": None
                    if triggered_targets
                    else "No target produced a new orchestration round.",
                }
    except (TypeError, ValueError) as e:
        result = {
            "success": False,
            "queued": False,
            "triggered": False,
            "root_agent_id": root_agent_id,
            "error": f"Failed to flush auto-triggered attack-surface orchestration: {e}",
        }
    finally:
        lock.release()

    _store_autorun_result_on_event_nodes(events, result)
    return result


def trigger_attack_surface_orchestration_on_child_completion(
    agent_state: Any,
    *,
    completion_status: str | None = None,
    dry_run: bool = False,
    debounce_seconds: float = DEFAULT_AUTORUN_DEBOUNCE_SECONDS,
) -> dict[str, Any]:
    try:
        _ensure_persisted_orchestration_autorun_queue_loaded()
        if getattr(agent_state, "parent_id", None) is None:
            return {
                "success": True,
                "queued": False,
                "triggered": False,
                "skip_reason": "Root agent completion does not auto-trigger orchestration.",
            }

        agent_id = str(getattr(agent_state, "agent_id", "") or "").strip()
        node = _agent_graph.get("nodes", {}).get(agent_id, {})
        normalized_status = (
            str(completion_status or node.get("status") or "").strip().lower() or "completed"
        )
        if normalized_status not in {"completed", "finished", "failed", "stopped", "error"}:
            return {
                "success": True,
                "queued": False,
                "triggered": False,
                "skip_reason": f"Status '{normalized_status}' is not eligible for orchestration follow-up.",
            }

        orchestrator_state = _orchestrator_agent_state(agent_state)
        root_agent_id = str(orchestrator_state.agent_id or "").strip()
        if not root_agent_id or root_agent_id == agent_id:
            return {
                "success": True,
                "queued": False,
                "triggered": False,
                "skip_reason": "No distinct root subtree was available for orchestration follow-up.",
            }

        root_node = _agent_graph.get("nodes", {}).get(root_agent_id, {})
        root_status = str(root_node.get("status") or "").strip().lower()
        if root_status in {"completed", "finished", "failed", "stopped", "error"}:
            return {
                "success": True,
                "queued": False,
                "triggered": False,
                "skip_reason": f"Root subtree is already terminal ({root_status}).",
            }

        event = {
            "agent_id": agent_id,
            "task": str(node.get("task") or getattr(agent_state, "task", "") or ""),
            "completion_status": normalized_status,
            "finished_at": str(node.get("finished_at") or "").strip() or None,
        }
        known_targets = _known_orchestration_targets(orchestrator_state)
        if not known_targets:
            known_targets = _task_target_candidates(str(event.get("task") or ""), [])
        if not known_targets:
            return {
                "success": True,
                "queued": False,
                "triggered": False,
                "skip_reason": "No assessment targets were available for orchestration follow-up.",
            }

        with _orchestration_autorun_queue_lock:
            queue_entry = _orchestration_autorun_queue.get(root_agent_id)
            if not isinstance(queue_entry, dict):
                queue_entry = {"events": [], "timer": None}
            queue_entry["events"] = _merge_autorun_events(
                list(queue_entry.get("events") or []),
                [event],
            )
            queue_entry["base_state"] = _root_base_state(root_agent_id, agent_state)
            queue_entry["root_runtime_snapshot"] = _root_runtime_snapshot(
                root_agent_id,
                queue_entry.get("base_state"),
            )
            queue_entry["dry_run"] = bool(dry_run)
            queue_entry["last_enqueued_monotonic"] = time.monotonic()
            queue_entry["persisted_created_at"] = str(
                queue_entry.get("persisted_created_at") or _utc_now()
            )
            existing_timer = queue_entry.get("timer")
            if isinstance(existing_timer, threading.Timer):
                existing_timer.cancel()
            _orchestration_autorun_queue[root_agent_id] = queue_entry

            if debounce_seconds <= 0:
                queue_entry["timer"] = None
                queue_entry["execute_after_epoch"] = time.time()
            else:
                queue_entry["execute_after_epoch"] = time.time() + debounce_seconds
                queue_entry["timer"] = _schedule_autorun_timer_unlocked(
                    root_agent_id,
                    debounce_seconds,
                )
            queue_entry["retry_count"] = 0
            _persist_orchestration_autorun_queue_locked()
            queue_depth = len(list(queue_entry.get("events") or []))

        if debounce_seconds <= 0:
            return _flush_orchestration_autorun_queue(
                root_agent_id,
                dry_run_override=dry_run,
            )

    except (TypeError, ValueError) as e:
        return {
            "success": False,
            "queued": False,
            "triggered": False,
            "error": f"Failed to auto-trigger attack-surface orchestration: {e}",
        }
    else:
        return {
            "success": True,
            "queued": True,
            "triggered": False,
            "root_agent_id": root_agent_id,
            "completion_status": normalized_status,
            "evaluated_targets": _task_target_candidates(str(event.get("task") or ""), known_targets),
            "queue_depth": queue_depth,
            "scheduled_delay_seconds": debounce_seconds,
            "coalesced_agent_ids": [
                str(item.get("agent_id") or "").strip()
                for item in list(queue_entry.get("events") or [])
                if isinstance(item, dict) and str(item.get("agent_id") or "").strip()
            ],
            "skip_reason": None,
        }


def _phase_strategy_orders(
    *,
    strategy: str,
    needs_more_data: bool,
) -> tuple[list[str], list[str]]:
    if strategy == "coverage_first":
        return (
            [PHASE_RECON, PHASE_VALIDATION, PHASE_GAP_CLOSURE, PHASE_CHAINING],
            [PHASE_RECON, PHASE_GAP_CLOSURE, PHASE_VALIDATION, PHASE_CHAINING],
        )
    if strategy == "depth_first":
        return (
            [PHASE_VALIDATION, PHASE_CHAINING, PHASE_RECON, PHASE_GAP_CLOSURE],
            [PHASE_VALIDATION, PHASE_CHAINING, PHASE_RECON, PHASE_GAP_CLOSURE],
        )
    if needs_more_data:
        return (
            [PHASE_RECON, PHASE_VALIDATION, PHASE_GAP_CLOSURE, PHASE_CHAINING],
            [PHASE_RECON, PHASE_VALIDATION, PHASE_GAP_CLOSURE, PHASE_CHAINING],
        )
    return (
        [PHASE_VALIDATION, PHASE_CHAINING, PHASE_RECON, PHASE_GAP_CLOSURE],
        [PHASE_VALIDATION, PHASE_CHAINING, PHASE_RECON, PHASE_GAP_CLOSURE],
    )


def _phase_counts(candidates: list[dict[str, Any]]) -> dict[str, int]:
    counts = {phase: 0 for phase in PHASE_SEQUENCE}
    for candidate in candidates:
        phase = str(candidate.get("phase") or "")
        if phase in counts:
            counts[phase] += 1
    return counts


def _kind_counts(candidates: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for candidate in candidates:
        kind = str(candidate.get("kind") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
    return dict(sorted(counts.items()))


def _select_phase_swarm(
    *,
    candidates: list[dict[str, Any]],
    max_agents: int,
    strategy: str,
    needs_more_data: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    mandatory_order, fill_order = _phase_strategy_orders(
        strategy=strategy,
        needs_more_data=needs_more_data,
    )
    buckets: dict[str, list[dict[str, Any]]] = {
        phase: sorted(
            [item for item in candidates if str(item.get("phase") or "") == phase],
            key=_candidate_sort_key,
        )
        for phase in PHASE_SEQUENCE
    }
    selected: list[dict[str, Any]] = []
    selected_keys: set[str] = set()

    def pull(phase: str) -> dict[str, Any] | None:
        bucket = buckets.get(phase) or []
        while bucket:
            candidate = bucket.pop(0)
            dedupe_key = str(candidate.get("dedupe_key") or "")
            if dedupe_key and dedupe_key in selected_keys:
                continue
            if dedupe_key:
                selected_keys.add(dedupe_key)
            return candidate
        return None

    for phase in mandatory_order:
        if len(selected) >= max_agents:
            break
        candidate = pull(phase)
        if candidate is not None:
            selected.append(candidate)

    while len(selected) < max_agents:
        progressed = False
        for phase in fill_order:
            if len(selected) >= max_agents:
                break
            candidate = pull(phase)
            if candidate is None:
                continue
            selected.append(candidate)
            progressed = True
        if not progressed:
            break

    selected_phase_counts = _phase_counts(selected)
    remaining_count = sum(len(bucket) for bucket in buckets.values())
    return (
        selected,
        {
            "strategy": strategy,
            "needs_more_data": needs_more_data,
            "mandatory_phase_order": mandatory_order,
            "fill_phase_order": fill_order,
            "selected_phase_counts": selected_phase_counts,
            "remaining_candidate_count": remaining_count,
        },
    )


def _candidate(
    *,
    dedupe_key: str,
    phase: str,
    name: str,
    task: str,
    skills: list[str],
    priority: str,
    kind: str,
) -> dict[str, Any]:
    return {
        "dedupe_key": dedupe_key,
        "phase": phase,
        "name": name,
        "task": task,
        "skills": _skills_csv(skills),
        "priority": priority,
        "kind": kind,
    }


@register_tool(sandbox_execution=False)
def spawn_attack_surface_agents(
    agent_state: Any,
    target: str,
    max_agents: int = 6,
    strategy: str = "balanced",
    dry_run: bool = False,
    inherit_context: bool = False,
    include_recon: bool = True,
    include_validation: bool = True,
    include_chains: bool = True,
    include_blind_spots: bool = True,
) -> dict[str, Any]:
    try:
        normalized_target = _normalize_non_empty(target, "target")
        if max_agents < 1:
            raise ValueError("max_agents must be >= 1")
        normalized_strategy = _normalize_swarm_strategy(strategy)

        review_result = list_attack_surface_reviews(
            agent_state=agent_state,
            target=normalized_target,
            include_report=True,
            max_items=1,
        )
        if not review_result.get("success"):
            raise ValueError(str(review_result.get("error") or "Failed to load review"))

        records = [item for item in list(review_result.get("records") or []) if isinstance(item, dict)]
        if not records:
            raise ValueError(f"No attack surface review found for target '{normalized_target}'")

        report = records[0].get("report") or {}
        if not isinstance(report, dict):
            raise ValueError("Attack surface review report is unavailable")

        priorities = report.get("priorities") or {}
        service_inventory = [
            item
            for item in list(report.get("service_inventory") or [])
            if isinstance(item, dict)
        ]
        prioritized_services = [
            item
            for item in list(priorities.get("top_services_next") or service_inventory)
            if isinstance(item, dict)
        ]
        application_inventory = [
            item
            for item in list(report.get("application_inventory") or [])
            if isinstance(item, dict)
        ]
        prioritized_modules = [
            item
            for item in list(priorities.get("top_modules_next") or application_inventory)
            if isinstance(item, dict)
        ]
        parameter_review = (
            report.get("parameter_object_review")
            if isinstance(report.get("parameter_object_review"), dict)
            else {}
        )
        object_inventory = [
            item
            for item in list(parameter_review.get("objects") or [])
            if isinstance(item, dict)
        ]
        prioritized_objects = [
            item
            for item in list(priorities.get("top_objects_next") or object_inventory)
            if isinstance(item, dict)
        ]
        coverage_ledger = (
            report.get("coverage_ledger")
            if isinstance(report.get("coverage_ledger"), dict)
            else {}
        )
        role_entries = [
            item
            for item in list(coverage_ledger.get("role_boundary") or [])
            if isinstance(item, dict)
        ]
        prioritized_role_entries = [
            item
            for item in list(priorities.get("top_role_boundaries_next") or role_entries)
            if isinstance(item, dict)
        ]
        bug_class_entries = [
            item for item in list(coverage_ledger.get("bug_class") or []) if isinstance(item, dict)
        ]
        prioritized_bug_class_entries = [
            item
            for item in list(priorities.get("top_bug_class_gaps_next") or bug_class_entries)
            if isinstance(item, dict)
        ]
        summary = report.get("summary") or {}
        needs_more_data = bool(summary.get("needs_more_data"))
        active_keys = _active_delegation_keys(agent_state.agent_id)
        suppressed_keys = _suppressed_delegation_keys(agent_state)
        terminal_blocked_keys = _blocked_terminal_delegation_keys(agent_state)
        blocked_keys = {*active_keys, *suppressed_keys, *terminal_blocked_keys}
        candidates: list[dict[str, Any]] = []
        seen_keys: set[str] = set()

        def enqueue(candidate: dict[str, Any]) -> None:
            key = str(candidate["dedupe_key"])
            if key in seen_keys:
                return
            seen_keys.add(key)
            candidate = dict(candidate)
            candidate["task"] = _with_round_followup(
                str(candidate.get("task") or ""),
                target=normalized_target,
            )
            candidates.append(candidate)

        if include_recon:
            for host_row in list(priorities.get("top_targets_next") or []):
                if not isinstance(host_row, dict):
                    continue
                host = str(host_row.get("host") or "").strip()
                if not host:
                    continue
                coverage_status = str(host_row.get("coverage_status") or "")
                if coverage_status == "covered":
                    continue
                if str(host_row.get("signal_classification") or "") == "out-of-scope":
                    continue
                host_type = str(host_row.get("preliminary_type") or "unknown")
                priority = str(host_row.get("priority") or "normal")
                signal_classification = str(host_row.get("signal_classification") or "").strip()
                resolve_status = str(host_row.get("resolve_status") or "").strip() or "needs more data"
                discovery_sources = list(host_row.get("sources") or [])
                host_notes = list(host_row.get("notes") or [])
                enqueue(
                    _candidate(
                        dedupe_key=f"recon-host|{host}",
                        phase=PHASE_RECON,
                        name=f"P1 Recon {host}",
                        priority=priority,
                        kind="host-recon",
                        skills=_host_recon_skills(
                            host_type,
                            signal_classification=signal_classification,
                            resolve_status=resolve_status,
                        ),
                        task=(
                            f"Delegation key: recon-host|{host}\n"
                            f"Phase: Phase 1 layered reconnaissance and surface expansion\n"
                            f"Target host: {host}\n"
                            f"Host type hint: {host_type}\n"
                            f"Signal classification: {signal_classification or 'needs more data'}\n"
                            f"Resolve status: {resolve_status}\n"
                            f"Discovery sources: {discovery_sources or ['needs more data']}\n"
                            f"Host notes: {host_notes or ['none recorded']}\n"
                            f"Coverage status: {coverage_status or 'needs more data'}\n"
                            "Objective:\n"
                            f"{_host_recon_objective(host_row)}"
                        ),
                    )
                )

            for service_row in prioritized_services:
                host = str(service_row.get("host") or "").strip()
                protocol = str(service_row.get("protocol") or "").strip() or "tcp"
                port = service_row.get("port")
                if not host or port is None:
                    continue
                coverage_status = str(service_row.get("coverage_status") or "").strip().lower()
                fingerprint = list(service_row.get("fingerprint") or [])
                auth_wall = str(service_row.get("auth_wall") or "").strip() or "needs more data"
                if coverage_status == "covered" and fingerprint != ["needs more data"] and auth_wall != "needs more data":
                    continue
                priority = "normal"
                if auth_wall in {"protected", "mixed", "likely protected"}:
                    priority = "high"
                if int(port) not in {80, 443} or fingerprint == ["needs more data"]:
                    priority = "high"
                if any(str(item).strip() for item in list(service_row.get("bug_classes") or [])):
                    priority = "critical"
                enqueue(
                    _candidate(
                        dedupe_key=f"recon-service|{host}|{port}|{protocol}",
                        phase=PHASE_RECON,
                        name=f"P1 Service {host}:{port}/{protocol}",
                        priority=priority,
                        kind="service-recon",
                        skills=_service_recon_skills(service_row),
                        task=(
                            f"Delegation key: recon-service|{host}|{port}|{protocol}\n"
                            "Phase: Phase 1 service/port/protocol reconnaissance\n"
                            f"Target service: {host}:{port}/{protocol}\n"
                            f"Fingerprint: {fingerprint or ['needs more data']}\n"
                            f"App family: {service_row.get('app_family') or ['unknown']}\n"
                            f"Auth wall: {auth_wall}\n"
                            f"Privilege boundary: {service_row.get('privilege_boundary') or ['needs more data']}\n"
                            "Objective:\n"
                            "- Fingerprint the service, redirect behavior, TLS/cert clues, and exposed app family.\n"
                            "- Check for docs, admin panels, GraphQL, WebSocket, status, debug, and alternate protocol hints.\n"
                            "- Reduce host -> service blind spots before deeper bug validation."
                        ),
                    )
                )

            for module_row in prioritized_modules:
                host = str(module_row.get("host") or "").strip()
                module_name = str(module_row.get("application_module") or "").strip()
                if not host or not module_name:
                    continue
                hidden_routes = list(module_row.get("hidden_routes") or [])
                docs_endpoints = list(module_row.get("docs_endpoints") or [])
                config_artifacts = list(module_row.get("config_artifacts") or [])
                backup_artifacts = list(module_row.get("backup_artifacts") or [])
                auth_surfaces = list(module_row.get("auth_surfaces") or [])
                billing_surfaces = list(module_row.get("billing_surfaces") or [])
                upload_surfaces = list(module_row.get("upload_surfaces") or [])
                coverage_status = str(module_row.get("coverage_status") or "").strip().lower()
                if (
                    coverage_status == "covered"
                    and not hidden_routes
                    and not docs_endpoints
                    and not config_artifacts
                    and not backup_artifacts
                ):
                    continue
                priority = "normal"
                if config_artifacts or backup_artifacts:
                    priority = "critical"
                elif hidden_routes or docs_endpoints or auth_surfaces or billing_surfaces or upload_surfaces:
                    priority = "high"
                enqueue(
                    _candidate(
                        dedupe_key=f"app-surface|{host}|{module_name}",
                        phase=PHASE_RECON,
                        name=f"P1 Module {host}:{module_name}",
                        priority=priority,
                        kind="app-surface-review",
                        skills=_module_review_skills(module_row),
                        task=(
                            f"Delegation key: app-surface|{host}|{module_name}\n"
                            "Phase: Phase 1 app/module surface expansion\n"
                            f"Target module: {module_name} on {host}\n"
                            f"Root paths: {module_row.get('root_paths') or ['needs more data']}\n"
                            f"Major sections: {module_row.get('major_sections') or ['needs more data']}\n"
                            f"Hidden routes: {hidden_routes or ['needs more data']}\n"
                            f"Docs endpoints: {docs_endpoints or ['needs more data']}\n"
                            f"Config artifacts: {config_artifacts or ['none seen']}\n"
                            f"Backup artifacts: {backup_artifacts or ['none seen']}\n"
                            "Objective:\n"
                            "- Map this module from root paths into hidden routes, docs, uploads/downloads, auth, and billing surfaces.\n"
                            "- Extract overlooked routes, files, and pivots that a broad crawl may have missed.\n"
                            "- Update the attack-surface graph and coverage ledger instead of narrating broadly."
                        ),
                    )
                )

        if include_validation:
            for endpoint_row in list(priorities.get("top_endpoints_next") or []):
                if not isinstance(endpoint_row, dict):
                    continue
                host = str(endpoint_row.get("host") or "").strip()
                path = str(endpoint_row.get("path") or "").strip()
                if not host or not path:
                    continue
                if str(endpoint_row.get("coverage_status") or "") == "covered":
                    continue
                if str(endpoint_row.get("signal_classification") or "") == "out-of-scope":
                    continue
                bug_classes = [
                    str(item)
                    for item in list(endpoint_row.get("bug_classes") or [])
                    if str(item).strip()
                ]
                methods = [str(item) for item in list(endpoint_row.get("methods") or []) if str(item).strip()]
                params = endpoint_row.get("params") or {}
                enqueue(
                    _candidate(
                        dedupe_key=f"validate-endpoint|{host}|{path}",
                        phase=PHASE_VALIDATION,
                        name=f"P2 Validate {host}{path}",
                        priority=str(endpoint_row.get("priority") or "normal"),
                        kind="endpoint-validation",
                        skills=_bug_skills(bug_classes, str(endpoint_row.get("application_module") or "")),
                        task=(
                            f"Delegation key: validate-endpoint|{host}|{path}\n"
                            "Phase: Phase 2 focused endpoint validation\n"
                            f"Target endpoint: {host}{path}\n"
                            f"Methods: {', '.join(methods) or 'needs more data'}\n"
                            f"Priority: {endpoint_row.get('priority') or 'normal'}\n"
                            f"Bug classes to prioritize: {', '.join(bug_classes) or 'needs more data'}\n"
                            f"Params seen: {params}\n"
                            f"Trust boundaries: {endpoint_row.get('trust_boundaries') or []}\n"
                            "Objective:\n"
                            "- Go deep on this exact endpoint instead of broad sweeping.\n"
                            "- Check authn/authz, hidden params, object-level access, business logic, and chain pivots relevant to the mapped bug classes.\n"
                            "- Compare contexts/roles/tenant boundaries when the surface implies it.\n"
                            "- If confirmed, spawn the narrow validation/reporting chain for this bug."
                        ),
                    )
                )

            for param_row in list(priorities.get("top_params_objects") or []):
                if not isinstance(param_row, dict):
                    continue
                host = str(param_row.get("host") or "").strip()
                path = str(param_row.get("path") or "").strip()
                parameter = str(param_row.get("parameter") or "").strip()
                if not host or not path or not parameter:
                    continue
                if not bool(param_row.get("pivot_point")):
                    continue
                enqueue(
                    _candidate(
                        dedupe_key=f"pivot-param|{host}|{path}|{parameter}",
                        phase=PHASE_VALIDATION,
                        name=f"P2 Pivot {parameter} on {host}{path}",
                        priority="high",
                        kind="param-pivot",
                        skills=_bug_skills(
                            [str(item) for item in list(param_row.get("bug_classes") or [])],
                            "",
                        ),
                        task=(
                            f"Delegation key: pivot-param|{host}|{path}|{parameter}\n"
                            "Phase: Phase 2 parameter/object pivot validation\n"
                            f"Target parameter: {parameter} on {host}{path}\n"
                            f"Locations: {param_row.get('locations') or []}\n"
                            f"Bug classes: {param_row.get('bug_classes') or []}\n"
                            "Objective:\n"
                            "- Treat this parameter as a possible pivot point for authz, SSRF, redirect, traversal, token, or business-state abuse.\n"
                            "- Test parameter semantics, object ownership, server-vs-client trust, and chain value.\n"
                            "- Record whether the signal is confirmed, suspected, or needs more data."
                        ),
                    )
                )

            for object_row in prioritized_objects:
                host = str(object_row.get("host") or "").strip()
                object_type = str(object_row.get("object_type") or "").strip()
                if not host or not object_type:
                    continue
                identifiers = [str(item) for item in list(object_row.get("identifiers") or []) if str(item).strip()]
                fields = [str(item) for item in list(object_row.get("fields") or []) if str(item).strip()]
                trust_boundaries = [
                    str(item)
                    for item in list(object_row.get("trust_boundaries") or [])
                    if str(item).strip()
                ]
                bug_classes = [
                    str(item) for item in list(object_row.get("bug_classes") or []) if str(item).strip()
                ]
                coverage_status = str(object_row.get("coverage_status") or "").strip().lower()
                if coverage_status == "covered" and not identifiers and not bug_classes:
                    continue
                priority = "high"
                if any(
                    marker in " ".join([object_type, *identifiers, *trust_boundaries, *bug_classes]).lower()
                    for marker in ["tenant", "role", "permission", "billing", "token", "invite"]
                ):
                    priority = "critical"
                enqueue(
                    _candidate(
                        dedupe_key=f"object-boundary|{host}|{object_type}",
                        phase=PHASE_VALIDATION,
                        name=f"P2 Object {object_type} on {host}",
                        priority=priority,
                        kind="object-boundary",
                        skills=_bug_skills([object_type, *bug_classes, *trust_boundaries], object_type),
                        task=(
                            f"Delegation key: object-boundary|{host}|{object_type}\n"
                            "Phase: Phase 2 object/boundary validation\n"
                            f"Target object type: {object_type} on {host}\n"
                            f"Related paths: {object_row.get('related_paths') or ['needs more data']}\n"
                            f"Identifiers: {identifiers or ['needs more data']}\n"
                            f"Fields: {fields or ['needs more data']}\n"
                            f"Trust boundaries: {trust_boundaries or ['needs more data']}\n"
                            f"Bug classes: {bug_classes or ['needs more data']}\n"
                            "Objective:\n"
                            "- Treat this object model as a pivot for BOLA, tenant isolation, field-level auth, mass assignment, and workflow abuse.\n"
                            "- Check whether identifiers, owner fields, role flags, or tenant hints open chainable access paths.\n"
                            "- Record confirmed, suspected, or needs more data against the exact object boundary."
                        ),
                    )
                )

        if include_chains:
            for exposure_row in list(priorities.get("top_recon_value_exposures") or []):
                if not isinstance(exposure_row, dict):
                    continue
                host = str(exposure_row.get("host") or "").strip()
                path = str(exposure_row.get("path") or "").strip()
                kind = str(exposure_row.get("kind") or "").strip()
                exposure_class = str(exposure_row.get("exposure_class") or "").strip().lower()
                if not host or not path:
                    continue
                if "chain" not in exposure_class and "exploit" not in exposure_class:
                    continue
                enqueue(
                    _candidate(
                        dedupe_key=f"exposure-chain|{host}|{path}|{kind}",
                        phase=PHASE_CHAINING,
                        name=f"P3 Exposure Chain {host}{path}",
                        priority="high",
                        kind="exposure-chain",
                        skills=["httpx", "katana", "graphql", "nuclei"],
                        task=(
                            f"Delegation key: exposure-chain|{host}|{path}|{kind}\n"
                            "Phase: Phase 3 chain-building from low-signal exposure\n"
                            f"Exposure asset: {host}{path}\n"
                            f"Exposure kind: {kind}\n"
                            f"Classification: {exposure_row.get('exposure_class')}\n"
                            "Objective:\n"
                            "- Treat this exposure as a pivot, not a final finding.\n"
                            "- Use it to uncover hidden routes, object model clarity, auth drift, workflow abuse, or other chained impact.\n"
                            "- Prefer concrete chained exploitability over isolated noise."
                        ),
                    )
                )

            for chain_row in list(priorities.get("top_chain_opportunities") or report.get("chain_analysis") or []):
                if not isinstance(chain_row, dict):
                    continue
                summary_text = str(chain_row.get("summary") or "").strip()
                if not summary_text:
                    continue
                boundary = str(chain_row.get("boundary") or "chain boundary").strip()
                skills = _bug_skills([summary_text, boundary], "")
                if not skills:
                    skills = ["business_logic", "idor", "ssrf"]
                key_fragment = summary_text.lower().replace(" ", "-")[:40]
                enqueue(
                    _candidate(
                        dedupe_key=f"chain-opportunity|{key_fragment}",
                        phase=PHASE_CHAINING,
                        name=f"P3 Chain {boundary}",
                        priority="high",
                        kind="chain-validation",
                        skills=skills,
                        task=(
                            f"Delegation key: chain-opportunity|{key_fragment}\n"
                            "Phase: Phase 3 chain validation\n"
                            f"Chain hypothesis: {summary_text}\n"
                            f"Boundary: {boundary}\n"
                            f"Assets: {chain_row.get('assets') or []}\n"
                            "Objective:\n"
                            "- Validate whether the mapped signals can be chained into materially higher impact.\n"
                            "- Prefer full end-to-end chains over isolated confirmations.\n"
                            "- If the chain fails, explain what evidence is still missing."
                        ),
                    )
                )

        if include_blind_spots:
            for blind_row in list(priorities.get("top_blind_spots") or []):
                if not isinstance(blind_row, dict):
                    continue
                area = str(blind_row.get("area") or "").strip()
                detail = str(blind_row.get("detail") or "").strip()
                target_asset = str(blind_row.get("target_asset") or "").strip()
                if not area:
                    continue
                enqueue(
                    _candidate(
                        dedupe_key=f"blind-spot|{area}|{target_asset}",
                        phase=PHASE_GAP_CLOSURE,
                        name=f"Gap {area}",
                        priority="high" if "needs more data" in detail.lower() else "normal",
                        kind="blind-spot-closure",
                        skills=_blind_spot_skills(area),
                        task=(
                            f"Delegation key: blind-spot|{area}|{target_asset}\n"
                            "Phase: Coverage gap closure\n"
                            f"Blind-spot area: {area}\n"
                            f"Target asset: {target_asset or 'broad scope'}\n"
                            f"Detail: {detail}\n"
                            "Objective:\n"
                            "- Reduce this blind spot with concrete evidence.\n"
                            "- Update coverage ledger with covered / blocked / needs more data rationale.\n"
                            "- Do not claim full coverage; focus on making the blind spot smaller and more explicit."
                        ),
                    )
                )

            for role_entry in prioritized_role_entries:
                boundary = str(role_entry.get("boundary") or "").strip()
                status = str(role_entry.get("status") or "").strip().lower()
                signal_classification = str(role_entry.get("signal_classification") or "").strip().lower()
                if not boundary:
                    continue
                if status == "covered" and signal_classification != "blind-spot":
                    continue
                priority = "high" if boundary in {"privileged test role", "tenant A/B"} else "normal"
                enqueue(
                    _candidate(
                        dedupe_key=f"role-boundary|{boundary}",
                        phase=PHASE_GAP_CLOSURE,
                        name=f"Gap role {boundary}",
                        priority=priority,
                        kind="role-boundary-closure",
                        skills=_boundary_skills(boundary),
                        task=(
                            f"Delegation key: role-boundary|{boundary}\n"
                            "Phase: Coverage gap closure\n"
                            f"Boundary gap: {boundary}\n"
                            f"Current status: {status or 'needs more data'}\n"
                            "Objective:\n"
                            "- Reduce this role or state boundary blind spot with concrete session, request, or browser evidence.\n"
                            "- Focus on guest/user/privileged/tenant/state separation rather than generic scanning.\n"
                            "- Mark clearly whether the gap is now covered, still blocked, or still needs more data."
                        ),
                    )
                )

            for bug_class_entry in prioritized_bug_class_entries:
                bug_class = str(bug_class_entry.get("bug_class") or "").strip()
                status = str(bug_class_entry.get("status") or "").strip().lower()
                if not bug_class or status in {"reasonably covered", "strong coverage"}:
                    continue
                priority = (
                    "high"
                    if bug_class in {"Authentication", "Authorization", "Business logic"}
                    else "normal"
                )
                enqueue(
                    _candidate(
                        dedupe_key=f"bug-class-gap|{bug_class}",
                        phase=PHASE_GAP_CLOSURE,
                        name=f"Gap {bug_class}",
                        priority=priority,
                        kind="bug-class-gap-closure",
                        skills=_bug_skills([bug_class], bug_class) or _blind_spot_skills("workflow coverage"),
                        task=(
                            f"Delegation key: bug-class-gap|{bug_class}\n"
                            "Phase: Coverage gap closure\n"
                            f"Bug-class coverage gap: {bug_class}\n"
                            f"Current status: {status or 'blocked by missing data'}\n"
                            f"Surface signal count: {bug_class_entry.get('surface_signal_count') or 0}\n"
                            f"Hypothesis count: {bug_class_entry.get('hypothesis_count') or 0}\n"
                            "Objective:\n"
                            "- Improve this bug-class coverage with concrete target selection, not generic checklists.\n"
                            "- Tie new testing back to exact assets, boundaries, and signals already present in the review.\n"
                            "- Leave an explicit ledger trail of what remains blind."
                        ),
                    )
                )

        duplicate_candidates = [
            candidate
            for candidate in candidates
            if str(candidate.get("dedupe_key") or "") in blocked_keys
        ]
        eligible_candidates = [
            candidate
            for candidate in candidates
            if str(candidate.get("dedupe_key") or "") not in blocked_keys
        ]
        recommended, phase_plan = _select_phase_swarm(
            candidates=eligible_candidates,
            max_agents=max_agents,
            strategy=normalized_strategy,
            needs_more_data=needs_more_data,
        )

        created: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = [
            {
                "dedupe_key": str(candidate.get("dedupe_key") or ""),
                "name": candidate.get("name"),
                "phase": candidate.get("phase"),
                "kind": candidate.get("kind"),
                "reason": (
                    "recent duplicate just completed in current agent subtree"
                    if str(candidate.get("dedupe_key") or "") in suppressed_keys
                    else (
                        "duplicate already completed earlier in current agent subtree and no new coverage/evidence/review was observed"
                        if str(candidate.get("dedupe_key") or "") in terminal_blocked_keys
                        else "active duplicate already exists in current agent subtree"
                    )
                ),
            }
            for candidate in duplicate_candidates
        ]
        for candidate in recommended:
            dedupe_key = str(candidate["dedupe_key"])
            if dry_run:
                created.append(
                    {
                        "dry_run": True,
                        "dedupe_key": dedupe_key,
                        "name": candidate["name"],
                        "phase": candidate["phase"],
                        "kind": candidate["kind"],
                        "skills": candidate["skills"].split(",") if candidate["skills"] else [],
                    }
                )
                continue

            result = create_agent(
                agent_state=agent_state,
                task=str(candidate["task"]),
                name=str(candidate["name"]),
                inherit_context=inherit_context,
                skills=candidate["skills"],
            )
            if result.get("success"):
                created.append(
                    {
                        "agent_id": result.get("agent_id"),
                        "dedupe_key": dedupe_key,
                        "name": candidate["name"],
                        "phase": candidate["phase"],
                        "kind": candidate["kind"],
                        "skills": result.get("active_skills") or [],
                    }
                )
                active_keys.add(dedupe_key)
            else:
                skipped.append(
                    {
                        "dedupe_key": dedupe_key,
                        "name": candidate["name"],
                        "reason": result.get("error") or "create_agent failed",
                    }
                )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to spawn attack-surface agents: {e}"}
    else:
        return {
            "success": True,
            "target": normalized_target,
            "summary": {
                "host_count": int(summary.get("host_count") or 0),
                "path_count": int(summary.get("path_count") or 0),
                "blind_spot_count": int(summary.get("blind_spot_count") or 0),
                "needs_more_data": bool(summary.get("needs_more_data")),
            },
            "strategy": normalized_strategy,
            "phase_plan": {
                **phase_plan,
                "available_phase_counts": _phase_counts(candidates),
                "eligible_phase_counts": _phase_counts(eligible_candidates),
                "duplicate_phase_counts": _phase_counts(duplicate_candidates),
                "available_kind_counts": _kind_counts(candidates),
                "eligible_kind_counts": _kind_counts(eligible_candidates),
                "duplicate_kind_counts": _kind_counts(duplicate_candidates),
            },
            "recommended_count": len(recommended),
            "created_count": len(created),
            "skipped_count": len(skipped),
            "dry_run": dry_run,
            "created_agents": created,
            "skipped_agents": skipped,
        }


@register_tool(sandbox_execution=False)
def spawn_strong_signal_agents(
    agent_state: Any,
    target: str,
    max_agents: int = 3,
    hypothesis_ids: list[str] | None = None,
    min_priority: str = "high",
    minimum_score: int = 4,
    dry_run: bool = False,
    inherit_context: bool = False,
) -> dict[str, Any]:
    try:
        normalized_target = _normalize_non_empty(target, "target")
        if max_agents < 1:
            raise ValueError("max_agents must be >= 1")
        if minimum_score < 1:
            raise ValueError("minimum_score must be >= 1")
        normalized_min_priority = str(min_priority).strip().lower()
        if normalized_min_priority not in VALID_PRIORITIES:
            raise ValueError(
                f"min_priority must be one of: {', '.join(VALID_PRIORITIES)}"
            )

        requested_hypothesis_ids = {
            str(item).strip()
            for item in list(hypothesis_ids or [])
            if str(item).strip()
        }
        assessment_result = list_assessment_state(
            agent_state=agent_state,
            include_resolved_coverage=True,
            include_evidence=True,
            max_items=max(100, max_agents * 40),
        )
        if not assessment_result.get("success"):
            raise ValueError(str(assessment_result.get("error") or "Failed to load assessment state"))

        hypotheses = [
            item
            for item in list(assessment_result.get("hypotheses") or [])
            if isinstance(item, dict) and str(item.get("target") or "").strip() == normalized_target
        ]
        evidence_records = [
            item for item in list(assessment_result.get("evidence") or []) if isinstance(item, dict)
        ]
        active_keys = _active_delegation_keys(agent_state.agent_id)
        suppressed_keys = _suppressed_delegation_keys(agent_state)
        terminal_blocked_keys = _blocked_terminal_delegation_keys(agent_state)
        blocked_keys = {*active_keys, *suppressed_keys, *terminal_blocked_keys}
        candidates: list[dict[str, Any]] = []

        for hypothesis in hypotheses:
            hypothesis_id = str(hypothesis.get("hypothesis_id") or "").strip()
            if not hypothesis_id:
                continue
            if requested_hypothesis_ids and hypothesis_id not in requested_hypothesis_ids:
                continue
            status = str(hypothesis.get("status") or "open").strip().lower()
            if status not in SUPPORTED_SIGNAL_STATUSES:
                continue

            priority = str(hypothesis.get("priority") or "normal").strip().lower()
            vulnerability_type = str(hypothesis.get("vulnerability_type") or "general").strip().lower()
            if (
                not requested_hypothesis_ids
                and vulnerability_type in {"", "general", "misconfiguration", "scanner_finding"}
            ):
                continue

            related_evidence = _evidence_for_hypothesis(
                evidence_records,
                hypothesis_id=hypothesis_id,
                component=str(hypothesis.get("component") or ""),
                target=normalized_target,
            )
            signal_score = _signal_score(hypothesis, related_evidence)
            if not requested_hypothesis_ids:
                if _priority_rank(priority) < _priority_rank(normalized_min_priority):
                    continue
                if signal_score < minimum_score:
                    continue

            hypothesis_text = str(hypothesis.get("hypothesis") or "").strip()
            rationale = str(hypothesis.get("rationale") or "").strip()
            component = str(hypothesis.get("component") or "").strip() or "general"
            focus = _focus_for_vulnerability(
                vulnerability_type,
                text=" ".join([hypothesis_text, rationale]),
            )
            candidate_urls = _signal_candidate_urls(hypothesis, related_evidence)
            component_hints = _component_asset_hints(component)
            host = str(component_hints.get("host") or "").strip()
            path = str(component_hints.get("path") or "/").strip() or "/"
            target_label = host + path if host else component
            evidence_ids = [
                str(item.get("evidence_id") or "").strip()
                for item in related_evidence
                if str(item.get("evidence_id") or "").strip()
            ]
            skills = _bug_skills(
                [vulnerability_type, hypothesis_text, rationale, focus or ""],
                component,
            )
            if not skills and focus:
                skills = _bug_skills([focus], component)
            if not skills:
                skills = ["httpx", "nuclei"]
            highlights = _evidence_highlights(related_evidence)
            dedupe_key = f"validate-hypothesis|{hypothesis_id}"
            candidates.append(
                {
                    "dedupe_key": dedupe_key,
                    "phase": PHASE_VALIDATION if status != "validated" else PHASE_CHAINING,
                    "kind": "signal-validation",
                    "name": (
                        f"Validate {vulnerability_type or 'signal'} on {target_label}"
                        if target_label
                        else f"Validate signal {hypothesis_id}"
                    ),
                    "priority": priority,
                    "skills": _skills_csv(skills),
                    "signal_score": signal_score,
                    "hypothesis_id": hypothesis_id,
                    "vulnerability_type": vulnerability_type,
                    "status": status,
                    "component": component,
                    "suggested_focus": focus,
                    "candidate_urls": candidate_urls,
                    "evidence_ids": evidence_ids,
                    "task": (
                        _with_round_followup(
                            (
                                f"Delegation key: {dedupe_key}\n"
                                "Phase: Narrow strong-signal validation and impact escalation\n"
                                f"Target label: {normalized_target}\n"
                                f"Hypothesis ID: {hypothesis_id}\n"
                                f"Vulnerability type: {vulnerability_type or 'needs more data'}\n"
                                f"Status: {status}\n"
                                f"Priority: {priority}\n"
                                f"Signal score: {signal_score}\n"
                                f"Component: {component}\n"
                                f"Suggested focus pipeline: {focus or 'needs more data'}\n"
                                f"Candidate URLs: {candidate_urls or ['needs more data']}\n"
                                f"Supporting evidence IDs: {evidence_ids or ['needs more data']}\n"
                                f"Evidence highlights: {highlights or ['needs more data']}\n"
                                "Objective:\n"
                                "- Validate or reject this exact signal quickly; avoid broadening scope prematurely.\n"
                                "- Reproduce with the narrowest meaningful request sequence or the mapped focus pipeline.\n"
                                "- If the signal holds, push beyond existence into auth boundary, object scope, exploitability, and chainable impact.\n"
                                f"- If you confirm or materially strengthen this bug, immediately call "
                                f"spawn_impact_chain_agents(target='{normalized_target}', hypothesis_ids=['{hypothesis_id}'], inherit_context=True) "
                                "before finishing so a dedicated impact/chaining agent continues the escalation.\n"
                                "- Update the assessment ledger with validated, rejected, or blocked state plus durable evidence.\n"
                                "- If the signal is insufficient, state needs more data explicitly instead of guessing."
                            ),
                            target=normalized_target,
                        )
                    ),
                }
            )

        candidates.sort(key=_signal_candidate_sort_key)
        duplicate_candidates = [
            candidate
            for candidate in candidates
            if str(candidate.get("dedupe_key") or "") in blocked_keys
        ]
        eligible_candidates = [
            candidate
            for candidate in candidates
            if str(candidate.get("dedupe_key") or "") not in blocked_keys
        ]
        recommended = eligible_candidates[:max_agents]

        created: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = [
            {
                "dedupe_key": str(candidate.get("dedupe_key") or ""),
                "name": candidate.get("name"),
                "hypothesis_id": candidate.get("hypothesis_id"),
                "reason": (
                    "recent duplicate just completed in current agent subtree"
                    if str(candidate.get("dedupe_key") or "") in suppressed_keys
                    else (
                        "duplicate already completed earlier in current agent subtree and no new coverage/evidence/review was observed"
                        if str(candidate.get("dedupe_key") or "") in terminal_blocked_keys
                        else "active duplicate already exists in current agent subtree"
                    )
                ),
            }
            for candidate in duplicate_candidates
        ]
        for candidate in recommended:
            if dry_run:
                created.append(
                    {
                        "dry_run": True,
                        "dedupe_key": candidate["dedupe_key"],
                        "name": candidate["name"],
                        "phase": candidate["phase"],
                        "kind": candidate["kind"],
                        "hypothesis_id": candidate["hypothesis_id"],
                        "signal_score": candidate["signal_score"],
                        "suggested_focus": candidate["suggested_focus"],
                        "candidate_urls": list(candidate["candidate_urls"]),
                        "evidence_ids": list(candidate["evidence_ids"]),
                        "skills": candidate["skills"].split(",") if candidate["skills"] else [],
                    }
                )
                continue

            result = create_agent(
                agent_state=agent_state,
                task=str(candidate["task"]),
                name=str(candidate["name"]),
                inherit_context=inherit_context,
                skills=candidate["skills"],
            )
            if result.get("success"):
                created.append(
                    {
                        "agent_id": result.get("agent_id"),
                        "dedupe_key": candidate["dedupe_key"],
                        "name": candidate["name"],
                        "phase": candidate["phase"],
                        "kind": candidate["kind"],
                        "hypothesis_id": candidate["hypothesis_id"],
                        "signal_score": candidate["signal_score"],
                        "suggested_focus": candidate["suggested_focus"],
                        "candidate_urls": list(candidate["candidate_urls"]),
                        "evidence_ids": list(candidate["evidence_ids"]),
                        "skills": result.get("active_skills") or [],
                    }
                )
                active_keys.add(str(candidate["dedupe_key"]))
            else:
                skipped.append(
                    {
                        "dedupe_key": candidate["dedupe_key"],
                        "name": candidate["name"],
                        "hypothesis_id": candidate["hypothesis_id"],
                        "reason": result.get("error") or "create_agent failed",
                    }
                )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to spawn strong-signal agents: {e}"}
    else:
        return {
            "success": True,
            "target": normalized_target,
            "requested_hypothesis_ids": sorted(requested_hypothesis_ids),
            "candidate_count": len(candidates),
            "eligible_count": len(eligible_candidates),
            "recommended_count": len(recommended),
            "created_count": len(created),
            "skipped_count": len(skipped),
            "dry_run": dry_run,
            "created_agents": created,
            "skipped_agents": skipped,
        }


@register_tool(sandbox_execution=False)
def spawn_impact_chain_agents(
    agent_state: Any,
    target: str,
    max_agents: int = 2,
    hypothesis_ids: list[str] | None = None,
    min_priority: str = "high",
    minimum_score: int = 6,
    dry_run: bool = False,
    inherit_context: bool = False,
) -> dict[str, Any]:
    try:
        normalized_target = _normalize_non_empty(target, "target")
        if max_agents < 1:
            raise ValueError("max_agents must be >= 1")
        if minimum_score < 1:
            raise ValueError("minimum_score must be >= 1")
        normalized_min_priority = str(min_priority).strip().lower()
        if normalized_min_priority not in VALID_PRIORITIES:
            raise ValueError(
                f"min_priority must be one of: {', '.join(VALID_PRIORITIES)}"
            )

        requested_hypothesis_ids = {
            str(item).strip()
            for item in list(hypothesis_ids or [])
            if str(item).strip()
        }
        assessment_result = list_assessment_state(
            agent_state=agent_state,
            include_resolved_coverage=True,
            include_evidence=True,
            max_items=max(100, max_agents * 50),
        )
        if not assessment_result.get("success"):
            raise ValueError(str(assessment_result.get("error") or "Failed to load assessment state"))

        hypotheses = [
            item
            for item in list(assessment_result.get("hypotheses") or [])
            if isinstance(item, dict) and str(item.get("target") or "").strip() == normalized_target
        ]
        evidence_records = [
            item for item in list(assessment_result.get("evidence") or []) if isinstance(item, dict)
        ]
        review_report = _load_review_report(agent_state, normalized_target)
        active_keys = _active_delegation_keys(agent_state.agent_id)
        suppressed_keys = _suppressed_delegation_keys(agent_state)
        terminal_blocked_keys = _blocked_terminal_delegation_keys(agent_state)
        blocked_keys = {*active_keys, *suppressed_keys, *terminal_blocked_keys}
        candidates: list[dict[str, Any]] = []

        for hypothesis in hypotheses:
            hypothesis_id = str(hypothesis.get("hypothesis_id") or "").strip()
            if not hypothesis_id:
                continue
            if requested_hypothesis_ids and hypothesis_id not in requested_hypothesis_ids:
                continue

            status = str(hypothesis.get("status") or "open").strip().lower()
            if status not in SUPPORTED_SIGNAL_STATUSES:
                continue
            priority = str(hypothesis.get("priority") or "normal").strip().lower()
            vulnerability_type = str(hypothesis.get("vulnerability_type") or "general").strip().lower()
            if vulnerability_type not in CHAINABLE_VULNERABILITY_TYPES and not requested_hypothesis_ids:
                continue

            related_evidence = _evidence_for_hypothesis(
                evidence_records,
                hypothesis_id=hypothesis_id,
                component=str(hypothesis.get("component") or ""),
                target=normalized_target,
            )
            if not requested_hypothesis_ids and not related_evidence:
                continue

            component = str(hypothesis.get("component") or "").strip() or "general"
            component_hints = _component_asset_hints(component)
            host = str(component_hints.get("host") or "").strip()
            path = str(component_hints.get("path") or "/").strip() or "/"
            review_context = _matching_review_chain_context(
                review_report,
                host=host,
                path=path,
            )
            signal_score = _signal_score(hypothesis, related_evidence)
            impact_score = _impact_score(
                hypothesis=hypothesis,
                related_evidence=related_evidence,
                signal_score=signal_score,
                chain_matches=list(review_context.get("chain_matches") or []),
                exposure_matches=list(review_context.get("exposure_matches") or []),
            )
            impact_text = _impact_ready_text(
                str(hypothesis.get("hypothesis") or ""),
                str(hypothesis.get("rationale") or ""),
                " ".join(_evidence_highlights(related_evidence)),
            )
            auto_selectable = (
                status == "validated"
                or bool(review_context.get("chain_matches") or review_context.get("exposure_matches"))
                or any(keyword in impact_text for keyword in IMPACT_CHAIN_HINTS)
            )
            if not requested_hypothesis_ids:
                if _priority_rank(priority) < _priority_rank(normalized_min_priority):
                    continue
                if impact_score < minimum_score:
                    continue
                if not auto_selectable:
                    continue

            hypothesis_text = str(hypothesis.get("hypothesis") or "").strip()
            rationale = str(hypothesis.get("rationale") or "").strip()
            candidate_urls = _signal_candidate_urls(hypothesis, related_evidence)
            evidence_ids = [
                str(item.get("evidence_id") or "").strip()
                for item in related_evidence
                if str(item.get("evidence_id") or "").strip()
            ]
            chain_matches = [dict(item) for item in list(review_context.get("chain_matches") or [])]
            exposure_matches = [dict(item) for item in list(review_context.get("exposure_matches") or [])]
            chain_summaries = [
                str(item.get("summary") or item.get("boundary") or "").strip()
                for item in chain_matches
                if str(item.get("summary") or item.get("boundary") or "").strip()
            ]
            exposure_summaries = [
                f"{item.get('host')}{item.get('path')} ({item.get('kind')})"
                for item in exposure_matches
                if str(item.get("host") or "").strip()
            ]
            target_label = host + path if host else component
            skills = _bug_skills(
                [vulnerability_type, hypothesis_text, rationale, "chain impact"],
                component,
            )
            for supplemental in ["business_logic", "idor", "ssrf", "xss", "path_traversal_lfi_rfi"]:
                if len(skills) >= 5:
                    break
                if supplemental not in skills:
                    skills.append(supplemental)
            highlights = _evidence_highlights(related_evidence)
            dedupe_key = f"impact-chain|{hypothesis_id}"
            candidates.append(
                {
                    "dedupe_key": dedupe_key,
                    "phase": PHASE_CHAINING,
                    "kind": "impact-chain",
                    "name": (
                        f"Chain {vulnerability_type or 'impact'} on {target_label}"
                        if target_label
                        else f"Chain impact for {hypothesis_id}"
                    ),
                    "priority": priority,
                    "skills": _skills_csv(skills),
                    "hypothesis_id": hypothesis_id,
                    "impact_score": impact_score,
                    "signal_score": signal_score,
                    "candidate_urls": candidate_urls,
                    "evidence_ids": evidence_ids,
                    "review_chain_summaries": chain_summaries,
                    "review_exposure_summaries": exposure_summaries,
                    "task": (
                        _with_round_followup(
                            (
                                f"Delegation key: {dedupe_key}\n"
                                "Phase: Impact escalation and safe chaining\n"
                                f"Target label: {normalized_target}\n"
                                f"Hypothesis ID: {hypothesis_id}\n"
                                f"Vulnerability type: {vulnerability_type or 'needs more data'}\n"
                                f"Status: {status}\n"
                                f"Priority: {priority}\n"
                                f"Signal score: {signal_score}\n"
                                f"Impact score: {impact_score}\n"
                                f"Component: {component}\n"
                                f"Candidate URLs: {candidate_urls or ['needs more data']}\n"
                                f"Supporting evidence IDs: {evidence_ids or ['needs more data']}\n"
                                f"Evidence highlights: {highlights or ['needs more data']}\n"
                                f"Review chain matches: {chain_summaries or ['needs more data']}\n"
                                f"Review exposure pivots: {exposure_summaries or ['needs more data']}\n"
                                "Objective:\n"
                                "- Assume the underlying bug is real or close to real; do not waste time reproving basics unless the evidence is contradictory.\n"
                                "- Escalate impact through boundary crossing, tenant crossing, privilege escalation, workflow abuse, exposed docs/routes, stored viewer context, file retrieval, or OOB reachability as appropriate.\n"
                                "- Prefer end-to-end chains that materially increase report impact over isolated confirmations.\n"
                                "- Stay within the mapped asset and explicit pivots; if more data is needed, state that clearly instead of inventing missing context.\n"
                                "- Record durable evidence for any successful chain or for the exact missing step that blocked escalation."
                            ),
                            target=normalized_target,
                        )
                    ),
                }
            )

        candidates.sort(
            key=lambda item: (
                -int(item.get("impact_score") or 0),
                -_priority_rank(str(item.get("priority") or "normal")),
                str(item.get("name") or ""),
            )
        )
        duplicate_candidates = [
            candidate
            for candidate in candidates
            if str(candidate.get("dedupe_key") or "") in blocked_keys
        ]
        eligible_candidates = [
            candidate
            for candidate in candidates
            if str(candidate.get("dedupe_key") or "") not in blocked_keys
        ]
        recommended = eligible_candidates[:max_agents]

        created: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = [
            {
                "dedupe_key": str(candidate.get("dedupe_key") or ""),
                "name": candidate.get("name"),
                "hypothesis_id": candidate.get("hypothesis_id"),
                "reason": (
                    "recent duplicate just completed in current agent subtree"
                    if str(candidate.get("dedupe_key") or "") in suppressed_keys
                    else (
                        "duplicate already completed earlier in current agent subtree and no new coverage/evidence/review was observed"
                        if str(candidate.get("dedupe_key") or "") in terminal_blocked_keys
                        else "active duplicate already exists in current agent subtree"
                    )
                ),
            }
            for candidate in duplicate_candidates
        ]
        for candidate in recommended:
            if dry_run:
                created.append(
                    {
                        "dry_run": True,
                        "dedupe_key": candidate["dedupe_key"],
                        "name": candidate["name"],
                        "phase": candidate["phase"],
                        "kind": candidate["kind"],
                        "hypothesis_id": candidate["hypothesis_id"],
                        "impact_score": candidate["impact_score"],
                        "signal_score": candidate["signal_score"],
                        "candidate_urls": list(candidate["candidate_urls"]),
                        "evidence_ids": list(candidate["evidence_ids"]),
                        "review_chain_summaries": list(candidate["review_chain_summaries"]),
                        "review_exposure_summaries": list(candidate["review_exposure_summaries"]),
                        "skills": candidate["skills"].split(",") if candidate["skills"] else [],
                    }
                )
                continue

            result = create_agent(
                agent_state=agent_state,
                task=str(candidate["task"]),
                name=str(candidate["name"]),
                inherit_context=inherit_context,
                skills=candidate["skills"],
            )
            if result.get("success"):
                created.append(
                    {
                        "agent_id": result.get("agent_id"),
                        "dedupe_key": candidate["dedupe_key"],
                        "name": candidate["name"],
                        "phase": candidate["phase"],
                        "kind": candidate["kind"],
                        "hypothesis_id": candidate["hypothesis_id"],
                        "impact_score": candidate["impact_score"],
                        "signal_score": candidate["signal_score"],
                        "candidate_urls": list(candidate["candidate_urls"]),
                        "evidence_ids": list(candidate["evidence_ids"]),
                        "review_chain_summaries": list(candidate["review_chain_summaries"]),
                        "review_exposure_summaries": list(candidate["review_exposure_summaries"]),
                        "skills": result.get("active_skills") or [],
                    }
                )
                active_keys.add(str(candidate["dedupe_key"]))
            else:
                skipped.append(
                    {
                        "dedupe_key": candidate["dedupe_key"],
                        "name": candidate["name"],
                        "hypothesis_id": candidate["hypothesis_id"],
                        "reason": result.get("error") or "create_agent failed",
                    }
                )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to spawn impact-chain agents: {e}"}
    else:
        return {
            "success": True,
            "target": normalized_target,
            "requested_hypothesis_ids": sorted(requested_hypothesis_ids),
            "candidate_count": len(candidates),
            "eligible_count": len(eligible_candidates),
            "recommended_count": len(recommended),
            "created_count": len(created),
            "skipped_count": len(skipped),
            "dry_run": dry_run,
            "created_agents": created,
            "skipped_agents": skipped,
        }


@register_tool(sandbox_execution=False)
def run_attack_surface_orchestration_round(
    agent_state: Any,
    target: str,
    scope_targets: list[str] | None = None,
    max_priorities: int = 16,
    strategy: str = "coverage_first",
    dry_run: bool = False,
    inherit_context: bool = True,
    force: bool = False,
    require_new_data: bool = True,
    include_review_swarm: bool = True,
    include_signal_swarm: bool = True,
    include_impact_swarm: bool = True,
    max_review_agents: int = 8,
    max_signal_agents: int = 4,
    max_impact_agents: int = 3,
) -> dict[str, Any]:
    try:
        normalized_target = _normalize_non_empty(target, "target")
        if max_priorities < 1:
            raise ValueError("max_priorities must be >= 1")
        if max_review_agents < 1:
            raise ValueError("max_review_agents must be >= 1")
        if max_signal_agents < 1:
            raise ValueError("max_signal_agents must be >= 1")
        if max_impact_agents < 1:
            raise ValueError("max_impact_agents must be >= 1")
        normalized_strategy = _normalize_swarm_strategy(strategy)

        orchestrator_state = _orchestrator_agent_state(agent_state)
        root_agent_id, round_store = _round_store(orchestrator_state)
        round_key = normalized_target
        previous_round = dict(round_store.get(round_key) or {})

        review_listing = list_attack_surface_reviews(
            agent_state=orchestrator_state,
            target=normalized_target,
            include_report=True,
            max_items=1,
        )
        current_review_record = None
        current_review_report = None
        if review_listing.get("success"):
            current_records = [
                item for item in list(review_listing.get("records") or []) if isinstance(item, dict)
            ]
            if current_records:
                current_review_record = current_records[0]
                report = current_review_record.get("report")
                current_review_report = report if isinstance(report, dict) else None

        assessment_result = list_assessment_state(
            agent_state=orchestrator_state,
            include_resolved_coverage=True,
            include_evidence=True,
            max_items=250,
        )
        if not assessment_result.get("success"):
            raise ValueError(
                str(assessment_result.get("error") or "Failed to load assessment state")
            )

        assessment_records = {
            "coverage": [
                item for item in list(assessment_result.get("coverage") or []) if isinstance(item, dict)
            ],
            "hypotheses": [
                item
                for item in list(assessment_result.get("hypotheses") or [])
                if isinstance(item, dict)
            ],
            "evidence": [
                item for item in list(assessment_result.get("evidence") or []) if isinstance(item, dict)
            ],
        }
        latest_ledger_timestamp = max(
            [
                candidate
                for candidate in [
                    _latest_timestamp(assessment_records["coverage"], "updated_at", "created_at"),
                    _latest_timestamp(assessment_records["hypotheses"], "updated_at", "created_at"),
                    _latest_timestamp(assessment_records["evidence"], "updated_at", "created_at"),
                ]
                if candidate
            ],
            default=None,
        )
        subtree_snapshot = _subtree_progress_snapshot(root_agent_id)
        current_review_updated_at = (
            str(current_review_record.get("updated_at") or "").strip()
            if isinstance(current_review_record, dict)
            else None
        )
        previous_latest_ledger_timestamp = str(previous_round.get("latest_ledger_timestamp") or "").strip() or None
        previous_latest_finished_at = str(previous_round.get("latest_finished_at") or "").strip() or None
        previous_finished_count = int(previous_round.get("finished_descendant_count") or 0)
        previous_review_updated_at = str(previous_round.get("review_updated_at") or "").strip() or None

        refresh_reason = {
            "force": force,
            "first_round": not bool(previous_round),
            "new_finished_descendants": (
                int(subtree_snapshot.get("finished_descendant_count") or 0) > previous_finished_count
            )
            or (
                bool(subtree_snapshot.get("latest_finished_at"))
                and (
                    previous_latest_finished_at is None
                    or str(subtree_snapshot.get("latest_finished_at")) > previous_latest_finished_at
                )
            ),
            "new_ledger_activity": bool(latest_ledger_timestamp)
            and (
                previous_latest_ledger_timestamp is None
                or str(latest_ledger_timestamp) > previous_latest_ledger_timestamp
            ),
            "review_missing": current_review_report is None,
            "review_outdated": bool(current_review_updated_at)
            and (
                previous_review_updated_at is None
                or str(current_review_updated_at) > previous_review_updated_at
            ),
        }

        should_refresh = any(refresh_reason.values())
        if require_new_data and not should_refresh:
            return {
                "success": True,
                "target": normalized_target,
                "root_agent_id": root_agent_id,
                "round_number": int(previous_round.get("round_number") or 0),
                "skipped": True,
                "skip_reason": "No new finished descendants, ledger updates, or review changes since the last orchestration round.",
                "refresh_reason": refresh_reason,
                "subtree_snapshot": subtree_snapshot,
                "latest_ledger_timestamp": latest_ledger_timestamp,
                "review_updated_at": current_review_updated_at,
            }

        resolved_scope_targets = _orchestration_scope_targets(
            orchestrator_state,
            target=normalized_target,
            explicit_scope_targets=scope_targets,
            review_report=current_review_report,
        )
        from .assessment_surface_review_actions import build_attack_surface_review

        review_result = build_attack_surface_review(
            agent_state=orchestrator_state,
            target=normalized_target,
            scope_targets=resolved_scope_targets or None,
            max_priorities=max_priorities,
        )
        if not review_result.get("success"):
            raise ValueError(str(review_result.get("error") or "Failed to build attack-surface review"))

        review_swarm_result = None
        strong_signal_result = None
        impact_chain_result = None
        completion_only_refresh = bool(refresh_reason.get("new_finished_descendants")) and not any(
            bool(refresh_reason.get(reason_key))
            for reason_key in ("force", "first_round", "new_ledger_activity", "review_missing", "review_outdated")
        )
        recently_completed_keys = _completed_delegation_keys_since(
            root_agent_id,
            after_finished_at=previous_latest_finished_at,
        )
        blocked_terminal_keys = (
            _terminal_delegation_keys(root_agent_id)
            if completion_only_refresh
            else set()
        )
        _set_suppressed_delegation_keys(orchestrator_state, recently_completed_keys)
        _set_blocked_terminal_delegation_keys(orchestrator_state, blocked_terminal_keys)
        try:
            if include_review_swarm:
                review_swarm_result = spawn_attack_surface_agents(
                    agent_state=orchestrator_state,
                    target=normalized_target,
                    max_agents=max_review_agents,
                    strategy=normalized_strategy,
                    dry_run=dry_run,
                    inherit_context=inherit_context,
                )
            if include_signal_swarm:
                strong_signal_result = spawn_strong_signal_agents(
                    agent_state=orchestrator_state,
                    target=normalized_target,
                    max_agents=max_signal_agents,
                    dry_run=dry_run,
                    inherit_context=inherit_context,
                )
            if include_impact_swarm:
                impact_chain_result = spawn_impact_chain_agents(
                    agent_state=orchestrator_state,
                    target=normalized_target,
                    max_agents=max_impact_agents,
                    dry_run=dry_run,
                    inherit_context=inherit_context,
                )
        finally:
            _set_suppressed_delegation_keys(orchestrator_state, set())
            _set_blocked_terminal_delegation_keys(orchestrator_state, set())

        refreshed_review_listing = list_attack_surface_reviews(
            agent_state=orchestrator_state,
            target=normalized_target,
            include_report=False,
            max_items=1,
        )
        refreshed_review_record = None
        if refreshed_review_listing.get("success"):
            refreshed_records = [
                item
                for item in list(refreshed_review_listing.get("records") or [])
                if isinstance(item, dict)
            ]
            if refreshed_records:
                refreshed_review_record = refreshed_records[0]

        round_number = int(previous_round.get("round_number") or 0) + 1
        round_store[round_key] = {
            "target": normalized_target,
            "round_number": round_number,
            "updated_at": str(refreshed_review_record.get("updated_at") or "")
            if isinstance(refreshed_review_record, dict)
            else "",
            "latest_ledger_timestamp": latest_ledger_timestamp or "",
            "finished_descendant_count": int(subtree_snapshot.get("finished_descendant_count") or 0),
            "latest_finished_at": str(subtree_snapshot.get("latest_finished_at") or ""),
            "review_updated_at": str(refreshed_review_record.get("updated_at") or "")
            if isinstance(refreshed_review_record, dict)
            else "",
            "strategy": normalized_strategy,
            "scope_targets": list(resolved_scope_targets),
            "suppressed_completed_dedupe_keys": sorted(recently_completed_keys),
            "blocked_terminal_dedupe_keys": sorted(blocked_terminal_keys),
        }

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to run attack-surface orchestration round: {e}"}
    else:
        return {
            "success": True,
            "target": normalized_target,
            "root_agent_id": root_agent_id,
            "round_number": round_number,
            "dry_run": dry_run,
            "strategy": normalized_strategy,
            "skipped": False,
            "refresh_reason": refresh_reason,
            "scope_targets": resolved_scope_targets,
            "subtree_snapshot": subtree_snapshot,
            "latest_ledger_timestamp": latest_ledger_timestamp,
            "review_updated_at": (
                str(refreshed_review_record.get("updated_at") or "")
                if isinstance(refreshed_review_record, dict)
                else None
            ),
            "suppressed_completed_dedupe_keys": sorted(recently_completed_keys),
            "blocked_terminal_dedupe_keys": sorted(blocked_terminal_keys),
            "attack_surface_review_result": review_result,
            "attack_surface_agent_result": review_swarm_result,
            "strong_signal_agent_result": strong_signal_result,
            "impact_chain_agent_result": impact_chain_result,
            "spawn_summary": {
                "review_created": int(review_swarm_result.get("created_count") or 0)
                if isinstance(review_swarm_result, dict)
                else 0,
                "signal_created": int(strong_signal_result.get("created_count") or 0)
                if isinstance(strong_signal_result, dict)
                else 0,
                "impact_created": int(impact_chain_result.get("created_count") or 0)
                if isinstance(impact_chain_result, dict)
                else 0,
            },
        }
