import json
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from strix.tools.registry import register_tool

from .assessment_actions import (
    _normalize_non_empty,
    _resolve_root_agent_id,
    _slug,
    _stable_id,
    _utc_now,
    record_coverage,
    record_evidence,
    record_hypothesis,
)


OOBHarness = dict[str, Any]
_oob_harness_storage: dict[str, dict[str, OOBHarness]] = {}
VALID_OOB_ACTIONS = {"start", "poll", "record", "list", "doctor"}


def clear_oob_harness_storage() -> None:
    _oob_harness_storage.clear()


def _get_oob_store(agent_state: Any) -> tuple[str, dict[str, OOBHarness]]:
    root_agent_id = _resolve_root_agent_id(agent_state)
    if root_agent_id not in _oob_harness_storage:
        _oob_harness_storage[root_agent_id] = {}
    return root_agent_id, _oob_harness_storage[root_agent_id]


def _update_agent_context(agent_state: Any, root_agent_id: str) -> None:
    if hasattr(agent_state, "update_context"):
        agent_state.update_context("oob_harness_root_agent_id", root_agent_id)


def _normalize_action(action: str) -> str:
    normalized = action.strip().lower()
    if normalized not in VALID_OOB_ACTIONS:
        raise ValueError(f"action must be one of: {', '.join(sorted(VALID_OOB_ACTIONS))}")
    return normalized


def _normalize_labels(labels: list[str] | None) -> list[str]:
    if not labels:
        return ["primary"]
    normalized: list[str] = []
    for label in labels:
        candidate = _normalize_non_empty(str(label), "labels")
        if candidate not in normalized:
            normalized.append(candidate)
    return normalized


def _normalize_callback_base_url(callback_base_url: str | None) -> str | None:
    if callback_base_url is None:
        return None
    normalized = _normalize_non_empty(callback_base_url, "callback_base_url").rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("callback_base_url must be an absolute http(s) URL")
    return normalized


def _priority_for_vulnerability(vulnerability_type: str) -> str:
    if vulnerability_type.lower() in {"ssrf", "xxe", "rce", "sqli"}:
        return "critical"
    return "high"


def _manual_payloads(callback_base_url: str, harness_id: str, labels: list[str]) -> list[dict[str, str]]:
    payloads = []
    for label in labels:
        callback_path = f"{_slug(harness_id).replace(' ', '-')}/{_slug(label).replace(' ', '-')}"
        payloads.append({"label": label, "url": urljoin(f"{callback_base_url}/", callback_path)})
    return payloads


def _resolve_interactsh_cli(interactsh_cli_path: str | None = None) -> str | None:
    if interactsh_cli_path:
        return interactsh_cli_path
    explicit_path = os.getenv("INTERACTSH_CLI_PATH")
    if explicit_path:
        return explicit_path
    return shutil.which("interactsh-client") or shutil.which("interactsh-client.exe")


def _resolve_interactsh_server(interactsh_server: str | None = None) -> str | None:
    return interactsh_server or os.getenv("INTERACTSH_SERVER")


def _resolve_interactsh_token(interactsh_token: str | None = None) -> str | None:
    return interactsh_token or os.getenv("INTERACTSH_TOKEN")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _parse_json_lines(raw_output: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in raw_output.splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        try:
            payload = json.loads(cleaned)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            events.append(payload)
    return events


def _doctor_interactsh(cli_path: str | None, interactsh_server: str | None) -> dict[str, Any]:
    version_output = ""
    cli_available = cli_path is not None and Path(cli_path).exists()
    if cli_available and cli_path is not None:
        try:
            completed = subprocess.run(
                [cli_path, "-version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            version_output = ""
        else:
            version_output = (completed.stdout or completed.stderr or "").strip()

    recommended_next_step = (
        "Use the resolved interactsh-client path or set INTERACTSH_CLI_PATH before starting an interactsh-backed harness"
        if cli_available
        else "Install interactsh-client or set callback_base_url for manual mode; then retry start or poll"
    )
    return {
        "cli_available": cli_available,
        "cli_path": cli_path,
        "version_output": version_output or None,
        "interactsh_server": interactsh_server,
        "token_present": bool(_resolve_interactsh_token(None)),
        "recommended_next_step": recommended_next_step,
    }


def _run_interactsh(
    cli_path: str,
    args: list[str],
    *,
    wait_seconds: int,
) -> tuple[str, str]:
    try:
        completed = subprocess.run(
            [cli_path, *args],
            capture_output=True,
            text=True,
            timeout=max(wait_seconds, 1),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return str(exc.stdout or ""), str(exc.stderr or "")
    else:
        if completed.returncode not in {0, 1}:
            raise ValueError(completed.stderr.strip() or "interactsh-client execution failed")
        return completed.stdout or "", completed.stderr or ""


def _start_interactsh_payloads(
    *,
    cli_path: str,
    labels: list[str],
    interactsh_server: str | None,
    interactsh_token: str | None,
    wait_seconds: int,
    poll_interval: int,
) -> tuple[str, str, list[dict[str, str]], str]:
    harness_dir = tempfile.mkdtemp(prefix="strix_oob_")
    session_file = Path(harness_dir) / "session.txt"
    payload_file = Path(harness_dir) / "payloads.txt"

    args = [
        "-json",
        "-sf",
        str(session_file),
        "-ps",
        "-psf",
        str(payload_file),
        "-n",
        str(len(labels)),
        "-pi",
        str(max(poll_interval, 1)),
    ]
    resolved_server = _resolve_interactsh_server(interactsh_server)
    resolved_token = _resolve_interactsh_token(interactsh_token)
    if resolved_server:
        args.extend(["-server", resolved_server])
    if resolved_token:
        args.extend(["-token", resolved_token])

    stdout, _ = _run_interactsh(cli_path, args, wait_seconds=wait_seconds)
    payload_lines = [line.strip() for line in _read_text(payload_file).splitlines() if line.strip()]
    payloads = [
        {"label": label, "url": payload}
        for label, payload in zip(labels, payload_lines, strict=False)
    ]
    if not payloads:
        raise ValueError("No interactsh payloads were generated")

    return harness_dir, str(session_file), payloads, stdout


def _poll_interactsh_payloads(
    *,
    cli_path: str,
    session_file: str,
    interactsh_server: str | None,
    interactsh_token: str | None,
    wait_seconds: int,
    poll_interval: int,
) -> list[dict[str, Any]]:
    args = [
        "-json",
        "-sf",
        session_file,
        "-pi",
        str(max(poll_interval, 1)),
    ]
    resolved_server = _resolve_interactsh_server(interactsh_server)
    resolved_token = _resolve_interactsh_token(interactsh_token)
    if resolved_server:
        args.extend(["-server", resolved_server])
    if resolved_token:
        args.extend(["-token", resolved_token])

    stdout, _ = _run_interactsh(cli_path, args, wait_seconds=wait_seconds)
    return _parse_json_lines(stdout)


def _normalize_interactions(
    payloads: list[dict[str, str]],
    interactions: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in interactions or []:
        if not isinstance(item, dict):
            continue
        serialized = json.dumps(item, sort_keys=True, ensure_ascii=False)
        matched_label = None
        for payload in payloads:
            if payload["url"] in serialized:
                matched_label = payload["label"]
                break
        normalized.append(
            {
                "label": str(item.get("label") or matched_label or "unknown"),
                "protocol": str(item.get("protocol") or item.get("q-type") or item.get("type") or "unknown"),
                "remote_address": str(
                    item.get("remote_address")
                    or item.get("remote-address")
                    or item.get("remote_addresss")
                    or ""
                ),
                "timestamp": str(item.get("timestamp") or item.get("time") or _utc_now()),
                "raw_event": item,
            }
        )
    return normalized


def _record_oob_observations(
    agent_state: Any,
    harness: OOBHarness,
    observations: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    rationale = (
        f"OOB harness observed {len(observations)} callback(s) for blind "
        f"{harness['vulnerability_type']} validation on {harness['surface']}."
    )
    priority = _priority_for_vulnerability(harness["vulnerability_type"])
    coverage_result = record_coverage(
        agent_state=agent_state,
        target=harness["target"],
        component=harness["component"],
        surface=harness["surface"],
        status="in_progress",
        rationale=rationale,
        priority=priority,
        next_step=(
            "Correlate the callback with a concrete payload path, confirm impact, and produce a "
            "focused validation or report artifact"
        ),
    )
    hypothesis_result = record_hypothesis(
        agent_state=agent_state,
        hypothesis=(
            f"Blind {harness['vulnerability_type']} behavior may be exploitable on "
            f"{harness['surface']}"
        ),
        target=harness["target"],
        component=harness["component"],
        vulnerability_type=harness["vulnerability_type"],
        status="open",
        priority=priority,
        rationale=rationale,
    )
    evidence_result = record_evidence(
        agent_state=agent_state,
        title=f"OOB interactions on {harness['surface']}",
        details=json.dumps(
            {
                "harness_id": harness["harness_id"],
                "provider": harness["provider"],
                "payloads": harness["payloads"],
                "observations": observations,
            },
            ensure_ascii=False,
        ),
        source="traffic",
        target=harness["target"],
        component=harness["component"],
        related_coverage_id=coverage_result.get("coverage_id"),
        related_hypothesis_id=(
            hypothesis_result.get("hypothesis_id")
            if isinstance(hypothesis_result, dict)
            else None
        ),
    )
    return coverage_result, hypothesis_result, evidence_result


@register_tool(sandbox_execution=False)
def oob_interaction_harness(
    agent_state: Any,
    action: str,
    target: str | None = None,
    component: str | None = None,
    surface: str | None = None,
    vulnerability_type: str = "ssrf",
    labels: list[str] | None = None,
    callback_base_url: str | None = None,
    harness_id: str | None = None,
    interactions: list[dict[str, Any]] | None = None,
    interactsh_cli_path: str | None = None,
    interactsh_server: str | None = None,
    interactsh_token: str | None = None,
    wait_seconds: int = 5,
    poll_interval: int = 5,
) -> dict[str, Any]:
    try:
        normalized_action = _normalize_action(action)
        root_agent_id, store = _get_oob_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        if normalized_action == "doctor":
            resolved_server = _resolve_interactsh_server(interactsh_server)
            resolved_cli = _resolve_interactsh_cli(interactsh_cli_path)
            doctor = _doctor_interactsh(resolved_cli, resolved_server)
            return {"success": True, **doctor}

        if normalized_action == "list":
            harnesses = list(store.values())
            harnesses.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
            return {
                "success": True,
                "root_agent_id": root_agent_id,
                "harness_count": len(store),
                "harnesses": harnesses[:50],
            }

        if not harness_id and normalized_action in {"poll", "record"}:
            raise ValueError("harness_id is required for poll and record actions")

        if normalized_action == "start":
            normalized_target = _normalize_non_empty(str(target or ""), "target")
            normalized_component = _normalize_non_empty(str(component or ""), "component")
            normalized_surface = _normalize_non_empty(str(surface or ""), "surface")
            normalized_vulnerability_type = _normalize_non_empty(
                vulnerability_type,
                "vulnerability_type",
            )
            normalized_labels = _normalize_labels(labels)
            generated_harness_id = _stable_id(
                "oob",
                normalized_target,
                normalized_component,
                normalized_surface,
                secrets.token_hex(4),
            )
            manual_callback_base = _normalize_callback_base_url(callback_base_url)

            provider = "manual"
            payloads: list[dict[str, str]]
            harness_dir = None
            session_file = None
            cli_path = None
            if manual_callback_base:
                payloads = _manual_payloads(manual_callback_base, generated_harness_id, normalized_labels)
            else:
                provider = "interactsh"
                cli_path = _resolve_interactsh_cli(interactsh_cli_path)
                if cli_path is None:
                    raise ValueError(
                        "No callback_base_url was provided and interactsh-client is not available; run action='doctor' to inspect interactsh readiness"
                    )
                harness_dir, session_file, payloads, _ = _start_interactsh_payloads(
                    cli_path=cli_path,
                    labels=normalized_labels,
                    interactsh_server=_resolve_interactsh_server(interactsh_server),
                    interactsh_token=_resolve_interactsh_token(interactsh_token),
                    wait_seconds=wait_seconds,
                    poll_interval=poll_interval,
                )

            harness: OOBHarness = {
                "harness_id": generated_harness_id,
                "target": normalized_target,
                "component": normalized_component,
                "surface": normalized_surface,
                "vulnerability_type": normalized_vulnerability_type,
                "provider": provider,
                "payloads": payloads,
                "labels": normalized_labels,
                "callback_base_url": manual_callback_base,
                "harness_dir": harness_dir,
                "session_file": session_file,
                "interactsh_server": _resolve_interactsh_server(interactsh_server),
                "updated_at": _utc_now(),
                "created_at": _utc_now(),
                "interaction_count": 0,
                "interaction_keys": [],
                "interactions": [],
            }
            store[generated_harness_id] = harness

            priority = _priority_for_vulnerability(normalized_vulnerability_type)
            coverage_result = record_coverage(
                agent_state=agent_state,
                target=normalized_target,
                component=normalized_component,
                surface=normalized_surface,
                status="in_progress",
                rationale=(
                    f"OOB harness prepared for blind {normalized_vulnerability_type} validation "
                    f"with {len(payloads)} callback payload(s)."
                ),
                priority=priority,
                next_step=(
                    "Inject the generated callback payloads into candidate inputs, then poll or "
                    "record resulting interactions before resolving this surface"
                ),
            )
            evidence_result = record_evidence(
                agent_state=agent_state,
                title=f"OOB harness prepared for {normalized_surface}",
                details=json.dumps(
                    {
                        "harness_id": generated_harness_id,
                        "provider": provider,
                        "payloads": payloads,
                    },
                    ensure_ascii=False,
                ),
                source="tool",
                target=normalized_target,
                component=normalized_component,
                related_coverage_id=coverage_result.get("coverage_id"),
            )
            return {
                "success": True,
                "harness_id": generated_harness_id,
                "provider": provider,
                "payloads": payloads,
                "coverage_result": coverage_result,
                "evidence_result": evidence_result,
            }

        harness = store.get(str(harness_id))
        if harness is None:
            raise ValueError(f"OOB harness '{harness_id}' was not found")

        if normalized_action == "poll":
            if harness["provider"] != "interactsh" or not harness.get("session_file"):
                raise ValueError("poll is only supported for interactsh-backed harnesses")
            cli_path = _resolve_interactsh_cli(interactsh_cli_path)
            if cli_path is None:
                raise ValueError("interactsh-client is not available for polling; run action='doctor'")
            observed = _normalize_interactions(
                harness["payloads"],
                _poll_interactsh_payloads(
                    cli_path=cli_path,
                    session_file=str(harness["session_file"]),
                    interactsh_server=_resolve_interactsh_server(
                        interactsh_server or harness.get("interactsh_server")
                    ),
                    interactsh_token=_resolve_interactsh_token(interactsh_token),
                    wait_seconds=wait_seconds,
                    poll_interval=poll_interval,
                ),
            )
        else:
            observed = _normalize_interactions(harness["payloads"], interactions)

        fresh_observations: list[dict[str, Any]] = []
        for observation in observed:
            fingerprint = _stable_id(
                "oobevt",
                harness["harness_id"],
                json.dumps(observation, sort_keys=True, ensure_ascii=False),
            )
            if fingerprint in harness["interaction_keys"]:
                continue
            harness["interaction_keys"].append(fingerprint)
            harness["interactions"].append(observation)
            fresh_observations.append(observation)

        harness["interaction_count"] = len(harness["interactions"])
        harness["updated_at"] = _utc_now()
        if not fresh_observations:
            return {
                "success": True,
                "harness_id": harness["harness_id"],
                "provider": harness["provider"],
                "new_interaction_count": 0,
                "interaction_count": harness["interaction_count"],
                "interactions": harness["interactions"],
            }

        coverage_result, hypothesis_result, evidence_result = _record_oob_observations(
            agent_state,
            harness,
            fresh_observations,
        )
    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to run oob_interaction_harness: {e}"}
    else:
        return {
            "success": True,
            "harness_id": harness["harness_id"],
            "provider": harness["provider"],
            "new_interaction_count": len(fresh_observations),
            "interaction_count": harness["interaction_count"],
            "interactions": harness["interactions"],
            "coverage_result": coverage_result,
            "hypothesis_result": hypothesis_result,
            "evidence_result": evidence_result,
        }
