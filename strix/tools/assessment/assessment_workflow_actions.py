import json
from collections import defaultdict
from typing import Any

from strix.tools.registry import register_tool

from .assessment_actions import (
    _resolve_root_agent_id,
    _slug,
    _stable_id,
    _utc_now,
    bulk_record_coverage,
    record_evidence,
)
from .assessment_runtime_actions import _normalize_runtime_path
from .assessment_session_actions import _parse_cookie_header


WorkflowRecord = dict[str, Any]
_workflow_storage: dict[str, dict[str, WorkflowRecord]] = {}
STATIC_PATH_MARKERS = ["/static/", "/assets/", "/_next/", "/favicon", "/robots.txt"]
RISKY_WORKFLOW_KEYWORDS = {
    "checkout": 5,
    "payment": 5,
    "wallet": 5,
    "transfer": 5,
    "invoice": 4,
    "coupon": 5,
    "redeem": 5,
    "invite": 4,
    "approval": 4,
    "approve": 4,
    "reset": 4,
    "password": 4,
    "otp": 4,
    "token": 4,
    "verify": 3,
    "login": 2,
    "admin": 2,
}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def clear_workflow_storage() -> None:
    _workflow_storage.clear()


def _get_workflow_store(agent_state: Any) -> tuple[str, dict[str, WorkflowRecord]]:
    root_agent_id = _resolve_root_agent_id(agent_state)
    if root_agent_id not in _workflow_storage:
        _workflow_storage[root_agent_id] = {}
    return root_agent_id, _workflow_storage[root_agent_id]


def _update_agent_context(agent_state: Any, root_agent_id: str) -> None:
    if hasattr(agent_state, "update_context"):
        agent_state.update_context("workflow_root_agent_id", root_agent_id)


def get_proxy_manager() -> Any:
    from strix.tools.proxy.proxy_manager import get_proxy_manager as _get_proxy_manager

    return _get_proxy_manager()


def _parse_request_headers(content: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    lines = content.splitlines()
    for line in lines[1:]:
        if line.strip() == "":
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def _is_static_path(path: str) -> bool:
    lowered = path.lower()
    if any(marker in lowered for marker in STATIC_PATH_MARKERS):
        return True
    return any(
        lowered.endswith(extension)
        for extension in [".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".png", ".svg", ".woff2"]
    )


def _actor_fingerprint(headers: dict[str, str], host: str) -> str:
    authorization = headers.get("Authorization") or headers.get("authorization") or ""
    if authorization:
        return f"auth:{authorization[:24]}"

    cookies = _parse_cookie_header(headers.get("Cookie") or headers.get("cookie") or "")
    for cookie_name in ["sid", "session", "sessionid", "connect.sid", "token"]:
        if cookie_name in cookies:
            return f"cookie:{cookie_name}:{cookies[cookie_name][:16]}"

    return f"anonymous:{host}"


def _workflow_type(steps: list[dict[str, Any]]) -> str:
    joined = " ".join(step["normalized_path"].lower() for step in steps)
    for keyword in RISKY_WORKFLOW_KEYWORDS:
        if keyword in joined:
            return keyword
    return "state_machine"


def _workflow_priority(steps: list[dict[str, Any]], repeated_write: bool) -> str:
    score = 0
    joined = " ".join(step["normalized_path"].lower() for step in steps)
    for keyword, weight in RISKY_WORKFLOW_KEYWORDS.items():
        if keyword in joined:
            score += weight
    score += sum(3 for step in steps if step["method"] in STATE_CHANGING_METHODS)
    if repeated_write:
        score += 3
    if score >= 11:
        return "critical"
    if score >= 7:
        return "high"
    return "normal"


def _workflow_surface(steps: list[dict[str, Any]]) -> str:
    rendered = [f"{step['method']} {step['normalized_path']}" for step in steps]
    return f"Workflow candidate {' -> '.join(rendered[:4])}"


def _workflow_next_step(workflow_type: str, repeated_write: bool) -> str:
    if repeated_write:
        return (
            "Replay the write out of order and concurrently with race_condition_harness, then validate "
            "whether the flow can be repeated, redeemed twice, or advanced without intended one-time checks"
        )
    if workflow_type in {"checkout", "payment", "wallet", "transfer", "coupon", "redeem"}:
        return (
            "Exercise the workflow with race_condition_harness, retry/replay variants, and alternate role "
            "sessions to probe double-spend, replay, or state-transition drift"
        )
    return (
        "Re-run the sequence out of order, skip intermediate steps, and compare owner, other-user, and "
        "admin behavior across the same object or token"
    )


def _record_for_response(record: WorkflowRecord, *, include_workflows: bool) -> WorkflowRecord:
    response = dict(record)
    if not include_workflows:
        response.pop("workflows", None)
        response.pop("selected_workflows", None)
    return response


@register_tool(sandbox_execution=False)
def discover_workflows_from_requests(
    agent_state: Any,
    target: str,
    max_request_pages: int = 3,
    page_size: int = 50,
    max_request_details: int = 120,
    max_workflows: int = 20,
    max_sequence_length: int = 4,
    httpql_filter: str | None = None,
    scope_id: str | None = None,
) -> dict[str, Any]:
    try:
        if max_request_pages < 1:
            raise ValueError("max_request_pages must be >= 1")
        if page_size < 1:
            raise ValueError("page_size must be >= 1")
        if max_request_details < 1:
            raise ValueError("max_request_details must be >= 1")
        if max_workflows < 1:
            raise ValueError("max_workflows must be >= 1")
        if max_sequence_length < 2:
            raise ValueError("max_sequence_length must be >= 2")

        manager = get_proxy_manager()
        request_rows: list[dict[str, Any]] = []
        for page in range(1, max_request_pages + 1):
            result = manager.list_requests(
                httpql_filter=httpql_filter,
                start_page=page,
                end_page=page,
                page_size=page_size,
                sort_by="timestamp",
                sort_order="asc",
                scope_id=scope_id,
            )
            if result.get("error"):
                raise ValueError(str(result["error"]))
            rows = result.get("requests", [])
            request_rows.extend(rows)
            if int(result.get("returned_count") or len(rows)) < page_size:
                break

        grouped_steps: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in request_rows[:max_request_details]:
            request_id = str(row.get("id") or "")
            host = str(row.get("host") or "").strip()
            path = str(row.get("path") or "").strip()
            method = str(row.get("method") or "GET").upper()
            if not request_id or not host or not path or _is_static_path(path):
                continue

            raw = manager.view_request(request_id=request_id, part="request", page=1, page_size=120)
            if raw.get("error") or not raw.get("content"):
                continue
            headers = _parse_request_headers(str(raw["content"]))
            actor = _actor_fingerprint(headers, host)
            grouped_steps[(host, actor)].append(
                {
                    "request_id": request_id,
                    "host": host,
                    "actor": actor,
                    "method": method,
                    "path": path,
                    "normalized_path": _normalize_runtime_path(path),
                    "timestamp": str(row.get("createdAt") or ""),
                }
            )

        workflow_candidates: list[dict[str, Any]] = []
        seen_signatures: set[str] = set()
        for (host, actor), steps in grouped_steps.items():
            if len(steps) < 2:
                continue

            for start_index in range(0, len(steps) - 1):
                for length in range(2, min(max_sequence_length, len(steps) - start_index) + 1):
                    window = steps[start_index : start_index + length]
                    state_changing_count = sum(
                        1 for step in window if step["method"] in STATE_CHANGING_METHODS
                    )
                    if state_changing_count == 0:
                        continue

                    repeated_write = len(
                        {
                            (step["method"], step["normalized_path"])
                            for step in window
                            if step["method"] in STATE_CHANGING_METHODS
                        }
                    ) < state_changing_count
                    workflow_type = _workflow_type(window)
                    priority = _workflow_priority(window, repeated_write)
                    signature = _stable_id(
                        "wfsig",
                        host,
                        actor,
                        "|".join(f"{step['method']} {step['normalized_path']}" for step in window),
                    )
                    if signature in seen_signatures:
                        continue
                    seen_signatures.add(signature)

                    workflow_candidates.append(
                        {
                            "workflow_id": _stable_id("wf", target, host, actor, signature),
                            "target": target,
                            "host": host,
                            "actor": actor,
                            "type": workflow_type,
                            "priority": priority,
                            "repeated_write": repeated_write,
                            "state_changing_count": state_changing_count,
                            "sequence": window,
                            "surface": _workflow_surface(window),
                        }
                    )

        workflow_candidates.sort(
            key=lambda item: (
                {"critical": 0, "high": 1, "normal": 2}.get(str(item.get("priority")), 2),
                -int(item.get("state_changing_count") or 0),
                str(item.get("surface") or ""),
            )
        )
        selected_workflows = workflow_candidates[:max_workflows]
        if not selected_workflows:
            return {
                "success": False,
                "error": "No multi-step state-changing workflows could be reconstructed from proxy history",
            }

        coverage_items = [
            {
                "target": target,
                "component": f"workflow:{workflow['host']}",
                "surface": workflow["surface"],
                "status": "uncovered",
                "priority": workflow["priority"],
                "rationale": (
                    f"Reconstructed {workflow['type']} workflow for actor {workflow['actor']} on "
                    f"{workflow['host']} with {len(workflow['sequence'])} steps and "
                    f"{workflow['state_changing_count']} state-changing transition(s)."
                ),
                "next_step": _workflow_next_step(
                    str(workflow["type"]),
                    bool(workflow["repeated_write"]),
                ),
            }
            for workflow in selected_workflows
        ]
        coverage_result = bulk_record_coverage(
            agent_state=agent_state,
            items=coverage_items,
            preserve_existing_status=True,
        )

        root_agent_id, store = _get_workflow_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)
        store[_slug(target)] = {
            "target": target,
            "workflows": workflow_candidates,
            "selected_workflows": selected_workflows,
            "workflow_total": len(workflow_candidates),
            "request_count": len(request_rows),
            "discovered_at": _utc_now(),
        }

        evidence_result = record_evidence(
            agent_state=agent_state,
            title=f"Workflow candidates for {target}",
            details=json.dumps(
                {
                    "workflow_total": len(workflow_candidates),
                    "selected_workflows": selected_workflows,
                },
                ensure_ascii=False,
            ),
            source="traffic",
            target=target,
            component="workflow_hunter",
        )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to discover workflows from requests: {e}"}
    else:
        return {
            "success": True,
            "workflow_total": len(workflow_candidates),
            "seeded_count": coverage_result.get("updated_count", 0),
            "workflows": selected_workflows,
            "coverage_result": coverage_result,
            "evidence_result": evidence_result,
        }


@register_tool(sandbox_execution=False)
def list_discovered_workflows(
    agent_state: Any,
    target: str | None = None,
    include_workflows: bool = True,
    max_items: int = 50,
) -> dict[str, Any]:
    try:
        if max_items < 1:
            raise ValueError("max_items must be >= 1")

        root_agent_id, store = _get_workflow_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)
        records = list(store.values())
        records.sort(key=lambda item: str(item.get("discovered_at", "")), reverse=True)

        if target:
            record = store.get(_slug(target))
            if record is None:
                raise ValueError(f"No discovered workflow record found for target '{target}'")
            records = [record]

        response_records = [
            _record_for_response(record, include_workflows=include_workflows)
            for record in records[:max_items]
        ]

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to list discovered workflows: {e}"}
    else:
        return {
            "success": True,
            "root_agent_id": root_agent_id,
            "record_count": len(records),
            "records": response_records,
        }
