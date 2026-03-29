import json
import re
from typing import Any
from urllib.parse import parse_qsl

from strix.tools.registry import register_tool

from .assessment_actions import (
    _resolve_root_agent_id,
    _slug,
    _utc_now,
    bulk_record_coverage,
    record_coverage,
    record_evidence,
)


METHOD_SCORES = {
    "DELETE": 5,
    "PATCH": 5,
    "POST": 4,
    "PUT": 4,
    "GET": 3,
    "HEAD": 2,
    "OPTIONS": 2,
    "ANY": 2,
}
HIGH_VALUE_KEYWORDS = {
    "admin": 6,
    "auth": 6,
    "login": 6,
    "token": 6,
    "password": 6,
    "oauth": 6,
    "session": 6,
    "billing": 5,
    "payment": 5,
    "invoice": 5,
    "wallet": 5,
    "order": 5,
    "checkout": 5,
    "tenant": 5,
    "user": 4,
    "profile": 4,
    "account": 4,
    "export": 4,
    "import": 4,
    "upload": 4,
    "download": 4,
    "webhook": 4,
    "callback": 4,
    "internal": 4,
    "debug": 3,
    "api": 2,
}
RuntimeInventoryRecord = dict[str, Any]
_runtime_inventory_storage: dict[str, dict[str, RuntimeInventoryRecord]] = {}


def clear_runtime_inventory_storage() -> None:
    _runtime_inventory_storage.clear()


def _get_inventory_store(agent_state: Any) -> tuple[str, dict[str, RuntimeInventoryRecord]]:
    root_agent_id = _resolve_root_agent_id(agent_state)
    if root_agent_id not in _runtime_inventory_storage:
        _runtime_inventory_storage[root_agent_id] = {}
    return root_agent_id, _runtime_inventory_storage[root_agent_id]


def _update_agent_context(agent_state: Any, root_agent_id: str) -> None:
    if hasattr(agent_state, "update_context"):
        agent_state.update_context("runtime_inventory_root_agent_id", root_agent_id)


def get_proxy_manager() -> Any:
    from strix.tools.proxy.proxy_manager import get_proxy_manager as _get_proxy_manager

    return _get_proxy_manager()


def _normalize_dynamic_segment(segment: str) -> str:
    if re.fullmatch(r"\d+", segment):
        return ":id"
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
        segment,
    ):
        return ":uuid"
    if re.fullmatch(r"[0-9a-fA-F]{24,64}", segment):
        return ":id"
    if len(segment) >= 16 and re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        return ":token"
    return segment


def _normalize_runtime_path(path: str) -> str:
    normalized = path.strip() or "/"
    if "?" in normalized:
        normalized = normalized.split("?", 1)[0]
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    parts = [_normalize_dynamic_segment(part) for part in normalized.split("/") if part]
    return "/" + "/".join(parts) if parts else "/"


def _query_params(query: str | None) -> list[str]:
    if not query:
        return []
    return sorted({key for key, _ in parse_qsl(query, keep_blank_values=True) if key})


def _parse_request_headers(content: str) -> tuple[dict[str, str], str]:
    headers: dict[str, str] = {}
    lines = content.splitlines()
    body_start = len(lines)
    for index, line in enumerate(lines[1:], 1):
        if line.strip() == "":
            body_start = index + 1
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""
    return headers, body


def _parse_body_params(content_type: str, body: str) -> list[str]:
    lowered = content_type.lower()
    if not body.strip():
        return []
    if "application/json" in lowered:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return []
        if isinstance(payload, dict):
            return sorted(str(key) for key in payload.keys())
        return []
    if "application/x-www-form-urlencoded" in lowered:
        return sorted({key for key, _ in parse_qsl(body, keep_blank_values=True) if key})
    return []


def _infer_auth_hint(headers: dict[str, str]) -> str:
    lowered = {key.lower(): value for key, value in headers.items()}
    hints: list[str] = []
    authorization = lowered.get("authorization", "")
    if authorization:
        if authorization.lower().startswith("bearer "):
            hints.append("bearer")
        else:
            hints.append("authorization")
    if "cookie" in lowered:
        hints.append("cookie")
    if "x-api-key" in lowered or "api-key" in lowered:
        hints.append("api_key")
    if "x-csrf-token" in lowered or "csrf-token" in lowered:
        hints.append("csrf")
    return "+".join(hints) if hints else "anonymous"


def _priority_for_endpoint(
    path: str,
    methods: list[str],
    *,
    query_params: list[str],
    body_params: list[str],
    auth_hints: list[str],
) -> str:
    score = max([METHOD_SCORES.get(method, 2) for method in methods] or [2])
    lowered_path = path.lower()
    for keyword, weight in HIGH_VALUE_KEYWORDS.items():
        if keyword in lowered_path:
            score += weight
    if query_params:
        score += 1
    if body_params:
        score += 1
    if any(hint != "anonymous" for hint in auth_hints):
        score += 1
    if path == "/":
        score -= 1

    if score >= 10:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 3:
        return "normal"
    return "low"


def _sort_inventory(item: dict[str, Any]) -> tuple[int, int, str, str]:
    priority_order = {"critical": 0, "high": 1, "normal": 2, "low": 3}
    return (
        priority_order.get(str(item.get("priority", "normal")), 2),
        -int(item.get("observed_count", 0)),
        str(item.get("host", "")),
        str(item.get("normalized_path", "")),
    )


def _collect_requests(
    manager: Any,
    *,
    max_request_pages: int,
    page_size: int,
    scope_id: str | None,
    httpql_filter: str | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    request_rows: list[dict[str, Any]] = []
    errors: list[str] = []

    for page in range(1, max_request_pages + 1):
        result = manager.list_requests(
            httpql_filter=httpql_filter,
            start_page=page,
            end_page=page,
            page_size=page_size,
            scope_id=scope_id,
        )
        if result.get("error"):
            errors.append(str(result["error"]))
            break

        request_rows.extend(result.get("requests", []))
        total_count = int(result.get("total_count") or 0)
        returned_count = int(result.get("returned_count") or len(result.get("requests", [])))
        if returned_count < page_size:
            break
        if total_count and page * page_size >= total_count:
            break

    return request_rows, errors


def _collect_sitemap_entries(
    manager: Any,
    *,
    max_sitemap_pages: int,
    scope_id: str | None,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    request_entries: list[dict[str, Any]] = []
    root_hosts: list[str] = []
    errors: list[str] = []
    root_entries: list[dict[str, Any]] = []

    for page in range(1, max_sitemap_pages + 1):
        result = manager.list_sitemap(scope_id=scope_id, page=page)
        if result.get("error"):
            errors.append(str(result["error"]))
            break
        root_entries.extend(result.get("entries", []))
        if not result.get("has_more"):
            break

    for root in root_entries[:10]:
        host = str(root.get("label") or "").strip()
        if host:
            root_hosts.append(host)
        if not root.get("hasDescendants"):
            continue

        for page in range(1, max_sitemap_pages + 1):
            result = manager.list_sitemap(parent_id=root.get("id"), depth="ALL", page=page)
            if result.get("error"):
                errors.append(str(result["error"]))
                break
            for entry in result.get("entries", []):
                request = entry.get("request") or {}
                if not request.get("path"):
                    continue
                request_entries.append(
                    {
                        "host": host,
                        "method": request.get("method"),
                        "path": request.get("path"),
                        "status_code": request.get("status"),
                    }
                )
            if not result.get("has_more"):
                break

    return request_entries, sorted({host for host in root_hosts if host}), errors


def _enrich_from_request_detail(manager: Any, request_id: str) -> dict[str, Any]:
    result = manager.view_request(request_id=request_id, part="request", page=1, page_size=80)
    if result.get("error") or not result.get("content"):
        return {}

    headers, body = _parse_request_headers(str(result["content"]))
    content_type = headers.get("Content-Type") or headers.get("content-type") or ""
    return {
        "content_type": content_type,
        "auth_hint": _infer_auth_hint(headers),
        "body_params": _parse_body_params(content_type, body),
    }


@register_tool(sandbox_execution=False)
def map_runtime_surface(
    agent_state: Any,
    target: str,
    max_request_pages: int = 2,
    max_sitemap_pages: int = 2,
    page_size: int = 50,
    max_seed_items: int = 40,
    sample_request_details: int = 12,
    scope_id: str | None = None,
    httpql_filter: str | None = None,
) -> dict[str, Any]:
    try:
        if max_request_pages < 1:
            raise ValueError("max_request_pages must be >= 1")
        if max_sitemap_pages < 1:
            raise ValueError("max_sitemap_pages must be >= 1")
        if page_size < 1:
            raise ValueError("page_size must be >= 1")
        if max_seed_items < 1:
            raise ValueError("max_seed_items must be >= 1")
        if sample_request_details < 0:
            raise ValueError("sample_request_details must be >= 0")

        manager = get_proxy_manager()
        request_rows, request_errors = _collect_requests(
            manager,
            max_request_pages=max_request_pages,
            page_size=page_size,
            scope_id=scope_id,
            httpql_filter=httpql_filter,
        )
        sitemap_rows, sitemap_hosts, sitemap_errors = _collect_sitemap_entries(
            manager,
            max_sitemap_pages=max_sitemap_pages,
            scope_id=scope_id,
        )

        endpoint_map: dict[tuple[str, str], dict[str, Any]] = {}
        for row in request_rows:
            host = str(row.get("host") or "").strip()
            path = str(row.get("path") or "").strip()
            if not host or not path:
                continue

            normalized_path = _normalize_runtime_path(path)
            key = (host, normalized_path)
            endpoint = endpoint_map.setdefault(
                key,
                {
                    "host": host,
                    "normalized_path": normalized_path,
                    "methods": set(),
                    "status_codes": set(),
                    "query_params": set(),
                    "body_params": set(),
                    "content_types": set(),
                    "auth_hints": set(),
                    "sources": set(),
                    "sample_request_ids": [],
                    "sample_urls": set(),
                    "observed_count": 0,
                    "origins": set(),
                },
            )
            endpoint["methods"].add(str(row.get("method") or "ANY").upper())
            if row.get("response") and isinstance(row["response"], dict):
                status_code = row["response"].get("statusCode")
                if status_code:
                    endpoint["status_codes"].add(int(status_code))
            endpoint["query_params"].update(_query_params(row.get("query")))
            endpoint["sources"].add(str(row.get("source") or "proxy"))
            if row.get("id"):
                endpoint["sample_request_ids"].append(str(row["id"]))
            scheme = "https" if bool(row.get("isTls")) else "http"
            endpoint["sample_urls"].add(f"{scheme}://{host}{path}")
            endpoint["observed_count"] += 1
            endpoint["origins"].add("requests")

        for row in sitemap_rows:
            host = str(row.get("host") or "").strip()
            path = str(row.get("path") or "").strip()
            if not host or not path:
                continue

            normalized_path = _normalize_runtime_path(path)
            key = (host, normalized_path)
            endpoint = endpoint_map.setdefault(
                key,
                {
                    "host": host,
                    "normalized_path": normalized_path,
                    "methods": set(),
                    "status_codes": set(),
                    "query_params": set(),
                    "body_params": set(),
                    "content_types": set(),
                    "auth_hints": set(),
                    "sources": set(),
                    "sample_request_ids": [],
                    "sample_urls": set(),
                    "observed_count": 0,
                    "origins": set(),
                },
            )
            endpoint["methods"].add(str(row.get("method") or "ANY").upper())
            if row.get("status_code"):
                endpoint["status_codes"].add(int(row["status_code"]))
            endpoint["sample_urls"].add(f"https://{host}{path}")
            endpoint["observed_count"] += 1
            endpoint["origins"].add("sitemap")

        sampled_request_ids: list[str] = []
        for endpoint in endpoint_map.values():
            if not endpoint["sample_request_ids"]:
                continue
            sampled_request_ids.append(endpoint["sample_request_ids"][0])
            if len(sampled_request_ids) >= sample_request_details:
                break

        for request_id in sampled_request_ids:
            detail = _enrich_from_request_detail(manager, request_id)
            if not detail:
                continue
            for endpoint in endpoint_map.values():
                if request_id not in endpoint["sample_request_ids"]:
                    continue
                if detail.get("content_type"):
                    endpoint["content_types"].add(detail["content_type"])
                if detail.get("auth_hint"):
                    endpoint["auth_hints"].add(detail["auth_hint"])
                endpoint["body_params"].update(detail.get("body_params", []))

        inventory: list[dict[str, Any]] = []
        for endpoint in endpoint_map.values():
            methods = sorted(endpoint["methods"]) or ["ANY"]
            query_params = sorted(endpoint["query_params"])
            body_params = sorted(endpoint["body_params"])
            auth_hints = sorted(endpoint["auth_hints"]) or ["anonymous"]
            priority = _priority_for_endpoint(
                endpoint["normalized_path"],
                methods,
                query_params=query_params,
                body_params=body_params,
                auth_hints=auth_hints,
            )
            inventory.append(
                {
                    "host": endpoint["host"],
                    "normalized_path": endpoint["normalized_path"],
                    "methods": methods,
                    "status_codes": sorted(endpoint["status_codes"]),
                    "query_params": query_params,
                    "body_params": body_params,
                    "content_types": sorted(endpoint["content_types"]),
                    "auth_hints": auth_hints,
                    "sources": sorted(endpoint["sources"]),
                    "origins": sorted(endpoint["origins"]),
                    "sample_urls": sorted(endpoint["sample_urls"])[:3],
                    "sample_request_ids": endpoint["sample_request_ids"][:3],
                    "observed_count": endpoint["observed_count"],
                    "priority": priority,
                }
            )

        inventory.sort(key=_sort_inventory)
        selected_inventory = inventory[:max_seed_items]
        coverage_items = []
        for item in selected_inventory:
            params_summary = ", ".join(item["query_params"] + item["body_params"])
            auth_summary = ", ".join(item["auth_hints"])
            for method in item["methods"]:
                next_step = (
                    "Save guest, owner, other-user, and admin sessions; run differential allow-vs-deny "
                    "checks across IDs, tenant markers, and state-changing inputs"
                )
                if method in {"POST", "PUT", "PATCH", "DELETE"}:
                    next_step = (
                        "Replay state-changing requests with multiple session profiles, compare "
                        "success and response parity, then probe race and workflow drift"
                    )

                rationale = (
                    f"Auto-seeded from observed proxy traffic on host {item['host']} for "
                    f"{method} {item['normalized_path']}. Auth hints: {auth_summary}."
                )
                if params_summary:
                    rationale += f" Observed parameters: {params_summary}."

                coverage_items.append(
                    {
                        "target": target,
                        "component": f"runtime:{item['host']}",
                        "surface": f"Runtime endpoint {method} {item['normalized_path']}",
                        "status": "uncovered",
                        "priority": item["priority"],
                        "rationale": rationale,
                        "next_step": next_step,
                    }
                )

        if not coverage_items:
            return {
                "success": False,
                "error": "No runtime endpoints could be mapped from proxy history",
                "inventory": [],
                "request_errors": request_errors,
                "sitemap_errors": sitemap_errors,
            }

        coverage_result = bulk_record_coverage(
            agent_state=agent_state,
            items=coverage_items,
            preserve_existing_status=True,
        )

        inventory_review_status = "covered"
        inventory_review_priority = "normal"
        inventory_review_rationale = (
            f"Runtime mapper seeded the full observed runtime inventory for {target}: "
            f"{len(selected_inventory)} normalized endpoint(s) across "
            f"{len({item['host'] for item in selected_inventory})} host(s)."
        )
        inventory_review_next_step = (
            "Refresh runtime mapping only after new authenticated traffic, crawling, or fuzzing "
            "reveals additional surface area"
        )

        if request_errors or sitemap_errors:
            inventory_review_status = "blocked"
            inventory_review_priority = "high"
            inventory_review_rationale = (
                f"Runtime mapper hit discovery errors while mapping {target}; request errors: "
                f"{len(request_errors)}, sitemap errors: {len(sitemap_errors)}."
            )
            inventory_review_next_step = (
                "Repair proxy access or scope settings, then re-run runtime mapping before "
                "declaring runtime coverage complete"
            )
        elif len(inventory) > len(selected_inventory):
            inventory_review_status = "in_progress"
            inventory_review_priority = "high"
            inventory_review_rationale = (
                f"Runtime mapper observed {len(inventory)} normalized endpoint(s) for {target}, "
                f"but only {len(selected_inventory)} were seeded due to max_seed_items or "
                "page limits."
            )
            inventory_review_next_step = (
                "Increase max_seed_items/max_request_pages or explicitly review the omitted "
                "runtime surface before finishing the scan"
            )

        inventory_review_result = record_coverage(
            agent_state=agent_state,
            target=target,
            component="runtime_inventory",
            surface=f"Runtime inventory completeness for {target}",
            status=inventory_review_status,
            rationale=inventory_review_rationale,
            priority=inventory_review_priority,
            next_step=inventory_review_next_step,
        )

        root_agent_id, inventory_store = _get_inventory_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)
        inventory_store[_slug(target)] = {
            "target": target,
            "inventory": inventory,
            "inventory_total": len(inventory),
            "inventory_truncated": len(inventory) > len(selected_inventory),
            "selected_inventory": selected_inventory,
            "request_count": len(request_rows),
            "sitemap_hosts": sitemap_hosts,
            "request_errors": request_errors,
            "sitemap_errors": sitemap_errors,
            "mapped_at": _utc_now(),
        }

        evidence_result = record_evidence(
            agent_state=agent_state,
            title=f"Runtime surface map for {target}",
            details=json.dumps(
                {
                    "inventory": selected_inventory,
                    "inventory_total": len(inventory),
                    "inventory_truncated": len(inventory) > len(selected_inventory),
                    "request_count": len(request_rows),
                    "sitemap_hosts": sitemap_hosts,
                },
                ensure_ascii=False,
            ),
            source="traffic",
            target=target,
            component="runtime_mapper",
        )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to map runtime surface: {e}"}
    else:
        return {
            "success": True,
            "inventory_total": len(inventory),
            "inventory_truncated": len(inventory) > len(selected_inventory),
            "seeded_count": coverage_result.get("updated_count", 0),
            "inventory": selected_inventory,
            "request_count": len(request_rows),
            "sitemap_hosts": sitemap_hosts,
            "coverage_result": coverage_result,
            "inventory_review_result": inventory_review_result,
            "evidence_result": evidence_result,
            "request_errors": request_errors,
            "sitemap_errors": sitemap_errors,
        }


@register_tool(sandbox_execution=False)
def list_runtime_inventory(
    agent_state: Any,
    target: str | None = None,
    include_inventory: bool = True,
    max_items: int = 50,
) -> dict[str, Any]:
    try:
        if max_items < 1:
            raise ValueError("max_items must be >= 1")

        root_agent_id, inventory_store = _get_inventory_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        records = list(inventory_store.values())
        records.sort(key=lambda item: str(item.get("mapped_at", "")), reverse=True)

        if target:
            lookup = inventory_store.get(_slug(target))
            if lookup is None:
                raise ValueError(f"No runtime inventory found for target '{target}'")
            records = [lookup]

        response_records = []
        for record in records[:max_items]:
            response_record = dict(record)
            if not include_inventory:
                response_record.pop("inventory", None)
                response_record.pop("selected_inventory", None)
            response_records.append(response_record)

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to list runtime inventory: {e}"}
    else:
        return {
            "success": True,
            "root_agent_id": root_agent_id,
            "inventory_count": len(records),
            "records": response_records,
        }
