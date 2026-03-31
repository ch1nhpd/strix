import json
import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool

from .assessment_actions import (
    _resolve_root_agent_id,
    _slug,
    _utc_now,
    bulk_record_coverage,
    record_evidence,
)
from .assessment_runtime_actions import _normalize_runtime_path, _priority_for_endpoint


SurfaceMiningRecord = dict[str, Any]
_surface_mining_storage: dict[str, dict[str, SurfaceMiningRecord]] = {}
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
JS_ROUTE_PATTERN = re.compile(
    r"""(?:"|')(?P<path>/(?:api|graphql|graphiql|socket(?:\.io)?|ws|websocket|subscriptions?|events?|internal|admin|v\d+)[A-Za-z0-9_./?&=%:-]*)""",
    re.IGNORECASE,
)
ABS_WS_PATTERN = re.compile(r"(?P<url>wss?://[A-Za-z0-9._:-]+/[A-Za-z0-9_./?&=%:-]*)", re.IGNORECASE)
STATIC_EXTENSIONS = {
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".map",
    ".png",
    ".svg",
    ".woff",
    ".woff2",
}
OPENAPI_PARAM_LOCATIONS = {"query", "path", "header", "cookie"}


def clear_surface_mining_storage() -> None:
    _surface_mining_storage.clear()


def _get_surface_store(agent_state: Any) -> tuple[str, dict[str, SurfaceMiningRecord]]:
    root_agent_id = _resolve_root_agent_id(agent_state)
    if root_agent_id not in _surface_mining_storage:
        _surface_mining_storage[root_agent_id] = {}
    return root_agent_id, _surface_mining_storage[root_agent_id]


def _update_agent_context(agent_state: Any, root_agent_id: str) -> None:
    if hasattr(agent_state, "update_context"):
        agent_state.update_context("surface_mining_root_agent_id", root_agent_id)


def get_proxy_manager() -> Any:
    from strix.tools.proxy.proxy_manager import get_proxy_manager as _get_proxy_manager

    return _get_proxy_manager()


def _split_http_message(content: str) -> tuple[str, dict[str, str], str]:
    lines = content.splitlines()
    if not lines:
        return "", {}, ""

    headers: dict[str, str] = {}
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
    return lines[0].strip(), headers, body


def _is_javascript(path: str, headers: dict[str, str]) -> bool:
    lowered_path = path.lower()
    if any(lowered_path.endswith(extension) for extension in [".js", ".mjs", ".cjs"]):
        return True
    content_type = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
    return "javascript" in content_type or "ecmascript" in content_type


def _normalize_path_candidate(candidate: str) -> str | None:
    raw = candidate.strip().strip("\"' ")
    if not raw:
        return None

    if raw.lower().startswith(("http://", "https://", "ws://", "wss://")):
        parsed = urlparse(raw)
        if not parsed.path:
            return None
        return _normalize_runtime_path(parsed.path)

    if not raw.startswith("/"):
        return None

    parsed = urlparse(raw)
    if not parsed.path:
        return None
    return _normalize_runtime_path(parsed.path)


def _extract_js_paths(response_body: str) -> list[str]:
    candidates = []
    for match in JS_ROUTE_PATTERN.finditer(response_body):
        candidate = _normalize_path_candidate(match.group("path"))
        if candidate:
            candidates.append(candidate)
    return sorted(set(candidates))


def _extract_ws_urls(response_body: str) -> list[str]:
    candidates = []
    for match in ABS_WS_PATTERN.finditer(response_body):
        parsed = urlparse(match.group("url"))
        normalized = _normalize_runtime_path(parsed.path)
        candidates.append(f"{parsed.scheme}://{parsed.netloc}{normalized}")
    return sorted(set(candidates))


def _request_detail(manager: Any, request_id: str) -> tuple[dict[str, str], str]:
    result = manager.view_request(request_id=request_id, part="request", page=1, page_size=120)
    if result.get("error") or not result.get("content"):
        return {}, ""
    _, headers, body = _split_http_message(str(result["content"]))
    return headers, body


def _response_detail(manager: Any, request_id: str) -> tuple[dict[str, str], str]:
    result = manager.view_request(request_id=request_id, part="response", page=1, page_size=200)
    if result.get("error") or not result.get("content"):
        return {}, ""
    _, headers, body = _split_http_message(str(result["content"]))
    return headers, body


def _seed_item(
    *,
    target: str,
    component: str,
    surface: str,
    priority: str,
    rationale: str,
    next_step: str,
) -> dict[str, Any]:
    return {
        "target": target,
        "component": component,
        "surface": surface,
        "status": "uncovered",
        "priority": priority,
        "rationale": rationale,
        "next_step": next_step,
    }


def _artifact_sort(item: dict[str, Any]) -> tuple[int, str, str]:
    order = {
        "openapi_spec": 0,
        "graphql_endpoint": 1,
        "graphql_persisted_query": 2,
        "websocket_endpoint": 3,
        "js_route": 4,
    }
    return (
        order.get(str(item.get("kind") or ""), 5),
        str(item.get("host") or ""),
        str(item.get("path") or ""),
    )


def _unique_strings(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        candidate = str(value).strip()
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return normalized


def _resolve_json_pointer(payload: dict[str, Any], pointer: str) -> dict[str, Any] | None:
    candidate = str(pointer or "").strip()
    if not candidate.startswith("#/"):
        return None
    current: Any = payload
    for token in candidate[2:].split("/"):
        if not isinstance(current, dict):
            return None
        key = token.replace("~1", "/").replace("~0", "~")
        current = current.get(key)
    return current if isinstance(current, dict) else None


def _schema_ref_name(schema: dict[str, Any]) -> str | None:
    reference = str(schema.get("$ref") or "").strip()
    if not reference:
        return None
    return reference.rsplit("/", 1)[-1] or None


def _resolve_openapi_object(payload: dict[str, Any], value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    reference = str(value.get("$ref") or "").strip()
    if not reference:
        return value
    resolved = _resolve_json_pointer(payload, reference)
    return resolved if isinstance(resolved, dict) else None


def _schema_required_names(
    schema: dict[str, Any],
    payload: dict[str, Any],
    *,
    prefix: str = "",
    depth: int = 0,
    visited: set[str] | None = None,
) -> list[str]:
    if depth > 2:
        return []
    resolved = _resolve_openapi_object(payload, schema)
    if resolved is None:
        return []

    local_visited = set(visited or set())
    reference = str(schema.get("$ref") or "").strip()
    if reference:
        if reference in local_visited:
            return []
        local_visited.add(reference)

    required_names = set()
    for name in list(resolved.get("required") or []):
        if not isinstance(name, str):
            continue
        required_names.add(f"{prefix}.{name}" if prefix else name)

    properties = resolved.get("properties") or {}
    if isinstance(properties, dict):
        for name, child_schema in properties.items():
            if not isinstance(name, str) or not isinstance(child_schema, dict):
                continue
            child_prefix = f"{prefix}.{name}" if prefix else name
            required_names.update(
                _schema_required_names(
                    child_schema,
                    payload,
                    prefix=child_prefix,
                    depth=depth + 1,
                    visited=local_visited,
                )
            )

    for keyword in ["allOf", "anyOf", "oneOf"]:
        for entry in list(resolved.get(keyword) or []):
            if not isinstance(entry, dict):
                continue
            required_names.update(
                _schema_required_names(
                    entry,
                    payload,
                    prefix=prefix,
                    depth=depth + 1,
                    visited=local_visited,
                )
            )

    items = resolved.get("items")
    if isinstance(items, dict):
        required_names.update(
            _schema_required_names(
                items,
                payload,
                prefix=prefix,
                depth=depth + 1,
                visited=local_visited,
            )
        )

    return sorted(required_names)


def _schema_details(
    schema: dict[str, Any],
    payload: dict[str, Any],
    *,
    prefix: str = "",
    depth: int = 0,
    visited: set[str] | None = None,
) -> dict[str, list[str]]:
    if depth > 2:
        return {
            "fields": [],
            "identifiers": [],
            "object_types": [],
            "required_fields": [],
        }

    resolved = _resolve_openapi_object(payload, schema)
    if resolved is None:
        return {
            "fields": [],
            "identifiers": [],
            "object_types": [],
            "required_fields": [],
        }

    local_visited = set(visited or set())
    reference = str(schema.get("$ref") or "").strip()
    if reference:
        if reference in local_visited:
            return {
                "fields": [],
                "identifiers": [],
                "object_types": [],
                "required_fields": [],
            }
        local_visited.add(reference)

    fields: list[str] = []
    identifiers: list[str] = []
    object_types: list[str] = []
    required_fields = _schema_required_names(
        schema,
        payload,
        prefix=prefix,
        depth=depth,
        visited=local_visited,
    )

    ref_name = _schema_ref_name(schema)
    if ref_name:
        object_types.append(ref_name)

    properties = resolved.get("properties") or {}
    if isinstance(properties, dict):
        for name, child_schema in properties.items():
            if not isinstance(name, str):
                continue
            field_name = f"{prefix}.{name}" if prefix else name
            fields.append(field_name)
            lowered = name.lower()
            if (
                lowered in {"id", "uuid", "token"}
                or lowered.endswith(("_id", "_token"))
                or "token" in lowered
            ):
                identifiers.append(field_name)
            if isinstance(child_schema, dict):
                child_ref_name = _schema_ref_name(child_schema)
                if child_ref_name:
                    object_types.append(child_ref_name)
                child_details = _schema_details(
                    child_schema,
                    payload,
                    prefix=field_name,
                    depth=depth + 1,
                    visited=local_visited,
                )
                fields.extend(child_details["fields"])
                identifiers.extend(child_details["identifiers"])
                object_types.extend(child_details["object_types"])
                required_fields.extend(child_details["required_fields"])

    items = resolved.get("items")
    if isinstance(items, dict):
        item_details = _schema_details(
            items,
            payload,
            prefix=prefix,
            depth=depth + 1,
            visited=local_visited,
        )
        fields.extend(item_details["fields"])
        identifiers.extend(item_details["identifiers"])
        object_types.extend(item_details["object_types"])
        required_fields.extend(item_details["required_fields"])

    for keyword in ["allOf", "anyOf", "oneOf"]:
        for entry in list(resolved.get(keyword) or []):
            if not isinstance(entry, dict):
                continue
            nested = _schema_details(
                entry,
                payload,
                prefix=prefix,
                depth=depth + 1,
                visited=local_visited,
            )
            fields.extend(nested["fields"])
            identifiers.extend(nested["identifiers"])
            object_types.extend(nested["object_types"])
            required_fields.extend(nested["required_fields"])

    return {
        "fields": _unique_strings(fields)[:80],
        "identifiers": _unique_strings(identifiers)[:40],
        "object_types": _unique_strings(object_types)[:24],
        "required_fields": _unique_strings(required_fields)[:80],
    }


def _security_requirement_names(requirements: Any) -> list[str]:
    names: list[str] = []
    for requirement in list(requirements or []):
        if not isinstance(requirement, dict):
            continue
        names.extend(str(name) for name in requirement.keys() if str(name).strip())
    return _unique_strings(names)


def _parse_openapi_document(response_body: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(response_body)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    if not payload.get("openapi") and not payload.get("swagger"):
        return None

    operations: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []
    request_fields: list[dict[str, Any]] = []
    objects: list[dict[str, Any]] = []
    paths = payload.get("paths") or {}
    top_level_security = _security_requirement_names(payload.get("security") or [])
    components = payload.get("components") or {}
    schemas = components.get("schemas") or {}

    if isinstance(paths, dict):
        for path, item in paths.items():
            if not isinstance(path, str) or not isinstance(item, dict):
                continue
            normalized_path = _normalize_runtime_path(path)
            path_parameters = [
                entry
                for entry in list(item.get("parameters") or [])
                if isinstance(entry, dict)
            ]
            for method, operation in item.items():
                normalized_method = str(method).upper()
                if normalized_method not in HTTP_METHODS or not isinstance(operation, dict):
                    continue

                content_types = _unique_strings(
                    [
                        str(content_type)
                        for content_type in list(
                            (operation.get("requestBody") or {}).get("content", {}).keys()
                        )
                        if str(content_type).strip()
                    ]
                )
                security = _security_requirement_names(operation.get("security") or [])
                requires_auth = bool(security or top_level_security)
                operations.append(
                    {
                        "method": normalized_method,
                        "path": normalized_path,
                        "content_types": content_types,
                        "security": security or top_level_security,
                        "requires_auth": requires_auth,
                    }
                )

                for raw_parameter in [*path_parameters, *list(operation.get("parameters") or [])]:
                    parameter = _resolve_openapi_object(payload, raw_parameter)
                    if parameter is None:
                        continue
                    name = str(parameter.get("name") or "").strip()
                    location = str(parameter.get("in") or "").strip().lower()
                    if not name or location not in OPENAPI_PARAM_LOCATIONS:
                        continue
                    parameter_schema = _resolve_openapi_object(
                        payload, parameter.get("schema") or {}
                    ) or {}
                    object_hint = (
                        _schema_ref_name(parameter_schema)
                        or _schema_ref_name(parameter.get("schema") or {})
                        or str(parameter_schema.get("title") or "").strip()
                        or None
                    )
                    parameters.append(
                        {
                            "method": normalized_method,
                            "path": normalized_path,
                            "name": name,
                            "location": location,
                            "required": bool(parameter.get("required")),
                            "schema_type": str(parameter_schema.get("type") or "").strip() or None,
                            "object_hint": object_hint,
                            "identifier": (
                                name.lower() in {"id", "uuid", "token"}
                                or name.lower().endswith(("_id", "_token"))
                            ),
                        }
                    )

                request_body = _resolve_openapi_object(payload, operation.get("requestBody") or {})
                if request_body is None:
                    continue
                content = request_body.get("content") or {}
                if not isinstance(content, dict):
                    continue
                for content_type, media in content.items():
                    if not isinstance(media, dict):
                        continue
                    schema = media.get("schema")
                    if not isinstance(schema, dict):
                        continue
                    details = _schema_details(schema, payload)
                    primary_object = next(iter(details["object_types"]), None)
                    required_fields = set(details["required_fields"])
                    for field_name in details["fields"]:
                        request_fields.append(
                            {
                                "method": normalized_method,
                                "path": normalized_path,
                                "name": field_name,
                                "location": "body",
                                "content_type": str(content_type),
                                "required": field_name in required_fields
                                or bool(request_body.get("required")),
                                "object_hint": primary_object,
                                "identifier": field_name in details["identifiers"],
                            }
                        )

    if isinstance(schemas, dict):
        for schema_name, schema in schemas.items():
            if not isinstance(schema_name, str) or not isinstance(schema, dict):
                continue
            details = _schema_details(schema, payload)
            objects.append(
                {
                    "object_type": schema_name,
                    "fields": details["fields"][:30],
                    "identifiers": details["identifiers"][:12],
                }
            )

    deduped_operations = []
    seen_operations: set[tuple[str, str]] = set()
    for item in operations:
        key = (str(item.get("method") or ""), str(item.get("path") or ""))
        if key in seen_operations:
            continue
        seen_operations.add(key)
        deduped_operations.append(item)

    deduped_parameters = []
    seen_parameters: set[tuple[str, str, str, str]] = set()
    for item in parameters:
        key = (
            str(item.get("method") or ""),
            str(item.get("path") or ""),
            str(item.get("name") or ""),
            str(item.get("location") or ""),
        )
        if key in seen_parameters:
            continue
        seen_parameters.add(key)
        deduped_parameters.append(item)

    deduped_request_fields = []
    seen_request_fields: set[tuple[str, str, str, str]] = set()
    for item in request_fields:
        key = (
            str(item.get("method") or ""),
            str(item.get("path") or ""),
            str(item.get("name") or ""),
            str(item.get("content_type") or ""),
        )
        if key in seen_request_fields:
            continue
        seen_request_fields.add(key)
        deduped_request_fields.append(item)

    deduped_objects = []
    seen_objects: set[str] = set()
    for item in objects:
        object_type = str(item.get("object_type") or "").strip()
        if not object_type or object_type in seen_objects:
            continue
        seen_objects.add(object_type)
        deduped_objects.append(item)

    return {
        "documented_operations": deduped_operations[:60],
        "documented_parameters": deduped_parameters[:120],
        "documented_request_fields": deduped_request_fields[:120],
        "documented_objects": deduped_objects[:60],
        "documented_operation_count": len(deduped_operations),
        "documented_parameter_count": len(deduped_parameters),
        "documented_request_field_count": len(deduped_request_fields),
        "documented_object_count": len(deduped_objects),
        "security_schemes": _unique_strings([*top_level_security, *list((components.get("securitySchemes") or {}).keys())])[:20],
    }


def _record_for_response(record: SurfaceMiningRecord, *, include_artifacts: bool) -> SurfaceMiningRecord:
    response = dict(record)
    if not include_artifacts:
        response.pop("artifacts", None)
        response.pop("selected_artifacts", None)
    return response


@register_tool(sandbox_execution=False)
def mine_additional_attack_surface(
    agent_state: Any,
    target: str,
    max_request_pages: int = 2,
    page_size: int = 50,
    max_response_samples: int = 20,
    max_seed_items: int = 50,
    httpql_filter: str | None = None,
    scope_id: str | None = None,
) -> dict[str, Any]:
    try:
        if max_request_pages < 1:
            raise ValueError("max_request_pages must be >= 1")
        if page_size < 1:
            raise ValueError("page_size must be >= 1")
        if max_response_samples < 1:
            raise ValueError("max_response_samples must be >= 1")
        if max_seed_items < 1:
            raise ValueError("max_seed_items must be >= 1")

        manager = get_proxy_manager()
        requests: list[dict[str, Any]] = []
        for page in range(1, max_request_pages + 1):
            result = manager.list_requests(
                httpql_filter=httpql_filter,
                start_page=page,
                end_page=page,
                page_size=page_size,
                sort_by="timestamp",
                sort_order="desc",
                scope_id=scope_id,
            )
            if result.get("error"):
                raise ValueError(str(result["error"]))
            rows = result.get("requests", [])
            requests.extend(rows)
            if int(result.get("returned_count") or len(rows)) < page_size:
                break

        artifacts: list[dict[str, Any]] = []
        coverage_items: list[dict[str, Any]] = []
        seen_artifacts: set[tuple[str, str, str]] = set()
        candidate_rows = requests[:max_response_samples]

        for row in candidate_rows:
            request_id = str(row.get("id") or "")
            host = str(row.get("host") or "").strip()
            path = str(row.get("path") or "").strip()
            method = str(row.get("method") or "GET").upper()
            if not request_id or not host or not path:
                continue

            request_headers, request_body = _request_detail(manager, request_id)
            response_headers, response_body = _response_detail(manager, request_id)
            normalized_path = _normalize_runtime_path(path)
            lowered_path = normalized_path.lower()

            openapi_document = _parse_openapi_document(response_body)
            documented_operations = (
                list(openapi_document.get("documented_operations") or [])
                if isinstance(openapi_document, dict)
                else []
            )
            if openapi_document is not None:
                key = ("openapi_spec", host, normalized_path)
                if key not in seen_artifacts:
                    seen_artifacts.add(key)
                    artifacts.append(
                        {
                            "kind": "openapi_spec",
                            "host": host,
                            "path": normalized_path,
                            "method": method,
                            "sample_request_id": request_id,
                            "documented_operation_count": int(
                                openapi_document.get("documented_operation_count") or 0
                            ),
                            "documented_operations": documented_operations[:20],
                            "documented_parameter_count": int(
                                openapi_document.get("documented_parameter_count") or 0
                            ),
                            "documented_parameters": list(
                                openapi_document.get("documented_parameters") or []
                            )[:40],
                            "documented_request_field_count": int(
                                openapi_document.get("documented_request_field_count") or 0
                            ),
                            "documented_request_fields": list(
                                openapi_document.get("documented_request_fields") or []
                            )[:40],
                            "documented_object_count": int(
                                openapi_document.get("documented_object_count") or 0
                            ),
                            "documented_objects": list(openapi_document.get("documented_objects") or [])[
                                :24
                            ],
                            "security_schemes": list(openapi_document.get("security_schemes") or [])[
                                :12
                            ],
                            "priority": "high",
                        }
                    )
                    coverage_items.append(
                        _seed_item(
                            target=target,
                            component=f"surface:{host}",
                            surface=f"OpenAPI/Swagger exposure {method} {normalized_path}",
                            priority="high",
                            rationale=(
                                f"Observed an OpenAPI/Swagger artifact on host {host} at "
                                f"{normalized_path}; documented operations may expose hidden or privileged routes."
                            ),
                            next_step=(
                                "Enumerate documented routes, compare them against runtime inventory, "
                                "and prioritize privileged or state-changing operations"
                            ),
                        )
                    )

                for operation in documented_operations:
                    op_priority = _priority_for_endpoint(
                        operation["path"],
                        [operation["method"]],
                        query_params=[],
                        body_params=[],
                        auth_hints=[],
                    )
                    coverage_items.append(
                        _seed_item(
                            target=target,
                            component=f"spec:{host}",
                            surface=f"Documented endpoint {operation['method']} {operation['path']}",
                            priority=op_priority,
                            rationale=(
                                f"Auto-seeded from OpenAPI/Swagger documentation observed at "
                                f"{normalized_path} on host {host}."
                            ),
                            next_step=(
                                "Validate whether the documented operation is reachable, hidden from "
                                "runtime inventory, or differently protected than adjacent routes"
                            ),
                        )
                    )

            is_graphql = "graphql" in lowered_path
            if not is_graphql and request_body:
                is_graphql = "\"query\"" in request_body or "\"mutation\"" in request_body
            if is_graphql:
                key = ("graphql_endpoint", host, normalized_path)
                if key not in seen_artifacts:
                    seen_artifacts.add(key)
                    artifacts.append(
                        {
                            "kind": "graphql_endpoint",
                            "host": host,
                            "path": normalized_path,
                            "method": method,
                            "sample_request_id": request_id,
                            "priority": "high",
                        }
                    )
                    coverage_items.append(
                        _seed_item(
                            target=target,
                            component=f"surface:{host}",
                            surface=f"GraphQL endpoint {method} {normalized_path}",
                            priority="high",
                            rationale=(
                                f"Observed GraphQL traffic on host {host} at {normalized_path}; "
                                "schema breadth and resolver-level authorization may diverge from HTTP routes."
                            ),
                            next_step=(
                                "Check introspection, persisted queries, object-level authorization, "
                                "and resolver parity across roles or tenants"
                            ),
                        )
                    )

            if "persistedquery" in request_body.lower() or "persistedquery" in response_body.lower():
                key = ("graphql_persisted_query", host, normalized_path)
                if key not in seen_artifacts:
                    seen_artifacts.add(key)
                    artifacts.append(
                        {
                            "kind": "graphql_persisted_query",
                            "host": host,
                            "path": normalized_path,
                            "method": method,
                            "sample_request_id": request_id,
                            "priority": "high",
                        }
                    )
                    coverage_items.append(
                        _seed_item(
                            target=target,
                            component=f"surface:{host}",
                            surface=f"GraphQL persisted-query surface {normalized_path}",
                            priority="high",
                            rationale=(
                                f"Observed persisted-query hints on host {host} at {normalized_path}; "
                                "alternate operation IDs can bypass superficial route-based validation."
                            ),
                            next_step=(
                                "Enumerate alternate hashes or operation names and compare resolver-level "
                                "authorization with normal GraphQL execution"
                            ),
                        )
                    )

            has_websocket_upgrade = (
                str(request_headers.get("Upgrade") or request_headers.get("upgrade") or "").lower()
                == "websocket"
            )
            if has_websocket_upgrade or "socket" in lowered_path or lowered_path.startswith("/ws"):
                key = ("websocket_endpoint", host, normalized_path)
                if key not in seen_artifacts:
                    seen_artifacts.add(key)
                    artifacts.append(
                        {
                            "kind": "websocket_endpoint",
                            "host": host,
                            "path": normalized_path,
                            "method": method,
                            "sample_request_id": request_id,
                            "priority": "high",
                        }
                    )
                    coverage_items.append(
                        _seed_item(
                            target=target,
                            component=f"surface:{host}",
                            surface=f"WebSocket endpoint {method} {normalized_path}",
                            priority="high",
                            rationale=(
                                f"Observed WebSocket or upgrade traffic on host {host} at {normalized_path}; "
                                "socket channels often miss the authorization checks present on HTTP routes."
                            ),
                            next_step=(
                                "Compare socket-level authorization and topic isolation against equivalent "
                                "HTTP operations or object boundaries"
                            ),
                        )
                    )

            if _is_javascript(path, response_headers):
                for js_path in _extract_js_paths(response_body):
                    if any(js_path.lower().endswith(extension) for extension in STATIC_EXTENSIONS):
                        continue
                    key = ("js_route", host, js_path)
                    if key in seen_artifacts:
                        continue
                    seen_artifacts.add(key)
                    priority = _priority_for_endpoint(
                        js_path,
                        ["ANY"],
                        query_params=[],
                        body_params=[],
                        auth_hints=[],
                    )
                    artifacts.append(
                        {
                            "kind": "js_route",
                            "host": host,
                            "path": js_path,
                            "method": "ANY",
                            "sample_request_id": request_id,
                            "priority": priority,
                            "source_asset": normalized_path,
                        }
                    )
                    coverage_items.append(
                        _seed_item(
                            target=target,
                            component=f"surface:{host}",
                            surface=f"JavaScript-discovered route ANY {js_path}",
                            priority=priority,
                            rationale=(
                                f"JavaScript asset {normalized_path} referenced hidden or client-side API "
                                f"path {js_path} on host {host}."
                            ),
                            next_step=(
                                "Probe the discovered route directly, compare privileged vs low-privilege "
                                "responses, and reconcile it against runtime inventory"
                            ),
                        )
                    )

                for ws_url in _extract_ws_urls(response_body):
                    parsed = urlparse(ws_url)
                    ws_path = _normalize_runtime_path(parsed.path)
                    resolved_host = parsed.netloc or host
                    key = ("websocket_endpoint", resolved_host, ws_path)
                    if key in seen_artifacts:
                        continue
                    seen_artifacts.add(key)
                    artifacts.append(
                        {
                            "kind": "websocket_endpoint",
                            "host": resolved_host,
                            "path": ws_path,
                            "method": "GET",
                            "sample_request_id": request_id,
                            "priority": "high",
                            "source_asset": normalized_path,
                        }
                    )
                    coverage_items.append(
                        _seed_item(
                            target=target,
                            component=f"surface:{resolved_host}",
                            surface=f"WebSocket endpoint GET {ws_path}",
                            priority="high",
                            rationale=(
                                f"JavaScript asset {normalized_path} referenced WebSocket endpoint {ws_url}; "
                                "realtime channels often hide authorization and subscription bugs."
                            ),
                            next_step=(
                                "Test socket connection setup, channel naming, and cross-user or cross-tenant "
                                "subscription isolation"
                            ),
                        )
                    )

        if not coverage_items:
            return {
                "success": False,
                "error": "No additional attack-surface artifacts could be mined from proxy history",
            }

        artifacts.sort(key=_artifact_sort)
        selected_artifacts = artifacts[:max_seed_items]
        coverage_result = bulk_record_coverage(
            agent_state=agent_state,
            items=coverage_items[:max_seed_items],
            preserve_existing_status=True,
        )

        root_agent_id, store = _get_surface_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)
        store[_slug(target)] = {
            "target": target,
            "artifacts": artifacts,
            "selected_artifacts": selected_artifacts,
            "artifacts_total": len(artifacts),
            "request_count": len(requests),
            "mined_at": _utc_now(),
        }

        evidence_result = record_evidence(
            agent_state=agent_state,
            title=f"Additional attack-surface artifacts for {target}",
            details=json.dumps(
                {
                    "artifacts": selected_artifacts,
                    "artifacts_total": len(artifacts),
                    "request_count": len(requests),
                },
                ensure_ascii=False,
            ),
            source="traffic",
            target=target,
            component="surface_miner",
        )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to mine additional attack surface: {e}"}
    else:
        return {
            "success": True,
            "artifacts_total": len(artifacts),
            "seeded_count": coverage_result.get("updated_count", 0),
            "artifacts": selected_artifacts,
            "coverage_result": coverage_result,
            "evidence_result": evidence_result,
        }


@register_tool(sandbox_execution=False)
def list_mined_attack_surface(
    agent_state: Any,
    target: str | None = None,
    include_artifacts: bool = True,
    max_items: int = 50,
) -> dict[str, Any]:
    try:
        if max_items < 1:
            raise ValueError("max_items must be >= 1")

        root_agent_id, store = _get_surface_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)
        records = list(store.values())
        records.sort(key=lambda item: str(item.get("mined_at", "")), reverse=True)

        if target:
            record = store.get(_slug(target))
            if record is None:
                raise ValueError(f"No mined attack-surface record found for target '{target}'")
            records = [record]

        response_records = [
            _record_for_response(record, include_artifacts=include_artifacts)
            for record in records[:max_items]
        ]

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to list mined attack surface: {e}"}
    else:
        return {
            "success": True,
            "root_agent_id": root_agent_id,
            "record_count": len(records),
            "records": response_records,
        }
