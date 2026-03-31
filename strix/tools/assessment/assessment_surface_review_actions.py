# ruff: noqa: E501, PERF401, PLR0911, PLR0912, PLR0915, PLR5501, SIM102, TRY301

import ipaddress
import json
import re
from collections import Counter
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool

from .assessment_actions import (
    _normalize_non_empty,
    _resolve_root_agent_id,
    _slug,
    _utc_now,
    list_assessment_state,
    record_evidence,
)
from .assessment_runtime_actions import (
    _normalize_runtime_path,
    _priority_for_endpoint,
    list_runtime_inventory,
)
from .assessment_session_actions import list_session_profiles
from .assessment_surface_actions import list_mined_attack_surface
from .assessment_toolchain_actions import list_security_tool_runs
from .assessment_workflow_actions import list_discovered_workflows


SurfaceReviewRecord = dict[str, Any]
_surface_review_storage: dict[str, dict[str, SurfaceReviewRecord]] = {}
COMMON_COMPOUND_SUFFIXES = {
    "co.id",
    "co.il",
    "co.in",
    "co.jp",
    "co.kr",
    "co.nz",
    "co.th",
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.hk",
    "com.mx",
    "com.sg",
    "com.tr",
}
LIKELY_SCOPE_PREFIXES = [
    "admin",
    "api",
    "auth",
    "assets",
    "beta",
    "cdn",
    "dashboard",
    "dev",
    "docs",
    "files",
    "graphql",
    "img",
    "internal",
    "m",
    "mobile",
    "old",
    "openapi",
    "portal",
    "qa",
    "sso",
    "stage",
    "static",
    "status",
    "uat",
    "vpn",
    "ws",
]
HOST_TYPE_HINTS = {
    "admin": {"admin", "dashboard", "manage", "moderation", "portal"},
    "api": {"api", "graphql", "grpc", "openapi", "swagger"},
    "auth": {"auth", "login", "oauth", "sso", "identity", "accounts"},
    "docs": {"docs", "swagger", "openapi", "postman", "developer"},
    "file": {"assets", "cdn", "files", "img", "media", "static", "upload"},
    "marketing": {"blog", "help", "home", "landing", "news", "support", "www"},
}
PATH_SECTION_HINTS = {
    "auth": {
        "auth",
        "login",
        "logout",
        "mfa",
        "oauth",
        "password",
        "recovery",
        "reset",
        "signup",
        "verify",
    },
    "billing": {
        "billing",
        "checkout",
        "coupon",
        "credit",
        "invoice",
        "payment",
        "plan",
        "price",
        "refund",
        "subscription",
        "wallet",
    },
    "docs": {"docs", "graphiql", "openapi", "postman", "swagger"},
    "file": {
        "attachment",
        "avatar",
        "document",
        "download",
        "export",
        "file",
        "image",
        "import",
        "media",
        "upload",
    },
}
GENERIC_OBJECT_SEGMENTS = {
    "admin",
    "api",
    "app",
    "auth",
    "graphql",
    "graphiql",
    "internal",
    "public",
    "rest",
    "service",
    "services",
    "v1",
    "v2",
    "v3",
    "v4",
    "v5",
}
ROLE_STATE_MARKERS = {
    "active": {"active", "enabled"},
    "deleted-like": {"archived", "deactivated", "deleted", "disabled", "removed"},
    "invited": {"invitation", "invite", "invited"},
    "suspended": {"blocked", "locked", "suspend", "suspended"},
    "unverified": {"pending", "unverified"},
    "verified": {"approved", "verified"},
}


def clear_surface_review_storage() -> None:
    _surface_review_storage.clear()


def _get_surface_review_store(agent_state: Any) -> tuple[str, dict[str, SurfaceReviewRecord]]:
    root_agent_id = _resolve_root_agent_id(agent_state)
    if root_agent_id not in _surface_review_storage:
        _surface_review_storage[root_agent_id] = {}
    return root_agent_id, _surface_review_storage[root_agent_id]


def _update_agent_context(agent_state: Any, root_agent_id: str) -> None:
    if hasattr(agent_state, "update_context"):
        agent_state.update_context("surface_review_root_agent_id", root_agent_id)


def _unique_strings(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        candidate = str(value).strip()
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return normalized


def _normalize_object_name(value: str) -> str:
    candidate = re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")
    return candidate or str(value).strip().lower()


def _extend_string_set(target: set[str], value: Any) -> None:
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _extend_string_set(target, item)
        return
    candidate = str(value).strip()
    if candidate:
        target.add(candidate)


def _priority_rank(priority: str) -> int:
    return {"low": 0, "normal": 1, "high": 2, "critical": 3}.get(str(priority), 1)


def _max_priority(values: list[str]) -> str:
    if not values:
        return "normal"
    return max(values, key=_priority_rank)


def _signal_classification(
    *,
    confirmed: bool = False,
    exposure: bool = False,
    duplicate: bool = False,
    in_scope: bool = True,
    blind: bool = False,
    weak: bool = False,
) -> str:
    if not in_scope:
        return "out-of-scope"
    if blind:
        return "blind-spot"
    if duplicate:
        return "duplicate-risk"
    if exposure:
        return "exposed-info"
    if confirmed:
        return "confirmed"
    if weak:
        return "weak-signal"
    return "suspected"


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _normalize_host(value: str) -> str | None:
    candidate = str(value).strip()
    if not candidate:
        return None
    if "://" in candidate:
        parsed = urlparse(candidate)
        if parsed.hostname:
            return parsed.hostname.lower()
        return None
    if "/" in candidate:
        candidate = candidate.split("/", 1)[0]
    if "?" in candidate:
        candidate = candidate.split("?", 1)[0]
    if ":" in candidate and not candidate.startswith("[") and candidate.count(":") == 1:
        host_part, port_part = candidate.split(":", 1)
        if port_part.isdigit():
            candidate = host_part
    normalized = candidate.strip().strip(".").lower()
    return normalized or None


def _root_domain_for_host(host: str) -> str:
    normalized = host.strip().strip(".").lower()
    if not normalized or _is_ip_address(normalized):
        return normalized
    labels = normalized.split(".")
    if len(labels) <= 2:
        return normalized
    compound_suffix = ".".join(labels[-2:])
    if compound_suffix in COMMON_COMPOUND_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _extract_scope_candidates_from_tool_runs(tool_runs: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for run in tool_runs:
        scope = run.get("scope") or {}
        if not isinstance(scope, dict):
            continue
        values.extend(str(item) for item in list(scope.get("targets") or []) if str(item).strip())
        if isinstance(scope.get("url"), str):
            values.append(str(scope["url"]))
    return _unique_strings(values)


def _build_scope_map(*, explicit_scope: list[str], derived_hosts: list[str]) -> dict[str, Any]:
    root_domains: list[str] = []
    wildcard_domains: list[str] = []
    fixed_hosts: list[str] = []
    path_based_scope: list[dict[str, str]] = []
    edge_cases: list[str] = []
    assumptions: list[str] = []

    for item in explicit_scope:
        candidate = str(item).strip()
        if not candidate:
            continue
        if candidate.startswith("*."):
            wildcard_host = _normalize_host(candidate[2:])
            if wildcard_host and wildcard_host not in wildcard_domains:
                wildcard_domains.append(wildcard_host)
                root_domain = _root_domain_for_host(wildcard_host)
                if root_domain not in root_domains:
                    root_domains.append(root_domain)
            continue

        parsed = urlparse(candidate) if "://" in candidate else None
        if parsed and parsed.hostname:
            host = parsed.hostname.lower()
            if parsed.path and parsed.path not in {"", "/"}:
                path_based_scope.append(
                    {"host": host, "path": _normalize_runtime_path(parsed.path)}
                )
                if host not in fixed_hosts:
                    fixed_hosts.append(host)
                root_domain = _root_domain_for_host(host)
                if root_domain not in root_domains:
                    root_domains.append(root_domain)
                continue
            candidate = host

        host = _normalize_host(candidate)
        if host is None:
            continue
        root_domain = _root_domain_for_host(host)
        if host == root_domain:
            if host not in root_domains:
                root_domains.append(host)
            continue
        if host not in fixed_hosts:
            fixed_hosts.append(host)
        if root_domain not in root_domains:
            root_domains.append(root_domain)

    if not explicit_scope:
        assumptions.append(
            "Scope map v1 is inferred from observed data only; authoritative scope boundaries need confirmation."
        )
    if wildcard_domains:
        edge_cases.append(
            "Wildcard scope implies likely hidden staging/admin/tenant/region hosts and CDN aliases."
        )
        assumptions.append(
            "Treat tenant-style, region, environment, vanity, storage, and admin prefixes under wildcard domains as likely in-scope until rules narrow them."
        )
    if path_based_scope:
        edge_cases.append(
            "Path-based scope can hide adjacent routes on the same host; non-matching paths remain edge-case or out-of-scope until confirmed."
        )

    known_hosts = set(derived_hosts) | set(fixed_hosts)
    likely_sibling_hosts: list[dict[str, Any]] = []
    for base in wildcard_domains or root_domains:
        for prefix in LIKELY_SCOPE_PREFIXES:
            guessed_host = f"{prefix}.{base}"
            if guessed_host in known_hosts:
                continue
            likely_sibling_hosts.append(
                {
                    "host": guessed_host,
                    "signal_classification": "weak-signal",
                    "reason": f"Guessed from naming pattern under {base}; needs more data.",
                }
            )
        if len(likely_sibling_hosts) >= 24:
            break

    return {
        "root_domains": _unique_strings(root_domains),
        "wildcard_domains": _unique_strings(wildcard_domains),
        "fixed_hosts": _unique_strings(fixed_hosts),
        "path_based_scope": path_based_scope,
        "edge_cases": edge_cases,
        "assumptions": assumptions,
        "likely_sibling_hosts": likely_sibling_hosts[:24],
        "needs_more_data": not bool(explicit_scope),
    }


def _host_in_scope(host: str, scope_map: dict[str, Any]) -> bool:
    normalized = _normalize_host(host)
    if normalized is None:
        return False
    fixed_hosts = {str(item) for item in list(scope_map.get("fixed_hosts") or [])}
    wildcard_domains = {str(item) for item in list(scope_map.get("wildcard_domains") or [])}
    root_domains = {str(item) for item in list(scope_map.get("root_domains") or [])}
    if not fixed_hosts and not wildcard_domains and not root_domains:
        return True
    if normalized in fixed_hosts or normalized in root_domains:
        return True
    return any(
        normalized.endswith(f".{domain}") or normalized == domain
        for domain in wildcard_domains | root_domains
    )


def _path_in_scope(host: str, path: str, scope_map: dict[str, Any]) -> bool:
    if not _host_in_scope(host, scope_map):
        return False
    scoped_paths = [
        item
        for item in list(scope_map.get("path_based_scope") or [])
        if isinstance(item, dict) and str(item.get("host") or "") == host
    ]
    if not scoped_paths:
        return True
    normalized = _normalize_runtime_path(path)
    return any(normalized.startswith(str(item.get("path") or "/")) for item in scoped_paths)


def _load_runtime_inventory_record(agent_state: Any, target: str) -> dict[str, Any] | None:
    try:
        result = list_runtime_inventory(
            agent_state=agent_state,
            target=target,
            include_inventory=True,
            max_items=1,
        )
    except Exception:  # noqa: BLE001
        return None
    if not result.get("success"):
        return None
    records = list(result.get("records") or [])
    if not records:
        return None
    return records[0] if isinstance(records[0], dict) else None


def _load_mined_surface_record(agent_state: Any, target: str) -> dict[str, Any] | None:
    try:
        result = list_mined_attack_surface(
            agent_state=agent_state,
            target=target,
            include_artifacts=True,
            max_items=1,
        )
    except Exception:  # noqa: BLE001
        return None
    if not result.get("success"):
        return None
    records = list(result.get("records") or [])
    if not records:
        return None
    return records[0] if isinstance(records[0], dict) else None


def _load_workflow_record(agent_state: Any, target: str) -> dict[str, Any] | None:
    try:
        result = list_discovered_workflows(
            agent_state=agent_state,
            target=target,
            include_workflows=True,
            max_items=1,
        )
    except Exception:  # noqa: BLE001
        return None
    if not result.get("success"):
        return None
    records = list(result.get("records") or [])
    if not records:
        return None
    return records[0] if isinstance(records[0], dict) else None


def _load_tool_runs(
    agent_state: Any,
    target: str,
    max_items: int,
) -> tuple[list[dict[str, Any]], bool]:
    try:
        result = list_security_tool_runs(
            agent_state=agent_state,
            target=target,
            include_findings=True,
            max_items=max_items,
        )
    except Exception:  # noqa: BLE001
        return [], False
    if not result.get("success"):
        return [], False
    runs = [item for item in list(result.get("runs") or []) if isinstance(item, dict)]
    truncated = int(result.get("run_count") or len(runs)) > len(runs)
    return runs, truncated


def _load_session_profiles(agent_state: Any, max_items: int) -> tuple[list[dict[str, Any]], bool]:
    try:
        result = list_session_profiles(
            agent_state=agent_state,
            include_values=True,
            max_items=max_items,
        )
    except Exception:  # noqa: BLE001
        return [], False
    if not result.get("success"):
        return [], False
    profiles = [item for item in list(result.get("profiles") or []) if isinstance(item, dict)]
    truncated = int(result.get("profile_count") or len(profiles)) > len(profiles)
    return profiles, truncated


def _coverage_status_for_asset(
    coverage_records: list[dict[str, Any]],
    *,
    host: str | None = None,
    path: str | None = None,
    component_prefix: str | None = None,
) -> str:
    related_statuses: list[str] = []
    for record in coverage_records:
        haystack = (
            f"{record.get('component') or ''} {record.get('surface') or ''} {record.get('target') or ''}"
        ).lower()
        if host and host.lower() not in haystack:
            continue
        if path and path.lower() not in haystack:
            continue
        if component_prefix and not str(record.get("component") or "").startswith(component_prefix):
            continue
        related_statuses.append(str(record.get("status") or "uncovered"))
    if "covered" in related_statuses:
        return "covered"
    if "in_progress" in related_statuses:
        return "in_progress"
    if "blocked" in related_statuses:
        return "blocked"
    if "uncovered" in related_statuses:
        return "uncovered"
    return "mapped"


def _path_segments(path: str) -> list[str]:
    return [segment for segment in _normalize_runtime_path(path).split("/") if segment]


def _module_for_path(path: str) -> str:
    segments = _path_segments(path)
    if not segments:
        return "root"
    if segments[0] == "api" and len(segments) >= 2 and re.fullmatch(r"v\d+", segments[1]):
        return f"api/{segments[1]}"
    return segments[0]


def _infer_object_types(path: str, params: list[str]) -> list[str]:
    objects: list[str] = []
    for segment in _path_segments(path):
        if segment.startswith(":") or segment in GENERIC_OBJECT_SEGMENTS:
            continue
        singular = segment[:-1] if segment.endswith("s") and len(segment) > 3 else segment
        if singular not in objects:
            objects.append(singular)
    for name in params:
        lowered = name.lower()
        if lowered.endswith("_id") and len(lowered) > 3:
            candidate = lowered[:-3]
            if candidate not in objects:
                objects.append(candidate)
    return objects[:6]


def _infer_identifiers(path: str, params: list[str]) -> list[str]:
    identifiers: list[str] = []
    for segment in _path_segments(path):
        if segment.startswith(":") and segment not in identifiers:
            identifiers.append(segment)
    for name in params:
        lowered = name.lower()
        if (
            lowered in {"id", "uuid", "token"} or lowered.endswith(("_id", "_token"))
        ) and name not in identifiers:
            identifiers.append(name)
    return identifiers


def _infer_trust_boundaries(
    *,
    host: str,
    path: str,
    auth_hints: list[str],
    param_names: list[str],
    object_types: list[str],
) -> list[str]:
    boundaries: list[str] = []
    combined = " ".join([host, path, *param_names, *object_types]).lower()
    if any(hint != "anonymous" for hint in auth_hints):
        boundaries.append("authenticated-session boundary")
    if any(keyword in combined for keyword in ["admin", "role", "staff", "manager"]):
        boundaries.append("privileged-role boundary")
    if any(keyword in combined for keyword in ["tenant", "workspace", "organization", "org"]):
        boundaries.append("tenant boundary")
    if any(
        keyword in combined
        for keyword in ["file", "upload", "download", "media", "avatar", "document"]
    ):
        boundaries.append("file-storage boundary")
    if any(keyword in combined for keyword in ["callback", "url", "uri", "webhook", "endpoint"]):
        boundaries.append("remote-callback boundary")
    if any(
        keyword in combined
        for keyword in ["billing", "checkout", "coupon", "invoice", "payment", "price", "wallet"]
    ):
        boundaries.append("financial/business-state boundary")
    return _unique_strings(boundaries)


def _review_record_for_response(
    record: SurfaceReviewRecord, *, include_report: bool
) -> SurfaceReviewRecord:
    response = dict(record)
    if not include_report:
        response.pop("report", None)
    return response


def _infer_bug_classes(
    *,
    path: str,
    methods: list[str],
    param_names: list[str],
    content_types: list[str],
    auth_hints: list[str],
    object_types: list[str],
    source_kinds: list[str],
    workflow_tags: list[str],
) -> list[str]:
    bug_classes: list[str] = []
    lowered = " ".join([path, *param_names, *object_types, *source_kinds, *workflow_tags]).lower()
    if any(
        keyword in lowered
        for keyword in [
            "auth",
            "login",
            "logout",
            "mfa",
            "otp",
            "password",
            "reset",
            "invite",
            "verify",
            "token",
            "jwt",
        ]
    ):
        bug_classes.extend(["authentication", "session handling"])
    if object_types or any(
        name.lower() == "id" or name.lower().endswith("_id") for name in param_names
    ):
        bug_classes.extend(["authorization", "bola/idor"])
    if "tenant" in lowered or "workspace" in lowered or "organization" in lowered:
        bug_classes.append("tenant isolation")
    if any(name.lower() in {"role", "is_admin", "status"} for name in param_names):
        bug_classes.append("field-level authorization")
    if any(
        name.lower() in {"q", "query", "search", "html", "content", "message", "bio", "comment"}
        for name in param_names
    ):
        bug_classes.extend(["xss/html injection", "filtering bypass"])
    if any(name.lower() in {"id", "query", "search", "filter", "sort"} for name in param_names):
        bug_classes.append("sqli/nosqli")
    if any(
        name.lower() in {"url", "uri", "endpoint", "callback", "webhook"} for name in param_names
    ):
        bug_classes.extend(["ssrf", "open redirect"])
    if any(
        name.lower() in {"file", "path", "filename", "document", "download"} for name in param_names
    ):
        bug_classes.extend(["path traversal", "unauthorized file access"])
    if "multipart/form-data" in " ".join(content_types).lower() or any(
        marker in lowered for marker in ["upload", "avatar", "attachment", "import"]
    ):
        bug_classes.extend(["file upload", "content-type validation"])
    if "graphql" in lowered:
        bug_classes.extend(["graphql overexposure", "resolver authorization"])
    if "ws" in lowered or "socket" in lowered or "websocket" in lowered:
        bug_classes.append("websocket authorization gap")
    if any(keyword in lowered for keyword in ["swagger", "openapi", "docs", "graphiql", "postman"]):
        bug_classes.append("undocumented/documented surface drift")
    if any(
        keyword in lowered
        for keyword in [
            "coupon",
            "checkout",
            "payment",
            "price",
            "quantity",
            "redeem",
            "refund",
            "wallet",
        ]
    ):
        bug_classes.extend(["business logic abuse", "replay/race"])
    if any(method in {"POST", "PUT", "PATCH", "DELETE"} for method in methods):
        bug_classes.append("workflow/state transition")
    if any(
        keyword in lowered
        for keyword in ["debug", "internal", "health", "metrics", "map", "backup", ".git", ".env"]
    ):
        bug_classes.append("debug/deployment exposure")
    return _unique_strings(bug_classes)


def _guess_host_type(host: str, paths: list[str]) -> str:
    lowered = f"{host} {' '.join(paths)}".lower()
    for host_type, keywords in HOST_TYPE_HINTS.items():
        if any(keyword in lowered for keyword in keywords):
            return host_type
    return "unknown"


def _guess_data_sensitivity(path: str, object_types: list[str]) -> str:
    lowered = f"{path} {' '.join(object_types)}".lower()
    if any(
        keyword in lowered
        for keyword in [
            "admin",
            "auth",
            "billing",
            "invoice",
            "password",
            "payment",
            "profile",
            "tenant",
            "token",
            "user",
            "wallet",
        ]
    ):
        return "high"
    if any(
        keyword in lowered for keyword in ["file", "invite", "settings", "support", "workspace"]
    ):
        return "medium"
    return "low"


def _classify_exposure(path: str, kind: str) -> str:
    lowered = f"{path} {kind}".lower()
    if any(keyword in lowered for keyword in [".env", ".git", ".map", "backup", "secret", "token"]):
        return "likely-reportable exposure"
    if any(
        keyword in lowered
        for keyword in ["openapi", "swagger", "graphiql", "postman", "persisted", "js_route"]
    ):
        return "chain-enabling exposure"
    if any(keyword in lowered for keyword in ["debug", "health", "internal", "metrics"]):
        return "exploit-enabling exposure"
    if any(keyword in lowered for keyword in ["graphql", "docs", "release", "version", "waf"]):
        return "recon-value exposure"
    return "harmless exposure"


def _bug_category_for_bug_class(bug_class: str) -> str:
    lowered = bug_class.lower()
    if any(keyword in lowered for keyword in ["authentication", "session", "mfa"]):
        return "Authentication"
    if any(
        keyword in lowered for keyword in ["authorization", "idor", "tenant", "field-level", "bola"]
    ):
        return "Authorization"
    if any(
        keyword in lowered
        for keyword in ["xss", "sqli", "ssrf", "redirect", "traversal", "upload", "content-type"]
    ):
        return "Input / output / content handling"
    if any(
        keyword in lowered for keyword in ["graphql", "websocket", "surface drift", "undocumented"]
    ):
        return "API logic"
    if any(
        keyword in lowered for keyword in ["business", "replay", "workflow", "state transition"]
    ):
        return "Business logic"
    return "Client-side / infra / deployment"


def _role_coverage_entries(
    *,
    session_profiles: list[dict[str, Any]],
    path_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    roles = {
        str(profile.get("role") or "").strip().lower()
        for profile in session_profiles
        if str(profile.get("role") or "").strip()
    }
    tenants = {
        str(profile.get("tenant") or "").strip()
        for profile in session_profiles
        if str(profile.get("tenant") or "").strip()
    }
    anonymous_seen = any(
        "guest" in list(item.get("roles_seen") or []) or item.get("auth_required") == "no"
        for item in path_rows
    )
    authenticated_seen = any(item.get("auth_required") == "yes" for item in path_rows) or bool(
        session_profiles
    )
    entries = [
        {
            "boundary": "guest",
            "status": "covered" if anonymous_seen else "needs more data",
            "signal_classification": "confirmed" if anonymous_seen else "blind-spot",
        },
        {
            "boundary": "user",
            "status": "covered" if authenticated_seen else "needs more data",
            "signal_classification": "confirmed" if authenticated_seen else "blind-spot",
        },
        {
            "boundary": "privileged test role",
            "status": (
                "covered"
                if any(role in {"admin", "manager", "staff", "superadmin"} for role in roles)
                else "needs more data"
            ),
            "signal_classification": (
                "confirmed"
                if any(role in {"admin", "manager", "staff", "superadmin"} for role in roles)
                else "blind-spot"
            ),
        },
        {
            "boundary": "tenant A/B",
            "status": "covered" if len(tenants) >= 2 else "needs more data",
            "signal_classification": "confirmed" if len(tenants) >= 2 else "blind-spot",
        },
    ]
    for state_name, markers in ROLE_STATE_MARKERS.items():
        covered = any(
            any(marker in str(item.get("path") or "").lower() for marker in markers)
            for item in path_rows
        )
        entries.append(
            {
                "boundary": state_name,
                "status": "covered" if covered else "needs more data",
                "signal_classification": "confirmed" if covered else "blind-spot",
            }
        )
    return entries


def _bug_class_coverage(
    *,
    bug_matrix: list[dict[str, Any]],
    hypotheses: list[dict[str, Any]],
    role_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    category_counts: Counter[str] = Counter()
    hypothesis_counts: Counter[str] = Counter()
    for item in bug_matrix:
        for bug_class in list(item.get("bug_classes") or []):
            category_counts[_bug_category_for_bug_class(str(bug_class))] += 1
    for item in hypotheses:
        vuln_type = str(item.get("vulnerability_type") or "").strip().lower()
        if vuln_type:
            hypothesis_counts[_bug_category_for_bug_class(vuln_type)] += 1

    privileged_covered = any(
        entry.get("boundary") == "privileged test role" and entry.get("status") == "covered"
        for entry in role_entries
    )
    tenant_covered = any(
        entry.get("boundary") == "tenant A/B" and entry.get("status") == "covered"
        for entry in role_entries
    )

    rows: list[dict[str, Any]] = []
    for category in [
        "Authentication",
        "Authorization",
        "Input / output / content handling",
        "API logic",
        "Business logic",
        "Client-side / infra / deployment",
    ]:
        count = int(category_counts.get(category, 0))
        hypothesis_count = int(hypothesis_counts.get(category, 0))
        status = "blocked by missing data"
        if count >= 1:
            status = "lightly checked"
        if count >= 3 or hypothesis_count >= 1:
            status = "reasonably covered"
        if count >= 5 or hypothesis_count >= 2:
            status = "strong coverage"
        if category == "Authorization" and (not privileged_covered or not tenant_covered):
            if status == "strong coverage":
                status = "reasonably covered"
        rows.append(
            {
                "bug_class": category,
                "status": status,
                "surface_signal_count": count,
                "hypothesis_count": hypothesis_count,
            }
        )
    return rows


@register_tool(sandbox_execution=False)
def build_attack_surface_review(
    agent_state: Any,
    target: str,
    scope_targets: list[str] | None = None,
    max_tool_runs: int = 100,
    max_session_profiles: int = 25,
    max_nodes: int = 250,
    max_edges: int = 400,
    max_priorities: int = 12,
) -> dict[str, Any]:
    try:
        normalized_target = _normalize_non_empty(target, "target")
        if max_tool_runs < 1:
            raise ValueError("max_tool_runs must be >= 1")
        if max_session_profiles < 1:
            raise ValueError("max_session_profiles must be >= 1")
        if max_nodes < 20:
            raise ValueError("max_nodes must be >= 20")
        if max_edges < 20:
            raise ValueError("max_edges must be >= 20")
        if max_priorities < 1:
            raise ValueError("max_priorities must be >= 1")

        runtime_record = _load_runtime_inventory_record(agent_state, normalized_target)
        surface_record = _load_mined_surface_record(agent_state, normalized_target)
        workflow_record = _load_workflow_record(agent_state, normalized_target)
        tool_runs, tool_runs_truncated = _load_tool_runs(
            agent_state=agent_state,
            target=normalized_target,
            max_items=max_tool_runs,
        )
        session_profiles, session_profiles_truncated = _load_session_profiles(
            agent_state=agent_state,
            max_items=max_session_profiles,
        )
        assessment_state = list_assessment_state(
            agent_state=agent_state,
            include_resolved_coverage=True,
            include_evidence=True,
            max_items=200,
        )
        coverage_records = [
            item for item in list(assessment_state.get("coverage") or []) if isinstance(item, dict)
        ]
        hypotheses = [
            item
            for item in list(assessment_state.get("hypotheses") or [])
            if isinstance(item, dict)
        ]

        runtime_inventory = []
        if runtime_record is not None:
            runtime_inventory = [
                item
                for item in list(
                    runtime_record.get("inventory")
                    or runtime_record.get("selected_inventory")
                    or []
                )
                if isinstance(item, dict)
            ]
        surface_artifacts = []
        if surface_record is not None:
            surface_artifacts = [
                item
                for item in list(
                    surface_record.get("artifacts")
                    or surface_record.get("selected_artifacts")
                    or []
                )
                if isinstance(item, dict)
            ]
        workflows = []
        if workflow_record is not None:
            workflows = [
                item
                for item in list(
                    workflow_record.get("workflows")
                    or workflow_record.get("selected_workflows")
                    or []
                )
                if isinstance(item, dict)
            ]

        derived_scope_candidates = _extract_scope_candidates_from_tool_runs(tool_runs)
        derived_hosts = _unique_strings(
            [
                *[str(item.get("host") or "") for item in runtime_inventory],
                *[str(item.get("host") or "") for item in surface_artifacts],
                *[
                    str(
                        urlparse(
                            str(finding.get("url") or finding.get("matched_at") or "")
                        ).hostname
                        or ""
                    )
                    for run in tool_runs
                    for finding in list(run.get("findings") or [])
                    if isinstance(finding, dict)
                ],
            ]
        )
        scope_map_v1 = _build_scope_map(
            explicit_scope=_unique_strings(list(scope_targets or []) + derived_scope_candidates),
            derived_hosts=derived_hosts,
        )

        host_index: dict[str, dict[str, Any]] = {}
        service_index: dict[tuple[str, int, str], dict[str, Any]] = {}
        path_index: dict[tuple[str, str], dict[str, Any]] = {}
        param_index: dict[tuple[str, str, str], dict[str, Any]] = {}
        object_index: dict[tuple[str, str], dict[str, Any]] = {}
        application_index: dict[tuple[str, str], dict[str, Any]] = {}
        exposures: list[dict[str, Any]] = []
        duplicate_risks: list[dict[str, Any]] = []
        blind_spots: list[dict[str, Any]] = []
        out_of_scope_assets: list[dict[str, Any]] = []
        seen_exposures: set[tuple[str, str, str]] = set()
        seen_duplicates: set[tuple[str, str]] = set()
        seen_blind_spots: set[str] = set()

        def add_blind_spot(area: str, detail: str, target_asset: str | None = None) -> None:
            blind_id = f"{area}|{detail}|{target_asset or ''}"
            if blind_id in seen_blind_spots:
                return
            seen_blind_spots.add(blind_id)
            blind_spots.append(
                {
                    "area": area,
                    "target_asset": target_asset,
                    "detail": detail,
                    "signal_classification": "blind-spot",
                    "status": "needs more data",
                }
            )

        def ensure_host(host: str) -> dict[str, Any]:
            normalized_host = _normalize_host(host)
            if normalized_host is None:
                raise ValueError("host must be non-empty")
            return host_index.setdefault(
                normalized_host,
                {
                    "host": normalized_host,
                    "sources": set(),
                    "provider_hints": set(),
                    "cdn_hints": set(),
                    "cname_chain": set(),
                    "ip_addresses": set(),
                    "asn": set(),
                    "paths": set(),
                    "services": set(),
                    "resolved": False,
                    "priority": "normal",
                    "preliminary_type": "unknown",
                    "coverage_status": "blind",
                    "signal_classification": "suspected",
                    "in_scope": _host_in_scope(normalized_host, scope_map_v1),
                    "notes": set(),
                    "raw_observation_count": 0,
                },
            )

        def ensure_service(host: str, port: int, protocol: str) -> dict[str, Any]:
            return service_index.setdefault(
                (host, port, protocol),
                {
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "fingerprints": set(),
                    "app_family": set(),
                    "titles": set(),
                    "status_codes": set(),
                    "tls_names": set(),
                    "redirect_targets": set(),
                    "auth_wall": "needs more data",
                    "data_sensitivity_guess": "low",
                    "privilege_boundary": set(),
                    "bug_classes": set(),
                    "coverage_status": "blind",
                    "signal_classification": "suspected",
                    "sources": set(),
                    "notes": set(),
                    "in_scope": _host_in_scope(host, scope_map_v1),
                    "raw_observation_count": 0,
                },
            )

        def ensure_path(host: str, path: str) -> dict[str, Any]:
            normalized_path = _normalize_runtime_path(path)
            return path_index.setdefault(
                (host, normalized_path),
                {
                    "host": host,
                    "path": normalized_path,
                    "port": None,
                    "application_module": _module_for_path(normalized_path),
                    "methods": set(),
                    "content_types": set(),
                    "auth_hints": set(),
                    "roles_seen": set(),
                    "query_params": set(),
                    "body_params": set(),
                    "header_params": set(),
                    "cookie_params": set(),
                    "path_identifiers": set(),
                    "object_types": set(),
                    "identifiers": set(),
                    "trust_boundaries": set(),
                    "bug_classes": set(),
                    "priority": "normal",
                    "coverage_status": "blind",
                    "signal_classification": "suspected",
                    "source_kinds": set(),
                    "sources": set(),
                    "sample_urls": set(),
                    "workflow_ids": set(),
                    "status_codes": set(),
                    "auth_required": "needs more data",
                    "in_scope": _path_in_scope(host, normalized_path, scope_map_v1),
                    "hidden_route": False,
                    "raw_observation_count": 0,
                },
            )

        def ensure_param(host: str, path: str, parameter: str) -> dict[str, Any]:
            normalized_path = _normalize_runtime_path(path)
            return param_index.setdefault(
                (host, normalized_path, parameter),
                {
                    "host": host,
                    "path": normalized_path,
                    "parameter": parameter,
                    "locations": set(),
                    "methods": set(),
                    "sources": set(),
                    "object_hints": set(),
                    "trust_boundaries": set(),
                    "client_controlled": "yes",
                    "bug_classes": set(),
                    "pivot_point": False,
                    "signal_classification": "suspected",
                    "coverage_status": _coverage_status_for_asset(
                        coverage_records,
                        host=host,
                        path=normalized_path,
                    ),
                },
            )

        def ensure_object(host: str, object_type: str) -> dict[str, Any]:
            normalized_object = _normalize_object_name(object_type)
            return object_index.setdefault(
                (host, normalized_object),
                {
                    "host": host,
                    "object_type": normalized_object,
                    "related_paths": set(),
                    "identifiers": set(),
                    "fields": set(),
                    "trust_boundaries": set(),
                    "bug_classes": set(),
                    "sources": set(),
                    "signal_classification": "suspected",
                    "coverage_status": "mapped",
                },
            )

        def inferred_service_endpoint(finding: dict[str, Any]) -> tuple[int, str, str]:
            sample_url = str(finding.get("url") or finding.get("matched_at") or "").strip()
            parsed = urlparse(sample_url)
            raw_port = finding.get("port")
            if raw_port is not None:
                port = int(raw_port)
            elif parsed.scheme == "http":
                port = 80 if parsed.port is None else parsed.port
            elif parsed.port is not None:
                port = parsed.port
            else:
                port = 443
            protocol = str(finding.get("scheme") or parsed.scheme or "").strip().lower()
            if not protocol:
                protocol = "https" if port == 443 else "http"
            return port, protocol, sample_url

        def add_exposure(
            *,
            host: str,
            path: str,
            kind: str,
            detail: str,
            source: str,
            confirmed: bool = False,
        ) -> None:
            key = (host, path, kind)
            if key in seen_exposures:
                return
            seen_exposures.add(key)
            exposures.append(
                {
                    "host": host,
                    "path": path,
                    "asset": f"{host}{path}",
                    "kind": kind,
                    "detail": detail,
                    "source": source,
                    "signal_classification": _signal_classification(
                        confirmed=confirmed,
                        exposure=True,
                        in_scope=_path_in_scope(host, path, scope_map_v1),
                    ),
                    "exposure_class": _classify_exposure(path, kind),
                    "coverage_status": _coverage_status_for_asset(
                        coverage_records,
                        host=host,
                        path=path,
                    ),
                }
            )

        def add_out_of_scope(asset_type: str, host: str, path: str, reason: str) -> None:
            out_of_scope_assets.append(
                {
                    "asset_type": asset_type,
                    "host": host,
                    "path": path,
                    "reason": reason,
                    "signal_classification": "out-of-scope",
                }
            )

        def add_duplicate_risk(asset_type: str, identifier: str, sources: list[str]) -> None:
            key = (asset_type, identifier)
            if key in seen_duplicates:
                return
            seen_duplicates.add(key)
            duplicate_risks.append(
                {
                    "asset_type": asset_type,
                    "identifier": identifier,
                    "sources": _unique_strings(sources),
                    "signal_classification": "duplicate-risk",
                }
            )

        for host in list(scope_map_v1.get("fixed_hosts") or []) + list(
            scope_map_v1.get("root_domains") or []
        ):
            record = ensure_host(str(host))
            record["sources"].add("scope")
        for candidate in list(scope_map_v1.get("likely_sibling_hosts") or []):
            host = str(candidate.get("host") or "").strip()
            if not host:
                continue
            record = ensure_host(host)
            record["sources"].add("scope_guess")
            record["notes"].add(str(candidate.get("reason") or "needs more data"))
            record["signal_classification"] = "weak-signal"

        if runtime_record is None:
            add_blind_spot(
                "runtime inventory",
                "No runtime inventory is stored yet; endpoint and parameter coverage needs more data.",
            )
        for item in runtime_inventory:
            host = str(item.get("host") or "").strip()
            path = str(item.get("normalized_path") or "/")
            if not host:
                continue
            host_record = ensure_host(host)
            host_record["sources"].add("runtime_inventory")
            host_record["resolved"] = True
            host_record["paths"].add(path)
            host_record["raw_observation_count"] += 1

            path_record = ensure_path(host, path)
            path_record["methods"].update(str(method) for method in list(item.get("methods") or []))
            path_record["content_types"].update(
                str(value) for value in list(item.get("content_types") or []) if str(value).strip()
            )
            path_record["auth_hints"].update(
                str(value) for value in list(item.get("auth_hints") or []) if str(value).strip()
            )
            path_record["query_params"].update(
                str(value) for value in list(item.get("query_params") or []) if str(value).strip()
            )
            path_record["body_params"].update(
                str(value) for value in list(item.get("body_params") or []) if str(value).strip()
            )
            path_record["sample_urls"].update(
                str(value) for value in list(item.get("sample_urls") or []) if str(value).strip()
            )
            path_record["source_kinds"].add("runtime")
            path_record["sources"].add("runtime_inventory")
            path_record["raw_observation_count"] += 1
            path_record["signal_classification"] = "confirmed"
            path_record["coverage_status"] = _coverage_status_for_asset(
                coverage_records,
                host=host,
                path=path,
            )
            port = 443
            if path_record["sample_urls"]:
                sample = next(iter(path_record["sample_urls"]))
                parsed = urlparse(sample)
                if parsed.scheme == "http":
                    port = 80 if parsed.port is None else parsed.port
                elif parsed.port is not None:
                    port = parsed.port
            path_record["port"] = port
            service_record = ensure_service(host, int(port), "https" if port == 443 else "http")
            service_record["sources"].add("runtime_inventory")
            service_record["app_family"].add("web")
            service_record["raw_observation_count"] += 1

        if surface_record is None:
            add_blind_spot(
                "surface mining",
                "No mined attack-surface artifacts are stored yet; JS/docs/GraphQL/WebSocket coverage needs more data.",
            )
        for artifact in surface_artifacts:
            host = str(artifact.get("host") or "").strip()
            path = str(artifact.get("path") or "/")
            kind = str(artifact.get("kind") or "artifact")
            if not host:
                continue
            host_record = ensure_host(host)
            host_record["sources"].add("surface_mining")
            host_record["paths"].add(path)
            host_record["raw_observation_count"] += 1
            if kind != "js_route":
                host_record["resolved"] = True

            path_record = ensure_path(host, path)
            path_record["sources"].add("surface_mining")
            path_record["source_kinds"].add(kind)
            path_record["raw_observation_count"] += 1
            if kind in {"graphql_endpoint", "websocket_endpoint", "openapi_spec"}:
                path_record["methods"].add(str(artifact.get("method") or "GET"))
            if kind == "js_route":
                path_record["hidden_route"] = True
                path_record["signal_classification"] = "exposed-info"
                add_exposure(
                    host=host,
                    path=path,
                    kind=kind,
                    detail="JavaScript bundle referenced a route that may be hidden from the visible UI.",
                    source="surface_mining",
                )
            elif kind == "openapi_spec":
                path_record["signal_classification"] = "confirmed"
                add_exposure(
                    host=host,
                    path=path,
                    kind=kind,
                    detail="OpenAPI/Swagger artifact exposes documented operations and hidden route clues.",
                    source="surface_mining",
                    confirmed=True,
                )
                for operation in list(artifact.get("documented_operations") or []):
                    if not isinstance(operation, dict):
                        continue
                    documented_record = ensure_path(host, str(operation.get("path") or "/"))
                    documented_record["methods"].add(str(operation.get("method") or "GET"))
                    documented_record["content_types"].update(
                        str(value)
                        for value in list(operation.get("content_types") or [])
                        if str(value).strip()
                    )
                    for security_name in list(operation.get("security") or []):
                        if not str(security_name).strip():
                            continue
                        documented_record["auth_hints"].add(f"doc:{security_name}")
                    if bool(operation.get("requires_auth")):
                        documented_record["auth_hints"].add("documented-auth")
                        documented_record["auth_required"] = "yes"
                    documented_record["source_kinds"].add("openapi_documented_operation")
                    documented_record["sources"].add("surface_mining")
                    documented_record["raw_observation_count"] += 1
                    if documented_record["signal_classification"] != "confirmed":
                        documented_record["signal_classification"] = "suspected"
                for parameter in list(artifact.get("documented_parameters") or []):
                    if not isinstance(parameter, dict):
                        continue
                    documented_path = str(parameter.get("path") or "/")
                    parameter_name = str(parameter.get("name") or "").strip()
                    parameter_location = str(parameter.get("location") or "query").strip().lower()
                    if not parameter_name:
                        continue
                    documented_record = ensure_path(host, documented_path)
                    documented_record["methods"].add(str(parameter.get("method") or "GET"))
                    if parameter_location == "query":
                        documented_record["query_params"].add(parameter_name)
                    elif parameter_location == "body":
                        documented_record["body_params"].add(parameter_name)
                    elif parameter_location == "path":
                        documented_record["path_identifiers"].add(
                            parameter_name
                            if parameter_name.startswith(":")
                            else f":{parameter_name}"
                        )
                    elif parameter_location == "header":
                        documented_record["header_params"].add(parameter_name)
                    elif parameter_location == "cookie":
                        documented_record["cookie_params"].add(parameter_name)
                    if bool(parameter.get("identifier")):
                        documented_record["identifiers"].add(parameter_name)
                    object_hint = _normalize_object_name(str(parameter.get("object_hint") or ""))
                    if object_hint:
                        documented_record["object_types"].add(object_hint)
                    param_record = ensure_param(host, documented_path, parameter_name)
                    param_record["sources"].add("openapi")
                    param_record["locations"].add(parameter_location)
                    param_record["methods"].add(str(parameter.get("method") or "GET"))
                    if object_hint:
                        param_record["object_hints"].add(object_hint)
                    if parameter_location in {"header", "cookie"} and any(
                        marker in parameter_name.lower()
                        for marker in ["auth", "key", "session", "token"]
                    ):
                        documented_record["auth_hints"].add(parameter_location)
                        param_record["trust_boundaries"].add("authenticated-session boundary")
                    if parameter_location == "path":
                        param_record["trust_boundaries"].add("object path boundary")
                    param_record["pivot_point"] = param_record["pivot_point"] or any(
                        marker in parameter_name.lower()
                        for marker in [
                            "callback",
                            "file",
                            "id",
                            "path",
                            "redirect",
                            "role",
                            "tenant",
                            "token",
                            "url",
                        ]
                    )
                for field in list(artifact.get("documented_request_fields") or []):
                    if not isinstance(field, dict):
                        continue
                    documented_path = str(field.get("path") or "/")
                    field_name = str(field.get("name") or "").strip()
                    if not field_name:
                        continue
                    documented_record = ensure_path(host, documented_path)
                    documented_record["methods"].add(str(field.get("method") or "GET"))
                    documented_record["body_params"].add(field_name)
                    content_type = str(field.get("content_type") or "").strip()
                    if content_type:
                        documented_record["content_types"].add(content_type)
                    if bool(field.get("identifier")):
                        documented_record["identifiers"].add(field_name)
                    object_hint = _normalize_object_name(str(field.get("object_hint") or ""))
                    if object_hint:
                        documented_record["object_types"].add(object_hint)
                    param_record = ensure_param(host, documented_path, field_name)
                    param_record["sources"].add("openapi")
                    param_record["locations"].add("body")
                    param_record["methods"].add(str(field.get("method") or "GET"))
                    if object_hint:
                        param_record["object_hints"].add(object_hint)
                    param_record["pivot_point"] = param_record["pivot_point"] or any(
                        marker in field_name.lower()
                        for marker in [
                            "amount",
                            "callback",
                            "coupon",
                            "discount",
                            "file",
                            "id",
                            "price",
                            "quantity",
                            "role",
                            "status",
                            "tenant",
                            "token",
                            "url",
                        ]
                    )
                for documented_object in list(artifact.get("documented_objects") or []):
                    if not isinstance(documented_object, dict):
                        continue
                    object_name = str(documented_object.get("object_type") or "").strip()
                    if not object_name:
                        continue
                    object_record = ensure_object(host, object_name)
                    object_record["sources"].add("openapi")
                    object_record["fields"].update(
                        str(value)
                        for value in list(documented_object.get("fields") or [])
                        if str(value).strip()
                    )
                    object_record["identifiers"].update(
                        str(value)
                        for value in list(documented_object.get("identifiers") or [])
                        if str(value).strip()
                    )
                    if object_record["fields"] or object_record["identifiers"]:
                        object_record["signal_classification"] = "confirmed"
            else:
                path_record["signal_classification"] = "confirmed"
                add_exposure(
                    host=host,
                    path=path,
                    kind=kind,
                    detail=f"{kind} artifact observed and should be reviewed for auth or hidden-surface drift.",
                    source="surface_mining",
                    confirmed=True,
                )

        if workflow_record is None:
            add_blind_spot(
                "workflow coverage",
                "No reconstructed state-changing workflow is stored yet; business-logic depth needs more data.",
            )
        for workflow in workflows:
            workflow_id = str(workflow.get("workflow_id") or "")
            workflow_type = str(workflow.get("type") or "state_machine")
            for step in list(workflow.get("sequence") or []):
                if not isinstance(step, dict):
                    continue
                host = str(step.get("host") or workflow.get("host") or "").strip()
                path = str(step.get("normalized_path") or step.get("path") or "/")
                if not host:
                    continue
                path_record = ensure_path(host, path)
                path_record["workflow_ids"].add(workflow_id)
                path_record["source_kinds"].add("workflow")
                path_record["sources"].add("workflow")
                path_record["raw_observation_count"] += 1
                if workflow_type in {
                    "checkout",
                    "coupon",
                    "payment",
                    "redeem",
                    "transfer",
                    "wallet",
                }:
                    path_record["bug_classes"].add("business logic abuse")
                    path_record["bug_classes"].add("replay/race")

        for run in tool_runs:
            tool_name = str(run.get("tool_name") or "").strip()
            findings = [item for item in list(run.get("findings") or []) if isinstance(item, dict)]
            for finding in findings:
                host = _normalize_host(
                    str(
                        finding.get("host")
                        or urlparse(str(finding.get("url") or "")).hostname
                        or ""
                    )
                )
                path = _normalize_runtime_path(
                    urlparse(str(finding.get("url") or finding.get("matched_at") or "")).path
                    or str(finding.get("path") or "/")
                )
                if tool_name == "subfinder":
                    discovered_host = _normalize_host(str(finding.get("host") or ""))
                    if discovered_host is None:
                        continue
                    host_record = ensure_host(discovered_host)
                    host_record["sources"].add("subfinder")
                    host_record["raw_observation_count"] += 1
                    continue
                if host is None:
                    continue

                host_record = ensure_host(host)
                host_record["sources"].add(tool_name)
                host_record["raw_observation_count"] += 1
                if tool_name in {"httpx", "naabu", "nmap", "ffuf", "dirsearch", "katana"}:
                    host_record["resolved"] = True
                if tool_name == "wafw00f":
                    host_record["provider_hints"].add(str(finding.get("name") or "unknown-waf"))
                    host_record["cdn_hints"].add(str(finding.get("name") or "unknown-waf"))
                if tool_name == "httpx":
                    _extend_string_set(host_record["cname_chain"], finding.get("cname"))
                    _extend_string_set(host_record["cname_chain"], finding.get("cnames"))
                    _extend_string_set(host_record["ip_addresses"], finding.get("ip"))
                    _extend_string_set(host_record["ip_addresses"], finding.get("ips"))
                    _extend_string_set(host_record["asn"], finding.get("asn"))
                    _extend_string_set(host_record["asn"], finding.get("asn_number"))
                    _extend_string_set(host_record["provider_hints"], finding.get("provider"))
                    _extend_string_set(host_record["provider_hints"], finding.get("asn_name"))
                    _extend_string_set(host_record["cdn_hints"], finding.get("cdn"))
                    _extend_string_set(host_record["cdn_hints"], finding.get("cdn_name"))
                    _extend_string_set(host_record["notes"], finding.get("tls_subject_names"))
                if tool_name == "naabu":
                    _extend_string_set(host_record["ip_addresses"], finding.get("ip"))

                if tool_name in {"naabu", "nmap"} and finding.get("port") is not None:
                    protocol = str(finding.get("protocol") or "tcp")
                    port = int(finding.get("port") or 0)
                    service_record = ensure_service(host, port, protocol)
                    service_record["sources"].add(tool_name)
                    service_record["raw_observation_count"] += 1
                    _extend_string_set(host_record["ip_addresses"], finding.get("ip"))
                    if finding.get("service"):
                        service_record["fingerprints"].add(str(finding.get("service")))
                    if str(finding.get("kind") or "port") == "script":
                        service_record["notes"].add(str(finding.get("message") or "script finding"))
                        add_exposure(
                            host=host,
                            path="/",
                            kind="service_script_signal",
                            detail=str(
                                finding.get("message")
                                or "Nmap script indicated suspicious behavior."
                            ),
                            source="nmap",
                            confirmed=True,
                        )
                    continue

                if tool_name in {
                    "httpx",
                    "katana",
                    "ffuf",
                    "dirsearch",
                    "nuclei",
                    "wapiti",
                    "zaproxy",
                }:
                    path_record = ensure_path(host, path)
                    path_record["sources"].add(tool_name)
                    path_record["source_kinds"].add(tool_name)
                    path_record["sample_urls"].add(
                        str(finding.get("url") or finding.get("matched_at") or "").strip()
                    )
                    path_record["raw_observation_count"] += 1
                    port, protocol, sample_url = inferred_service_endpoint(finding)
                    path_record["port"] = port
                    service_record = ensure_service(host, int(port), protocol)
                    service_record["sources"].add(tool_name)
                    service_record["app_family"].add("web")
                    service_record["raw_observation_count"] += 1
                    if tool_name == "httpx":
                        path_record["methods"].add("GET")
                        if str(finding.get("title") or "").strip():
                            service_record["titles"].add(str(finding.get("title")))
                        if str(finding.get("webserver") or "").strip():
                            service_record["fingerprints"].add(str(finding.get("webserver")))
                        service_record["app_family"].update(
                            str(item)
                            for item in list(finding.get("tech") or [])
                            if str(item).strip()
                        )
                        service_record["tls_names"].update(
                            str(item)
                            for item in list(finding.get("tls_subject_names") or [])
                            if str(item).strip()
                        )
                        if str(finding.get("redirect_location") or "").strip():
                            service_record["redirect_targets"].add(
                                str(finding.get("redirect_location"))
                            )
                        if finding.get("status_code") is not None:
                            status_code = int(finding.get("status_code") or 0)
                            path_record["status_codes"].add(status_code)
                            service_record["status_codes"].add(status_code)
                            if status_code in {401, 403}:
                                path_record["auth_required"] = "yes"
                    if tool_name in {"ffuf", "dirsearch"}:
                        path_record["hidden_route"] = True
                    if tool_name == "nuclei":
                        triage = finding.get("triage") or {}
                        confidence = str(triage.get("confidence") or "low")
                        verification = str(triage.get("verification_state") or "raw")
                        if confidence == "low" and verification == "raw":
                            path_record["signal_classification"] = "weak-signal"
                        add_exposure(
                            host=host,
                            path=path,
                            kind="scanner_signal",
                            detail=str(
                                finding.get("name")
                                or finding.get("template_id")
                                or "Scanner reported a path-level signal."
                            ),
                            source="nuclei",
                            confirmed=confidence in {"medium", "high"},
                        )
                    else:
                        path_record["signal_classification"] = "confirmed"
                    if not path_record["in_scope"]:
                        add_out_of_scope(
                            "path",
                            host,
                            path,
                            "Observed path does not match the currently scoped host/path boundary.",
                        )
                    if sample_url and tool_name == "httpx":
                        parsed = urlparse(sample_url)
                        if parsed.scheme == "http":
                            service_record["fingerprints"].add("scheme:http")
                        elif parsed.scheme == "https":
                            service_record["fingerprints"].add("scheme:https")

                if tool_name in {"arjun", "wapiti", "zaproxy", "sqlmap"}:
                    param_name = str(finding.get("parameter") or "").strip()
                    if not param_name:
                        continue
                    path_record = ensure_path(host, path)
                    param_record = ensure_param(host, path_record["path"], param_name)
                    param_record["sources"].add(tool_name)
                    param_record["locations"].add("query")
                    param_record["pivot_point"] = param_record["pivot_point"] or any(
                        marker in param_name.lower()
                        for marker in [
                            "callback",
                            "file",
                            "id",
                            "path",
                            "redirect",
                            "role",
                            "tenant",
                            "token",
                            "url",
                        ]
                    )
                    path_record["query_params"].add(param_name)
                    if tool_name == "arjun":
                        param_record["signal_classification"] = "confirmed"

        if tool_runs_truncated:
            add_blind_spot(
                "tool runs",
                "Stored tool runs exceeded the review cap; some scanner evidence needs more data.",
            )
        if session_profiles_truncated:
            add_blind_spot(
                "session profiles",
                "Stored session profiles exceeded the review cap; role/tenant coverage needs more data.",
            )
        if not tool_runs:
            add_blind_spot(
                "blackbox recon",
                "No wrapped tool runs are stored yet; domain/service/path discovery needs more data.",
            )

        for path_record in path_index.values():
            param_names = sorted(
                path_record["query_params"]
                | path_record["body_params"]
                | path_record["header_params"]
                | path_record["cookie_params"]
            )
            object_types = set(_infer_object_types(path_record["path"], param_names))
            path_record["object_types"].update(object_types)
            path_record["identifiers"].update(_infer_identifiers(path_record["path"], param_names))
            path_record["path_identifiers"].update(
                segment
                for segment in _path_segments(path_record["path"])
                if segment.startswith(":")
            )
            path_record["trust_boundaries"].update(
                _infer_trust_boundaries(
                    host=str(path_record["host"]),
                    path=str(path_record["path"]),
                    auth_hints=sorted(path_record["auth_hints"]),
                    param_names=param_names,
                    object_types=sorted(object_types),
                )
            )
            path_record["bug_classes"].update(
                _infer_bug_classes(
                    path=str(path_record["path"]),
                    methods=sorted(path_record["methods"]),
                    param_names=param_names,
                    content_types=sorted(path_record["content_types"]),
                    auth_hints=sorted(path_record["auth_hints"]),
                    object_types=sorted(object_types),
                    source_kinds=sorted(path_record["source_kinds"]),
                    workflow_tags=list(path_record["workflow_ids"]),
                )
            )
            if not path_record["auth_hints"]:
                if path_record["auth_required"] != "yes":
                    path_record["auth_required"] = "no"
                    path_record["roles_seen"].add("guest")
            else:
                if any(hint != "anonymous" for hint in path_record["auth_hints"]):
                    path_record["auth_required"] = "yes"
                    path_record["roles_seen"].add("authenticated")
                else:
                    path_record["auth_required"] = "no"
                    path_record["roles_seen"].add("guest")
            if path_record["hidden_route"] and path_record["signal_classification"] == "suspected":
                path_record["signal_classification"] = "exposed-info"
            if not path_record["in_scope"]:
                path_record["signal_classification"] = "out-of-scope"
            path_record["priority"] = _priority_for_endpoint(
                str(path_record["path"]),
                sorted(path_record["methods"]) or ["GET"],
                query_params=sorted(path_record["query_params"]),
                body_params=sorted(
                    path_record["body_params"]
                    | path_record["header_params"]
                    | path_record["cookie_params"]
                ),
                auth_hints=sorted(path_record["auth_hints"] or {"anonymous"}),
            )
            for object_type in object_types:
                object_record = ensure_object(str(path_record["host"]), object_type)
                object_record["related_paths"].add(str(path_record["path"]))
                object_record["identifiers"].update(path_record["identifiers"])
                object_record["fields"].update(param_names)
                object_record["trust_boundaries"].update(path_record["trust_boundaries"])
                object_record["bug_classes"].update(path_record["bug_classes"])
                object_record["sources"].update(path_record["sources"])
                if path_record["signal_classification"] == "confirmed":
                    object_record["signal_classification"] = "confirmed"

        for host_record in host_index.values():
            host_record["preliminary_type"] = _guess_host_type(
                str(host_record["host"]),
                [str(path) for path in list(host_record["paths"])],
            )
            priorities = ["normal"]
            if any(
                keyword in str(host_record["host"]) for keyword in ["admin", "auth", "api", "files"]
            ):
                priorities.append("high")
            if host_record["preliminary_type"] in {"admin", "auth"}:
                priorities.append("critical")
            if host_record["signal_classification"] == "weak-signal":
                priorities.append("low")
            host_record["priority"] = _max_priority(priorities)
            host_record["coverage_status"] = _coverage_status_for_asset(
                coverage_records,
                host=str(host_record["host"]),
                component_prefix="host:",
            )
            if not host_record["in_scope"]:
                host_record["signal_classification"] = "out-of-scope"
            elif host_record["resolved"] and host_record["signal_classification"] != "weak-signal":
                host_record["signal_classification"] = "confirmed"
            if host_record["raw_observation_count"] >= 3:
                add_duplicate_risk("host", str(host_record["host"]), sorted(host_record["sources"]))

        for service_record in service_index.values():
            host = str(service_record["host"])
            related_paths = [
                item
                for item in path_index.values()
                if str(item["host"]) == host and item.get("port") == service_record["port"]
            ]
            saw_public_path = False
            saw_protected_path = False
            for path_record in related_paths:
                module_name = str(path_record["application_module"])
                if module_name in {"api", "api/v1", "api/v2", "graphql"}:
                    service_record["app_family"].add(module_name)
                service_record["privilege_boundary"].update(path_record["trust_boundaries"])
                service_record["bug_classes"].update(path_record["bug_classes"])
                service_record["data_sensitivity_guess"] = max(
                    service_record["data_sensitivity_guess"],
                    _guess_data_sensitivity(
                        str(path_record["path"]),
                        [str(value) for value in list(path_record["object_types"])],
                    ),
                    key=lambda item: {"low": 0, "medium": 1, "high": 2}.get(str(item), 0),
                )
                if path_record["auth_required"] == "yes":
                    saw_protected_path = True
                elif path_record["auth_required"] == "no":
                    saw_public_path = True
            if saw_public_path and saw_protected_path:
                service_record["auth_wall"] = "mixed"
            elif saw_protected_path:
                service_record["auth_wall"] = "protected"
            elif saw_public_path:
                service_record["auth_wall"] = "public"
            elif any(int(code) in {401, 403} for code in list(service_record["status_codes"])):
                service_record["auth_wall"] = "likely protected"
            service_record["signal_classification"] = _signal_classification(
                confirmed=bool(service_record["sources"]),
                in_scope=bool(service_record["in_scope"]),
            )
            service_record["coverage_status"] = _coverage_status_for_asset(
                coverage_records,
                host=host,
                component_prefix="service:",
            )
            if service_record["raw_observation_count"] >= 2:
                add_duplicate_risk(
                    "service",
                    f"{host}:{service_record['port']}/{service_record['protocol']}",
                    sorted(service_record["sources"]),
                )

        parameter_rows: list[dict[str, Any]] = []
        for param_record in param_index.values():
            lowered_param = str(param_record["parameter"]).lower()
            if any(
                marker in lowered_param for marker in ["id", "user", "account", "role", "tenant"]
            ):
                param_record["trust_boundaries"].add("authorization boundary")
                param_record["bug_classes"].update(["authorization", "bola/idor"])
            if any(marker in lowered_param for marker in ["token", "reset", "invite", "verify"]):
                param_record["trust_boundaries"].add("authentication token boundary")
                param_record["bug_classes"].add("authentication")
            if any(
                marker in lowered_param
                for marker in ["callback", "url", "uri", "webhook", "redirect", "next"]
            ):
                param_record["trust_boundaries"].add("remote callback boundary")
                param_record["bug_classes"].update(["ssrf", "open redirect"])
            if any(marker in lowered_param for marker in ["file", "path", "filename"]):
                param_record["trust_boundaries"].add("filesystem boundary")
                param_record["bug_classes"].update(["path traversal", "unauthorized file access"])
            if any(
                marker in lowered_param
                for marker in ["amount", "coupon", "discount", "price", "quantity", "status"]
            ):
                param_record["trust_boundaries"].add("business-state boundary")
                param_record["bug_classes"].update(
                    ["business logic abuse", "workflow/state transition"]
                )
            parameter_rows.append(
                {
                    "host": param_record["host"],
                    "path": param_record["path"],
                    "parameter": param_record["parameter"],
                    "locations": sorted(param_record["locations"]),
                    "methods": sorted(param_record["methods"]),
                    "sources": sorted(param_record["sources"]),
                    "object_hints": sorted(param_record["object_hints"]),
                    "trust_boundaries": sorted(param_record["trust_boundaries"]),
                    "client_controlled": param_record["client_controlled"],
                    "bug_classes": sorted(param_record["bug_classes"]),
                    "pivot_point": bool(param_record["pivot_point"]),
                    "signal_classification": param_record["signal_classification"],
                    "coverage_status": param_record["coverage_status"],
                }
            )

        object_rows = [
            {
                "host": item["host"],
                "object_type": item["object_type"],
                "related_paths": sorted(item["related_paths"]),
                "identifiers": sorted(item["identifiers"]),
                "fields": sorted(item["fields"]),
                "trust_boundaries": sorted(item["trust_boundaries"]),
                "bug_classes": sorted(item["bug_classes"]),
                "sources": sorted(item["sources"]),
                "signal_classification": item["signal_classification"],
                "coverage_status": item["coverage_status"],
            }
            for item in object_index.values()
        ]

        host_rows = [
            {
                "host": item["host"],
                "sources": sorted(item["sources"]),
                "resolve_status": "resolved" if item["resolved"] else "needs more data",
                "cname_chain": sorted(item["cname_chain"]) or ["needs more data"],
                "provider": sorted(item["provider_hints"]) or ["needs more data"],
                "ip": sorted(item["ip_addresses"]) or ["needs more data"],
                "asn": sorted(item["asn"]) or ["needs more data"],
                "cdn": sorted(item["cdn_hints"]) or ["needs more data"],
                "priority": item["priority"],
                "preliminary_type": item["preliminary_type"],
                "duplicate_risk": False,
                "coverage_status": item["coverage_status"],
                "signal_classification": item["signal_classification"],
                "notes": sorted(item["notes"]),
            }
            for item in host_index.values()
        ]
        service_rows = [
            {
                "host": item["host"],
                "port": item["port"],
                "protocol": item["protocol"],
                "fingerprint": sorted(item["fingerprints"]) or ["needs more data"],
                "app_family": sorted(item["app_family"]) or ["unknown"],
                "titles": sorted(item["titles"]),
                "status_codes": sorted(item["status_codes"]),
                "tls_names": sorted(item["tls_names"]),
                "redirect_targets": sorted(item["redirect_targets"]),
                "auth_wall": item["auth_wall"],
                "data_sensitivity_guess": item["data_sensitivity_guess"],
                "privilege_boundary": sorted(item["privilege_boundary"]),
                "bug_classes": sorted(item["bug_classes"]),
                "coverage_status": item["coverage_status"],
                "signal_classification": item["signal_classification"],
            }
            for item in service_index.values()
        ]
        path_rows = [
            {
                "host": item["host"],
                "port": item["port"],
                "application_module": item["application_module"],
                "path": item["path"],
                "methods": sorted(item["methods"]) or ["GET"],
                "content_type": sorted(item["content_types"]),
                "auth_required": item["auth_required"],
                "roles_seen": sorted(item["roles_seen"]),
                "object_types": sorted(item["object_types"]),
                "identifiers": sorted(item["identifiers"]),
                "params": {
                    "query": sorted(item["query_params"]),
                    "body": sorted(item["body_params"]),
                    "header": sorted(item["header_params"]),
                    "cookie": sorted(item["cookie_params"]),
                    "path": sorted(item["path_identifiers"]),
                },
                "trust_boundaries": sorted(item["trust_boundaries"]),
                "leakage_risks": [],
                "bug_classes": sorted(item["bug_classes"]),
                "priority": item["priority"],
                "coverage_status": item["coverage_status"],
                "signal_classification": item["signal_classification"],
                "sources": sorted(item["sources"]),
                "auth_hints": sorted(item["auth_hints"]),
            }
            for item in path_index.values()
        ]

        for item in path_rows:
            module_record = application_index.setdefault(
                (str(item["host"]), str(item["application_module"])),
                {
                    "host": str(item["host"]),
                    "application_module": str(item["application_module"]),
                    "root_paths": set(),
                    "major_sections": set(),
                    "hidden_routes": set(),
                    "versioned_apis": set(),
                    "docs_endpoints": set(),
                    "source_maps": set(),
                    "config_artifacts": set(),
                    "backup_artifacts": set(),
                    "upload_surfaces": set(),
                    "download_surfaces": set(),
                    "auth_surfaces": set(),
                    "billing_surfaces": set(),
                    "bug_classes": set(),
                    "coverage_status": "mapped",
                    "signal_classification": "suspected",
                },
            )
            module_record["root_paths"].add(str(item["path"]))
            if any(
                keyword in str(item["path"]).lower()
                for keyword in ["docs", "swagger", "openapi", "graphiql", "postman"]
            ):
                module_record["docs_endpoints"].add(str(item["path"]))
            if any(keyword in str(item["path"]).lower() for keyword in [".env", ".git", "config"]):
                module_record["config_artifacts"].add(str(item["path"]))
            if any(
                keyword in str(item["path"]).lower()
                for keyword in ["backup", ".bak", ".old", ".zip", ".tar", ".gz"]
            ):
                module_record["backup_artifacts"].add(str(item["path"]))
            if any(
                keyword in str(item["path"]).lower()
                for keyword in ["upload", "avatar", "attachment", "import"]
            ):
                module_record["upload_surfaces"].add(str(item["path"]))
            if any(
                keyword in str(item["path"]).lower()
                for keyword in ["download", "export", "file", "media"]
            ):
                module_record["download_surfaces"].add(str(item["path"]))
            if any(keyword in str(item["path"]).lower() for keyword in PATH_SECTION_HINTS["auth"]):
                module_record["auth_surfaces"].add(str(item["path"]))
            if any(
                keyword in str(item["path"]).lower() for keyword in PATH_SECTION_HINTS["billing"]
            ):
                module_record["billing_surfaces"].add(str(item["path"]))
            if "hidden_route" in str(item["sources"]):
                module_record["hidden_routes"].add(str(item["path"]))
            for section_name, keywords in PATH_SECTION_HINTS.items():
                if any(keyword in str(item["path"]).lower() for keyword in keywords):
                    module_record["major_sections"].add(section_name)
            if re.search(r"/api/v\d+", str(item["path"]).lower()):
                module_record["versioned_apis"].add(str(item["path"]))
            module_record["bug_classes"].update(item["bug_classes"])
            if item["signal_classification"] == "confirmed":
                module_record["signal_classification"] = "confirmed"

            if len(item["sources"]) >= 3:
                add_duplicate_risk("path", f"{item['host']}{item['path']}", item["sources"])
            if item["signal_classification"] == "out-of-scope":
                add_out_of_scope(
                    "path",
                    str(item["host"]),
                    str(item["path"]),
                    "Observed path falls outside the currently scoped path boundary.",
                )

        application_rows = [
            {
                "host": item["host"],
                "application_module": item["application_module"],
                "root_paths": sorted(item["root_paths"]),
                "major_sections": sorted(item["major_sections"]),
                "hidden_routes": sorted(item["hidden_routes"]),
                "versioned_apis": sorted(item["versioned_apis"]),
                "docs_endpoints": sorted(item["docs_endpoints"]),
                "source_maps": sorted(item["source_maps"]),
                "config_artifacts": sorted(item["config_artifacts"]),
                "backup_artifacts": sorted(item["backup_artifacts"]),
                "upload_surfaces": sorted(item["upload_surfaces"]),
                "download_surfaces": sorted(item["download_surfaces"]),
                "auth_surfaces": sorted(item["auth_surfaces"]),
                "billing_surfaces": sorted(item["billing_surfaces"]),
                "bug_classes": sorted(item["bug_classes"]),
                "coverage_status": item["coverage_status"],
                "signal_classification": item["signal_classification"],
            }
            for item in application_index.values()
        ]

        bug_class_matrix = [
            {
                "asset": f"{item['host']}{item['path']}",
                "host": item["host"],
                "path": item["path"],
                "bug_classes": item["bug_classes"],
                "priority": item["priority"],
                "signal_classification": item["signal_classification"],
                "coverage_status": item["coverage_status"],
            }
            for item in path_rows
            if item["bug_classes"]
        ]

        chain_opportunities: list[dict[str, Any]] = []
        if any(item["kind"] == "openapi_spec" for item in surface_artifacts):
            authz_paths = [
                item
                for item in bug_class_matrix
                if "authorization" in " ".join(item["bug_classes"]).lower()
            ]
            if authz_paths:
                chain_opportunities.append(
                    {
                        "summary": "Exposed docs/spec -> hidden or documented endpoint -> authorization drift",
                        "assets": [authz_paths[0]["asset"]],
                        "boundary": "authz / object boundary",
                        "signal_classification": "suspected",
                    }
                )
        if any(
            item["kind"] in {"js_route", "graphql_persisted_query"} for item in surface_artifacts
        ):
            object_paths = [
                item
                for item in bug_class_matrix
                if any(
                    keyword in " ".join(item["bug_classes"]).lower()
                    for keyword in ["idor", "authorization", "tenant"]
                )
            ]
            if object_paths:
                chain_opportunities.append(
                    {
                        "summary": "Client-side route leak -> object model clarity -> BOLA/tenant pivot",
                        "assets": [object_paths[0]["asset"]],
                        "boundary": "object / tenant boundary",
                        "signal_classification": "suspected",
                    }
                )
        if any("replay/race" in list(item.get("bug_classes") or []) for item in bug_class_matrix):
            chain_opportunities.append(
                {
                    "summary": "Workflow edge -> replay or race -> state/credit abuse",
                    "assets": [
                        item["asset"]
                        for item in bug_class_matrix
                        if "replay/race" in list(item.get("bug_classes") or [])
                    ][:3],
                    "boundary": "business-state boundary",
                    "signal_classification": "suspected",
                }
            )

        role_entries = _role_coverage_entries(
            session_profiles=session_profiles,
            path_rows=path_rows,
        )
        bug_class_rows = _bug_class_coverage(
            bug_matrix=bug_class_matrix,
            hypotheses=hypotheses,
            role_entries=role_entries,
        )

        domain_coverage = {
            "discovered": len(host_rows),
            "resolved": sum(1 for item in host_rows if item["resolve_status"] == "resolved"),
            "classified": sum(1 for item in host_rows if item["preliminary_type"] != "unknown"),
            "validated": sum(
                1 for item in host_rows if item["signal_classification"] == "confirmed"
            ),
            "reviewed": sum(
                1
                for item in host_rows
                if item["coverage_status"] in {"covered", "in_progress", "mapped"}
            ),
            "blind": len(blind_spots),
        }
        service_coverage = {
            "found": len(service_rows),
            "fingerprinted": sum(
                1 for item in service_rows if item["fingerprint"] != ["needs more data"]
            ),
            "auth_assessed": sum(
                1 for item in service_rows if item["auth_wall"] != "needs more data"
            ),
            "bug_mapped": sum(1 for item in service_rows if item["bug_classes"]),
            "blind": len([item for item in blind_spots if item["area"] == "service"]),
        }
        app_coverage = {
            "mapped": len(path_rows),
            "js_reviewed": sum(1 for item in exposures if str(item.get("kind")) == "js_route"),
            "docs_reviewed": sum(
                1
                for item in exposures
                if str(item.get("kind"))
                in {"openapi_spec", "graphql_endpoint", "graphql_persisted_query"}
            ),
            "params_extracted": len(parameter_rows),
            "flow_reviewed": len(workflows),
            "blind": len(
                [
                    item
                    for item in blind_spots
                    if str(item.get("area") or "")
                    in {"runtime inventory", "surface mining", "workflow coverage"}
                ]
            ),
        }

        classification_counter = Counter()
        for collection in [
            host_rows,
            service_rows,
            path_rows,
            parameter_rows,
            object_rows,
            exposures,
            duplicate_risks,
            out_of_scope_assets,
            blind_spots,
            chain_opportunities,
            role_entries,
        ]:
            for item in collection:
                classification = str(item.get("signal_classification") or "").strip()
                if classification:
                    classification_counter[classification] += 1

        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        for item in host_rows:
            nodes.append(
                {
                    "id": f"host:{item['host']}",
                    "type": "host",
                    "label": item["host"],
                    "signal_classification": item["signal_classification"],
                    "coverage_status": item["coverage_status"],
                }
            )
        for item in service_rows:
            service_id = f"service:{item['host']}:{item['port']}/{item['protocol']}"
            nodes.append(
                {
                    "id": service_id,
                    "type": "service",
                    "label": f"{item['host']}:{item['port']}/{item['protocol']}",
                    "signal_classification": item["signal_classification"],
                    "coverage_status": item["coverage_status"],
                }
            )
            edges.append(
                {"source": f"host:{item['host']}", "target": service_id, "relation": "exposes"}
            )
        for item in path_rows:
            path_id = f"path:{item['host']}{item['path']}"
            nodes.append(
                {
                    "id": path_id,
                    "type": "path",
                    "label": f"{item['host']}{item['path']}",
                    "signal_classification": item["signal_classification"],
                    "coverage_status": item["coverage_status"],
                }
            )
            if item["port"] is not None:
                edges.append(
                    {
                        "source": f"service:{item['host']}:{item['port']}/{'https' if item['port'] == 443 else 'http'}",
                        "target": path_id,
                        "relation": "serves",
                    }
                )
        for item in parameter_rows:
            param_id = f"param:{item['host']}{item['path']}:{item['parameter']}"
            nodes.append(
                {
                    "id": param_id,
                    "type": "param",
                    "label": item["parameter"],
                    "signal_classification": item["signal_classification"],
                    "coverage_status": item["coverage_status"],
                }
            )
            edges.append(
                {
                    "source": f"path:{item['host']}{item['path']}",
                    "target": param_id,
                    "relation": "accepts",
                }
            )

        report = {
            "target": normalized_target,
            "scope_map_v1": scope_map_v1,
            "domain_dns_host_inventory": {
                "hosts": sorted(host_rows, key=lambda item: item["host"]),
                "dns_blind_spots": [
                    {
                        "area": "dns",
                        "detail": "CNAME/NS/MX/TXT/SPF/DKIM/DMARC data is not stored yet; needs more data.",
                        "signal_classification": "blind-spot",
                    }
                ],
            },
            "service_inventory": sorted(
                service_rows, key=lambda item: (item["host"], item["port"], item["protocol"])
            ),
            "application_inventory": sorted(
                application_rows, key=lambda item: (item["host"], item["application_module"])
            ),
            "path_inventory": sorted(path_rows, key=lambda item: (item["host"], item["path"])),
            "parameter_object_review": {
                "parameters": sorted(
                    parameter_rows, key=lambda item: (item["host"], item["path"], item["parameter"])
                ),
                "objects": sorted(
                    object_rows, key=lambda item: (item["host"], item["object_type"])
                ),
            },
            "exposure_review": sorted(
                exposures, key=lambda item: (item["host"], item["path"], item["kind"])
            ),
            "bug_class_matrix": bug_class_matrix,
            "chain_analysis": chain_opportunities[:max_priorities],
            "duplicate_risks": duplicate_risks[:max_priorities],
            "out_of_scope": out_of_scope_assets[:max_priorities],
            "blind_spots": blind_spots[:max_priorities],
            "coverage_ledger": {
                "domain_subdomain": domain_coverage,
                "service_port": service_coverage,
                "app_module_path": app_coverage,
                "role_boundary": role_entries,
                "bug_class": bug_class_rows,
            },
            "priorities": {
                "top_targets_next": sorted(
                    host_rows,
                    key=lambda item: (-_priority_rank(str(item["priority"])), item["host"]),
                )[:max_priorities],
                "top_endpoints_next": sorted(
                    path_rows,
                    key=lambda item: (-_priority_rank(str(item["priority"])), item["path"]),
                )[:max_priorities],
                "top_params_objects": sorted(
                    parameter_rows,
                    key=lambda item: (0 if item["pivot_point"] else 1, item["parameter"]),
                )[:max_priorities],
                "top_recon_value_exposures": sorted(
                    exposures, key=lambda item: (item["exposure_class"], item["asset"])
                )[:max_priorities],
                "top_reportable_hypotheses": sorted(
                    hypotheses,
                    key=lambda item: (
                        -_priority_rank(str(item.get("priority") or "normal")),
                        str(item.get("hypothesis") or ""),
                    ),
                )[:max_priorities],
                "top_chain_opportunities": chain_opportunities[:max_priorities],
                "top_blind_spots": blind_spots[:max_priorities],
            },
            "attack_surface_graph": {
                "node_count": min(len(nodes), max_nodes),
                "edge_count": min(len(edges), max_edges),
                "nodes": nodes[:max_nodes],
                "edges": edges[:max_edges],
            },
            "summary": {
                "host_count": len(host_rows),
                "service_count": len(service_rows),
                "path_count": len(path_rows),
                "parameter_count": len(parameter_rows),
                "object_count": len(object_rows),
                "exposure_count": len(exposures),
                "workflow_count": len(workflows),
                "needs_more_data": bool(blind_spots),
                "classification_counts": dict(classification_counter),
            },
        }

        root_agent_id, review_store = _get_surface_review_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)
        review_store[_slug(normalized_target)] = {
            "target": normalized_target,
            "report": report,
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "summary": report["summary"],
        }
        evidence_result = record_evidence(
            agent_state=agent_state,
            title=f"Attack surface review for {normalized_target}",
            details=json.dumps(
                {
                    "summary": report["summary"],
                    "top_targets_next": report["priorities"]["top_targets_next"][:5],
                    "top_endpoints_next": report["priorities"]["top_endpoints_next"][:5],
                    "top_blind_spots": report["priorities"]["top_blind_spots"][:5],
                },
                ensure_ascii=False,
            ),
            source="research",
            target=normalized_target,
            component="attack_surface_review",
        )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to build attack surface review: {e}"}
    else:
        return {
            "success": True,
            "root_agent_id": root_agent_id,
            "target": normalized_target,
            "report": report,
            "evidence_result": evidence_result,
        }


@register_tool(sandbox_execution=False)
def list_attack_surface_reviews(
    agent_state: Any,
    target: str | None = None,
    include_report: bool = True,
    max_items: int = 25,
) -> dict[str, Any]:
    try:
        if max_items < 1:
            raise ValueError("max_items must be >= 1")

        root_agent_id, review_store = _get_surface_review_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)
        records = list(review_store.values())
        records.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)

        if target is not None:
            normalized_target = _normalize_non_empty(target, "target")
            record = review_store.get(_slug(normalized_target))
            if record is None:
                raise ValueError(f"No attack surface review found for target '{normalized_target}'")
            records = [record]

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to list attack surface reviews: {e}"}
    else:
        return {
            "success": True,
            "root_agent_id": root_agent_id,
            "review_count": len(records),
            "records": [
                _review_record_for_response(record, include_report=include_report)
                for record in records[:max_items]
            ],
        }
