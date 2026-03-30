from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool

from .assessment_actions import _get_ledger, _stable_id, record_evidence
from .assessment_differential_actions import analyze_differential_access
from .assessment_runtime_actions import list_runtime_inventory
from .assessment_session_actions import list_session_profiles


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
PRIORITY_ORDER = {"critical": 0, "high": 1, "normal": 2, "low": 3}
IMPACT_RANK = {"critical": 3, "high": 2, "normal": 1, "low": 0}
CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}


def _role_rank(profile: dict[str, Any]) -> int:
    role = str(profile.get("role") or profile.get("name") or "").lower()
    for keyword, rank in ROLE_KEYWORDS:
        if keyword in role:
            return rank
    return 1


def _priority_allowed(priority: str, min_priority: str) -> bool:
    return PRIORITY_ORDER.get(priority, 2) <= PRIORITY_ORDER.get(min_priority, 1)


def _host_for_profile(profile: dict[str, Any]) -> str | None:
    base_url = str(profile.get("base_url") or "").strip()
    if not base_url:
        return None
    return urlparse(base_url).netloc


def _expected_access(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    normalized_path: str,
) -> str:
    baseline_rank = _role_rank(baseline)
    candidate_rank = _role_rank(candidate)
    baseline_tenant = str(baseline.get("tenant") or "").strip().lower()
    candidate_tenant = str(candidate.get("tenant") or "").strip().lower()

    if candidate_rank < baseline_rank:
        return "deny"
    if baseline_tenant and candidate_tenant and baseline_tenant != candidate_tenant:
        return "deny"
    if ":" in normalized_path and str(candidate.get("name")) != str(baseline.get("name")):
        return "deny"
    return "unknown"


def _surface_status(agent_state: Any, target: str, component: str, surface: str) -> str | None:
    _, ledger = _get_ledger(agent_state)
    coverage_id = _stable_id("cov", target, component, surface)
    record = ledger["coverage"].get(coverage_id)
    if not record:
        return None
    return str(record.get("status") or "")


def _case_for_profile(
    profile: dict[str, Any],
    *,
    method: str,
    url: str,
    path: str,
    expected_access: str,
    compare_to: str | None,
) -> dict[str, Any]:
    case = {
        "name": str(profile.get("name")),
        "method": method,
        "expected_access": expected_access,
        "session_profile": str(profile.get("name")),
        "role": profile.get("role"),
        "tenant": profile.get("tenant"),
        "actor": str(profile.get("name")),
        "compare_to": compare_to,
    }
    if profile.get("base_url"):
        case["path"] = path
    else:
        case["url"] = url
    return case


def _top_suspicious_observation(result: dict[str, Any]) -> dict[str, Any] | None:
    suspicious = [
        item for item in list(result.get("suspicious_observations") or []) if isinstance(item, dict)
    ]
    if not suspicious:
        return None
    suspicious.sort(
        key=lambda item: (
            IMPACT_RANK.get(str(item.get("impact_level") or "low"), 0),
            CONFIDENCE_RANK.get(str(item.get("confidence") or "low"), 0),
            int(item.get("parity_score") or 0),
        ),
        reverse=True,
    )
    return suspicious[0]


@register_tool(sandbox_execution=False)
def run_inventory_differential_hunt(
    agent_state: Any,
    target: str,
    max_endpoints: int = 10,
    min_priority: str = "high",
    include_state_changing: bool = False,
    only_unresolved: bool = True,
    host_regex: str | None = None,
    path_regex: str | None = None,
    profile_names: list[str] | None = None,
    similarity_threshold: float = 0.98,
    timeout: int = 15,
) -> dict[str, Any]:
    try:
        if max_endpoints < 1:
            raise ValueError("max_endpoints must be >= 1")

        runtime_result = list_runtime_inventory(
            agent_state=agent_state,
            target=target,
            include_inventory=True,
            max_items=1,
        )
        if not runtime_result.get("success") or not runtime_result.get("records"):
            raise ValueError(f"No runtime inventory available for target '{target}'")

        inventory_record = runtime_result["records"][0]
        inventory = inventory_record.get("inventory", [])
        profiles_result = list_session_profiles(agent_state=agent_state, include_values=False)
        if not profiles_result.get("success"):
            raise ValueError("Failed to load session profiles")

        selected_profile_names = {
            str(name).strip().lower()
            for name in (profile_names or [])
            if isinstance(name, str) and name.strip()
        }
        profiles = [
            profile
            for profile in profiles_result.get("profiles", [])
            if not selected_profile_names
            or str(profile.get("name", "")).strip().lower() in selected_profile_names
        ]
        if len(profiles) < 2:
            raise ValueError("At least 2 session profiles are required for inventory hunting")

        import re

        host_pattern = re.compile(host_regex) if host_regex else None
        path_pattern = re.compile(path_regex) if path_regex else None

        candidates: list[dict[str, Any]] = []
        for item in inventory:
            if not _priority_allowed(str(item.get("priority", "normal")), min_priority):
                continue
            if host_pattern and not host_pattern.search(str(item.get("host", ""))):
                continue
            if path_pattern and not path_pattern.search(str(item.get("normalized_path", ""))):
                continue

            sample_urls = [url for url in item.get("sample_urls", []) if isinstance(url, str)]
            if not sample_urls:
                continue
            path = urlparse(sample_urls[0]).path or str(item.get("normalized_path", "/"))
            endpoint_profiles = [
                profile
                for profile in profiles
                if _host_for_profile(profile) == str(item.get("host"))
            ]
            if len(endpoint_profiles) < 2:
                continue

            endpoint_profiles.sort(
                key=lambda profile: (
                    -_role_rank(profile),
                    str(profile.get("tenant") or ""),
                    str(profile.get("name") or ""),
                )
            )
            baseline = endpoint_profiles[0]

            for method in item.get("methods", []):
                if not include_state_changing and method not in {"GET", "HEAD", "OPTIONS"}:
                    continue
                surface = f"Runtime endpoint {method} {item['normalized_path']}"
                status = _surface_status(
                    agent_state,
                    target,
                    f"runtime:{item['host']}",
                    surface,
                )
                if only_unresolved and status in {"covered", "not_applicable"}:
                    continue

                cases = [
                    _case_for_profile(
                        baseline,
                        method=method,
                        url=sample_urls[0],
                        path=path,
                        expected_access="allow",
                        compare_to=None,
                    )
                ]
                for profile in endpoint_profiles[1:]:
                    cases.append(
                        _case_for_profile(
                            profile,
                            method=method,
                            url=sample_urls[0],
                            path=path,
                            expected_access=_expected_access(
                                baseline,
                                profile,
                                str(item.get("normalized_path", "")),
                            ),
                            compare_to=str(baseline.get("name")),
                        )
                    )

                if len(cases) < 2:
                    continue

                candidates.append(
                    {
                        "target": target,
                        "component": f"runtime:{item['host']}",
                        "surface": surface,
                        "method": method,
                        "url": sample_urls[0],
                        "cases": cases,
                        "baseline_case": str(baseline.get("name")),
                        "priority": item.get("priority", "normal"),
                    }
                )

        candidates.sort(
            key=lambda item: (
                PRIORITY_ORDER.get(str(item.get("priority", "normal")), 2),
                str(item.get("surface", "")),
            )
        )

        executed: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        suspicious_count = 0
        critical_impact_count = 0
        for candidate in candidates[:max_endpoints]:
            result = analyze_differential_access(
                agent_state=agent_state,
                target=candidate["target"],
                component=candidate["component"],
                surface=candidate["surface"],
                method=candidate["method"],
                url=candidate["url"],
                cases=candidate["cases"],
                baseline_case=candidate["baseline_case"],
                similarity_threshold=similarity_threshold,
                timeout=timeout,
            )
            if not result.get("success"):
                skipped.append(
                    {
                        "surface": candidate["surface"],
                        "reason": result.get("error", "execution_failed"),
                    }
                )
                continue
            suspicious_matches = len(result.get("suspicious_observations", []))
            suspicious_count += suspicious_matches
            top_observation = _top_suspicious_observation(result)
            if top_observation and str(top_observation.get("impact_level") or "") == "critical":
                critical_impact_count += 1
            executed.append(
                {
                    "surface": candidate["surface"],
                    "url": candidate["url"],
                    "method": candidate["method"],
                    "case_count": len(candidate["cases"]),
                    "suspicious_observations": suspicious_matches,
                    "top_impact_level": (
                        top_observation.get("impact_level")
                        if isinstance(top_observation, dict)
                        else None
                    ),
                    "top_impact_category": (
                        top_observation.get("impact_category")
                        if isinstance(top_observation, dict)
                        else None
                    ),
                    "top_confidence": (
                        top_observation.get("confidence")
                        if isinstance(top_observation, dict)
                        else None
                    ),
                }
            )

        executed.sort(
            key=lambda item: (
                IMPACT_RANK.get(str(item.get("top_impact_level") or "low"), 0),
                CONFIDENCE_RANK.get(str(item.get("top_confidence") or "low"), 0),
                int(item.get("suspicious_observations") or 0),
            ),
            reverse=True,
        )

        if not executed and not skipped:
            return {
                "success": False,
                "error": "No eligible runtime endpoints matched the current inventory/profile filters",
            }

        summary_evidence = record_evidence(
            agent_state=agent_state,
            title=f"Inventory differential hunt summary for {target}",
            details=(
                f"Executed {len(executed)} runtime differential comparison(s); "
                f"{suspicious_count} suspicious observation(s); "
                f"{critical_impact_count} critical-impact candidate(s); {len(skipped)} skipped."
            ),
            source="tool",
            target=target,
            component="inventory_hunt",
        )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to run inventory differential hunt: {e}"}
    else:
        return {
            "success": True,
            "executed_count": len(executed),
            "suspicious_observation_count": suspicious_count,
            "critical_impact_count": critical_impact_count,
            "executed": executed,
            "skipped": skipped,
            "evidence_result": summary_evidence,
        }
