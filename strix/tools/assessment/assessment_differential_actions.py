import json
from typing import Any

from strix.tools.registry import register_tool

from .assessment_actions import record_coverage, record_evidence, record_hypothesis
from .assessment_validation_actions import (
    _execute_request,
    _normalize_request_spec,
    _normalize_success_statuses,
    _responses_match,
    _summarize_assessment,
)


VALID_EXPECTED_ACCESS = {"allow", "deny", "unknown"}


def _normalize_access_case(agent_state: Any, item: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_request_spec(item, field_name="cases", agent_state=agent_state)
    expected_access = str(item.get("expected_access") or "unknown").strip().lower()
    if expected_access not in VALID_EXPECTED_ACCESS:
        raise ValueError("expected_access must be one of: allow, deny, unknown")

    normalized["expected_access"] = expected_access
    normalized["role"] = str(item.get("role") or normalized.get("session_role") or "").strip() or None
    normalized["tenant"] = (
        str(item.get("tenant") or normalized.get("session_tenant") or "").strip() or None
    )
    normalized["ownership"] = str(item.get("ownership") or "").strip().lower() or None
    normalized["object_ref"] = str(item.get("object_ref") or item.get("object_id") or "").strip() or None
    normalized["actor"] = str(item.get("actor") or normalized["name"]).strip()
    normalized["compare_to"] = str(item.get("compare_to") or "").strip() or None
    return normalized


def _dimension_deltas(case: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    deltas: list[str] = []
    for key in ["role", "tenant", "ownership", "object_ref", "actor"]:
        if case.get(key) != baseline.get(key) and (case.get(key) or baseline.get(key)):
            deltas.append(key)
    return deltas


def _issue_type(deltas: list[str]) -> str:
    if "tenant" in deltas:
        return "cross_tenant_access"
    if "ownership" in deltas or "object_ref" in deltas:
        return "idor_bola"
    if "role" in deltas:
        return "role_based_access"
    return "differential_access"


def _comparison_pairs(
    cases: list[dict[str, Any]],
    *,
    baseline_case: str | None,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    by_name = {case["name"]: case for case in cases}
    if baseline_case:
        if baseline_case not in by_name:
            raise ValueError(f"baseline_case '{baseline_case}' was not found in cases")
        baseline = by_name[baseline_case]
        return [(case, baseline) for case in cases if case["name"] != baseline_case]

    allowed = [case for case in cases if case["expected_access"] == "allow"]
    if not allowed:
        raise ValueError("Provide baseline_case or at least one case with expected_access='allow'")

    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for case in cases:
        if case["expected_access"] == "allow":
            continue
        explicit_baseline = case.get("compare_to")
        if explicit_baseline:
            if explicit_baseline not in by_name:
                raise ValueError(
                    f"compare_to '{explicit_baseline}' for case '{case['name']}' was not found"
                )
            pairs.append((case, by_name[explicit_baseline]))
            continue
        for baseline in allowed:
            if baseline["name"] != case["name"]:
                pairs.append((case, baseline))
    return pairs


def _suspicion_priority(method: str, observations: list[dict[str, Any]]) -> str:
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        return "critical"
    if any(
        observation["issue_type"] in {"cross_tenant_access", "idor_bola"}
        for observation in observations
    ):
        return "critical"
    return "high"


def _best_vulnerability_type(observations: list[dict[str, Any]]) -> str:
    if any(
        observation["issue_type"] in {"cross_tenant_access", "idor_bola"}
        for observation in observations
    ):
        return "idor"
    return "authorization"


@register_tool(sandbox_execution=False)
def analyze_differential_access(
    agent_state: Any,
    target: str,
    component: str,
    surface: str,
    method: str,
    url: str,
    cases: list[dict[str, Any]],
    baseline_case: str | None = None,
    timeout: int = 15,
    follow_redirects: bool = False,
    similarity_threshold: float = 0.98,
    success_statuses: list[int] | None = None,
) -> dict[str, Any]:
    try:
        normalized_cases = [_normalize_access_case(agent_state, item) for item in cases]
        if len(normalized_cases) < 2:
            raise ValueError("cases must contain at least 2 request variants")

        normalized_method = method.strip().upper()
        normalized_url = url.strip()
        if not normalized_method or not normalized_url:
            raise ValueError("method and url are required")

        statuses = _normalize_success_statuses(success_statuses)
        results = [
            _execute_request(case, timeout=timeout, follow_redirects=follow_redirects)
            for case in normalized_cases
        ]
        result_by_name = {result["name"]: result for result in results}
        pairs = _comparison_pairs(normalized_cases, baseline_case=baseline_case)

        observations: list[dict[str, Any]] = []
        suspicious_observations: list[dict[str, Any]] = []
        for case, baseline in pairs:
            case_result = result_by_name[case["name"]]
            baseline_result = result_by_name[baseline["name"]]
            if case_result.get("error") or baseline_result.get("error"):
                observations.append(
                    {
                        "case": case["name"],
                        "baseline_case": baseline["name"],
                        "error": case_result.get("error") or baseline_result.get("error"),
                    }
                )
                continue

            deltas = _dimension_deltas(case, baseline)
            matches, ratio = _responses_match(case_result, baseline_result, similarity_threshold)
            case_success = int(case_result.get("status_code") or 0) in statuses
            baseline_success = int(baseline_result.get("status_code") or 0) in statuses
            issue_type = _issue_type(deltas)
            observation = {
                "case": case["name"],
                "baseline_case": baseline["name"],
                "expected_access": case["expected_access"],
                "status_code": case_result.get("status_code"),
                "baseline_status_code": baseline_result.get("status_code"),
                "dimensions": deltas,
                "issue_type": issue_type,
                "similarity": round(ratio, 3),
                "matched_response": matches,
                "case_body_hash": case_result.get("body_hash"),
                "baseline_body_hash": baseline_result.get("body_hash"),
            }
            observations.append(observation)

            suspicious = False
            if case["expected_access"] == "deny":
                suspicious = case_success and (matches or baseline_success)
            elif case["expected_access"] == "unknown":
                suspicious = case_success and matches and bool(deltas)
            elif baseline_case:
                suspicious = case_success and matches and bool(deltas)

            if suspicious:
                suspicious_observations.append(observation)

        error_count = sum(1 for result in results if result.get("error"))
        if error_count == len(results):
            coverage_status = "blocked"
            coverage_priority = "high"
            coverage_rationale = (
                f"Differential access testing could not reach {normalized_method} {normalized_url}; "
                "all request variants failed."
            )
            next_step = "Restore connectivity or authentication context before concluding coverage"
        elif suspicious_observations:
            coverage_status = "in_progress"
            coverage_priority = _suspicion_priority(normalized_method, suspicious_observations)
            coverage_rationale = (
                f"Differential access analysis found {len(suspicious_observations)} suspicious "
                f"allow-vs-deny or cross-context parity comparison(s) on "
                f"{normalized_method} {normalized_url}."
            )
            next_step = (
                "Validate object ownership, tenant isolation, and role enforcement with concrete "
                "business-impact PoCs before reporting"
            )
        elif error_count > 0:
            coverage_status = "blocked"
            coverage_priority = "normal"
            coverage_rationale = (
                f"Differential access testing partially executed on {normalized_method} "
                f"{normalized_url}, but some variants failed and coverage remains incomplete."
            )
            next_step = "Repair failing cases or session profiles and re-run the differential set"
        else:
            coverage_status = "covered"
            coverage_priority = "normal"
            coverage_rationale = (
                f"Differential access testing completed on {normalized_method} {normalized_url} "
                "without suspicious allow-vs-deny parity."
            )
            next_step = (
                "Expand comparisons only if new objects, tenants, or privileged flows are discovered"
            )

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
        evidence_result = None
        if suspicious_observations:
            vulnerability_type = _best_vulnerability_type(suspicious_observations)
            hypothesis_result = record_hypothesis(
                agent_state=agent_state,
                hypothesis=(
                    f"Differential access controls may not distinguish denied contexts from "
                    f"allowed contexts on {normalized_method} {normalized_url}"
                ),
                target=target,
                component=component,
                vulnerability_type=vulnerability_type,
                status="open",
                priority=coverage_priority,
                rationale=coverage_rationale,
            )
            evidence_result = record_evidence(
                agent_state=agent_state,
                title=f"Differential access observations on {normalized_method} {normalized_url}",
                details=json.dumps(
                    {
                        "url": normalized_url,
                        "method": normalized_method,
                        "suspicious_observations": suspicious_observations,
                        "all_observations": observations,
                        "case_summaries": results,
                    },
                    ensure_ascii=False,
                ),
                source="traffic",
                target=target,
                component=component,
                related_coverage_id=coverage_result.get("coverage_id"),
                related_hypothesis_id=(
                    hypothesis_result.get("hypothesis_id")
                    if isinstance(hypothesis_result, dict)
                    else None
                ),
            )
        elif error_count > 0:
            evidence_result = record_evidence(
                agent_state=agent_state,
                title=f"Differential access execution issue on {normalized_method} {normalized_url}",
                details=json.dumps(
                    {"url": normalized_url, "method": normalized_method, "case_summaries": results},
                    ensure_ascii=False,
                ),
                source="tool",
                target=target,
                component=component,
                related_coverage_id=coverage_result.get("coverage_id"),
            )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to analyze differential access: {e}"}
    else:
        return {
            "success": True,
            "url": normalized_url,
            "method": normalized_method,
            "cases": results,
            "observations": observations,
            "suspicious_observations": suspicious_observations,
            "coverage_result": coverage_result,
            "hypothesis_result": hypothesis_result,
            "evidence_result": evidence_result,
            "assessment_summary": _summarize_assessment(
                coverage_result,
                hypothesis_result,
                evidence_result,
            ),
        }
