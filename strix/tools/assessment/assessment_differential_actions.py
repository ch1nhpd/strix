import json
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool

from .assessment_actions import record_coverage, record_evidence, record_hypothesis
from .assessment_validation_actions import (
    _execute_request,
    _normalize_request_spec,
    _normalize_success_statuses,
    _responses_match,
    _spawn_followup_agents,
    _summarize_assessment,
)


VALID_EXPECTED_ACCESS = {"allow", "deny", "unknown"}
PRIORITY_RANK = {"low": 0, "normal": 1, "high": 2, "critical": 3}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
FINANCIAL_KEYWORDS = (
    "billing",
    "cart",
    "checkout",
    "coupon",
    "invoice",
    "order",
    "payment",
    "plan",
    "redeem",
    "refund",
    "subscription",
    "transfer",
    "wallet",
    "withdraw",
)
ACCOUNT_KEYWORDS = (
    "account",
    "credential",
    "email",
    "login",
    "mfa",
    "otp",
    "passkey",
    "password",
    "profile",
    "reset",
    "session",
    "token",
)
PRIVILEGED_KEYWORDS = (
    "admin",
    "approve",
    "config",
    "invite",
    "member",
    "permission",
    "role",
    "setting",
    "staff",
    "user",
)


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


def _status_family(status_code: Any) -> int | None:
    try:
        value = int(status_code or 0)
    except (TypeError, ValueError):
        return None
    return value // 100 if value >= 100 else None


def _body_lengths_close(left: dict[str, Any], right: dict[str, Any]) -> bool:
    try:
        left_length = int(left.get("body_length") or 0)
        right_length = int(right.get("body_length") or 0)
    except (TypeError, ValueError):
        return False
    if left_length <= 0 or right_length <= 0:
        return False
    delta = abs(left_length - right_length)
    return delta <= max(64, int(max(left_length, right_length) * 0.1))


def _parity_evidence(
    candidate_result: dict[str, Any],
    baseline_result: dict[str, Any],
    *,
    similarity_threshold: float,
) -> dict[str, Any]:
    matches, ratio = _responses_match(candidate_result, baseline_result, similarity_threshold)
    same_body_hash = (
        bool(candidate_result.get("body_hash"))
        and candidate_result.get("body_hash") == baseline_result.get("body_hash")
    )
    candidate_location = str(candidate_result.get("location") or "").strip().lower()
    baseline_location = str(baseline_result.get("location") or "").strip().lower()
    same_location = bool(candidate_location and candidate_location == baseline_location)
    same_status = candidate_result.get("status_code") == baseline_result.get("status_code")
    same_status_family = (
        _status_family(candidate_result.get("status_code"))
        == _status_family(baseline_result.get("status_code"))
        and _status_family(candidate_result.get("status_code")) is not None
    )
    same_content_type = (
        str(candidate_result.get("content_type") or "").strip().lower()
        == str(baseline_result.get("content_type") or "").strip().lower()
    )
    length_close = _body_lengths_close(candidate_result, baseline_result)
    both_success = bool(candidate_result.get("status_code")) and bool(baseline_result.get("status_code"))

    score = 0
    reasons: list[str] = []
    if same_body_hash:
        score += 6
        reasons.append("same_body_hash")
    elif matches:
        score += 4
        reasons.append("high_preview_similarity")
    if same_status:
        score += 2
        reasons.append("same_status")
    elif same_status_family:
        score += 1
        reasons.append("same_status_family")
    if same_location:
        score += 3
        reasons.append("same_location")
    if same_content_type:
        score += 1
        reasons.append("same_content_type")
    if length_close:
        score += 1
        reasons.append("similar_body_length")
    if both_success:
        score += 1
        reasons.append("both_success")

    if score >= 9 or same_body_hash:
        confidence = "high"
    elif score >= 6:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "score": score,
        "confidence": confidence,
        "reasons": reasons,
        "primary_parity": bool(same_body_hash or matches or same_location),
        "matched_response": matches,
        "similarity": round(ratio, 3),
        "same_status": same_status,
        "same_location": same_location,
        "same_content_type": same_content_type,
        "same_body_hash": same_body_hash,
        "length_close": length_close,
    }


def _contains_keyword(blob: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in blob for keyword in keywords)


def _impact_assessment(
    *,
    method: str,
    url: str,
    deltas: list[str],
    issue_type: str,
    case: dict[str, Any],
    baseline: dict[str, Any],
) -> dict[str, str]:
    normalized_method = str(method).strip().upper()
    state_changing = normalized_method in STATE_CHANGING_METHODS
    path_blob = " ".join(
        [
            urlparse(str(url or "")).path.lower(),
            str(case.get("actor") or case.get("name") or "").lower(),
            str(baseline.get("actor") or baseline.get("name") or "").lower(),
            str(case.get("role") or "").lower(),
            str(baseline.get("role") or "").lower(),
        ]
    )

    if issue_type == "cross_tenant_access":
        if state_changing:
            return {
                "impact_category": "cross_tenant_action",
                "impact_level": "critical",
                "impact_rationale": (
                    "A lower-trust actor appears able to perform a state-changing action across tenant boundaries."
                ),
            }
        return {
            "impact_category": "cross_tenant_data",
            "impact_level": "critical",
            "impact_rationale": (
                "A lower-trust actor appears able to read tenant-isolated data that should stay separated."
            ),
        }

    if _contains_keyword(path_blob, ACCOUNT_KEYWORDS):
        return {
            "impact_category": "account_takeover_action" if state_changing else "account_takeover_exposure",
            "impact_level": "critical" if state_changing else "high",
            "impact_rationale": (
                "The affected surface looks account- or credential-related, so authorization drift could affect identity control."
            ),
        }

    if _contains_keyword(path_blob, FINANCIAL_KEYWORDS):
        return {
            "impact_category": "financial_action" if state_changing else "financial_data",
            "impact_level": "critical" if state_changing else "high",
            "impact_rationale": (
                "The path appears financial or transactional, so parity likely has direct business impact."
            ),
        }

    if _contains_keyword(path_blob, PRIVILEGED_KEYWORDS) or "role" in deltas:
        return {
            "impact_category": "privileged_action" if state_changing else "privileged_data",
            "impact_level": "critical" if state_changing else "high",
            "impact_rationale": (
                "The affected surface looks administrative or privilege-bearing, which raises the impact of authorization drift."
            ),
        }

    if "ownership" in deltas or "object_ref" in deltas:
        return {
            "impact_category": "object_level_action" if state_changing else "object_level_data",
            "impact_level": "high",
            "impact_rationale": (
                "The comparison differs by object or ownership context, which is typical of BOLA/IDOR-style impact."
            ),
        }

    if state_changing:
        return {
            "impact_category": "unauthorized_state_change",
            "impact_level": "high",
            "impact_rationale": (
                "A lower-trust actor appears able to reach a state-changing surface with response parity."
            ),
        }

    return {
        "impact_category": "sensitive_data_access",
        "impact_level": "high" if issue_type in {"idor_bola", "role_based_access"} else "normal",
        "impact_rationale": (
            "The surface appears readable across contexts, which may expose data that should remain isolated."
        ),
    }


def _higher_priority(*values: str) -> str:
    winner = "low"
    for value in values:
        if PRIORITY_RANK.get(str(value or "low"), 0) > PRIORITY_RANK.get(winner, 0):
            winner = str(value or "low")
    return winner


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
    priority = "critical" if method.upper() in STATE_CHANGING_METHODS else "high"
    if any(
        observation["issue_type"] in {"cross_tenant_access", "idor_bola"}
        for observation in observations
    ):
        priority = _higher_priority(priority, "critical")
    for observation in observations:
        priority = _higher_priority(priority, str(observation.get("impact_level") or "low"))
    return priority


def _best_vulnerability_type(observations: list[dict[str, Any]]) -> str:
    if any(
        observation["issue_type"] in {"cross_tenant_access", "idor_bola"}
        for observation in observations
    ):
        return "idor"
    return "authorization"


def _differential_followup_decision(
    observations: list[dict[str, Any]],
) -> tuple[str, bool]:
    if not observations:
        return ("none", False)
    top = observations[0]
    confidence = str(top.get("confidence") or "").strip().lower()
    impact_level = str(top.get("impact_level") or "").strip().lower()
    parity_score = int(top.get("parity_score") or 0)
    if confidence == "high" and parity_score >= 8 and impact_level in {"high", "critical"}:
        return ("impact", True)
    return ("signal", False)


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
    auto_spawn_signal_agents: bool = True,
    auto_spawn_impact_agents: bool = True,
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
            parity = _parity_evidence(
                case_result,
                baseline_result,
                similarity_threshold=similarity_threshold,
            )
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
                "similarity": parity["similarity"],
                "matched_response": parity["matched_response"],
                "case_body_hash": case_result.get("body_hash"),
                "baseline_body_hash": baseline_result.get("body_hash"),
                "parity_score": parity["score"],
                "confidence": parity["confidence"],
                "parity_signals": parity["reasons"],
                "same_location": parity["same_location"],
            }
            observations.append(observation)

            suspicious = False
            evidence_threshold = 6 if case["expected_access"] == "deny" else 7
            if case["expected_access"] == "deny":
                suspicious = (
                    bool(deltas)
                    and case_success
                    and baseline_success
                    and parity["primary_parity"]
                    and int(parity["score"]) >= evidence_threshold
                )
            elif case["expected_access"] == "unknown":
                suspicious = (
                    bool(deltas)
                    and case_success
                    and baseline_success
                    and parity["primary_parity"]
                    and int(parity["score"]) >= evidence_threshold
                )
            elif baseline_case:
                suspicious = (
                    bool(deltas)
                    and case_success
                    and baseline_success
                    and parity["primary_parity"]
                    and int(parity["score"]) >= evidence_threshold
                )

            if suspicious:
                suspicious_observations.append(
                    {
                        **observation,
                        **_impact_assessment(
                            method=normalized_method,
                            url=normalized_url,
                            deltas=deltas,
                            issue_type=issue_type,
                            case=case,
                            baseline=baseline,
                        ),
                    }
                )

        suspicious_observations.sort(
            key=lambda item: (
                PRIORITY_RANK.get(str(item.get("impact_level") or "low"), 0),
                CONFIDENCE_RANK.get(str(item.get("confidence") or "low"), 0),
                int(item.get("parity_score") or 0),
                len(list(item.get("dimensions") or [])),
            ),
            reverse=True,
        )

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
            top_impact = suspicious_observations[0]
            coverage_rationale = (
                f"Differential access analysis found {len(suspicious_observations)} suspicious "
                f"allow-vs-deny or cross-context parity comparison(s) on "
                f"{normalized_method} {normalized_url}, with top impact "
                f"{top_impact.get('impact_category', 'authorization_drift')}."
            )
            next_step = (
                f"Validate the highest-signal {top_impact.get('impact_category', 'authorization')} "
                "path with a concrete business-impact PoC before reporting"
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
        followup_mode, validated_signal = _differential_followup_decision(
            suspicious_observations
        )
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
                status="validated" if validated_signal else "open",
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
        followup_agent_result = None
        if followup_mode == "impact":
            if auto_spawn_impact_agents:
                followup_agent_result = _spawn_followup_agents(
                    agent_state,
                    target=target,
                    hypothesis_result=hypothesis_result,
                    prefer_impact=True,
                )
            elif auto_spawn_signal_agents:
                followup_agent_result = _spawn_followup_agents(
                    agent_state,
                    target=target,
                    hypothesis_result=hypothesis_result,
                    prefer_signal=True,
                )
        elif followup_mode == "signal" and auto_spawn_signal_agents:
            followup_agent_result = _spawn_followup_agents(
                agent_state,
                target=target,
                hypothesis_result=hypothesis_result,
                prefer_signal=True,
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
            "followup_agent_result": followup_agent_result,
            "assessment_summary": _summarize_assessment(
                coverage_result,
                hypothesis_result,
                evidence_result,
            ),
        }
