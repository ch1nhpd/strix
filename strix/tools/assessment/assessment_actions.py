import hashlib
from datetime import UTC, datetime
from typing import Any

from strix.tools.registry import register_tool


VALID_COVERAGE_STATUSES = ["uncovered", "in_progress", "covered", "not_applicable", "blocked"]
VALID_HYPOTHESIS_STATUSES = ["open", "in_progress", "validated", "rejected", "blocked"]
VALID_PRIORITIES = ["low", "normal", "high", "critical"]
VALID_EVIDENCE_SOURCES = ["code", "runtime", "traffic", "tool", "research", "user", "other"]
UNRESOLVED_COVERAGE_STATUSES = {"uncovered", "in_progress"}
ACTIVE_HYPOTHESIS_STATUSES = {"open", "in_progress"}

AssessmentRecord = dict[str, Any]
AssessmentLedger = dict[str, dict[str, AssessmentRecord]]
_assessment_storage: dict[str, AssessmentLedger] = {}


def clear_assessment_storage() -> None:
    _assessment_storage.clear()
    try:
        from .assessment_session_actions import clear_session_profile_storage
    except ImportError:
        clear_session_profile_storage = None
    try:
        from .assessment_oob_actions import clear_oob_harness_storage
    except ImportError:
        clear_oob_harness_storage = None
    try:
        from .assessment_runtime_actions import clear_runtime_inventory_storage
    except ImportError:
        clear_runtime_inventory_storage = None
    try:
        from .assessment_surface_actions import clear_surface_mining_storage
    except ImportError:
        clear_surface_mining_storage = None
    try:
        from .assessment_surface_review_actions import clear_surface_review_storage
    except ImportError:
        clear_surface_review_storage = None
    try:
        from .assessment_workflow_actions import clear_workflow_storage
    except ImportError:
        clear_workflow_storage = None
    try:
        from .assessment_toolchain_actions import clear_tool_scan_storage
    except ImportError:
        clear_tool_scan_storage = None
    if clear_session_profile_storage is not None:
        clear_session_profile_storage()
    if clear_oob_harness_storage is not None:
        clear_oob_harness_storage()
    if clear_runtime_inventory_storage is not None:
        clear_runtime_inventory_storage()
    if clear_surface_mining_storage is not None:
        clear_surface_mining_storage()
    if clear_surface_review_storage is not None:
        clear_surface_review_storage()
    if clear_workflow_storage is not None:
        clear_workflow_storage()
    if clear_tool_scan_storage is not None:
        clear_tool_scan_storage()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_non_empty(value: str, field_name: str) -> str:
    normalized = " ".join(value.strip().split())
    if not normalized:
        raise ValueError(f"{field_name} cannot be empty")
    return normalized


def _normalize_priority(priority: str | None) -> str:
    candidate = (priority or "normal").strip().lower()
    if candidate not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority. Must be one of: {', '.join(VALID_PRIORITIES)}")
    return candidate


def _normalize_coverage_status(status: str) -> str:
    candidate = status.strip().lower()
    if candidate not in VALID_COVERAGE_STATUSES:
        raise ValueError(
            f"Invalid coverage status. Must be one of: {', '.join(VALID_COVERAGE_STATUSES)}"
        )
    return candidate


def _normalize_hypothesis_status(status: str) -> str:
    candidate = status.strip().lower()
    if candidate not in VALID_HYPOTHESIS_STATUSES:
        raise ValueError(
            "Invalid hypothesis status. "
            f"Must be one of: {', '.join(VALID_HYPOTHESIS_STATUSES)}"
        )
    return candidate


def _normalize_evidence_source(source: str) -> str:
    candidate = source.strip().lower()
    if candidate not in VALID_EVIDENCE_SOURCES:
        raise ValueError(
            f"Invalid evidence source. Must be one of: {', '.join(VALID_EVIDENCE_SOURCES)}"
        )
    return candidate


def _slug(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _stable_id(prefix: str, *parts: str) -> str:
    normalized = "||".join(_slug(part) for part in parts)
    digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def _resolve_root_agent_id(agent_state: Any) -> str:
    agent_id = getattr(agent_state, "agent_id", None)
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError("agent_state.agent_id is required")

    parent_id = getattr(agent_state, "parent_id", None)
    if not isinstance(parent_id, str) or not parent_id:
        return agent_id

    try:
        from strix.tools.agents_graph.agents_graph_actions import _agent_graph

        current_parent = parent_id
        seen = {agent_id}
        while current_parent and current_parent not in seen:
            seen.add(current_parent)
            node = _agent_graph.get("nodes", {}).get(current_parent, {})
            next_parent = node.get("parent_id")
            if not isinstance(next_parent, str) or not next_parent:
                return current_parent
            current_parent = next_parent
    except Exception:
        return parent_id
    else:
        return current_parent or parent_id


def _get_ledger(agent_state: Any) -> tuple[str, AssessmentLedger]:
    root_agent_id = _resolve_root_agent_id(agent_state)
    if root_agent_id not in _assessment_storage:
        _assessment_storage[root_agent_id] = {
            "coverage": {},
            "hypotheses": {},
            "evidence": {},
        }
    return root_agent_id, _assessment_storage[root_agent_id]


def _coverage_record_for_response(record_id: str, record: AssessmentRecord) -> AssessmentRecord:
    response_record = dict(record)
    response_record["coverage_id"] = record_id
    return response_record


def _hypothesis_record_for_response(record_id: str, record: AssessmentRecord) -> AssessmentRecord:
    response_record = dict(record)
    response_record["hypothesis_id"] = record_id
    return response_record


def _evidence_record_for_response(record_id: str, record: AssessmentRecord) -> AssessmentRecord:
    response_record = dict(record)
    response_record["evidence_id"] = record_id
    return response_record


def _summarize_ledger(ledger: AssessmentLedger) -> dict[str, Any]:
    coverage_records = list(ledger["coverage"].items())
    hypothesis_records = list(ledger["hypotheses"].items())
    evidence_records = list(ledger["evidence"].items())

    coverage_counts = {status: 0 for status in VALID_COVERAGE_STATUSES}
    for _, record in coverage_records:
        status = str(record.get("status", "uncovered"))
        coverage_counts.setdefault(status, 0)
        coverage_counts[status] += 1

    hypothesis_counts = {status: 0 for status in VALID_HYPOTHESIS_STATUSES}
    for _, record in hypothesis_records:
        status = str(record.get("status", "open"))
        hypothesis_counts.setdefault(status, 0)
        hypothesis_counts[status] += 1

    unresolved_coverage = [
        _coverage_record_for_response(record_id, record)
        for record_id, record in coverage_records
        if record.get("status") in UNRESOLVED_COVERAGE_STATUSES
    ]
    unresolved_hypotheses = [
        _hypothesis_record_for_response(record_id, record)
        for record_id, record in hypothesis_records
        if record.get("status") in ACTIVE_HYPOTHESIS_STATUSES
    ]

    unresolved_coverage.sort(
        key=lambda item: (
            VALID_PRIORITIES.index(str(item.get("priority", "normal"))),
            str(item.get("updated_at", "")),
        )
    )
    unresolved_hypotheses.sort(
        key=lambda item: (
            VALID_PRIORITIES.index(str(item.get("priority", "normal"))),
            str(item.get("updated_at", "")),
        )
    )

    return {
        "coverage_counts": coverage_counts,
        "hypothesis_counts": hypothesis_counts,
        "coverage_total": len(coverage_records),
        "hypothesis_total": len(hypothesis_records),
        "evidence_total": len(evidence_records),
        "unresolved_coverage_count": len(unresolved_coverage),
        "unresolved_hypothesis_count": len(unresolved_hypotheses),
        "ready_to_finish": len(coverage_records) > 0 and len(unresolved_coverage) == 0,
        "unresolved_coverage": unresolved_coverage[:20],
        "unresolved_hypotheses": unresolved_hypotheses[:20],
    }


def get_finish_blockers(agent_state: Any) -> dict[str, Any] | None:
    _, ledger = _get_ledger(agent_state)
    summary = _summarize_ledger(ledger)

    if summary["coverage_total"] == 0:
        return {
            "success": False,
            "error": "assessment_coverage_missing",
            "message": (
                "Cannot finish scan: no structured coverage ledger has been recorded yet."
            ),
            "suggestions": [
                "Use bulk_record_coverage to register the highest-value attack surfaces first",
                "Update each coverage item until it is covered, blocked, or not_applicable",
                "Use list_assessment_state to review unresolved surfaces before finishing",
            ],
            "assessment_summary": summary,
        }

    if summary["unresolved_coverage_count"] > 0:
        return {
            "success": False,
            "error": "assessment_coverage_incomplete",
            "message": "Cannot finish scan: attack-surface coverage is still incomplete",
            "unresolved_coverage": summary["unresolved_coverage"],
            "suggestions": [
                "Continue testing or explicitly mark unreachable paths as blocked with rationale",
                "Mark non-applicable surfaces as not_applicable instead of leaving them unresolved",
                "Use list_assessment_state to inspect the full ledger before trying again",
            ],
            "assessment_summary": summary,
        }

    return None


def _update_agent_context(agent_state: Any, root_agent_id: str) -> None:
    if hasattr(agent_state, "update_context"):
        agent_state.update_context("assessment_root_agent_id", root_agent_id)


@register_tool(sandbox_execution=False)
def record_coverage(
    agent_state: Any,
    target: str,
    component: str,
    surface: str,
    status: str,
    rationale: str,
    priority: str = "normal",
    next_step: str | None = None,
) -> dict[str, Any]:
    try:
        normalized_target = _normalize_non_empty(target, "target")
        normalized_component = _normalize_non_empty(component, "component")
        normalized_surface = _normalize_non_empty(surface, "surface")
        normalized_rationale = _normalize_non_empty(rationale, "rationale")
        normalized_status = _normalize_coverage_status(status)
        normalized_priority = _normalize_priority(priority)

        root_agent_id, ledger = _get_ledger(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        coverage_id = _stable_id(
            "cov",
            normalized_target,
            normalized_component,
            normalized_surface,
        )
        timestamp = _utc_now()
        existing = ledger["coverage"].get(coverage_id)

        record: AssessmentRecord = {
            "target": normalized_target,
            "component": normalized_component,
            "surface": normalized_surface,
            "status": normalized_status,
            "priority": normalized_priority,
            "rationale": normalized_rationale,
            "next_step": (
                next_step.strip()
                if isinstance(next_step, str) and next_step.strip()
                else None
            ),
            "owner_agent_id": getattr(agent_state, "agent_id", None),
            "updated_at": timestamp,
        }
        if existing and "created_at" in existing:
            record["created_at"] = existing["created_at"]
        else:
            record["created_at"] = timestamp

        ledger["coverage"][coverage_id] = record
        summary = _summarize_ledger(ledger)

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to record coverage: {e}"}
    else:
        return {
            "success": True,
            "coverage_id": coverage_id,
            "updated_existing": existing is not None,
            "record": _coverage_record_for_response(coverage_id, record),
            "assessment_summary": summary,
        }


@register_tool(sandbox_execution=False)
def bulk_record_coverage(
    agent_state: Any,
    items: list[dict[str, Any]],
    preserve_existing_status: bool = False,
) -> dict[str, Any]:
    try:
        if not items:
            return {"success": False, "error": "items cannot be empty", "updated_count": 0}

        created_or_updated: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        _, ledger = _get_ledger(agent_state)

        for index, item in enumerate(items):
            if not isinstance(item, dict):
                errors.append({"index": index, "error": "Each item must be an object"})
                continue

            resolved_item = dict(item)
            if preserve_existing_status:
                coverage_id = _stable_id(
                    "cov",
                    str(item.get("target", "")),
                    str(item.get("component", "")),
                    str(item.get("surface", "")),
                )
                existing = ledger["coverage"].get(coverage_id)
                if existing:
                    resolved_item.update(
                        {
                            "status": existing.get("status", item.get("status", "")),
                            "rationale": existing.get("rationale", item.get("rationale", "")),
                            "priority": existing.get("priority", item.get("priority", "normal")),
                            "next_step": existing.get("next_step", item.get("next_step")),
                        }
                    )

            result = record_coverage(
                agent_state=agent_state,
                target=str(resolved_item.get("target", "")),
                component=str(resolved_item.get("component", "")),
                surface=str(resolved_item.get("surface", "")),
                status=str(resolved_item.get("status", "")),
                rationale=str(resolved_item.get("rationale", "")),
                priority=str(resolved_item.get("priority", "normal")),
                next_step=(
                    str(resolved_item["next_step"])
                    if "next_step" in resolved_item and resolved_item.get("next_step") is not None
                    else None
                ),
            )
            if result.get("success"):
                created_or_updated.append(result["record"])
            else:
                errors.append({"index": index, "error": result.get("error", "Unknown error")})

        summary = _summarize_ledger(ledger)

    except (TypeError, ValueError) as e:
        return {
            "success": False,
            "error": f"Failed to record bulk coverage: {e}",
            "updated_count": 0,
        }
    else:
        response: dict[str, Any] = {
            "success": len(errors) == 0,
            "updated_count": len(created_or_updated),
            "records": created_or_updated,
            "assessment_summary": summary,
        }
        if errors:
            response["errors"] = errors
        return response


@register_tool(sandbox_execution=False)
def record_hypothesis(
    agent_state: Any,
    hypothesis: str,
    target: str,
    component: str | None = None,
    vulnerability_type: str | None = None,
    status: str = "open",
    priority: str = "normal",
    rationale: str | None = None,
) -> dict[str, Any]:
    try:
        normalized_hypothesis = _normalize_non_empty(hypothesis, "hypothesis")
        normalized_target = _normalize_non_empty(target, "target")
        normalized_component = (
            _normalize_non_empty(component, "component") if component is not None else "general"
        )
        normalized_vulnerability_type = (
            _normalize_non_empty(vulnerability_type, "vulnerability_type")
            if vulnerability_type is not None
            else "general"
        )
        normalized_status = _normalize_hypothesis_status(status)
        normalized_priority = _normalize_priority(priority)
        normalized_rationale = (
            rationale.strip() if isinstance(rationale, str) and rationale.strip() else None
        )

        root_agent_id, ledger = _get_ledger(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        hypothesis_id = _stable_id(
            "hyp",
            normalized_target,
            normalized_component,
            normalized_vulnerability_type,
            normalized_hypothesis,
        )
        timestamp = _utc_now()
        existing = ledger["hypotheses"].get(hypothesis_id)

        record: AssessmentRecord = {
            "hypothesis": normalized_hypothesis,
            "target": normalized_target,
            "component": normalized_component,
            "vulnerability_type": normalized_vulnerability_type,
            "status": normalized_status,
            "priority": normalized_priority,
            "rationale": normalized_rationale,
            "owner_agent_id": getattr(agent_state, "agent_id", None),
            "updated_at": timestamp,
        }
        if existing and "created_at" in existing:
            record["created_at"] = existing["created_at"]
        else:
            record["created_at"] = timestamp

        ledger["hypotheses"][hypothesis_id] = record
        summary = _summarize_ledger(ledger)

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to record hypothesis: {e}"}
    else:
        return {
            "success": True,
            "hypothesis_id": hypothesis_id,
            "updated_existing": existing is not None,
            "record": _hypothesis_record_for_response(hypothesis_id, record),
            "assessment_summary": summary,
        }


@register_tool(sandbox_execution=False)
def record_evidence(
    agent_state: Any,
    title: str,
    details: str,
    source: str = "other",
    target: str | None = None,
    component: str | None = None,
    related_coverage_id: str | None = None,
    related_hypothesis_id: str | None = None,
) -> dict[str, Any]:
    try:
        normalized_title = _normalize_non_empty(title, "title")
        normalized_details = _normalize_non_empty(details, "details")
        normalized_source = _normalize_evidence_source(source)

        root_agent_id, ledger = _get_ledger(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        evidence_id = _stable_id(
            "evi",
            normalized_title,
            normalized_details,
            target or "",
            component or "",
            normalized_source,
        )
        timestamp = _utc_now()
        record: AssessmentRecord = {
            "title": normalized_title,
            "details": normalized_details,
            "source": normalized_source,
            "target": target.strip() if isinstance(target, str) and target.strip() else None,
            "component": component.strip() if isinstance(component, str) and component.strip() else None,
            "related_coverage_id": (
                related_coverage_id.strip()
                if isinstance(related_coverage_id, str) and related_coverage_id.strip()
                else None
            ),
            "related_hypothesis_id": (
                related_hypothesis_id.strip()
                if isinstance(related_hypothesis_id, str) and related_hypothesis_id.strip()
                else None
            ),
            "owner_agent_id": getattr(agent_state, "agent_id", None),
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        ledger["evidence"][evidence_id] = record
        summary = _summarize_ledger(ledger)

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to record evidence: {e}"}
    else:
        return {
            "success": True,
            "evidence_id": evidence_id,
            "record": _evidence_record_for_response(evidence_id, record),
            "assessment_summary": summary,
        }


@register_tool(sandbox_execution=False)
def list_assessment_state(
    agent_state: Any,
    include_resolved_coverage: bool = True,
    include_evidence: bool = True,
    max_items: int = 50,
) -> dict[str, Any]:
    try:
        if max_items < 1:
            raise ValueError("max_items must be >= 1")

        root_agent_id, ledger = _get_ledger(agent_state)
        _update_agent_context(agent_state, root_agent_id)
        summary = _summarize_ledger(ledger)

        coverage_records = [
            _coverage_record_for_response(record_id, record)
            for record_id, record in ledger["coverage"].items()
        ]
        if not include_resolved_coverage:
            coverage_records = [
                record
                for record in coverage_records
                if record.get("status") in UNRESOLVED_COVERAGE_STATUSES
            ]
        coverage_records.sort(
            key=lambda item: (
                VALID_PRIORITIES.index(str(item.get("priority", "normal"))),
                str(item.get("updated_at", "")),
            )
        )

        hypothesis_records = [
            _hypothesis_record_for_response(record_id, record)
            for record_id, record in ledger["hypotheses"].items()
        ]
        hypothesis_records.sort(
            key=lambda item: (
                VALID_PRIORITIES.index(str(item.get("priority", "normal"))),
                str(item.get("updated_at", "")),
            )
        )

        evidence_records = [
            _evidence_record_for_response(record_id, record)
            for record_id, record in ledger["evidence"].items()
        ]
        evidence_records.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to list assessment state: {e}"}
    else:
        response: dict[str, Any] = {
            "success": True,
            "root_agent_id": root_agent_id,
            "assessment_summary": summary,
            "coverage": coverage_records[:max_items],
            "hypotheses": hypothesis_records[:max_items],
        }
        if include_evidence:
            response["evidence"] = evidence_records[:max_items]
        return response
