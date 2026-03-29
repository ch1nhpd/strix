import sys
import types
from typing import Any

fake_posthog = types.ModuleType("strix.telemetry.posthog")
fake_posthog.error = lambda *args, **kwargs: None  # type: ignore[attr-defined]

fake_telemetry = types.ModuleType("strix.telemetry")
fake_telemetry.__path__ = []  # type: ignore[attr-defined]
fake_telemetry.posthog = fake_posthog  # type: ignore[attr-defined]

sys.modules.setdefault("strix.telemetry", fake_telemetry)
sys.modules.setdefault("strix.telemetry.posthog", fake_posthog)

from strix.tools.agents_graph import agents_graph_actions
from strix.tools.assessment.assessment_actions import (
    clear_assessment_storage,
    list_assessment_state,
    record_coverage,
    record_evidence,
    record_hypothesis,
)


class DummyState:
    def __init__(self, agent_id: str, parent_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.parent_id = parent_id
        self.context: dict[str, Any] = {}

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()


def test_record_coverage_updates_existing_surface() -> None:
    state = DummyState("agent_root")

    first = record_coverage(
        agent_state=state,
        target="api",
        component="auth",
        surface="JWT verification",
        status="uncovered",
        rationale="Initial seed",
        priority="high",
    )
    second = record_coverage(
        agent_state=state,
        target="api",
        component="auth",
        surface="JWT verification",
        status="covered",
        rationale="Validated signing and key handling",
        priority="high",
    )

    assert first["success"] is True
    assert second["success"] is True
    assert second["updated_existing"] is True
    assert first["coverage_id"] == second["coverage_id"]

    summary = list_assessment_state(agent_state=state, include_evidence=False)
    assert summary["assessment_summary"]["coverage_total"] == 1
    assert summary["assessment_summary"]["unresolved_coverage_count"] == 0
    assert summary["assessment_summary"]["ready_to_finish"] is True


def test_child_agent_updates_root_assessment_ledger() -> None:
    root_state = DummyState("agent_root")
    child_state = DummyState("agent_child", parent_id="agent_root")

    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {"parent_id": None}
    agents_graph_actions._agent_graph["nodes"]["agent_child"] = {"parent_id": "agent_root"}

    coverage = record_coverage(
        agent_state=child_state,
        target="web",
        component="orders",
        surface="Order ID authorization",
        status="in_progress",
        rationale="Cross-tenant access still being validated",
        priority="critical",
    )
    hypothesis = record_hypothesis(
        agent_state=child_state,
        hypothesis="Order ID may be tenant-agnostic",
        target="web",
        component="orders",
        vulnerability_type="idor",
        priority="critical",
    )
    evidence = record_evidence(
        agent_state=child_state,
        title="Cross-tenant response diff",
        details="Two users received different authorization behavior for adjacent order IDs",
        source="runtime",
        target="web",
        component="orders",
        related_coverage_id=coverage["coverage_id"],
        related_hypothesis_id=hypothesis["hypothesis_id"],
    )

    root_summary = list_assessment_state(agent_state=root_state)

    assert coverage["success"] is True
    assert hypothesis["success"] is True
    assert evidence["success"] is True
    assert child_state.context["assessment_root_agent_id"] == "agent_root"
    assert root_summary["assessment_summary"]["coverage_total"] == 1
    assert root_summary["assessment_summary"]["hypothesis_total"] == 1
    assert root_summary["assessment_summary"]["evidence_total"] == 1
    assert root_summary["assessment_summary"]["unresolved_coverage_count"] == 1
