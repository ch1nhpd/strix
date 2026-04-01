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
from strix.tools.assessment import clear_assessment_storage, list_assessment_state
from strix.tools.assessment import assessment_differential_actions as differential_actions
from strix.tools.assessment import assessment_orchestration_actions as orchestration_actions


class DummyState:
    def __init__(self, agent_id: str, parent_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.parent_id = parent_id
        self.context: dict[str, Any] = {}

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value


class SpawnCapableState(DummyState):
    def get_conversation_history(self) -> list[dict[str, Any]]:
        return []


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()


def test_analyze_differential_access_records_cross_tenant_parity(monkeypatch: Any) -> None:
    responses = {
        "owner_allow": {
            "name": "owner_allow",
            "method": "GET",
            "url": "https://app.test/orders/123",
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 32,
            "body_hash": "samehash",
            "body_preview": '{"id":123,"tenant":"a"}',
            "elapsed_ms": 10,
        },
        "other_tenant_deny": {
            "name": "other_tenant_deny",
            "method": "GET",
            "url": "https://app.test/orders/123",
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 32,
            "body_hash": "samehash",
            "body_preview": '{"id":123,"tenant":"a"}',
            "elapsed_ms": 12,
        },
    }

    monkeypatch.setattr(
        differential_actions,
        "_execute_request",
        lambda spec, timeout, follow_redirects: responses[spec["name"]],
    )

    state = DummyState("agent_root")
    result = differential_actions.analyze_differential_access(
        agent_state=state,
        target="web",
        component="orders",
        surface="Order differential access",
        method="GET",
        url="https://app.test/orders/123",
        baseline_case="owner_allow",
        cases=[
            {
                "name": "owner_allow",
                "method": "GET",
                "url": "https://app.test/orders/123",
                "expected_access": "allow",
                "role": "owner",
                "tenant": "tenant-a",
                "ownership": "owner",
                "object_ref": "order-123",
            },
            {
                "name": "other_tenant_deny",
                "method": "GET",
                "url": "https://app.test/orders/123",
                "expected_access": "deny",
                "role": "user",
                "tenant": "tenant-b",
                "ownership": "other",
                "object_ref": "order-123",
            },
        ],
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["suspicious_observations"]
    assert result["suspicious_observations"][0]["issue_type"] == "cross_tenant_access"
    assert result["suspicious_observations"][0]["impact_category"] == "cross_tenant_data"
    assert result["suspicious_observations"][0]["impact_level"] == "critical"
    assert result["suspicious_observations"][0]["confidence"] == "high"
    assert result["coverage_result"]["record"]["status"] == "in_progress"
    assert ledger["assessment_summary"]["hypothesis_total"] == 1
    assert ledger["assessment_summary"]["evidence_total"] == 1


def test_analyze_differential_access_auto_spawns_impact_agent(monkeypatch: Any) -> None:
    responses = {
        "owner_allow": {
            "name": "owner_allow",
            "method": "POST",
            "url": "https://app.test/orders/123/refund",
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 32,
            "body_hash": "samehash",
            "body_preview": '{"id":123,"tenant":"a"}',
            "elapsed_ms": 10,
            "location": "https://app.test/orders/123/refund",
        },
        "other_tenant_deny": {
            "name": "other_tenant_deny",
            "method": "POST",
            "url": "https://app.test/orders/123/refund",
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 32,
            "body_hash": "samehash",
            "body_preview": '{"id":123,"tenant":"a"}',
            "elapsed_ms": 12,
            "location": "https://app.test/orders/123/refund",
        },
    }
    spawn_calls: list[dict[str, Any]] = []

    monkeypatch.setattr(
        differential_actions,
        "_execute_request",
        lambda spec, timeout, follow_redirects: responses[spec["name"]],
    )
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_impact_chain_agents",
        lambda agent_state, target, hypothesis_ids, max_agents, inherit_context: spawn_calls.append(
            {
                "target": target,
                "hypothesis_ids": hypothesis_ids,
                "max_agents": max_agents,
                "inherit_context": inherit_context,
            }
        )
        or {
            "success": True,
            "target": target,
            "created_count": 1,
            "hypothesis_ids": hypothesis_ids,
        },
    )

    state = SpawnCapableState("agent_root")
    result = differential_actions.analyze_differential_access(
        agent_state=state,
        target="web",
        component="refunds",
        surface="Refund differential access",
        method="POST",
        url="https://app.test/orders/123/refund",
        baseline_case="owner_allow",
        cases=[
            {
                "name": "owner_allow",
                "method": "POST",
                "url": "https://app.test/orders/123/refund",
                "expected_access": "allow",
                "tenant": "tenant-a",
                "role": "owner",
            },
            {
                "name": "other_tenant_deny",
                "method": "POST",
                "url": "https://app.test/orders/123/refund",
                "expected_access": "deny",
                "tenant": "tenant-b",
                "role": "user",
                "compare_to": "owner_allow",
            },
        ],
    )

    assert result["success"] is True
    assert result["hypothesis_result"]["record"]["status"] == "validated"
    assert result["followup_agent_result"]["success"] is True
    assert spawn_calls[0]["target"] == "web"
    assert spawn_calls[0]["hypothesis_ids"] == [result["hypothesis_result"]["hypothesis_id"]]


def test_analyze_differential_access_ignores_low_signal_success_without_parity(
    monkeypatch: Any,
) -> None:
    responses = {
        "owner_allow": {
            "name": "owner_allow",
            "method": "GET",
            "url": "https://app.test/orders/123",
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 32,
            "body_hash": "ownerhash",
            "body_preview": '{"id":123,"tenant":"a"}',
            "elapsed_ms": 10,
        },
        "other_tenant_deny": {
            "name": "other_tenant_deny",
            "method": "GET",
            "url": "https://app.test/orders/123",
            "status_code": 200,
            "content_type": "text/html",
            "body_length": 18,
            "body_hash": "denyhash",
            "body_preview": "<html>blocked</html>",
            "elapsed_ms": 12,
        },
    }

    monkeypatch.setattr(
        differential_actions,
        "_execute_request",
        lambda spec, timeout, follow_redirects: responses[spec["name"]],
    )

    state = DummyState("agent_root")
    result = differential_actions.analyze_differential_access(
        agent_state=state,
        target="web",
        component="orders",
        surface="Order differential access",
        method="GET",
        url="https://app.test/orders/123",
        baseline_case="owner_allow",
        cases=[
            {
                "name": "owner_allow",
                "method": "GET",
                "url": "https://app.test/orders/123",
                "expected_access": "allow",
                "role": "owner",
                "tenant": "tenant-a",
                "ownership": "owner",
                "object_ref": "order-123",
            },
            {
                "name": "other_tenant_deny",
                "method": "GET",
                "url": "https://app.test/orders/123",
                "expected_access": "deny",
                "role": "user",
                "tenant": "tenant-b",
                "ownership": "other",
                "object_ref": "order-123",
            },
        ],
    )

    assert result["success"] is True
    assert result["suspicious_observations"] == []
    assert result["coverage_result"]["record"]["status"] == "covered"
