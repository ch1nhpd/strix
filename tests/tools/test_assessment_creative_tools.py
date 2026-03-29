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
from strix.tools.assessment import clear_assessment_storage
from strix.tools.assessment import assessment_creative_actions as creative_actions
from strix.tools.assessment.assessment_actions import list_assessment_state


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


def test_synthesize_attack_hypotheses_builds_chain_from_multiple_signal_sources(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(
        creative_actions,
        "_safe_list_runtime_inventory",
        lambda agent_state, target: [
            {
                "host": "app.test",
                "normalized_path": "/api/orders/:id",
                "methods": ["GET", "PATCH"],
                "priority": "critical",
            }
        ],
    )
    monkeypatch.setattr(
        creative_actions,
        "_safe_list_surface_artifacts",
        lambda agent_state, target: [
            {
                "kind": "openapi_spec",
                "host": "app.test",
                "path": "/openapi.json",
                "documented_operations": [{"method": "POST", "path": "/admin/users"}],
            },
            {
                "kind": "graphql_endpoint",
                "host": "app.test",
                "path": "/graphql",
            },
        ],
    )
    monkeypatch.setattr(
        creative_actions,
        "_safe_list_workflows",
        lambda agent_state, target: [
            {
                "host": "app.test",
                "type": "payment",
                "priority": "high",
                "repeated_write": True,
                "sequence": [
                    {"method": "POST", "normalized_path": "/checkout"},
                    {"method": "POST", "normalized_path": "/payment/confirm"},
                ],
            }
        ],
    )
    monkeypatch.setattr(
        creative_actions,
        "list_session_profiles",
        lambda agent_state, include_values=False, max_items=100: {
            "success": True,
            "profile_count": 3,
            "profiles": [{"name": "admin"}, {"name": "owner"}, {"name": "guest"}],
        },
    )
    monkeypatch.setattr(
        creative_actions,
        "_safe_list_assessment_state",
        lambda agent_state: {"coverage": [], "hypotheses": []},
    )

    state = DummyState("agent_root")
    result = creative_actions.synthesize_attack_hypotheses(agent_state=state, target="web")
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["hypothesis_count"] >= 3
    assert any("GraphQL" in item["hypothesis"] for item in result["hypotheses"])
    assert any("Workflow payment" in item["hypothesis"] for item in result["hypotheses"])
    assert ledger["assessment_summary"]["hypothesis_total"] >= 3


def test_generate_contextual_payloads_produces_oob_and_encoded_variants() -> None:
    result = creative_actions.generate_contextual_payloads(
        vulnerability_type="ssrf",
        surface="Avatar fetch URL",
        parameter_names=["avatar_url"],
        callback_urls=["https://oob.test/ssrf"],
        max_variants=12,
    )

    assert result["success"] is True
    assert result["variant_count"] == 12
    payloads = {item["payload"] for item in result["variants"]}
    assert "https://oob.test/ssrf" in payloads
    assert any("169.254.169.254" in payload for payload in payloads)
    assert any(item["encoding"] == "url" for item in result["variants"])


def test_generate_contextual_payloads_include_semantic_markers_for_traversal_and_ssti() -> None:
    traversal = creative_actions.generate_contextual_payloads(
        vulnerability_type="path_traversal",
        surface="Download file parameter",
        parameter_names=["file"],
        max_variants=12,
    )
    ssti = creative_actions.generate_contextual_payloads(
        vulnerability_type="ssti",
        surface="Template render parameter",
        parameter_names=["template"],
        max_variants=8,
    )

    assert traversal["success"] is True
    assert any("root:x:0:0" in item.get("expected_markers", []) for item in traversal["variants"])
    assert any("[fonts]" in item.get("expected_markers", []) for item in traversal["variants"])
    assert ssti["success"] is True
    assert any("49" in item.get("expected_markers", []) for item in ssti["variants"])


def test_triage_attack_anomalies_flags_parity_and_oob_signals() -> None:
    state = DummyState("agent_root")
    result = creative_actions.triage_attack_anomalies(
        agent_state=state,
        target="web",
        component="orders",
        surface="Order detail anomalies",
        baseline_name="admin",
        observations=[
            {
                "name": "admin",
                "status_code": 200,
                "body_hash": "samehash",
                "body_length": 140,
                "body_preview": '{"id":1,"owner":"alice"}',
                "elapsed_ms": 150,
            },
            {
                "name": "guest",
                "status_code": 200,
                "body_hash": "samehash",
                "body_length": 140,
                "body_preview": '{"id":1,"owner":"alice"}',
                "elapsed_ms": 180,
            },
            {
                "name": "probe-oob",
                "status_code": 202,
                "body_hash": "different",
                "body_length": 20,
                "body_preview": "accepted",
                "elapsed_ms": 300,
                "oob_interaction": True,
                "callback_protocol": "dns",
            },
        ],
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert len(result["suspicious_observations"]) == 2
    top_issues = {item["top_issue_type"] for item in result["suspicious_observations"]}
    assert "authorization_parity" in top_issues
    assert "blind_interaction" in top_issues
    assert result["coverage_result"]["record"]["status"] == "in_progress"
    assert ledger["assessment_summary"]["hypothesis_total"] == 1


def test_triage_attack_anomalies_flags_semantic_marker_hits() -> None:
    state = DummyState("agent_root")
    result = creative_actions.triage_attack_anomalies(
        agent_state=state,
        target="web",
        component="download",
        surface="Traversal marker anomalies",
        baseline_name="baseline",
        observations=[
            {
                "name": "baseline",
                "status_code": 200,
                "body_hash": "base",
                "body_length": 16,
                "body_preview": "download ready",
                "elapsed_ms": 90,
                "matcher_hits": [],
            },
            {
                "name": "probe",
                "status_code": 200,
                "body_hash": "passwd",
                "body_length": 64,
                "body_preview": "root:x:0:0:root:/root:/bin/bash",
                "elapsed_ms": 95,
                "matcher_hits": ["root:x:0:0", "/bin/bash"],
            },
        ],
    )

    assert result["success"] is True
    assert result["suspicious_observations"][0]["top_issue_type"] == "semantic_indicator"
    assert "root:x:0:0" in result["suspicious_observations"][0]["matcher_hits"]


def test_triage_attack_anomalies_flags_dangerous_variant_acceptance() -> None:
    state = DummyState("agent_root")
    result = creative_actions.triage_attack_anomalies(
        agent_state=state,
        target="web",
        component="upload",
        surface="Upload dangerous variant acceptance",
        baseline_name="baseline",
        observations=[
            {
                "name": "baseline",
                "status_code": 200,
                "body_hash": "samehash",
                "body_length": 24,
                "body_preview": '{"status":"uploaded"}',
                "elapsed_ms": 80,
            },
            {
                "name": "variant_php",
                "status_code": 200,
                "body_hash": "samehash",
                "body_length": 24,
                "body_preview": '{"status":"uploaded"}',
                "elapsed_ms": 85,
                "expected_rejection": True,
            },
        ],
    )

    assert result["success"] is True
    assert result["suspicious_observations"][0]["top_issue_type"] == "dangerous_variant_acceptance"
