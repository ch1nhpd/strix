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
from strix.tools.assessment import assessment_oob_actions as oob_actions


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


def test_oob_harness_manual_mode_records_observations() -> None:
    state = DummyState("agent_root")
    started = oob_actions.oob_interaction_harness(
        agent_state=state,
        action="start",
        target="web",
        component="media",
        surface="Avatar fetch SSRF",
        vulnerability_type="ssrf",
        callback_base_url="https://oob.test/callbacks",
        labels=["probe_a", "probe_b"],
    )

    assert started["success"] is True
    assert started["provider"] == "manual"
    assert len(started["payloads"]) == 2

    recorded = oob_actions.oob_interaction_harness(
        agent_state=state,
        action="record",
        harness_id=started["harness_id"],
        interactions=[
            {
                "label": "probe_a",
                "protocol": "http",
                "remote_address": "10.0.0.12",
                "path": started["payloads"][0]["url"],
            }
        ],
    )
    ledger = list_assessment_state(agent_state=state)

    assert recorded["success"] is True
    assert recorded["new_interaction_count"] == 1
    assert ledger["assessment_summary"]["hypothesis_total"] == 1
    assert ledger["assessment_summary"]["evidence_total"] >= 2
    surfaces = {item["surface"]: item["status"] for item in ledger["coverage"]}
    assert surfaces["Avatar fetch SSRF"] == "in_progress"


def test_oob_harness_doctor_reports_missing_interactsh_cli(monkeypatch: Any) -> None:
    monkeypatch.setattr(oob_actions, "_resolve_interactsh_cli", lambda path=None: None)

    state = DummyState("agent_root")
    result = oob_actions.oob_interaction_harness(agent_state=state, action="doctor")

    assert result["success"] is True
    assert result["cli_available"] is False
    assert "interactsh-client" in result["recommended_next_step"]
