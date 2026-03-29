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
from strix.tools.assessment import assessment_workflow_actions as workflow_actions


class DummyState:
    def __init__(self, agent_id: str, parent_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.parent_id = parent_id
        self.context: dict[str, Any] = {}

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value


class FakeProxyManager:
    def list_requests(
        self,
        httpql_filter: str | None = None,
        start_page: int = 1,
        end_page: int = 1,
        page_size: int = 50,
        sort_by: str = "timestamp",
        sort_order: str = "asc",
        scope_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "requests": [
                {"id": "req_login", "method": "POST", "host": "app.test", "path": "/login"},
                {"id": "req_cart", "method": "POST", "host": "app.test", "path": "/cart/items"},
                {"id": "req_checkout", "method": "POST", "host": "app.test", "path": "/checkout"},
                {"id": "req_confirm_1", "method": "POST", "host": "app.test", "path": "/payment/confirm"},
                {"id": "req_confirm_2", "method": "POST", "host": "app.test", "path": "/payment/confirm"},
            ],
            "returned_count": 5,
            "total_count": 5,
        }

    def view_request(
        self,
        request_id: str,
        part: str = "request",
        search_pattern: str | None = None,
        page: int = 1,
        page_size: int = 120,
    ) -> dict[str, Any]:
        return {
            "content": (
                f"POST /{request_id} HTTP/1.1\n"
                "Host: app.test\n"
                "Cookie: sid=flow-123\n"
                "\n"
            )
        }


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()


def test_discover_workflows_from_requests_identifies_state_machine_candidates(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(workflow_actions, "get_proxy_manager", lambda: FakeProxyManager())

    state = DummyState("agent_root")
    result = workflow_actions.discover_workflows_from_requests(
        agent_state=state,
        target="web",
        max_workflows=5,
    )
    ledger = list_assessment_state(agent_state=state)
    listed = workflow_actions.list_discovered_workflows(agent_state=state, target="web")

    assert result["success"] is True
    assert result["workflow_total"] >= 1
    assert any(workflow["repeated_write"] for workflow in result["workflows"])
    surfaces = {item["surface"] for item in ledger["coverage"]}
    assert any("payment/confirm" in surface for surface in surfaces)
    assert listed["success"] is True
    assert listed["records"][0]["workflow_total"] == result["workflow_total"]
