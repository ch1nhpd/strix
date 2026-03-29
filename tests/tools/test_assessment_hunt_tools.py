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
from strix.tools.assessment import assessment_hunt_actions as hunt_actions
from strix.tools.assessment import assessment_runtime_actions as runtime_actions
from strix.tools.assessment import assessment_session_actions as session_actions


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
        sort_order: str = "desc",
        scope_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "requests": [
                {
                    "id": "req_orders",
                    "method": "GET",
                    "host": "app.test",
                    "path": "/api/orders/123",
                    "query": "",
                    "isTls": True,
                    "source": "proxy",
                    "response": {"statusCode": 200},
                },
                {
                    "id": "req_admin",
                    "method": "POST",
                    "host": "app.test",
                    "path": "/admin/users",
                    "query": "",
                    "isTls": True,
                    "source": "proxy",
                    "response": {"statusCode": 201},
                },
            ],
            "total_count": 2,
            "returned_count": 2,
        }

    def list_sitemap(
        self,
        scope_id: str | None = None,
        parent_id: str | None = None,
        depth: str = "DIRECT",
        page: int = 1,
    ) -> dict[str, Any]:
        return {"entries": [], "has_more": False}

    def view_request(
        self,
        request_id: str,
        part: str = "request",
        search_pattern: str | None = None,
        page: int = 1,
        page_size: int = 80,
    ) -> dict[str, Any]:
        return {
            "content": (
                "GET /api/orders/123 HTTP/1.1\n"
                "Host: app.test\n"
                "Authorization: Bearer owner-token\n"
                "\n"
            )
        }


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()


def test_run_inventory_differential_hunt_builds_cases_from_inventory_and_sessions(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(runtime_actions, "get_proxy_manager", lambda: FakeProxyManager())

    captured_calls: list[dict[str, Any]] = []

    def fake_analyze_differential_access(**kwargs: Any) -> dict[str, Any]:
        captured_calls.append(kwargs)
        return {
            "success": True,
            "suspicious_observations": [{"issue_type": "role_based_access"}],
        }

    monkeypatch.setattr(hunt_actions, "analyze_differential_access", fake_analyze_differential_access)

    state = DummyState("agent_root")
    runtime_actions.map_runtime_surface(agent_state=state, target="web")
    session_actions.save_session_profile(
        agent_state=state,
        name="admin",
        base_url="https://app.test",
        headers={"Authorization": "Bearer admin"},
        role="admin",
        tenant="tenant-a",
    )
    session_actions.save_session_profile(
        agent_state=state,
        name="guest",
        base_url="https://app.test",
        role="guest",
    )

    result = hunt_actions.run_inventory_differential_hunt(
        agent_state=state,
        target="web",
        path_regex="orders",
        max_endpoints=1,
    )

    assert result["success"] is True
    assert result["executed_count"] == 1
    assert result["suspicious_observation_count"] == 1
    assert len(captured_calls) == 1
    assert captured_calls[0]["surface"] == "Runtime endpoint GET /api/orders/:id"
    assert captured_calls[0]["baseline_case"] == "admin"

    cases = {item["name"]: item for item in captured_calls[0]["cases"]}
    assert cases["admin"]["expected_access"] == "allow"
    assert cases["guest"]["expected_access"] == "deny"
    assert cases["admin"]["path"] == "/api/orders/123"
