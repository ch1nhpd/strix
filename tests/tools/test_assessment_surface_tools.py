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
from strix.tools.assessment import assessment_surface_actions as surface_actions


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
                {"id": "req_openapi", "method": "GET", "host": "app.test", "path": "/openapi.json"},
                {"id": "req_js", "method": "GET", "host": "app.test", "path": "/static/app.js"},
                {"id": "req_graphql", "method": "POST", "host": "app.test", "path": "/graphql"},
                {"id": "req_ws", "method": "GET", "host": "app.test", "path": "/ws/chat"},
            ],
            "returned_count": 4,
            "total_count": 4,
        }

    def view_request(
        self,
        request_id: str,
        part: str = "request",
        search_pattern: str | None = None,
        page: int = 1,
        page_size: int = 120,
    ) -> dict[str, Any]:
        if request_id == "req_openapi" and part == "response":
            return {
                "content": (
                    "HTTP/1.1 200 OK\n"
                    "Content-Type: application/json\n"
                    "\n"
                    '{"openapi":"3.0.0","paths":{"/api/admin/users":{"get":{},"post":{}}}}'
                )
            }
        if request_id == "req_js" and part == "response":
            return {
                "content": (
                    "HTTP/1.1 200 OK\n"
                    "Content-Type: application/javascript\n"
                    "\n"
                    'const api="/api/invoices"; const gql="/graphql"; '
                    'const ws="wss://app.test/realtime/socket";'
                )
            }
        if request_id == "req_graphql" and part == "request":
            return {
                "content": (
                    "POST /graphql HTTP/1.1\n"
                    "Host: app.test\n"
                    "Content-Type: application/json\n"
                    "\n"
                    '{"query":"{viewer{id}}","extensions":{"persistedQuery":{"sha256Hash":"abc"}}}'
                )
            }
        if request_id == "req_graphql" and part == "response":
            return {"content": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"data\":{}}"}
        if request_id == "req_ws" and part == "request":
            return {
                "content": (
                    "GET /ws/chat HTTP/1.1\n"
                    "Host: app.test\n"
                    "Upgrade: websocket\n"
                    "\n"
                )
            }
        return {"content": "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nok"}


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()


def test_mine_additional_attack_surface_seeds_protocol_artifacts(monkeypatch: Any) -> None:
    monkeypatch.setattr(surface_actions, "get_proxy_manager", lambda: FakeProxyManager())

    state = DummyState("agent_root")
    result = surface_actions.mine_additional_attack_surface(agent_state=state, target="web")
    ledger = list_assessment_state(agent_state=state)
    listed = surface_actions.list_mined_attack_surface(agent_state=state, target="web")

    assert result["success"] is True
    assert result["artifacts_total"] >= 5
    kinds = {artifact["kind"] for artifact in result["artifacts"]}
    assert "openapi_spec" in kinds
    assert "graphql_endpoint" in kinds
    assert "graphql_persisted_query" in kinds
    assert "websocket_endpoint" in kinds
    surfaces = {item["surface"] for item in ledger["coverage"]}
    assert "OpenAPI/Swagger exposure GET /openapi.json" in surfaces
    assert "Documented endpoint GET /api/admin/users" in surfaces
    assert "GraphQL endpoint POST /graphql" in surfaces
    assert "JavaScript-discovered route ANY /api/invoices" in surfaces
    assert "WebSocket endpoint GET /ws/chat" in surfaces
    assert listed["success"] is True
    assert listed["records"][0]["artifacts_total"] == result["artifacts_total"]
