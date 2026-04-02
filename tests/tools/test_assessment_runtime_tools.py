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
from strix.tools.assessment.assessment_actions import _slug, record_coverage
from strix.tools.assessment import assessment_runtime_actions as runtime_actions


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
        assert start_page == end_page == 1
        return {
            "requests": [
                {
                    "id": "req_orders",
                    "method": "GET",
                    "host": "app.test",
                    "path": "/api/orders/123",
                    "query": "view=full",
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
                    "source": "repeater",
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
        if parent_id is None:
            return {
                "entries": [
                    {
                        "id": "dom1",
                        "kind": "DOMAIN",
                        "label": "app.test",
                        "hasDescendants": True,
                    }
                ],
                "has_more": False,
            }
        return {
            "entries": [
                {
                    "id": "req3",
                    "kind": "REQUEST",
                    "label": "/admin/export",
                    "hasDescendants": False,
                    "request": {"method": "GET", "path": "/admin/export", "status": 200},
                }
            ],
            "has_more": False,
        }

    def view_request(
        self,
        request_id: str,
        part: str = "request",
        search_pattern: str | None = None,
        page: int = 1,
        page_size: int = 80,
    ) -> dict[str, Any]:
        if request_id == "req_orders":
            return {
                "content": (
                    "GET /api/orders/123?view=full HTTP/1.1\n"
                    "Host: app.test\n"
                    "Authorization: Bearer owner-token\n"
                    "\n"
                )
            }
        return {
            "content": (
                "POST /admin/users HTTP/1.1\n"
                "Host: app.test\n"
                "Cookie: sid=admin\n"
                "Content-Type: application/json\n"
                "\n"
                '{"email":"new@app.test","role":"staff"}'
            )
        }


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()


def test_map_runtime_surface_seeds_normalized_inventory(monkeypatch: Any) -> None:
    monkeypatch.setattr(runtime_actions, "get_proxy_manager", lambda: FakeProxyManager())

    state = DummyState("agent_root")
    result = runtime_actions.map_runtime_surface(agent_state=state, target="web")
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["seeded_count"] >= 3
    assert result["inventory"][0]["host"] == "app.test"

    surfaces = {item["surface"] for item in ledger["coverage"]}
    assert "Runtime endpoint GET /api/orders/:id" in surfaces
    assert "Runtime endpoint POST /admin/users" in surfaces
    assert "Runtime endpoint GET /admin/export" in surfaces
    assert "Runtime inventory completeness for web" in surfaces
    assert result["inventory_review_result"]["record"]["status"] == "covered"
    assert ledger["assessment_summary"]["evidence_total"] == 1

    inventory_state = runtime_actions.list_runtime_inventory(agent_state=state, target="web")
    assert inventory_state["success"] is True
    assert inventory_state["records"][0]["inventory_total"] == result["inventory_total"]
    assert inventory_state["records"][0]["target"] == "web"


def test_map_runtime_surface_preserves_existing_status_and_marks_truncated_inventory(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(runtime_actions, "get_proxy_manager", lambda: FakeProxyManager())

    state = DummyState("agent_root")
    first = runtime_actions.map_runtime_surface(agent_state=state, target="web", max_seed_items=2)
    assert first["inventory_truncated"] is True
    assert first["inventory_review_result"]["record"]["status"] == "in_progress"

    record_coverage(
        agent_state=state,
        target="web",
        component="runtime:app.test",
        surface="Runtime endpoint GET /api/orders/:id",
        status="covered",
        rationale="Validated owner and tenant isolation on this endpoint",
        priority="critical",
    )

    second = runtime_actions.map_runtime_surface(agent_state=state, target="web", max_seed_items=10)
    ledger = list_assessment_state(agent_state=state)

    surface_index = {item["surface"]: item for item in ledger["coverage"]}
    assert second["inventory_truncated"] is False
    assert surface_index["Runtime endpoint GET /api/orders/:id"]["status"] == "covered"
    assert surface_index["Runtime inventory completeness for web"]["status"] == "covered"


def test_list_runtime_inventory_returns_empty_success_when_target_is_missing() -> None:
    state = DummyState("agent_root")

    result = runtime_actions.list_runtime_inventory(agent_state=state, target="*.winticket.jp")

    assert result["success"] is True
    assert result["inventory_count"] == 0
    assert result["target"] == "*.winticket.jp"
    assert result["needs_more_data"] is True
    assert result["records"] == []


def test_list_runtime_inventory_matches_related_host_records_for_wildcard_target() -> None:
    state = DummyState("agent_root")
    target_key = _slug("admin.winticket.jp")
    runtime_actions._runtime_inventory_storage[state.agent_id] = {
        target_key: {
            "target": "admin.winticket.jp",
            "inventory": [
                {
                    "host": "admin.winticket.jp",
                    "normalized_path": "/login",
                    "methods": ["GET"],
                    "status_codes": [200],
                    "query_params": [],
                    "body_params": [],
                    "content_types": ["text/html"],
                    "auth_hints": ["anonymous"],
                    "sources": ["proxy"],
                    "origins": ["requests"],
                    "sample_urls": ["https://admin.winticket.jp/login"],
                    "sample_request_ids": ["req_admin"],
                    "observed_count": 1,
                    "priority": "high",
                }
            ],
            "selected_inventory": [],
            "inventory_total": 1,
            "mapped_at": "2026-04-02T00:00:00+00:00",
        }
    }

    result = runtime_actions.list_runtime_inventory(agent_state=state, target="*.winticket.jp")

    assert result["success"] is True
    assert result["inventory_count"] == 1
    assert result["needs_more_data"] is False
    assert result["records"][0]["target"] == "admin.winticket.jp"
