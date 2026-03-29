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
from strix.tools.assessment.assessment_actions import clear_assessment_storage, record_coverage
from strix.tools.assessment import assessment_runtime_actions as runtime_actions
from strix.tools.finish.finish_actions import finish_scan


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


def _install_fake_tracer() -> None:
    fake_module = types.ModuleType("strix.telemetry.tracer")

    class FakeTracer:
        def __init__(self) -> None:
            self.vulnerability_reports = [{"id": "vuln-1"}]
            self.updated_fields: dict[str, str] | None = None

        def update_scan_final_fields(
            self,
            executive_summary: str,
            methodology: str,
            technical_analysis: str,
            recommendations: str,
        ) -> None:
            self.updated_fields = {
                "executive_summary": executive_summary,
                "methodology": methodology,
                "technical_analysis": technical_analysis,
                "recommendations": recommendations,
            }

    tracer = FakeTracer()
    fake_module.get_global_tracer = lambda: tracer  # type: ignore[attr-defined]
    sys.modules["strix.telemetry.tracer"] = fake_module


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()
    sys.modules.pop("strix.telemetry.tracer", None)


def test_finish_scan_requires_coverage_ledger() -> None:
    state = DummyState("agent_root")

    result = finish_scan(
        executive_summary="summary",
        methodology="method",
        technical_analysis="analysis",
        recommendations="recs",
        agent_state=state,
    )

    assert result["success"] is False
    assert result["error"] == "assessment_coverage_missing"


def test_finish_scan_requires_all_coverage_to_be_resolved() -> None:
    state = DummyState("agent_root")

    record_coverage(
        agent_state=state,
        target="api",
        component="billing",
        surface="Invoice ownership checks",
        status="in_progress",
        rationale="Need one more role pair to confirm",
        priority="high",
    )

    result = finish_scan(
        executive_summary="summary",
        methodology="method",
        technical_analysis="analysis",
        recommendations="recs",
        agent_state=state,
    )

    assert result["success"] is False
    assert result["error"] == "assessment_coverage_incomplete"
    assert result["assessment_summary"]["unresolved_coverage_count"] == 1


def test_finish_scan_succeeds_when_coverage_is_complete() -> None:
    state = DummyState("agent_root")
    _install_fake_tracer()

    record_coverage(
        agent_state=state,
        target="api",
        component="billing",
        surface="Invoice ownership checks",
        status="covered",
        rationale="Confirmed authorization enforcement across tenant boundaries",
        priority="high",
    )

    result = finish_scan(
        executive_summary="summary",
        methodology="method",
        technical_analysis="analysis",
        recommendations="recs",
        agent_state=state,
    )

    assert result["success"] is True
    assert result["scan_completed"] is True
    assert result["vulnerabilities_found"] == 1


def test_finish_scan_blocks_when_runtime_inventory_completeness_is_unresolved(
    monkeypatch: Any,
) -> None:
    state = DummyState("agent_root")
    monkeypatch.setattr(runtime_actions, "get_proxy_manager", lambda: FakeProxyManager())

    runtime_actions.map_runtime_surface(agent_state=state, target="web", max_seed_items=1)
    record_coverage(
        agent_state=state,
        target="web",
        component="runtime:app.test",
        surface="Runtime endpoint POST /admin/users",
        status="covered",
        rationale="Validated admin user creation controls",
        priority="critical",
    )

    result = finish_scan(
        executive_summary="summary",
        methodology="method",
        technical_analysis="analysis",
        recommendations="recs",
        agent_state=state,
    )

    assert result["success"] is False
    assert result["error"] == "assessment_coverage_incomplete"
    unresolved_surfaces = {item["surface"] for item in result["unresolved_coverage"]}
    assert "Runtime inventory completeness for web" in unresolved_surfaces
