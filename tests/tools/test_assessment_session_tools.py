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
from strix.tools.assessment import assessment_session_actions as session_actions
from strix.tools.assessment import assessment_validation_actions as validation_actions


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
        page_size: int = 20,
    ) -> dict[str, Any]:
        return {
            "requests": [
                {"id": "req_auth"},
                {"id": "req_auth_duplicate"},
                {"id": "req_guest"},
            ]
        }

    def view_request(
        self,
        request_id: str,
        part: str = "request",
        page: int = 1,
        page_size: int = 120,
    ) -> dict[str, Any]:
        if request_id == "req_guest":
            return {
                "content": (
                    "GET /dashboard HTTP/1.1\n"
                    "Host: app.test\n"
                    "\n"
                )
            }
        return {
            "content": (
                "GET /orders/123?token=abc HTTP/1.1\n"
                "Host: app.test\n"
                "Authorization: Bearer owner-token\n"
                "Cookie: sid=owner-cookie\n"
                "X-CSRF-Token: csrf-1\n"
                "\n"
            )
        }


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()


def test_session_profiles_can_drive_role_matrix(monkeypatch: Any) -> None:
    captured_specs: dict[str, dict[str, Any]] = {}

    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        captured_specs[spec["name"]] = spec
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 24,
            "body_hash": "samehash",
            "body_preview": '{"id":123,"owner":"alice"}',
            "elapsed_ms": 8,
        }

    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)

    state = DummyState("agent_root")
    saved = session_actions.save_session_profile(
        agent_state=state,
        name="owner",
        base_url="https://app.test",
        headers={"Authorization": "Bearer owner-token"},
        cookies={"sid": "owner-cookie"},
        role="owner",
        tenant="tenant-a",
    )

    assert saved["success"] is True

    listed = session_actions.list_session_profiles(agent_state=state, include_values=True)
    assert listed["profile_count"] == 1
    assert listed["profiles"][0]["name"] == "owner"

    result = validation_actions.role_matrix_test(
        agent_state=state,
        target="web",
        component="orders",
        surface="Order authorization matrix",
        method="GET",
        url="https://app.test/orders/123",
        cases=[
            {"name": "guest", "method": "GET", "url": "https://app.test/orders/123"},
            {"name": "owner", "method": "GET", "path": "/orders/123", "session_profile": "owner"},
        ],
        baseline_case="owner",
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert captured_specs["owner"]["url"] == "https://app.test/orders/123"
    assert captured_specs["owner"]["headers"]["Authorization"] == "Bearer owner-token"
    assert captured_specs["owner"]["cookies"]["sid"] == "owner-cookie"
    assert ledger["assessment_summary"]["hypothesis_total"] == 1

    deleted = session_actions.delete_session_profile(agent_state=state, name="owner")
    assert deleted["success"] is True
    assert session_actions.list_session_profiles(agent_state=state)["profile_count"] == 0


def test_extract_session_profiles_from_requests_deduplicates_proxy_material(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(session_actions, "get_proxy_manager", lambda: FakeProxyManager())

    state = DummyState("agent_root")
    result = session_actions.extract_session_profiles_from_requests(
        agent_state=state,
        name_prefix="captured",
        default_role="owner",
        default_tenant="tenant-a",
    )
    listed = session_actions.list_session_profiles(agent_state=state, include_values=True)

    assert result["success"] is True
    assert result["extracted_count"] == 1
    assert any(item["reason"] == "duplicate_session_material" for item in result["skipped"])
    assert any(item["reason"] == "anonymous_request_skipped" for item in result["skipped"])
    assert listed["profile_count"] == 1
    assert listed["profiles"][0]["role"] == "owner"
    assert listed["profiles"][0]["tenant"] == "tenant-a"
    assert listed["profiles"][0]["headers"]["Authorization"] == "Bearer owner-token"
    assert listed["profiles"][0]["cookies"]["sid"] == "owner-cookie"
