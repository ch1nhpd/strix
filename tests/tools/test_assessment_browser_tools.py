import asyncio
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
from strix.tools.assessment import assessment_browser_actions as browser_assessment_actions
from strix.tools.assessment import assessment_session_actions as session_actions


class DummyState:
    def __init__(self, agent_id: str, parent_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.parent_id = parent_id
        self.context: dict[str, Any] = {}

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value


class FakePage:
    def __init__(self) -> None:
        self.url = "https://app.test/dashboard"

    async def evaluate(self, _script: str) -> dict[str, Any]:
        return {
            "origin": "https://app.test",
            "cookie": "theme=light; browser_seen=1",
            "localStorage": {
                "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature",
                "csrfToken": "csrf-123",
            },
            "sessionStorage": {"profile": '{"api_key":"secret-api-key"}'},
            "meta": {"csrf-token": "csrf-123"},
            "hiddenInputs": {},
            "nextData": {"props": {"pageProps": {"authToken": "fallback-token"}}},
        }


class FakeContext:
    async def cookies(self, _urls: list[str]) -> list[dict[str, Any]]:
        return [{"name": "sid", "value": "browser-cookie"}]


class FakeBrowser:
    def __init__(self) -> None:
        self.current_page_id = "tab_1"
        self.pages = {"tab_1": FakePage()}
        self.context = FakeContext()

    def _run_async(self, coro: Any) -> Any:
        return asyncio.run(coro)


class FakeBrowserManager:
    def _get_agent_browser(self) -> FakeBrowser:
        return FakeBrowser()


class PassivePage:
    def __init__(self, url: str) -> None:
        self.url = url


class ArtifactProbePage:
    def __init__(self) -> None:
        self.url = "https://app.test/uploads/avatar.svg"
        self.console_logs = [
            {
                "type": "log",
                "text": "__strix_browser_signal__:alert:1",
                "location": {},
                "timestamp": 1,
            }
        ]

    async def add_init_script(self, _script: str) -> None:
        return None

    async def goto(self, url: str, wait_until: str = "domcontentloaded") -> None:
        self.url = url

    async def wait_for_timeout(self, _milliseconds: int) -> None:
        return None

    async def evaluate(self, _script: str) -> dict[str, Any]:
        return {
            "href": self.url,
            "title": "avatar",
            "readyState": "complete",
            "htmlSnippet": "<svg onload=\"alert(1)\"></svg>",
            "textSnippet": "",
            "svgCount": 1,
            "scriptCount": 0,
            "activeNodes": [{"tag": "svg", "attrs": {"onload": "alert(1)"}}],
            "matchedArtifactNodes": [],
            "matchedArtifactCount": 0,
            "browserSignals": [{"kind": "alert", "value": "1"}],
        }

    async def close(self) -> None:
        return None


class ArtifactContext:
    def __init__(self) -> None:
        self.page = ArtifactProbePage()

    async def new_page(self) -> ArtifactProbePage:
        return self.page


class FakeArtifactBrowser:
    def __init__(self) -> None:
        self.current_page_id = "tab_1"
        self.pages = {"tab_1": PassivePage("https://app.test/dashboard")}
        self.context = ArtifactContext()
        self._next_tab_id = 2
        self.console_logs: dict[str, list[dict[str, Any]]] = {}

    def _run_async(self, coro: Any) -> Any:
        return asyncio.run(coro)

    async def _setup_console_logging(self, page: ArtifactProbePage, tab_id: str) -> None:
        self.console_logs[tab_id] = list(page.console_logs)


class FakeArtifactBrowserManager:
    def _get_agent_browser(self) -> FakeArtifactBrowser:
        return FakeArtifactBrowser()


class WorkflowViewerPage(ArtifactProbePage):
    def __init__(self) -> None:
        super().__init__()
        self.console_logs = [
            {
                "type": "log",
                "text": "__strix_browser_signal__:alert:viewer-hit",
                "location": {},
                "timestamp": 1,
            }
        ]

    async def evaluate(self, _script: str) -> dict[str, Any]:
        if self.url == "https://app.test/profile":
            return {
                "href": self.url,
                "title": "profile",
                "readyState": "complete",
                "htmlSnippet": "<img src=\"/uploads/avatar.svg\">",
                "textSnippet": "",
                "svgCount": 0,
                "scriptCount": 0,
                "activeNodes": [],
                "matchedArtifactNodes": [{"tag": "img", "attrs": {"src": "/uploads/avatar.svg"}}],
                "matchedArtifactCount": 1,
                "browserSignals": [{"kind": "alert", "value": "viewer-hit"}],
            }
        return await super().evaluate(_script)


class WorkflowViewerContext:
    async def new_page(self) -> WorkflowViewerPage:
        return WorkflowViewerPage()


class FakeWorkflowViewerBrowser(FakeArtifactBrowser):
    def __init__(self) -> None:
        super().__init__()
        self.context = WorkflowViewerContext()


class FakeWorkflowViewerBrowserManager:
    def _get_agent_browser(self) -> FakeWorkflowViewerBrowser:
        return FakeWorkflowViewerBrowser()


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()


def test_bootstrap_session_profile_from_browser_extracts_auth_material(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        browser_assessment_actions,
        "_browser_manager",
        lambda: FakeBrowserManager(),
    )

    state = DummyState("agent_root")
    result = browser_assessment_actions.bootstrap_session_profile_from_browser(
        agent_state=state,
        name="browser-owner",
        role="owner",
        tenant="tenant-a",
    )
    listed = session_actions.list_session_profiles(agent_state=state, include_values=True)

    assert result["success"] is True
    assert result["page_url"] == "https://app.test/dashboard"
    assert listed["profile_count"] == 1
    assert listed["profiles"][0]["headers"]["Authorization"].startswith("Bearer eyJ")
    assert listed["profiles"][0]["headers"]["X-CSRF-Token"] == "csrf-123"
    assert listed["profiles"][0]["headers"]["X-API-Key"] == "secret-api-key"
    assert listed["profiles"][0]["cookies"]["sid"] == "browser-cookie"
    assert listed["profiles"][0]["base_url"] == "https://app.test"


def test_confirm_active_artifact_in_browser_records_execution_proof(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        browser_assessment_actions,
        "_browser_manager",
        lambda: FakeArtifactBrowserManager(),
    )

    state = DummyState("agent_root")
    result = browser_assessment_actions.confirm_active_artifact_in_browser(
        agent_state=state,
        target="web",
        component="focus:file_upload:app.test/uploads/avatar.svg:browser",
        surface="Browser execution proof for uploaded SVG",
        url="https://app.test/uploads/avatar.svg",
        expected_dom_markers=["<svg", "onload="],
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["available"] is True
    assert result["confirmed_execution"] is True
    assert result["signal_logs"]
    assert any(item["vulnerability_type"] == "xss" for item in ledger["hypotheses"])


def test_confirm_active_artifact_in_browser_replays_viewer_url(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        browser_assessment_actions,
        "_browser_manager",
        lambda: FakeWorkflowViewerBrowserManager(),
    )

    state = DummyState("agent_root")
    result = browser_assessment_actions.confirm_active_artifact_in_browser(
        agent_state=state,
        target="web",
        component="focus:file_upload:app.test/profile:browser",
        surface="Viewer page replay for uploaded SVG",
        url="https://app.test/uploads/avatar.svg",
        viewer_urls=["https://app.test/profile"],
        artifact_filename="avatar.svg",
        expected_dom_markers=["/uploads/avatar.svg"],
    )

    assert result["success"] is True
    assert result["viewer_context_detected"] is True
    assert result["confirmed_execution"] is True
    assert result["execution_context_url"] == "https://app.test/profile"
    assert result["workflow_replay_results"][0]["viewer_url"] == "https://app.test/profile"
