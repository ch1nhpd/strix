import asyncio
import json
import re
import sys
import types
from typing import Any
from urllib.parse import parse_qs, urlparse

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
from strix.tools.assessment import assessment_orchestration_actions as orchestration_actions
from strix.tools.assessment import assessment_runtime_actions as runtime_actions
from strix.tools.assessment import assessment_session_actions as session_actions
from strix.tools.assessment import assessment_surface_actions as surface_actions
from strix.tools.browser.tab_manager import BrowserTabManager
from strix.tools.context import set_current_agent_id


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


def _asset_url_from_fetch_script(script: str) -> str | None:
    if browser_assessment_actions.BROWSER_ASSET_FETCH_MARKER not in script:
        return None
    match = re.search(r"const url = (?P<value>\".*?\");", script, re.DOTALL)
    if not match:
        return None
    return json.loads(match.group("value"))


def _browser_asset_fetch_payload(url: str) -> dict[str, Any]:
    normalized_url = str(url).strip()
    parsed = urlparse(normalized_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    body = ""
    content_type = "application/javascript"
    if base_url == "https://app.test/static/dashboard.js":
        body = (
            'const admin="/admin/beta/users";'
            ' const audit="/api/admin/audit?scope=full";'
            ' const exportRoute="/billing/exports/history";'
            ' //# sourceMappingURL=/static/dashboard.js.map'
        )
    elif base_url == "https://app.test/static/dashboard.js.map":
        content_type = "application/json"
        body = json.dumps(
            {
                "version": 3,
                "sources": ["src/admin/users.ts", "src/security/featureFlags.ts"],
                "names": [
                    "tenantId",
                    "accountId",
                    "isAdmin",
                    "featureFlags",
                    "clientSecret",
                    "callbackUrl",
                ],
                "mappings": "",
                "sourcesContent": [
                    "const tenantId = activeTenant.id; const featureFlags = { betaAdmin: true };",
                    "const clientSecret = config.clientSecret; const callbackUrl = buildCallback();",
                ],
                "x_routes": ["/api/internal/reports", "/admin/reports/export"],
            }
        )
    elif base_url == "https://app.test/static/chunks/team-settings.js":
        body = (
            'router.push("/teams/blue/members");'
            ' const sock="wss://app.test/realtime/teams";'
        )
    elif base_url == "https://app.test/_next/static/chunks/pages/dashboard.js":
        body = 'fetch("/api/dashboard/summary");'
    elif base_url == "https://app.test/_next/static/chunks/dashboard.js":
        body = 'window.location="/admin/reports/export";'
    else:
        return {
            "marker": browser_assessment_actions.BROWSER_ASSET_FETCH_MARKER,
            "ok": False,
            "status": 404,
            "content_type": "text/plain",
            "final_url": normalized_url,
            "body": "",
            "error": "not-found",
        }
    return {
        "marker": browser_assessment_actions.BROWSER_ASSET_FETCH_MARKER,
        "ok": True,
        "status": 200,
        "content_type": content_type,
        "final_url": normalized_url,
        "body": body,
    }


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


class AutoBootstrapBrowser(FakeBrowser):
    def goto(self, url: str, tab_id: str | None = None) -> dict[str, Any]:
        resolved_tab_id = tab_id or self.current_page_id
        assert resolved_tab_id is not None
        self.pages[resolved_tab_id].url = url
        return {
            "tab_id": resolved_tab_id,
            "url": url,
            "title": "Dashboard",
            "screenshot": "",
            "is_running": True,
        }

    def click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        resolved_tab_id = tab_id or self.current_page_id
        assert resolved_tab_id is not None
        return {
            "tab_id": resolved_tab_id,
            "url": self.pages[resolved_tab_id].url,
            "title": "Dashboard",
            "screenshot": "",
            "is_running": True,
        }

    def press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        resolved_tab_id = tab_id or self.current_page_id
        assert resolved_tab_id is not None
        return {
            "tab_id": resolved_tab_id,
            "url": self.pages[resolved_tab_id].url,
            "title": "Dashboard",
            "screenshot": "",
            "is_running": True,
        }

    def wait(self, duration: float, tab_id: str | None = None) -> dict[str, Any]:
        resolved_tab_id = tab_id or self.current_page_id
        assert resolved_tab_id is not None
        return {
            "tab_id": resolved_tab_id,
            "url": self.pages[resolved_tab_id].url,
            "title": "Dashboard",
            "screenshot": "",
            "is_running": True,
        }


class FakeBrowserManager:
    def _get_agent_browser(self) -> FakeBrowser:
        return FakeBrowser()


class SurfacePage(FakePage):
    async def evaluate(self, _script: str) -> dict[str, Any]:
        asset_url = _asset_url_from_fetch_script(_script)
        if asset_url:
            return _browser_asset_fetch_payload(asset_url)
        return {
            "origin": "https://app.test",
            "cookie": "sid=browser-cookie; theme=light",
            "localStorage": {"accessToken": "eyJ.surface.token"},
            "sessionStorage": {},
            "meta": {},
            "hiddenInputs": {},
            "nextData": {"buildManifest": "/_next/static/chunks/dashboard.js"},
            "page_url": self.url,
            "title": "Dashboard",
            "links": [
                {"href": "/dashboard", "text": "Dashboard", "rel": "", "nav": True},
                {"href": "/admin/users", "text": "Users", "rel": "", "nav": True},
                {"href": "/search?q=report", "text": "Search", "rel": "", "nav": False},
            ],
            "forms": [
                {
                    "action": "/billing/export",
                    "method": "POST",
                    "inputNames": ["format", "date_from"],
                    "buttonLabels": ["Export"],
                }
            ],
            "routeHints": [
                {"attr": "data-endpoint", "value": "/api/orders", "tag": "button", "label": "Orders API"},
                {"attr": "script-src", "value": "/static/dashboard.js", "tag": "script", "label": "dashboard"},
            ],
            "scriptHints": [
                {
                    "attr": "inline-script",
                    "value": "//# sourceMappingURL=/static/dashboard.js.map",
                    "tag": "script",
                    "label": "dashboard-map",
                }
            ],
            "interactive": [{"label": "Export", "target": "/billing/export", "role": "button"}],
            "headings": ["Dashboard", "Billing", "Users"],
        }


class SurfaceBrowser(FakeBrowser):
    def __init__(self) -> None:
        self.current_page_id = "tab_1"
        self.pages = {"tab_1": SurfacePage()}
        self.context = FakeContext()


class SurfaceBrowserManager:
    def _get_agent_browser(self) -> SurfaceBrowser:
        return SurfaceBrowser()


def _traversal_payload(url: str, ui_state: str = "default") -> dict[str, Any]:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    base = {
        "origin": "https://app.test",
        "cookie": "sid=browser-cookie; theme=light",
        "localStorage": {"accessToken": "eyJ.surface.token"},
        "sessionStorage": {},
        "meta": {},
        "hiddenInputs": {},
        "nextData": None,
        "page_url": url,
        "title": "Dashboard",
        "links": [],
        "forms": [],
        "routeHints": [],
        "scriptHints": [],
        "interactive": [],
        "headings": [],
    }
    if base_url == "https://app.test/dashboard":
        base.update(
            {
                "title": "Dashboard",
                "links": [
                    {"href": "/settings/profile", "text": "Profile", "rel": "", "nav": True},
                    {"href": "/admin/users", "text": "Users", "rel": "", "nav": True},
                    {"href": "/logout", "text": "Logout", "rel": "", "nav": True},
                    {"href": "https://outside.test/help", "text": "External", "rel": "", "nav": False},
                ],
                "sessionStorage": {
                    "recentNavigation": '{"links":{"teamSettings":"teams/blue/settings","auditApi":"/api/teams/blue/audit?limit=20","chunk":"/static/chunks/team-settings.js"}}'
                },
                "nextData": {
                    "props": {
                        "pageProps": {
                            "bootstrap": {
                                "defaultRoute": "/teams/blue/settings",
                                "membersApi": "/api/teams/blue/members?role=admin",
                                "routeLoader": "/_next/static/chunks/pages/dashboard.js",
                            }
                        }
                    }
                },
                "routeHints": [
                    {"attr": "data-endpoint", "value": "/api/orders", "tag": "button", "label": "Orders API"},
                    {"attr": "script-src", "value": "/static/dashboard.js", "tag": "script", "label": "dashboard"},
                    {
                        "attr": "onclick",
                        "value": "window.location='/support/tickets'; fetch('/api/tickets?filter=open')",
                        "tag": "button",
                        "label": "Support",
                    },
                ],
                "scriptHints": [
                    {
                        "attr": "inline-script",
                        "value": "router.push('/projects/alpha/settings'); axios.get('/api/projects/alpha/members?role=owner'); //# sourceMappingURL=/static/dashboard.js.map",
                        "tag": "script",
                        "label": "dashboard-router",
                    }
                ],
                "interactive": [
                    {"label": "Audit Log", "target": "/reports/audit", "role": "button"},
                    {"label": "Security Panel", "target": "", "role": "tab"},
                ],
                "headings": ["Dashboard", "Users", "Profile"],
            }
        )
        if ui_state == "security_panel":
            base["links"] = list(base["links"]) + [
                {"href": "/settings/security", "text": "Security", "rel": "", "nav": True}
            ]
            base["headings"] = list(base["headings"]) + ["Security"]
    elif base_url == "https://app.test/settings/profile":
        base.update(
            {
                "title": "Profile",
                "links": [
                    {"href": "/billing/invoices", "text": "Invoices", "rel": "", "nav": True}
                ],
                "headings": ["Profile", "Invoices"],
            }
        )
    elif base_url == "https://app.test/admin/users":
        base.update(
            {
                "title": "Users",
                "links": [{"href": "/admin/roles", "text": "Roles", "rel": "", "nav": True}],
                "headings": ["Users", "Roles"],
            }
        )
    elif base_url == "https://app.test/billing/invoices":
        base.update(
            {
                "title": "Invoices",
                "forms": [
                    {
                        "action": "/billing/export",
                        "method": "POST",
                        "inputNames": ["month"],
                        "buttonLabels": ["Export"],
                    }
                ],
                "headings": ["Invoices"],
            }
        )
    elif base_url == "https://app.test/admin/roles":
        base.update(
            {
                "title": "Roles",
                "headings": ["Roles"],
            }
        )
    elif base_url == "https://app.test/reports/audit":
        base.update(
            {
                "title": "Audit Log",
                "headings": ["Audit Log"],
            }
        )
    elif base_url == "https://app.test/projects/alpha/settings":
        base.update(
            {
                "title": "Project Settings",
                "headings": ["Project Settings", "Members"],
            }
        )
    elif base_url == "https://app.test/teams/blue/settings":
        base.update(
            {
                "title": "Team Settings",
                "headings": ["Team Settings", "Members"],
            }
        )
    elif base_url == "https://app.test/teams/blue/members":
        base.update(
            {
                "title": "Team Members",
                "headings": ["Team Members", "Roles"],
            }
        )
    elif base_url == "https://app.test/support/tickets":
        base.update(
            {
                "title": "Support Tickets",
                "links": [
                    {"href": "/support/tickets/123", "text": "Ticket 123", "rel": "", "nav": True}
                ],
                "headings": ["Support Tickets", "Open Cases"],
            }
        )
    elif base_url == "https://app.test/support/tickets/123":
        base.update(
            {
                "title": "Ticket 123",
                "headings": ["Ticket 123", "Details"],
            }
        )
    elif base_url == "https://app.test/settings/security":
        base.update(
            {
                "title": "Security",
                "forms": [
                    {
                        "action": "/settings/security",
                        "method": "GET",
                        "inputNames": ["tab", "q"],
                        "buttonLabels": ["Search"],
                    }
                ],
                "headings": ["Security", "MFA"],
            }
        )
        if query.get("tab") == ["mfa"]:
            base["title"] = "Security MFA"
            base["links"] = [
                {"href": "/settings/security/mfa", "text": "MFA Details", "rel": "", "nav": False}
            ]
            base["headings"] = ["Security", "MFA", "Results"]
    elif base_url == "https://app.test/settings/security/mfa":
        base.update(
            {
                "title": "MFA Details",
                "headings": ["MFA Details", "Backup Codes"],
            }
        )
    elif base_url == "https://app.test/admin/beta/users":
        base.update(
            {
                "title": "Beta Users",
                "headings": ["Beta Users", "Preview"],
            }
        )
    elif base_url == "https://app.test/admin/reports/export":
        base.update(
            {
                "title": "Admin Export",
                "headings": ["Admin Export", "Reports"],
            }
        )
    elif base_url == "https://app.test/admin/shadow/audit":
        base.update(
            {
                "title": "Shadow Audit",
                "headings": ["Shadow Audit", "Exports"],
            }
        )
    elif base_url == "https://app.test/billing/exports/history":
        base.update(
            {
                "title": "Export History",
                "headings": ["Export History", "Downloads"],
            }
        )
    return base


class TraversalPage:
    def __init__(self, url: str = "https://app.test/dashboard") -> None:
        self.url = url
        self.ui_state = "default"

    async def evaluate(self, _script: str) -> dict[str, Any]:
        asset_url = _asset_url_from_fetch_script(_script)
        if asset_url:
            return _browser_asset_fetch_payload(asset_url)
        if "__STRIX_CLICK_CANDIDATE_MARKER__" in _script:
            if self.url == "https://app.test/dashboard" and "Security Panel" in _script:
                self.ui_state = "security_panel"
                return {
                    "matched": True,
                    "clicked": True,
                    "label": "Security Panel",
                    "role": "tab",
                    "target": "",
                }
            return {"matched": False, "clicked": False}
        return _traversal_payload(self.url, self.ui_state)

    async def goto(self, url: str, wait_until: str = "domcontentloaded") -> None:
        self.url = url
        self.ui_state = "default"

    async def wait_for_timeout(self, _milliseconds: int) -> None:
        return None

    async def close(self) -> None:
        return None


class TraversalContext:
    async def cookies(self, _urls: list[str]) -> list[dict[str, Any]]:
        return [{"name": "sid", "value": "browser-cookie"}]

    async def new_page(self) -> TraversalPage:
        return TraversalPage("https://app.test/dashboard")


class TraversalBrowser:
    def __init__(self) -> None:
        self.current_page_id = "tab_1"
        self.pages = {"tab_1": TraversalPage("https://app.test/dashboard")}
        self.context = TraversalContext()
        self._next_tab_id = 2
        self.console_logs: dict[str, list[dict[str, Any]]] = {}

    def _run_async(self, coro: Any) -> Any:
        return asyncio.run(coro)

    async def _setup_console_logging(self, _page: TraversalPage, tab_id: str) -> None:
        self.console_logs[tab_id] = []


class TraversalBrowserManager:
    def _get_agent_browser(self) -> TraversalBrowser:
        return TraversalBrowser()


class RecordingSurfacePage:
    def __init__(self) -> None:
        self.last_script = ""

    async def evaluate(self, script: str) -> dict[str, Any]:
        self.last_script = script
        return {
            "page_url": "https://app.test/dashboard",
            "origin": "https://app.test",
            "title": "Dashboard",
            "links": [],
            "forms": [],
            "routeHints": [],
            "scriptHints": [],
            "interactive": [],
            "headings": [],
        }


class RecordingSurfaceBrowser:
    def __init__(self) -> None:
        self.current_page_id = "tab_1"
        self.page = RecordingSurfacePage()
        self.pages = {"tab_1": self.page}


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
    agents_graph_actions._agent_states.clear()
    set_current_agent_id("default")


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


def test_map_browser_surface_seeds_runtime_inventory_and_coverage(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        browser_assessment_actions,
        "_browser_manager",
        lambda: SurfaceBrowserManager(),
    )

    state = DummyState("agent_root")
    result = browser_assessment_actions.map_browser_surface(
        agent_state=state,
        target="web",
    )
    ledger = list_assessment_state(agent_state=state)
    inventory_state = runtime_actions.list_runtime_inventory(agent_state=state, target="web")
    surface_state = surface_actions.list_mined_attack_surface(agent_state=state, target="web")

    assert result["success"] is True
    assert result["discovered_count"] >= 4
    assert result["artifact_count"] >= 3
    assert "admin" in result["discovered_modules"]
    surfaces = {item["surface"] for item in ledger["coverage"]}
    assert "Runtime endpoint GET /dashboard" in surfaces
    assert "Runtime endpoint GET /admin/users" in surfaces
    assert "Runtime endpoint GET /search" in surfaces
    assert "Runtime endpoint POST /billing/export" in surfaces
    assert "Runtime endpoint GET /admin/beta/users" in surfaces
    assert "Runtime endpoint ANY /api/admin/audit" in surfaces
    assert "Runtime endpoint GET /billing/exports/history" in surfaces
    assert "Runtime endpoint ANY /api/internal/reports" in surfaces
    assert "Runtime endpoint GET /admin/reports/export" in surfaces
    assert "Browser-discovered JavaScript asset GET /static/dashboard.js" in surfaces
    assert "Browser-discovered JavaScript asset GET /_next/static/chunks/dashboard.js" in surfaces
    assert "Browser-discovered source map GET /static/dashboard.js.map" in surfaces
    assert "Browser-mined route ANY /admin/beta/users" in surfaces
    assert "Browser-mined route ANY /api/admin/audit" in surfaces
    assert "Browser-visible surface completeness for web" in surfaces
    assert inventory_state["success"] is True
    assert inventory_state["records"][0]["inventory_total"] >= 9
    assert surface_state["success"] is True
    artifact_kinds = {item["kind"] for item in surface_state["records"][0]["artifacts"]}
    artifact_paths = {item["path"] for item in surface_state["records"][0]["artifacts"]}
    source_map_artifact = next(
        item for item in surface_state["records"][0]["artifacts"] if item["path"] == "/static/dashboard.js.map"
    )
    assert "js_asset" in artifact_kinds
    assert "source_map" in artifact_kinds
    assert "js_route" in artifact_kinds
    assert "/static/dashboard.js" in artifact_paths
    assert "/static/dashboard.js.map" in artifact_paths
    assert "/_next/static/chunks/dashboard.js" in artifact_paths
    assert "/admin/beta/users" in artifact_paths
    assert "/api/admin/audit" in artifact_paths
    assert "src/admin/users.ts" in source_map_artifact["source_files"]
    assert "src/security/featureFlags.ts" in source_map_artifact["source_files"]
    assert "tenantId" in source_map_artifact["object_hints"]
    assert "accountId" in source_map_artifact["object_hints"]
    assert "isAdmin" in source_map_artifact["role_hints"]
    assert "featureFlags" in source_map_artifact["feature_hints"]
    assert "clientSecret" in source_map_artifact["secret_hints"]
    assert "callbackUrl" in source_map_artifact["param_hints"]


def test_collect_browser_surface_uses_dynamic_route_selector_and_script_markers() -> None:
    browser = RecordingSurfaceBrowser()

    result = asyncio.run(browser_assessment_actions._collect_browser_surface(browser, "tab_1"))

    assert result["page_url"] == "https://app.test/dashboard"
    assert "querySelectorAll(routeSelector)" in browser.page.last_script
    assert '"onclick"' in browser.page.last_script
    assert '"routerlink"' in browser.page.last_script
    assert '"hx-get"' in browser.page.last_script
    assert "const scriptHints = [];" in browser.page.last_script
    assert "const scriptMarkers =" in browser.page.last_script


def test_traverse_browser_surface_visits_internal_pages_and_seeds_deeper_inventory(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(
        browser_assessment_actions,
        "_browser_manager",
        lambda: TraversalBrowserManager(),
    )

    state = DummyState("agent_root")
    result = browser_assessment_actions.traverse_browser_surface(
        agent_state=state,
        target="web",
        max_pages=18,
        max_depth=3,
        max_clicks=2,
    )
    ledger = list_assessment_state(agent_state=state)
    inventory_state = runtime_actions.list_runtime_inventory(agent_state=state, target="web")
    surface_state = surface_actions.list_mined_attack_surface(agent_state=state, target="web")

    assert result["success"] is True
    assert result["pages_visited"] >= 11
    assert result["clicks_performed"] == 1
    assert result["artifact_count"] >= 5
    visited_urls = {item["url"] for item in result["traversed_pages"]}
    assert "https://app.test/admin/users" in visited_urls
    assert "https://app.test/settings/profile" in visited_urls
    assert "https://app.test/admin/roles" in visited_urls
    assert "https://app.test/billing/invoices" in visited_urls
    assert "https://app.test/reports/audit" in visited_urls
    assert "https://app.test/projects/alpha/settings" in visited_urls
    assert "https://app.test/teams/blue/settings" in visited_urls
    assert "https://app.test/teams/blue/members" in visited_urls
    assert "https://app.test/support/tickets" in visited_urls
    assert "https://app.test/settings/security" in visited_urls
    assert "https://app.test/settings/security?tab=mfa&q=security" in visited_urls
    assert "https://app.test/settings/security/mfa" in visited_urls
    assert "https://app.test/admin/beta/users" in visited_urls
    assert "https://app.test/admin/reports/export" in visited_urls
    assert "https://app.test/billing/exports/history" in visited_urls
    assert "https://app.test/logout" not in visited_urls
    assert all(url.startswith("https://app.test/") for url in visited_urls)
    assert result["click_states"][0]["label"] == "Security Panel"
    assert result["workflow_states"][0]["submitted_params"] == {"tab": "mfa", "q": "security"}

    surfaces = {item["surface"] for item in ledger["coverage"]}
    assert "Runtime endpoint GET /admin/users" in surfaces
    assert "Runtime endpoint GET /settings/profile" in surfaces
    assert "Runtime endpoint GET /billing/invoices" in surfaces
    assert "Runtime endpoint POST /billing/export" in surfaces
    assert "Runtime endpoint GET /reports/audit" in surfaces
    assert "Runtime endpoint GET /projects/alpha/settings" in surfaces
    assert "Runtime endpoint GET /api/projects/alpha/members" in surfaces
    assert "Runtime endpoint GET /teams/blue/settings" in surfaces
    assert "Runtime endpoint GET /api/teams/blue/members" in surfaces
    assert "Runtime endpoint GET /api/teams/blue/audit" in surfaces
    assert "Runtime endpoint GET /admin/beta/users" in surfaces
    assert "Runtime endpoint ANY /api/admin/audit" in surfaces
    assert "Runtime endpoint GET /billing/exports/history" in surfaces
    assert "Runtime endpoint GET /teams/blue/members" in surfaces
    assert "Runtime endpoint ANY /api/dashboard/summary" in surfaces
    assert "Browser-discovered JavaScript asset GET /static/dashboard.js" in surfaces
    assert "Browser-discovered JavaScript asset GET /static/chunks/team-settings.js" in surfaces
    assert "Browser-discovered JavaScript asset GET /_next/static/chunks/pages/dashboard.js" in surfaces
    assert "Browser-discovered source map GET /static/dashboard.js.map" in surfaces
    assert "Browser-mined route ANY /teams/blue/members" in surfaces
    assert "Browser-mined WebSocket endpoint GET /realtime/teams" in surfaces
    assert "Runtime endpoint GET /support/tickets" in surfaces
    assert "Runtime endpoint GET /api/tickets" in surfaces
    assert "Runtime endpoint GET /settings/security" in surfaces
    assert "Runtime endpoint GET /settings/security/mfa" in surfaces
    assert "Browser traversal coverage for web" in surfaces

    assert inventory_state["success"] is True
    selected_inventory = inventory_state["records"][0]["selected_inventory"]
    inventory_paths = {item["normalized_path"] for item in selected_inventory}
    assert "/admin/users" in inventory_paths
    assert "/settings/profile" in inventory_paths
    assert "/billing/invoices" in inventory_paths
    assert "/billing/export" in inventory_paths
    assert "/reports/audit" in inventory_paths
    assert "/projects/alpha/settings" in inventory_paths
    assert "/api/projects/alpha/members" in inventory_paths
    assert "/teams/blue/settings" in inventory_paths
    assert "/api/teams/blue/members" in inventory_paths
    assert "/api/teams/blue/audit" in inventory_paths
    assert "/admin/beta/users" in inventory_paths
    assert "/api/admin/audit" in inventory_paths
    assert "/billing/exports/history" in inventory_paths
    assert "/teams/blue/members" in inventory_paths
    assert "/api/dashboard/summary" in inventory_paths
    assert "/support/tickets" in inventory_paths
    assert "/api/tickets" in inventory_paths
    assert "/settings/security" in inventory_paths
    assert "/settings/security/mfa" in inventory_paths
    assert surface_state["success"] is True
    artifact_kinds = {item["kind"] for item in surface_state["records"][0]["artifacts"]}
    artifact_paths = {item["path"] for item in surface_state["records"][0]["artifacts"]}
    assert "js_route" in artifact_kinds
    assert "websocket_endpoint" in artifact_kinds
    assert "/static/dashboard.js" in artifact_paths
    assert "/static/dashboard.js.map" in artifact_paths
    assert "/static/chunks/team-settings.js" in artifact_paths
    assert "/_next/static/chunks/pages/dashboard.js" in artifact_paths
    assert "/teams/blue/members" in artifact_paths
    assert "/realtime/teams" in artifact_paths


def test_traverse_browser_surface_prioritizes_seed_urls(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        browser_assessment_actions,
        "_browser_manager",
        lambda: TraversalBrowserManager(),
    )

    state = DummyState("agent_root")
    result = browser_assessment_actions.traverse_browser_surface(
        agent_state=state,
        target="web",
        max_pages=1,
        max_depth=1,
        max_clicks=0,
        seed_urls=[
            "/admin/shadow/audit?view=full",
            "https://outside.test/help",
            "https://app.test/dashboard",
        ],
    )

    assert result["success"] is True
    assert result["seed_url_count"] == 1
    assert result["pages_visited"] == 1
    assert result["traversed_pages"][0]["url"] == "https://app.test/admin/shadow/audit?view=full"


def test_browser_tab_manager_auto_bootstraps_session_after_state_change() -> None:
    state = DummyState("agent_root")
    agents_graph_actions._agent_states[state.agent_id] = state
    set_current_agent_id(state.agent_id)

    manager = BrowserTabManager()
    manager._set_agent_browser(AutoBootstrapBrowser())

    result = manager.press_key("Enter")
    listed = session_actions.list_session_profiles(agent_state=state, include_values=True)

    assert result["session_profile_bootstrap"]["auto_bootstrapped"] is True
    assert "session bootstrapped" in result["message"]
    assert listed["profile_count"] == 1
    assert listed["profiles"][0]["name"] == "browser-auto-app-test"
    assert listed["profiles"][0]["role"] == "authenticated"


def test_browser_tab_manager_deduplicates_unchanged_auto_bootstrap() -> None:
    state = DummyState("agent_root")
    agents_graph_actions._agent_states[state.agent_id] = state
    set_current_agent_id(state.agent_id)

    manager = BrowserTabManager()
    manager._set_agent_browser(AutoBootstrapBrowser())

    first = manager.press_key("Enter")
    second = manager.wait_browser(0.5)
    listed = session_actions.list_session_profiles(agent_state=state, include_values=True)

    assert first["session_profile_bootstrap"]["auto_bootstrapped"] is True
    assert "session_profile_bootstrap" not in second
    assert listed["profile_count"] == 1


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


def test_confirm_active_artifact_in_browser_auto_spawns_impact_agent(
    monkeypatch: Any,
) -> None:
    spawn_calls: list[dict[str, Any]] = []

    monkeypatch.setattr(
        browser_assessment_actions,
        "_browser_manager",
        lambda: FakeArtifactBrowserManager(),
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
    result = browser_assessment_actions.confirm_active_artifact_in_browser(
        agent_state=state,
        target="web",
        component="focus:file_upload:app.test/uploads/avatar.svg:browser",
        surface="Browser execution proof for uploaded SVG",
        url="https://app.test/uploads/avatar.svg",
        expected_dom_markers=["<svg", "onload="],
    )

    assert result["success"] is True
    assert result["hypothesis_result"]["record"]["status"] == "validated"
    assert result["followup_agent_result"]["success"] is True
    assert spawn_calls[0]["target"] == "web"
    assert spawn_calls[0]["hypothesis_ids"] == [result["hypothesis_result"]["hypothesis_id"]]
