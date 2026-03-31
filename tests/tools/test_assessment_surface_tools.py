# ruff: noqa: E402, ARG002, ARG005, I001, PLW0108

import json
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
from strix.tools.assessment import assessment_actions as assessment_actions_module
from strix.tools.assessment import assessment_runtime_actions as runtime_actions
from strix.tools.assessment import assessment_surface_actions as surface_actions
from strix.tools.assessment import assessment_surface_review_actions as surface_review_actions
from strix.tools.assessment import assessment_toolchain_actions as toolchain_actions
from strix.tools.assessment import assessment_workflow_actions as workflow_actions
from strix.tools.assessment import clear_assessment_storage, list_assessment_state
from strix.tools.assessment import record_coverage, record_hypothesis, save_session_profile


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
            payload = {
                "openapi": "3.0.0",
                "paths": {
                    "/api/admin/users": {
                        "parameters": [
                            {
                                "name": "tenant_id",
                                "in": "query",
                                "schema": {"type": "string"},
                            }
                        ],
                        "get": {
                            "security": [{"bearerAuth": []}],
                            "parameters": [
                                {
                                    "name": "user_id",
                                    "in": "path",
                                    "required": True,
                                    "schema": {"type": "string"},
                                }
                            ],
                        },
                        "post": {
                            "requestBody": {
                                "required": True,
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/CreateUserRequest"}
                                    }
                                },
                            }
                        },
                    }
                },
                "components": {
                    "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
                    "schemas": {
                        "CreateUserRequest": {
                            "type": "object",
                            "required": ["email", "role"],
                            "properties": {
                                "email": {"type": "string"},
                                "role": {"type": "string"},
                                "tenant_id": {"type": "string"},
                            },
                        }
                    },
                },
            }
            return {
                "content": (
                    "HTTP/1.1 200 OK\n"
                    "Content-Type: application/json\n"
                    "\n"
                    f"{json.dumps(payload)}"
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
            return {"content": 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"data":{}}'}
        if request_id == "req_ws" and part == "request":
            return {"content": ("GET /ws/chat HTTP/1.1\nHost: app.test\nUpgrade: websocket\n\n")}
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
    openapi_artifact = next(
        artifact for artifact in result["artifacts"] if artifact["kind"] == "openapi_spec"
    )
    assert openapi_artifact["documented_parameter_count"] >= 2
    assert openapi_artifact["documented_request_field_count"] >= 3
    assert openapi_artifact["documented_object_count"] >= 1
    assert any(item["name"] == "tenant_id" for item in openapi_artifact["documented_parameters"])
    assert any(item["name"] == "role" for item in openapi_artifact["documented_request_fields"])
    assert any(item["object_type"] == "CreateUserRequest" for item in openapi_artifact["documented_objects"])
    surfaces = {item["surface"] for item in ledger["coverage"]}
    assert "OpenAPI/Swagger exposure GET /openapi.json" in surfaces
    assert "Documented endpoint GET /api/admin/users" in surfaces
    assert "GraphQL endpoint POST /graphql" in surfaces
    assert "JavaScript-discovered route ANY /api/invoices" in surfaces
    assert "WebSocket endpoint GET /ws/chat" in surfaces
    assert listed["success"] is True
    assert listed["records"][0]["artifacts_total"] == result["artifacts_total"]


def test_build_attack_surface_review_maps_layers_and_blind_spots() -> None:
    state = DummyState("agent_root")
    target_key = assessment_actions_module._slug("web")

    runtime_actions._runtime_inventory_storage[state.agent_id] = {
        target_key: {
            "target": "web",
            "inventory": [
                {
                    "host": "app.test",
                    "normalized_path": "/app",
                    "methods": ["GET"],
                    "status_codes": [200],
                    "query_params": [],
                    "body_params": [],
                    "content_types": ["text/html"],
                    "auth_hints": ["anonymous"],
                    "sources": ["proxy"],
                    "origins": ["requests"],
                    "sample_urls": ["https://app.test/app"],
                    "sample_request_ids": ["req_app"],
                    "observed_count": 1,
                    "priority": "normal",
                },
                {
                    "host": "app.test",
                    "normalized_path": "/api/users/:id",
                    "methods": ["GET", "PATCH"],
                    "status_codes": [200],
                    "query_params": ["view"],
                    "body_params": ["role", "tenant_id"],
                    "content_types": ["application/json"],
                    "auth_hints": ["cookie"],
                    "sources": ["proxy"],
                    "origins": ["requests"],
                    "sample_urls": ["https://app.test/api/users/123"],
                    "sample_request_ids": ["req_user"],
                    "observed_count": 2,
                    "priority": "high",
                },
            ],
            "selected_inventory": [],
            "mapped_at": "2026-03-31T00:00:00+00:00",
        }
    }
    surface_actions._surface_mining_storage[state.agent_id] = {
        target_key: {
            "target": "web",
            "artifacts": [
                {
                    "kind": "openapi_spec",
                    "host": "app.test",
                    "path": "/openapi.json",
                    "method": "GET",
                    "priority": "high",
                    "documented_operations": [
                        {
                            "method": "GET",
                            "path": "/api/admin/users",
                            "security": ["bearerAuth"],
                            "requires_auth": True,
                        },
                        {
                            "method": "POST",
                            "path": "/api/admin/users",
                            "content_types": ["application/json"],
                        },
                    ],
                    "documented_parameters": [
                        {
                            "method": "GET",
                            "path": "/api/admin/users",
                            "name": "tenant_id",
                            "location": "query",
                            "object_hint": "Tenant",
                            "identifier": True,
                        },
                        {
                            "method": "GET",
                            "path": "/api/admin/users",
                            "name": "Authorization",
                            "location": "header",
                        },
                    ],
                    "documented_request_fields": [
                        {
                            "method": "POST",
                            "path": "/api/admin/users",
                            "name": "role",
                            "location": "body",
                            "content_type": "application/json",
                        },
                        {
                            "method": "POST",
                            "path": "/api/admin/users",
                            "name": "tenant_id",
                            "location": "body",
                            "content_type": "application/json",
                            "identifier": True,
                        },
                    ],
                    "documented_objects": [
                        {
                            "object_type": "AdminUser",
                            "fields": ["email", "role", "tenant_id"],
                            "identifiers": ["tenant_id"],
                        }
                    ],
                },
                {
                    "kind": "js_route",
                    "host": "app.test",
                    "path": "/hidden/report",
                    "method": "ANY",
                    "priority": "high",
                    "source_asset": "/static/app.js",
                },
                {
                    "kind": "graphql_persisted_query",
                    "host": "app.test",
                    "path": "/graphql",
                    "method": "POST",
                    "priority": "high",
                },
            ],
            "selected_artifacts": [],
            "mined_at": "2026-03-31T00:00:00+00:00",
        }
    }
    workflow_actions._workflow_storage[state.agent_id] = {
        target_key: {
            "target": "web",
            "workflows": [
                {
                    "workflow_id": "wf_coupon",
                    "host": "app.test",
                    "type": "coupon",
                    "sequence": [
                        {"host": "app.test", "method": "POST", "path": "/coupon/redeem"},
                        {"host": "app.test", "method": "POST", "path": "/coupon/redeem"},
                    ],
                }
            ],
            "selected_workflows": [],
            "discovered_at": "2026-03-31T00:00:00+00:00",
        }
    }
    toolchain_actions._tool_scan_storage[state.agent_id] = {
        "scan_subfinder": {
            "run_id": "scan_subfinder",
            "tool_name": "subfinder",
            "target": "web",
            "updated_at": "2026-03-31T00:00:01+00:00",
            "findings": [{"host": "admin.app.test"}],
            "scope": {"targets": ["*.app.test"]},
        },
        "scan_httpx": {
            "run_id": "scan_httpx",
            "tool_name": "httpx",
            "target": "web",
            "updated_at": "2026-03-31T00:00:02+00:00",
            "findings": [
                {
                    "url": "https://app.test/app",
                    "status_code": 200,
                    "title": "Portal",
                    "webserver": "nginx",
                    "tech": ["nextjs"],
                    "ip": ["104.16.0.10"],
                    "cname": ["edge.app.test"],
                    "asn": ["AS13335"],
                    "asn_name": ["Cloudflare"],
                    "cdn": ["cloudflare"],
                    "tls_subject_names": ["app.test", "admin.app.test"],
                },
                {"url": "https://app.test/admin", "status_code": 403},
            ],
            "scope": {"targets": ["app.test"], "url": "https://app.test/app"},
        },
        "scan_ffuf": {
            "run_id": "scan_ffuf",
            "tool_name": "ffuf",
            "target": "web",
            "updated_at": "2026-03-31T00:00:03+00:00",
            "findings": [{"url": "https://app.test/admin", "path": "/admin", "status_code": 403}],
            "scope": {"url": "https://app.test/FUZZ"},
        },
        "scan_dirsearch": {
            "run_id": "scan_dirsearch",
            "tool_name": "dirsearch",
            "target": "web",
            "updated_at": "2026-03-31T00:00:04+00:00",
            "findings": [{"url": "https://app.test/admin", "path": "/admin", "status_code": 403}],
            "scope": {"url": "https://app.test/"},
        },
        "scan_arjun": {
            "run_id": "scan_arjun",
            "tool_name": "arjun",
            "target": "web",
            "updated_at": "2026-03-31T00:00:05+00:00",
            "findings": [
                {
                    "url": "https://app.test/api/users/123",
                    "path": "/api/users/123",
                    "parameter": "callback_url",
                },
                {
                    "url": "https://app.test/api/users/123",
                    "path": "/api/users/123",
                    "parameter": "tenant_id",
                },
            ],
            "scope": {"url": "https://app.test/api/users/123"},
        },
        "scan_nuclei": {
            "run_id": "scan_nuclei",
            "tool_name": "nuclei",
            "target": "web",
            "updated_at": "2026-03-31T00:00:06+00:00",
            "findings": [
                {
                    "matched_at": "https://app.test/app",
                    "host": "app.test",
                    "path": "/app",
                    "template_id": "tech-detect",
                    "name": "Modern Web Application",
                    "triage": {
                        "confidence": "low",
                        "verification_state": "raw",
                    },
                }
            ],
            "scope": {"targets": ["https://app.test"]},
        },
    }

    record_coverage(
        agent_state=state,
        target="web",
        component="runtime:app.test",
        surface="Runtime endpoint GET /api/users/:id",
        status="in_progress",
        rationale="Observed authenticated object endpoint.",
        priority="high",
    )
    record_hypothesis(
        agent_state=state,
        hypothesis="Cross-tenant access may exist on /api/users/:id",
        target="web",
        component="runtime:app.test",
        vulnerability_type="authorization",
        priority="high",
    )
    save_session_profile(
        agent_state=state,
        name="user",
        headers={"Authorization": "Bearer abc"},
        role="user",
        tenant="tenant-a",
        base_url="https://app.test",
    )

    result = surface_review_actions.build_attack_surface_review(
        agent_state=state,
        target="web",
        scope_targets=["app.test", "*.app.test", "https://app.test/app"],
    )
    listed = surface_review_actions.list_attack_surface_reviews(agent_state=state, target="web")

    assert result["success"] is True
    report = result["report"]
    assert report["scope_map_v1"]["fixed_hosts"] == ["app.test"]
    assert report["scope_map_v1"]["wildcard_domains"] == ["app.test"]
    assert report["scope_map_v1"]["path_based_scope"][0]["path"] == "/app"
    counts = report["summary"]["classification_counts"]
    assert counts["confirmed"] >= 1
    assert counts["suspected"] >= 1
    assert counts["exposed-info"] >= 1
    assert counts["weak-signal"] >= 1
    assert counts["duplicate-risk"] >= 1
    assert counts["out-of-scope"] >= 1
    assert counts["blind-spot"] >= 1
    assert any(item["path"] == "/api/admin/users" for item in report["path_inventory"])
    admin_path = next(item for item in report["path_inventory"] if item["path"] == "/api/admin/users")
    assert admin_path["auth_required"] == "yes"
    assert "tenant_id" in admin_path["params"]["query"]
    assert "Authorization" in admin_path["params"]["header"]
    assert "role" in admin_path["params"]["body"]
    host_entry = next(item for item in report["domain_dns_host_inventory"]["hosts"] if item["host"] == "app.test")
    assert "104.16.0.10" in host_entry["ip"]
    assert "edge.app.test" in host_entry["cname_chain"]
    assert "AS13335" in host_entry["asn"]
    service_entry = next(item for item in report["service_inventory"] if item["host"] == "app.test")
    assert "nginx" in service_entry["fingerprint"]
    assert "Portal" in service_entry["titles"]
    assert "app.test" in service_entry["tls_names"]
    assert any(item["kind"] == "openapi_spec" for item in report["exposure_review"])
    assert any(
        item["parameter"] == "tenant_id"
        for item in report["parameter_object_review"]["parameters"]
    )
    assert any(
        item["object_type"] == "adminuser"
        for item in report["parameter_object_review"]["objects"]
    )
    assert any(item["identifier"] == "app.test/admin" for item in report["duplicate_risks"])
    assert any(item["path"] == "/admin" for item in report["out_of_scope"])
    assert (
        report["domain_dns_host_inventory"]["dns_blind_spots"][0]["signal_classification"]
        == "blind-spot"
    )
    assert report["coverage_ledger"]["role_boundary"][2]["status"] == "needs more data"
    assert report["chain_analysis"] != []
    assert listed["success"] is True
    assert listed["records"][0]["summary"] == report["summary"]


def test_build_attack_surface_review_returns_needs_more_data_when_empty() -> None:
    state = DummyState("agent_root")

    result = surface_review_actions.build_attack_surface_review(agent_state=state, target="empty")

    assert result["success"] is True
    report = result["report"]
    assert report["summary"]["host_count"] == 0
    assert report["summary"]["needs_more_data"] is True
    assert report["scope_map_v1"]["needs_more_data"] is True
    assert any(item["signal_classification"] == "blind-spot" for item in report["blind_spots"])
