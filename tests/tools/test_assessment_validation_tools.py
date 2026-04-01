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
from strix.tools.assessment import assessment_orchestration_actions as orchestration_actions
from strix.tools.assessment import assessment_validation_actions as validation_actions


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


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()


def test_role_matrix_test_records_suspicious_parity(monkeypatch: Any) -> None:
    responses = {
        "guest": {
            "name": "guest",
            "method": "GET",
            "url": "https://app.test/orders/123",
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 32,
            "body_hash": "samehash",
            "body_preview": '{"id":123,"owner":"alice"}',
            "elapsed_ms": 10,
        },
        "admin": {
            "name": "admin",
            "method": "GET",
            "url": "https://app.test/orders/123",
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 32,
            "body_hash": "samehash",
            "body_preview": '{"id":123,"owner":"alice"}',
            "elapsed_ms": 12,
        },
    }

    monkeypatch.setattr(
        validation_actions,
        "_execute_request",
        lambda spec, timeout, follow_redirects: responses[spec["name"]],
    )

    state = DummyState("agent_root")
    result = validation_actions.role_matrix_test(
        agent_state=state,
        target="web",
        component="orders",
        surface="Order authorization matrix",
        method="GET",
        url="https://app.test/orders/123",
        cases=[
            {"name": "guest", "method": "GET", "url": "https://app.test/orders/123"},
            {"name": "admin", "method": "GET", "url": "https://app.test/orders/123"},
        ],
        baseline_case="admin",
    )

    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert len(result["suspicious_matches"]) == 1
    assert result["coverage_result"]["record"]["status"] == "in_progress"
    assert ledger["assessment_summary"]["hypothesis_total"] == 1
    assert ledger["assessment_summary"]["evidence_total"] == 1


def test_role_matrix_test_auto_spawns_impact_agent_for_guest_admin_parity(
    monkeypatch: Any,
) -> None:
    responses = {
        "guest": {
            "name": "guest",
            "method": "GET",
            "url": "https://app.test/admin/users",
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 32,
            "body_hash": "samehash",
            "body_preview": '{"users":[{"id":1}]}',
            "elapsed_ms": 10,
        },
        "admin": {
            "name": "admin",
            "method": "GET",
            "url": "https://app.test/admin/users",
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 32,
            "body_hash": "samehash",
            "body_preview": '{"users":[{"id":1}]}',
            "elapsed_ms": 12,
        },
    }
    spawn_calls: list[dict[str, Any]] = []

    monkeypatch.setattr(
        validation_actions,
        "_execute_request",
        lambda spec, timeout, follow_redirects: responses[spec["name"]],
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
    result = validation_actions.role_matrix_test(
        agent_state=state,
        target="web",
        component="admin",
        surface="Admin authorization matrix",
        method="GET",
        url="https://app.test/admin/users",
        cases=[
            {"name": "guest", "method": "GET", "url": "https://app.test/admin/users"},
            {"name": "admin", "method": "GET", "url": "https://app.test/admin/users"},
        ],
        baseline_case="admin",
    )

    assert result["success"] is True
    assert result["hypothesis_result"]["record"]["status"] == "validated"
    assert result["followup_agent_result"]["success"] is True
    assert spawn_calls[0]["target"] == "web"
    assert spawn_calls[0]["hypothesis_ids"] == [result["hypothesis_result"]["hypothesis_id"]]


def test_race_condition_harness_records_multiple_successes(monkeypatch: Any) -> None:
    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 24,
            "body_hash": spec["name"],
            "body_preview": '{"ok":true}',
            "elapsed_ms": 8,
        }

    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)

    state = DummyState("agent_root")
    result = validation_actions.race_condition_harness(
        agent_state=state,
        target="web",
        component="billing",
        surface="Coupon redemption race",
        requests=[
            {"name": "claim_1", "method": "POST", "url": "https://app.test/coupon/redeem"},
            {"name": "claim_2", "method": "POST", "url": "https://app.test/coupon/redeem"},
        ],
        iterations=2,
        expect_single_success=True,
    )

    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["anomalies"]
    assert result["coverage_result"]["record"]["status"] == "in_progress"
    assert ledger["assessment_summary"]["hypothesis_total"] == 1
    assert ledger["assessment_summary"]["evidence_total"] == 1


def test_payload_probe_harness_flags_timing_anomaly(monkeypatch: Any) -> None:
    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        if spec["name"] == "baseline":
            return {
                "name": "baseline",
                "method": spec["method"],
                "url": spec["url"],
                "status_code": 200,
                "content_type": "application/json",
                "body_length": 20,
                "body_hash": "base",
                "body_preview": '{"ok":true}',
                "elapsed_ms": 100,
            }
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 20,
            "body_hash": "slow",
            "body_preview": '{"ok":true}',
            "elapsed_ms": 2500,
        }

    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)

    state = DummyState("agent_root")
    result = validation_actions.payload_probe_harness(
        agent_state=state,
        target="web",
        component="search",
        surface="Search SQLi probe",
        vulnerability_type="sqli",
        parameter_name="q",
        base_request={"method": "GET", "url": "https://app.test/search?q=book"},
        payloads=[{"payload": "' OR SLEEP(5)--", "strategy": "time_based", "encoding": "raw"}],
        baseline_value="book",
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["triage_result"]["suspicious_observations"]
    assert result["triage_result"]["coverage_result"]["record"]["status"] == "in_progress"
    assert "q=book" in result["request_variants"][0]["request"]["url"]
    assert any(item["vulnerability_type"] == "sqli" for item in ledger["hypotheses"])


def test_payload_probe_harness_marks_oob_interaction(monkeypatch: Any) -> None:
    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 200,
            "content_type": "text/html",
            "body_length": 16,
            "body_hash": spec["name"],
            "body_preview": "<html>ok</html>",
            "elapsed_ms": 80,
        }

    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)
    monkeypatch.setattr(
        oob_actions,
        "oob_interaction_harness",
        lambda agent_state, action, **kwargs: {
            "success": True,
            "interactions": [
                {
                    "label": "variant",
                    "protocol": "http",
                    "raw_event": {"url": "http://cb.test/oob"},
                }
            ],
        },
    )

    state = DummyState("agent_root")
    result = validation_actions.payload_probe_harness(
        agent_state=state,
        target="web",
        component="fetch",
        surface="Callback SSRF probe",
        vulnerability_type="ssrf",
        parameter_name="callback_url",
        base_request={"method": "GET", "url": "https://app.test/fetch"},
        payloads=[{"payload": "http://cb.test/oob", "strategy": "oob", "encoding": "raw"}],
        baseline_value="https://example.com/",
        oob_harness_id="oob_1",
        poll_oob=True,
    )

    assert result["success"] is True
    assert result["oob_result"]["success"] is True
    assert any(item.get("oob_interaction") for item in result["observations"])
    assert result["triage_result"]["suspicious_observations"]


def test_payload_probe_harness_marks_oob_interaction_for_embedded_callback_url(monkeypatch: Any) -> None:
    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 200,
            "content_type": "application/xml",
            "body_length": 11,
            "body_hash": spec["name"],
            "body_preview": "<ok></ok>",
            "elapsed_ms": 55,
        }

    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)
    monkeypatch.setattr(
        oob_actions,
        "oob_interaction_harness",
        lambda agent_state, action, **kwargs: {
            "success": True,
            "interactions": [
                {
                    "label": "variant",
                    "protocol": "http",
                    "raw_event": {"url": "http://cb.test/xxe"},
                }
            ],
        },
    )

    state = DummyState("agent_root")
    result = validation_actions.payload_probe_harness(
        agent_state=state,
        target="web",
        component="import",
        surface="Encoded XXE callback probe",
        vulnerability_type="xxe",
        parameter_name="xml_body",
        base_request={
            "method": "POST",
            "url": "https://app.test/import",
            "headers": {"Content-Type": "application/xml"},
            "body": "<root>safe</root>",
        },
        payloads=[
            {
                "payload": (
                    "%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C%21DOCTYPE%20root%20%5B"
                    "%3C%21ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2Fcb.test%2Fxxe%22%3E"
                    "%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E"
                ),
                "strategy": "external_entity_fetch",
                "encoding": "url",
            }
        ],
        baseline_value="<root>safe</root>",
        injection_mode="raw_body",
        oob_harness_id="oob_xxe",
        poll_oob=True,
    )

    assert result["success"] is True
    assert any(
        item.get("oob_interaction")
        for item in result["observations"]
        if item["name"] != "baseline"
    )


def test_payload_probe_harness_mutates_nested_json_field(monkeypatch: Any) -> None:
    captured_requests: list[dict[str, Any]] = []

    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        captured_requests.append(spec)
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 20,
            "body_hash": spec["name"],
            "body_preview": '{"ok":true}',
            "elapsed_ms": 90,
        }

    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)

    state = DummyState("agent_root")
    result = validation_actions.payload_probe_harness(
        agent_state=state,
        target="web",
        component="search",
        surface="Nested JSON SQLi probe",
        vulnerability_type="sqli",
        parameter_name="filters.query",
        base_request={
            "method": "POST",
            "url": "https://app.test/search",
            "json_body": {"filters": {"query": "books", "page": 1}},
        },
        payloads=[{"payload": "' OR SLEEP(5)--", "strategy": "time_based", "encoding": "raw"}],
        baseline_value="books",
        injection_mode="json",
    )

    assert result["success"] is True
    assert captured_requests[0]["json_body"]["filters"]["query"] == "books"
    assert captured_requests[1]["json_body"]["filters"]["query"] == "' OR SLEEP(5)--"
    assert captured_requests[1]["json_body"]["filters"]["page"] == 1


def test_payload_probe_harness_flags_semantic_matcher_hits_for_path_traversal(monkeypatch: Any) -> None:
    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        if spec["name"] == "baseline":
            return {
                "name": "baseline",
                "method": spec["method"],
                "url": spec["url"],
                "status_code": 200,
                "content_type": "text/plain",
                "body_length": 16,
                "body_hash": "base",
                "body_preview": "download ready",
                "elapsed_ms": 50,
            }
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 200,
            "content_type": "text/plain",
            "body_length": 64,
            "body_hash": "passwd",
            "body_preview": "root:x:0:0:root:/root:/bin/bash",
            "elapsed_ms": 55,
        }

    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)

    state = DummyState("agent_root")
    result = validation_actions.payload_probe_harness(
        agent_state=state,
        target="web",
        component="download",
        surface="File download traversal probe",
        vulnerability_type="path_traversal",
        parameter_name="file",
        base_request={"method": "GET", "url": "https://app.test/download?file=report.pdf"},
        payloads=[
            {
                "payload": "../../../../etc/passwd",
                "strategy": "unix_file_read",
                "encoding": "raw",
                "expected_markers": ["root:x:0:0"],
            }
        ],
        baseline_value="report.pdf",
    )

    assert result["success"] is True
    suspicious = result["triage_result"]["suspicious_observations"]
    assert suspicious
    assert suspicious[0]["top_issue_type"] == "semantic_indicator"
    assert "root:x:0:0" in suspicious[0]["matcher_hits"]


def test_payload_probe_harness_supports_raw_body_xml_mutation(monkeypatch: Any) -> None:
    captured_requests: list[dict[str, Any]] = []

    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        captured_requests.append(spec)
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 200,
            "content_type": "application/xml",
            "body_length": 20,
            "body_hash": spec["name"],
            "body_preview": "<ok/>",
            "elapsed_ms": 40,
        }

    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)

    state = DummyState("agent_root")
    result = validation_actions.payload_probe_harness(
        agent_state=state,
        target="web",
        component="import",
        surface="Raw XML XXE probe",
        vulnerability_type="xxe",
        parameter_name="xml_body",
        base_request={
            "method": "POST",
            "url": "https://app.test/import",
            "headers": {"Content-Type": "application/xml"},
            "body": "<root>safe</root>",
        },
        payloads=[
            {
                "payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://cb.test\">]><root>&xxe;</root>",
                "strategy": "external_entity_fetch",
                "encoding": "raw",
            }
        ],
        baseline_value="<root>safe</root>",
        injection_mode="raw_body",
    )

    assert result["success"] is True
    assert captured_requests[0]["body"] == "<root>safe</root>"
    assert "<!DOCTYPE root" in captured_requests[1]["body"]


def test_payload_probe_harness_flags_dangerous_variant_acceptance(monkeypatch: Any) -> None:
    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 24,
            "body_hash": "samehash",
            "body_preview": '{"status":"uploaded"}',
            "elapsed_ms": 70,
        }

    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)

    state = DummyState("agent_root")
    result = validation_actions.payload_probe_harness(
        agent_state=state,
        target="web",
        component="upload",
        surface="Upload validation bypass probe",
        vulnerability_type="file_upload",
        parameter_name="multipart_body",
        base_request={
            "method": "POST",
            "url": "https://app.test/upload",
            "headers": {"Content-Type": "multipart/form-data; boundary=abc"},
            "body": "--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"avatar.jpg\"\r\n\r\nJPEG\r\n--abc--\r\n",
        },
        payloads=[
            {
                "payload": "--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n<?php echo 49; ?>\r\n--abc--\r\n",
                "strategy": "php_extension_swap",
                "encoding": "raw",
                "expected_rejection": True,
            }
        ],
        baseline_value="--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"avatar.jpg\"\r\n\r\nJPEG\r\n--abc--\r\n",
        injection_mode="raw_body",
    )

    assert result["success"] is True
    assert result["triage_result"]["suspicious_observations"][0]["top_issue_type"] == "dangerous_variant_acceptance"


def test_jwt_variant_harness_flags_forged_token_parity(monkeypatch: Any) -> None:
    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        auth_value = str((spec.get("headers") or {}).get("Authorization") or "")
        if spec["name"] == "baseline_valid":
            return {
                "name": spec["name"],
                "method": spec["method"],
                "url": spec["url"],
                "status_code": 200,
                "content_type": "application/json",
                "body_length": 30,
                "body_hash": "samehash",
                "body_preview": '{"sub":"1","role":"user"}',
                "elapsed_ms": 75,
            }
        if "Bearer " not in auth_value:
            return {
                "name": spec["name"],
                "method": spec["method"],
                "url": spec["url"],
                "status_code": 401,
                "content_type": "application/json",
                "body_length": 16,
                "body_hash": "deny",
                "body_preview": '{"error":"auth"}',
                "elapsed_ms": 50,
            }
        if spec["name"] == "invalid_signature":
            return {
                "name": spec["name"],
                "method": spec["method"],
                "url": spec["url"],
                "status_code": 200,
                "content_type": "application/json",
                "body_length": 30,
                "body_hash": "samehash",
                "body_preview": '{"sub":"1","role":"user"}',
                "elapsed_ms": 80,
            }
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 401,
            "content_type": "application/json",
            "body_length": 16,
            "body_hash": "deny",
            "body_preview": '{"error":"auth"}',
            "elapsed_ms": 60,
        }

    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)

    state = DummyState("agent_root")
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ."
        "signature"
    )
    result = validation_actions.jwt_variant_harness(
        agent_state=state,
        target="web",
        component="auth",
        surface="Profile JWT validation",
        base_request={"method": "GET", "url": "https://app.test/api/profile"},
        jwt_token=token,
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert any(item["name"] == "invalid_signature" for item in result["suspicious_variants"])
    assert result["coverage_result"]["record"]["status"] == "in_progress"
    assert any(item["vulnerability_type"] == "jwt" for item in ledger["hypotheses"])


def test_jwt_variant_harness_auto_spawns_impact_agent_for_signature_bypass(
    monkeypatch: Any,
) -> None:
    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        if spec["name"] == "baseline_valid":
            return {
                "name": spec["name"],
                "method": spec["method"],
                "url": spec["url"],
                "status_code": 200,
                "content_type": "application/json",
                "body_length": 30,
                "body_hash": "samehash",
                "body_preview": '{"sub":"1","role":"user"}',
                "elapsed_ms": 75,
            }
        if spec["name"] == "invalid_signature":
            return {
                "name": spec["name"],
                "method": spec["method"],
                "url": spec["url"],
                "status_code": 200,
                "content_type": "application/json",
                "body_length": 30,
                "body_hash": "samehash",
                "body_preview": '{"sub":"1","role":"user"}',
                "elapsed_ms": 80,
            }
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 401,
            "content_type": "application/json",
            "body_length": 16,
            "body_hash": "deny",
            "body_preview": '{"error":"auth"}',
            "elapsed_ms": 60,
        }

    spawn_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)
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
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ."
        "signature"
    )
    result = validation_actions.jwt_variant_harness(
        agent_state=state,
        target="web",
        component="auth",
        surface="Profile JWT validation",
        base_request={"method": "GET", "url": "https://app.test/api/profile"},
        jwt_token=token,
    )

    assert result["success"] is True
    assert result["hypothesis_result"]["record"]["status"] == "validated"
    assert result["followup_agent_result"]["success"] is True
    assert spawn_calls[0]["target"] == "web"
    assert spawn_calls[0]["max_agents"] == 1
    assert spawn_calls[0]["inherit_context"] is True
    assert spawn_calls[0]["hypothesis_ids"] == [result["hypothesis_result"]["hypothesis_id"]]


def test_jwt_variant_harness_supports_cookie_tokens(monkeypatch: Any) -> None:
    captured_specs: list[dict[str, Any]] = []

    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        captured_specs.append(spec)
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 200 if spec.get("cookies", {}).get("session") else 401,
            "content_type": "application/json",
            "body_length": 24,
            "body_hash": "samehash" if spec.get("cookies", {}).get("session") else "deny",
            "body_preview": '{"ok":true}' if spec.get("cookies", {}).get("session") else '{"error":"auth"}',
            "elapsed_ms": 70,
        }

    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)

    state = DummyState("agent_root")
    token = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ."
        "signature"
    )
    result = validation_actions.jwt_variant_harness(
        agent_state=state,
        target="web",
        component="auth",
        surface="Cookie JWT validation",
        base_request={
            "method": "GET",
            "url": "https://app.test/api/profile",
            "cookies": {"session": token},
        },
        jwt_token=token,
        token_location="cookie",
        cookie_name="session",
    )

    assert result["success"] is True
    assert result["token_carrier"]["location"] == "cookie"
    assert captured_specs[0]["cookies"]["session"] == token
    assert all("Authorization" not in spec.get("headers", {}) for spec in captured_specs)


def test_jwt_variant_harness_supports_query_tokens(monkeypatch: Any) -> None:
    captured_specs: list[dict[str, Any]] = []

    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        captured_specs.append(spec)
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 200,
            "content_type": "application/json",
            "body_length": 24,
            "body_hash": "samehash",
            "body_preview": '{"ok":true}',
            "elapsed_ms": 70,
        }

    monkeypatch.setattr(validation_actions, "_execute_request", fake_execute_request)

    state = DummyState("agent_root")
    token = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ."
        "signature"
    )
    result = validation_actions.jwt_variant_harness(
        agent_state=state,
        target="web",
        component="auth",
        surface="Query JWT validation",
        base_request={
            "method": "GET",
            "url": f"https://app.test/api/profile?token={token}",
        },
        jwt_token=token,
        token_location="query",
        query_parameter_name="token",
    )

    assert result["success"] is True
    assert result["token_carrier"]["location"] == "query"
    assert "token=" in captured_specs[0]["url"]
    assert all("Authorization" not in spec.get("headers", {}) for spec in captured_specs)
