# ruff: noqa: E402, ARG002, I001

import sys
import types
from datetime import UTC, datetime
from pathlib import Path
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
from strix.tools.assessment import assessment_actions
from strix.tools.assessment import assessment_orchestration_actions as orchestration_actions
from strix.tools.assessment import assessment_surface_review_actions as surface_review_actions


class DummyState:
    def __init__(self, agent_id: str, parent_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.parent_id = parent_id
        self.context: dict[str, Any] = {}

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value


class ThreadState:
    def __init__(self, *, agent_id: str, agent_name: str, parent_id: str | None, task: str) -> None:
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.parent_id = parent_id
        self.task = task
        self.context: dict[str, Any] = {}
        self.messages: list[dict[str, Any]] = []
        self.stop_requested = False
        self.start_time = datetime.now(UTC).isoformat()

    def add_message(self, role: str, content: Any) -> None:
        self.messages.append({"role": role, "content": content})

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value

    def model_dump(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "parent_id": self.parent_id,
            "task": self.task,
            "context": dict(self.context),
            "messages": list(self.messages),
            "stop_requested": self.stop_requested,
            "start_time": self.start_time,
        }


class DummyTimer:
    def __init__(self) -> None:
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()
    agents_graph_actions._agent_messages.clear()
    agents_graph_actions._running_agents.clear()
    agents_graph_actions._agent_instances.clear()
    agents_graph_actions._agent_states.clear()
    agents_graph_actions._root_agent_id = None


def _seed_review(state: DummyState) -> None:
    surface_review_actions._surface_review_storage[state.agent_id] = {
        "web": {
            "target": "web",
            "updated_at": "2026-04-01T00:00:00+00:00",
            "report": {
                "summary": {
                    "host_count": 1,
                    "path_count": 2,
                    "blind_spot_count": 1,
                    "needs_more_data": True,
                },
                "priorities": {
                    "top_targets_next": [
                        {
                            "host": "api.app.test",
                            "preliminary_type": "api",
                            "coverage_status": "mapped",
                            "signal_classification": "confirmed",
                            "priority": "critical",
                        }
                    ],
                    "top_endpoints_next": [
                        {
                            "host": "api.app.test",
                            "path": "/api/admin/users",
                            "methods": ["GET", "POST"],
                            "priority": "high",
                            "coverage_status": "mapped",
                            "signal_classification": "suspected",
                            "bug_classes": ["authorization", "bola/idor"],
                            "params": {"query": ["tenant_id"], "body": ["role"], "path": []},
                            "trust_boundaries": ["tenant boundary", "privileged-role boundary"],
                            "application_module": "api",
                        }
                    ],
                    "top_params_objects": [
                        {
                            "host": "api.app.test",
                            "path": "/api/admin/users",
                            "parameter": "callback_url",
                            "locations": ["query"],
                            "bug_classes": ["ssrf", "open redirect"],
                            "pivot_point": True,
                        }
                    ],
                    "top_recon_value_exposures": [
                        {
                            "host": "api.app.test",
                            "path": "/openapi.json",
                            "kind": "openapi_spec",
                            "exposure_class": "chain-enabling exposure",
                        }
                    ],
                    "top_chain_opportunities": [
                        {
                            "summary": "Exposed docs -> hidden endpoint -> authz drift",
                            "boundary": "authz / object boundary",
                            "assets": ["api.app.test/api/admin/users"],
                        }
                    ],
                    "top_blind_spots": [
                        {
                            "area": "workflow coverage",
                            "detail": "No reconstructed state-changing workflow is stored yet; needs more data.",
                            "target_asset": "api.app.test",
                        }
                    ],
                },
            },
        }
    }


def _seed_phase_heavy_review(state: DummyState) -> None:
    surface_review_actions._surface_review_storage[state.agent_id] = {
        "web": {
            "target": "web",
            "updated_at": "2026-04-01T00:00:00+00:00",
            "report": {
                "summary": {
                    "host_count": 2,
                    "path_count": 8,
                    "blind_spot_count": 2,
                    "needs_more_data": True,
                },
                "priorities": {
                    "top_targets_next": [
                        {
                            "host": "edge.app.test",
                            "preliminary_type": "api",
                            "coverage_status": "mapped",
                            "signal_classification": "suspected",
                            "priority": "normal",
                        }
                    ],
                    "top_endpoints_next": [
                        {
                            "host": "api.app.test",
                            "path": "/api/admin/users",
                            "methods": ["GET"],
                            "priority": "critical",
                            "coverage_status": "mapped",
                            "signal_classification": "suspected",
                            "bug_classes": ["authorization", "bola/idor"],
                            "params": {"query": ["tenant_id"], "body": [], "path": []},
                            "trust_boundaries": ["tenant boundary"],
                            "application_module": "api",
                        },
                        {
                            "host": "api.app.test",
                            "path": "/api/billing/export",
                            "methods": ["POST"],
                            "priority": "critical",
                            "coverage_status": "mapped",
                            "signal_classification": "suspected",
                            "bug_classes": ["business logic", "authorization"],
                            "params": {"query": [], "body": ["format"], "path": []},
                            "trust_boundaries": ["billing boundary"],
                            "application_module": "api",
                        },
                    ],
                    "top_params_objects": [
                        {
                            "host": "api.app.test",
                            "path": "/api/admin/users",
                            "parameter": "tenant_id",
                            "locations": ["query"],
                            "bug_classes": ["idor"],
                            "pivot_point": True,
                        }
                    ],
                    "top_recon_value_exposures": [
                        {
                            "host": "api.app.test",
                            "path": "/swagger.json",
                            "kind": "openapi_spec",
                            "exposure_class": "chain-enabling exposure",
                        }
                    ],
                    "top_chain_opportunities": [
                        {
                            "summary": "Swagger leak -> hidden admin action -> authz drift",
                            "boundary": "admin boundary",
                            "assets": ["api.app.test/api/admin/users"],
                        }
                    ],
                    "top_blind_spots": [
                        {
                            "area": "workflow coverage",
                            "detail": "No reconstructed billing workflow yet; needs more data.",
                            "target_asset": "api.app.test",
                        }
                    ],
                },
            },
        }
    }


def _seed_layered_review(state: DummyState) -> None:
    surface_review_actions._surface_review_storage[state.agent_id] = {
        "web": {
            "target": "web",
            "updated_at": "2026-04-01T00:00:00+00:00",
            "report": {
                "summary": {
                    "host_count": 1,
                    "service_count": 1,
                    "path_count": 3,
                    "object_count": 1,
                    "needs_more_data": True,
                },
                "priorities": {
                    "top_targets_next": [],
                    "top_endpoints_next": [],
                    "top_params_objects": [],
                    "top_recon_value_exposures": [],
                    "top_chain_opportunities": [],
                    "top_blind_spots": [],
                },
                "service_inventory": [
                    {
                        "host": "api.app.test",
                        "port": 8443,
                        "protocol": "https",
                        "fingerprint": ["needs more data"],
                        "app_family": ["api"],
                        "auth_wall": "protected",
                        "privilege_boundary": ["tenant boundary"],
                        "bug_classes": ["authorization"],
                        "coverage_status": "mapped",
                    }
                ],
                "application_inventory": [
                    {
                        "host": "api.app.test",
                        "application_module": "api",
                        "root_paths": ["/api"],
                        "major_sections": ["auth", "billing"],
                        "hidden_routes": ["/api/internal/export"],
                        "docs_endpoints": ["/swagger.json"],
                        "config_artifacts": [],
                        "backup_artifacts": [],
                        "upload_surfaces": [],
                        "download_surfaces": ["/api/export"],
                        "auth_surfaces": ["/api/login"],
                        "billing_surfaces": ["/api/billing/export"],
                        "bug_classes": ["authorization", "business logic"],
                        "coverage_status": "mapped",
                    }
                ],
                "parameter_object_review": {
                    "parameters": [],
                    "objects": [
                        {
                            "host": "api.app.test",
                            "object_type": "invoice",
                            "related_paths": ["/api/invoices/:invoice_id"],
                            "identifiers": ["invoice_id", "tenant_id"],
                            "fields": ["status", "amount", "tenant_id"],
                            "trust_boundaries": ["authorization boundary", "business-state boundary"],
                            "bug_classes": ["authorization", "business logic abuse"],
                            "coverage_status": "mapped",
                        }
                    ],
                },
                "coverage_ledger": {
                    "role_boundary": [
                        {
                            "boundary": "tenant A/B",
                            "status": "needs more data",
                            "signal_classification": "blind-spot",
                        }
                    ],
                    "bug_class": [
                        {
                            "bug_class": "Authorization",
                            "status": "blocked by missing data",
                            "surface_signal_count": 1,
                            "hypothesis_count": 0,
                        }
                    ],
                },
            },
        }
    }


def test_spawn_attack_surface_agents_dry_run_builds_phase_swarm(monkeypatch: Any) -> None:
    state = DummyState("agent_root")
    _seed_review(state)

    called = False

    def fake_create_agent(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"success": True}

    monkeypatch.setattr(orchestration_actions, "create_agent", fake_create_agent)

    result = orchestration_actions.spawn_attack_surface_agents(
        agent_state=state,
        target="web",
        max_agents=6,
        dry_run=True,
    )

    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["created_count"] == 6
    assert called is False
    kinds = {item["kind"] for item in result["created_agents"]}
    assert "host-recon" in kinds
    assert "endpoint-validation" in kinds
    assert "param-pivot" in kinds
    assert "exposure-chain" in kinds
    assert "chain-validation" in kinds
    assert "blind-spot-closure" in kinds


def test_spawn_attack_surface_agents_skips_active_duplicates(monkeypatch: Any) -> None:
    state = DummyState("agent_root")
    _seed_review(state)
    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }
    agents_graph_actions._agent_graph["nodes"]["agent_child"] = {
        "id": "agent_child",
        "name": "P1 Recon api.app.test",
        "task": "Delegation key: recon-host|api.app.test\nPhase: Phase 1 layered reconnaissance and surface expansion",
        "status": "running",
        "parent_id": "agent_root",
    }

    created_calls: list[dict[str, Any]] = []

    def fake_create_agent(
        agent_state: Any,
        task: str,
        name: str,
        inherit_context: bool = True,
        skills: str | None = None,
    ) -> dict[str, Any]:
        created_calls.append({"task": task, "name": name, "skills": skills})
        return {"success": True, "agent_id": f"agent_{len(created_calls)}", "active_skills": skills.split(",") if skills else []}

    monkeypatch.setattr(orchestration_actions, "create_agent", fake_create_agent)

    result = orchestration_actions.spawn_attack_surface_agents(
        agent_state=state,
        target="web",
        max_agents=2,
        dry_run=False,
    )

    assert result["success"] is True
    assert result["created_count"] == 2
    assert result["skipped_count"] == 1
    assert any(item["dedupe_key"] == "recon-host|api.app.test" for item in result["skipped_agents"])
    assert created_calls[0]["name"] != "P1 Recon api.app.test"
    assert "auto-refreshes follow-up when this child finishes" in created_calls[0]["task"]


def test_spawn_attack_surface_agents_host_recon_task_requires_passive_fallback_for_weak_unresolved_host(
    monkeypatch: Any,
) -> None:
    state = DummyState("agent_root")
    surface_review_actions._surface_review_storage[state.agent_id] = {
        "web": {
            "target": "web",
            "updated_at": "2026-04-01T00:00:00+00:00",
            "report": {
                "summary": {
                    "host_count": 1,
                    "path_count": 0,
                    "blind_spot_count": 1,
                    "needs_more_data": True,
                },
                "priorities": {
                    "top_targets_next": [
                        {
                            "host": "dashboard.app.test",
                            "preliminary_type": "admin",
                            "coverage_status": "mapped",
                            "signal_classification": "weak-signal",
                            "priority": "low",
                            "resolve_status": "needs more data",
                            "sources": ["scope_guess"],
                            "notes": ["Guessed from naming pattern under app.test; needs more data."],
                        }
                    ],
                    "top_endpoints_next": [],
                    "top_params_objects": [],
                    "top_recon_value_exposures": [],
                    "top_chain_opportunities": [],
                    "top_blind_spots": [],
                },
            },
        }
    }

    create_calls: list[dict[str, Any]] = []

    monkeypatch.setattr(
        orchestration_actions,
        "create_agent",
        lambda agent_state, task, name, inherit_context=True, skills=None: create_calls.append(
            {"task": task, "name": name, "skills": skills}
        )
        or {"success": True, "agent_id": "agent_weak", "active_skills": skills.split(",") if skills else []},
    )

    result = orchestration_actions.spawn_attack_surface_agents(
        agent_state=state,
        target="web",
        max_agents=1,
        dry_run=False,
    )

    assert result["success"] is True
    assert result["created_count"] == 1
    assert create_calls[0]["name"] == "P1 Recon dashboard.app.test"
    assert "Signal classification: weak-signal" in create_calls[0]["task"]
    assert "Resolve status: needs more data" in create_calls[0]["task"]
    assert "do not stop after a single failed request" in create_calls[0]["task"]
    assert "Exhaust passive/off-host recon before concluding blocked" in create_calls[0]["task"]
    assert "Only attempt port scanning or directory fuzzing when you have a resolvable host" in create_calls[0]["task"]
    assert "subfinder" in str(create_calls[0]["skills"])
    assert "ffuf" in str(create_calls[0]["skills"])


def test_spawn_attack_surface_agents_coverage_first_reserves_phase_mix(monkeypatch: Any) -> None:
    state = DummyState("agent_root")
    _seed_phase_heavy_review(state)

    monkeypatch.setattr(
        orchestration_actions,
        "create_agent",
        lambda *args, **kwargs: {"success": True},
    )

    result = orchestration_actions.spawn_attack_surface_agents(
        agent_state=state,
        target="web",
        max_agents=3,
        dry_run=True,
        strategy="coverage_first",
    )

    assert result["success"] is True
    assert result["strategy"] == "coverage_first"
    assert result["recommended_count"] == 3
    assert [item["phase"] for item in result["created_agents"]] == [
        orchestration_actions.PHASE_RECON,
        orchestration_actions.PHASE_VALIDATION,
        orchestration_actions.PHASE_GAP_CLOSURE,
    ]
    assert result["phase_plan"]["selected_phase_counts"][orchestration_actions.PHASE_CHAINING] == 0


def test_spawn_attack_surface_agents_depth_first_biases_validation_and_chains(
    monkeypatch: Any,
) -> None:
    state = DummyState("agent_root")
    _seed_phase_heavy_review(state)

    monkeypatch.setattr(
        orchestration_actions,
        "create_agent",
        lambda *args, **kwargs: {"success": True},
    )

    result = orchestration_actions.spawn_attack_surface_agents(
        agent_state=state,
        target="web",
        max_agents=2,
        dry_run=True,
        strategy="depth_first",
    )

    assert result["success"] is True
    assert result["strategy"] == "depth_first"
    assert [item["phase"] for item in result["created_agents"]] == [
        orchestration_actions.PHASE_VALIDATION,
        orchestration_actions.PHASE_CHAINING,
    ]
    assert result["phase_plan"]["selected_phase_counts"][orchestration_actions.PHASE_RECON] == 0
    assert result["phase_plan"]["selected_phase_counts"][orchestration_actions.PHASE_GAP_CLOSURE] == 0


def test_spawn_attack_surface_agents_includes_layered_service_module_object_and_role_tasks(
    monkeypatch: Any,
) -> None:
    state = DummyState("agent_root")
    _seed_layered_review(state)

    monkeypatch.setattr(
        orchestration_actions,
        "create_agent",
        lambda *args, **kwargs: {"success": True},
    )

    result = orchestration_actions.spawn_attack_surface_agents(
        agent_state=state,
        target="web",
        max_agents=5,
        dry_run=True,
        strategy="coverage_first",
    )

    assert result["success"] is True
    kinds = {item["kind"] for item in result["created_agents"]}
    assert "service-recon" in kinds
    assert "app-surface-review" in kinds
    assert "object-boundary" in kinds
    assert "role-boundary-closure" in kinds or "bug-class-gap-closure" in kinds
    assert result["phase_plan"]["available_kind_counts"]["service-recon"] == 1


def test_spawn_strong_signal_agents_dry_run_selects_evidenced_hypothesis(monkeypatch: Any) -> None:
    state = DummyState("agent_root")
    hypothesis_result = assessment_actions.record_hypothesis(
        agent_state=state,
        hypothesis="Authorization drift may expose cross-tenant admin user data",
        target="web",
        component="focus:authz:api.app.test/api/admin/users",
        vulnerability_type="authorization",
        status="open",
        priority="critical",
        rationale="Correlated runtime and tool signals indicate unauthorized admin exposure.",
    )
    assessment_actions.record_evidence(
        agent_state=state,
        title="Unauthorized admin users response",
        details=(
            "GET https://api.app.test/api/admin/users returned data for another tenant; "
            "browser confirmed session stayed low-privileged."
        ),
        source="runtime",
        target="web",
        component="focus:authz:api.app.test/api/admin/users",
        related_hypothesis_id=str(hypothesis_result["hypothesis_id"]),
    )

    monkeypatch.setattr(
        orchestration_actions,
        "create_agent",
        lambda *args: {"success": True},
    )

    result = orchestration_actions.spawn_strong_signal_agents(
        agent_state=state,
        target="web",
        max_agents=1,
        dry_run=True,
    )

    assert result["success"] is True
    assert result["candidate_count"] == 1
    assert result["recommended_count"] == 1
    assert result["created_agents"][0]["hypothesis_id"] == hypothesis_result["hypothesis_id"]
    assert result["created_agents"][0]["suggested_focus"] == "authz"
    assert result["created_agents"][0]["candidate_urls"] == [
        "https://api.app.test/api/admin/users"
    ]


def test_spawn_strong_signal_agents_task_instructs_next_chain_spawn(monkeypatch: Any) -> None:
    state = DummyState("agent_root")
    hypothesis_result = assessment_actions.record_hypothesis(
        agent_state=state,
        hypothesis="Authorization drift may expose cross-tenant admin user data",
        target="web",
        component="focus:authz:api.app.test/api/admin/users",
        vulnerability_type="authorization",
        status="open",
        priority="critical",
        rationale="Correlated runtime and tool signals indicate unauthorized admin exposure.",
    )
    assessment_actions.record_evidence(
        agent_state=state,
        title="Unauthorized admin users response",
        details="GET https://api.app.test/api/admin/users leaked another tenant.",
        source="runtime",
        target="web",
        component="focus:authz:api.app.test/api/admin/users",
        related_hypothesis_id=str(hypothesis_result["hypothesis_id"]),
    )

    create_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        orchestration_actions,
        "create_agent",
        lambda agent_state, task, name, inherit_context, skills: create_calls.append(
            {"task": task, "name": name, "skills": skills}
        )
        or {
            "success": True,
            "agent_id": "agent_signal",
            "active_skills": skills.split(",") if skills else [],
        },
    )

    result = orchestration_actions.spawn_strong_signal_agents(
        agent_state=state,
        target="web",
        max_agents=1,
        dry_run=False,
        inherit_context=True,
    )

    assert result["success"] is True
    assert result["created_count"] == 1
    assert "spawn_impact_chain_agents" in create_calls[0]["task"]
    assert "Do not manually launch another orchestration round from this child." in create_calls[0]["task"]
    assert str(hypothesis_result["hypothesis_id"]) in create_calls[0]["task"]


def test_spawn_strong_signal_agents_backfills_when_duplicate_is_active(monkeypatch: Any) -> None:
    state = DummyState("agent_root")
    first = assessment_actions.record_hypothesis(
        agent_state=state,
        hypothesis="Authorization drift may expose cross-tenant admin user data",
        target="web",
        component="focus:authz:api.app.test/api/admin/users",
        vulnerability_type="authorization",
        status="open",
        priority="critical",
        rationale="Correlated unauthorized access signal.",
    )
    second = assessment_actions.record_hypothesis(
        agent_state=state,
        hypothesis="Billing export workflow may allow replay abuse",
        target="web",
        component="focus:workflow_race:api.app.test/api/billing/export",
        vulnerability_type="business_logic",
        status="open",
        priority="high",
        rationale="Validated duplicate submission pattern on export workflow.",
    )
    assessment_actions.record_evidence(
        agent_state=state,
        title="Unauthorized admin users response",
        details="GET https://api.app.test/api/admin/users leaked another tenant.",
        source="runtime",
        target="web",
        component="focus:authz:api.app.test/api/admin/users",
        related_hypothesis_id=str(first["hypothesis_id"]),
    )
    assessment_actions.record_evidence(
        agent_state=state,
        title="Billing export duplicate processing",
        details="POST https://api.app.test/api/billing/export processed replayed request twice.",
        source="tool",
        target="web",
        component="focus:workflow_race:api.app.test/api/billing/export",
        related_hypothesis_id=str(second["hypothesis_id"]),
    )

    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }
    agents_graph_actions._agent_graph["nodes"]["agent_child"] = {
        "id": "agent_child",
        "name": "Validate authorization on api.app.test/api/admin/users",
        "task": f"Delegation key: validate-hypothesis|{first['hypothesis_id']}\nPhase: Narrow strong-signal validation and impact escalation",
        "status": "running",
        "parent_id": "agent_root",
    }

    create_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        orchestration_actions,
        "create_agent",
        lambda agent_state, task, name, inherit_context, skills: create_calls.append(
            {"task": task, "name": name, "skills": skills}
        )
        or {
            "success": True,
            "agent_id": "agent_new",
            "active_skills": skills.split(",") if skills else [],
        },
    )

    result = orchestration_actions.spawn_strong_signal_agents(
        agent_state=state,
        target="web",
        max_agents=1,
        dry_run=False,
    )

    assert result["success"] is True
    assert result["created_count"] == 1
    assert result["skipped_count"] == 1
    assert result["created_agents"][0]["hypothesis_id"] == second["hypothesis_id"]
    assert any(
        item["dedupe_key"] == f"validate-hypothesis|{first['hypothesis_id']}"
        for item in result["skipped_agents"]
    )
    assert "api.app.test/api/billing/export" in create_calls[0]["name"]


def test_spawn_impact_chain_agents_uses_review_context(monkeypatch: Any) -> None:
    state = DummyState("agent_root")
    _seed_review(state)
    hypothesis_result = assessment_actions.record_hypothesis(
        agent_state=state,
        hypothesis="Authorization drift may expose cross-tenant admin user data",
        target="web",
        component="focus:authz:api.app.test/api/admin/users",
        vulnerability_type="authorization",
        status="validated",
        priority="critical",
        rationale="Browser confirmed another tenant's admin user data was reachable.",
    )
    assessment_actions.record_evidence(
        agent_state=state,
        title="Cross-tenant admin data exposure",
        details=(
            "GET https://api.app.test/api/admin/users returned another tenant's records; "
            "browser confirmed the low-privileged viewer context."
        ),
        source="runtime",
        target="web",
        component="focus:authz:api.app.test/api/admin/users",
        related_hypothesis_id=str(hypothesis_result["hypothesis_id"]),
    )

    monkeypatch.setattr(
        orchestration_actions,
        "create_agent",
        lambda *args, **kwargs: {"success": True},
    )

    result = orchestration_actions.spawn_impact_chain_agents(
        agent_state=state,
        target="web",
        max_agents=1,
        dry_run=True,
    )

    assert result["success"] is True
    assert result["candidate_count"] == 1
    assert result["created_agents"][0]["hypothesis_id"] == hypothesis_result["hypothesis_id"]
    assert result["created_agents"][0]["review_chain_summaries"] == [
        "Exposed docs -> hidden endpoint -> authz drift"
    ]
    assert result["created_agents"][0]["review_exposure_summaries"] == [
        "api.app.test/openapi.json (openapi_spec)"
    ]


def test_spawn_impact_chain_agents_task_instructs_round_followup(monkeypatch: Any) -> None:
    state = DummyState("agent_root")
    _seed_review(state)
    hypothesis_result = assessment_actions.record_hypothesis(
        agent_state=state,
        hypothesis="Authorization drift may expose cross-tenant admin user data",
        target="web",
        component="focus:authz:api.app.test/api/admin/users",
        vulnerability_type="authorization",
        status="validated",
        priority="critical",
        rationale="Browser confirmed another tenant's admin user data was reachable.",
    )
    assessment_actions.record_evidence(
        agent_state=state,
        title="Cross-tenant admin data exposure",
        details="GET https://api.app.test/api/admin/users returned another tenant's records.",
        source="runtime",
        target="web",
        component="focus:authz:api.app.test/api/admin/users",
        related_hypothesis_id=str(hypothesis_result["hypothesis_id"]),
    )

    create_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        orchestration_actions,
        "create_agent",
        lambda agent_state, task, name, inherit_context, skills: create_calls.append(
            {"task": task, "name": name, "skills": skills}
        )
        or {
            "success": True,
            "agent_id": "agent_chain",
            "active_skills": skills.split(",") if skills else [],
        },
    )

    result = orchestration_actions.spawn_impact_chain_agents(
        agent_state=state,
        target="web",
        max_agents=1,
        dry_run=False,
        inherit_context=True,
    )

    assert result["success"] is True
    assert result["created_count"] == 1
    assert "Do not manually launch another orchestration round from this child." in create_calls[0]["task"]


def test_trigger_attack_surface_orchestration_on_child_completion_uses_root_targets(
    monkeypatch: Any,
) -> None:
    root_state = DummyState("agent_root")
    child_state = DummyState("agent_child", parent_id="agent_root")
    _seed_review(root_state)
    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }
    agents_graph_actions._agent_graph["nodes"]["agent_child"] = {
        "id": "agent_child",
        "name": "Child",
        "task": (
            "Delegation key: validate-endpoint|api.app.test|/api/admin/users\n"
            "Target label: web\n"
            "Continuation:\n"
            "- The root orchestrator already tracks target 'web' and auto-refreshes follow-up when this child finishes.\n"
            "- Do not manually launch another orchestration round from this child."
        ),
        "status": "completed",
        "parent_id": "agent_root",
    }

    round_calls: list[dict[str, Any]] = []

    monkeypatch.setattr(
        orchestration_actions,
        "run_attack_surface_orchestration_round",
        lambda agent_state, target, **kwargs: round_calls.append(
            {"agent_id": agent_state.agent_id, "target": target, **kwargs}
        )
        or {
            "success": True,
            "skipped": False,
            "round_number": 2,
        },
    )

    result = orchestration_actions.trigger_attack_surface_orchestration_on_child_completion(
        agent_state=child_state,
        completion_status="completed",
        debounce_seconds=0,
    )

    assert result["success"] is True
    assert result["triggered"] is True
    assert result["queued"] is False
    assert result["triggered_targets"] == ["web"]
    assert round_calls[0]["agent_id"] == "agent_root"
    assert round_calls[0]["target"] == "web"
    assert round_calls[0]["require_new_data"] is True


def test_trigger_attack_surface_orchestration_on_child_completion_coalesces_events(
    monkeypatch: Any,
) -> None:
    root_state = DummyState("agent_root")
    _seed_review(root_state)
    child_a = DummyState("agent_child_a", parent_id="agent_root")
    child_b = DummyState("agent_child_b", parent_id="agent_root")
    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }
    agents_graph_actions._agent_graph["nodes"]["agent_child_a"] = {
        "id": "agent_child_a",
        "name": "Child A",
        "task": "call run_attack_surface_orchestration_round(target='web', require_new_data=True)",
        "status": "completed",
        "parent_id": "agent_root",
    }
    agents_graph_actions._agent_graph["nodes"]["agent_child_b"] = {
        "id": "agent_child_b",
        "name": "Child B",
        "task": "call run_attack_surface_orchestration_round(target='web', require_new_data=True)",
        "status": "completed",
        "parent_id": "agent_root",
    }

    round_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        orchestration_actions,
        "run_attack_surface_orchestration_round",
        lambda agent_state, target, **kwargs: round_calls.append(
            {"agent_id": agent_state.agent_id, "target": target, **kwargs}
        )
        or {"success": True, "skipped": False, "round_number": 2},
    )

    first = orchestration_actions.trigger_attack_surface_orchestration_on_child_completion(
        agent_state=child_a,
        completion_status="completed",
        debounce_seconds=60,
    )
    second = orchestration_actions.trigger_attack_surface_orchestration_on_child_completion(
        agent_state=child_b,
        completion_status="completed",
        debounce_seconds=60,
    )
    flushed = orchestration_actions._flush_orchestration_autorun_queue("agent_root")

    assert first["success"] is True
    assert second["success"] is True
    assert first["queued"] is True
    assert second["queued"] is True
    assert first["triggered"] is False
    assert second["queue_depth"] == 2
    assert flushed["success"] is True
    assert flushed["triggered"] is True
    assert flushed["batch_event_count"] == 2
    assert flushed["coalesced_agent_ids"] == ["agent_child_a", "agent_child_b"]
    assert len(round_calls) == 1
    assert round_calls[0]["target"] == "web"
    assert (
        agents_graph_actions._agent_graph["nodes"]["agent_child_a"]["orchestration_autorun"][
            "batch_event_count"
        ]
        == 2
    )


def test_persisted_autorun_queue_survives_memory_reset(monkeypatch: Any, tmp_path: Path) -> None:
    root_state = DummyState("agent_root")
    child_state = DummyState("agent_child", parent_id="agent_root")
    _seed_review(root_state)
    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }
    agents_graph_actions._agent_graph["nodes"]["agent_child"] = {
        "id": "agent_child",
        "name": "Child",
        "task": "call run_attack_surface_orchestration_round(target='web', require_new_data=True)",
        "status": "completed",
        "parent_id": "agent_root",
    }
    monkeypatch.setattr(
        orchestration_actions,
        "_autorun_queue_storage_path",
        lambda: tmp_path / "autorun-queue.json",
    )
    monkeypatch.setattr(
        orchestration_actions,
        "_schedule_autorun_timer_unlocked",
        lambda root_agent_id, delay_seconds: DummyTimer(),
    )

    queued = orchestration_actions.trigger_attack_surface_orchestration_on_child_completion(
        agent_state=child_state,
        completion_status="completed",
        debounce_seconds=60,
    )

    persisted = (tmp_path / "autorun-queue.json").read_text(encoding="utf-8")
    assert queued["success"] is True
    assert queued["queued"] is True
    assert '"agent_root"' in persisted
    assert '"agent_child"' in persisted

    orchestration_actions._orchestration_autorun_queue.clear()
    orchestration_actions._orchestration_autorun_queue_loaded = False

    round_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        orchestration_actions,
        "run_attack_surface_orchestration_round",
        lambda agent_state, target, **kwargs: round_calls.append(
            {"agent_id": agent_state.agent_id, "target": target, **kwargs}
        )
        or {"success": True, "skipped": False, "round_number": 2},
    )

    flushed = orchestration_actions._flush_orchestration_autorun_queue("agent_root")

    assert flushed["success"] is True
    assert flushed["triggered"] is True
    assert flushed["queued"] is False
    assert flushed["coalesced_agent_ids"] == ["agent_child"]
    assert round_calls[0]["agent_id"] == "agent_root"
    assert round_calls[0]["target"] == "web"
    assert not (tmp_path / "autorun-queue.json").exists()


def test_persisted_autorun_queue_recovers_root_snapshot_when_graph_is_missing(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    root_state = DummyState("agent_root")
    root_state.context["auto_loaded_framework_skills"] = ["httpx", "katana"]
    child_state = DummyState("agent_child", parent_id="agent_root")
    _seed_review(root_state)
    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }
    agents_graph_actions._agent_graph["nodes"]["agent_child"] = {
        "id": "agent_child",
        "name": "Child",
        "task": "call run_attack_surface_orchestration_round(target='web', require_new_data=True)",
        "status": "completed",
        "parent_id": "agent_root",
    }
    agents_graph_actions._agent_states["agent_root"] = root_state

    class FakeRootLLMConfig:
        timeout = 123
        scan_mode = "standard"
        assessment_objective = "remediation"
        interactive = True

    class FakeRootLLM:
        _system_prompt_context = {
            "assessment_objective": "remediation",
            "authorized_targets": [{"type": "web_application", "value": "https://app.test"}],
        }

    class FakeRootAgent:
        llm_config = FakeRootLLMConfig()
        llm = FakeRootLLM()

    agents_graph_actions._agent_instances["agent_root"] = FakeRootAgent()

    monkeypatch.setattr(
        orchestration_actions,
        "_autorun_queue_storage_path",
        lambda: tmp_path / "autorun-queue.json",
    )
    monkeypatch.setattr(
        orchestration_actions,
        "_schedule_autorun_timer_unlocked",
        lambda root_agent_id, delay_seconds: DummyTimer(),
    )

    queued = orchestration_actions.trigger_attack_surface_orchestration_on_child_completion(
        agent_state=child_state,
        completion_status="completed",
        debounce_seconds=60,
    )

    persisted = (tmp_path / "autorun-queue.json").read_text(encoding="utf-8")
    assert queued["success"] is True
    assert queued["queued"] is True
    assert '"root_runtime_snapshot"' in persisted
    assert '"scan_mode": "standard"' in persisted

    orchestration_actions._orchestration_autorun_queue.clear()
    orchestration_actions._orchestration_autorun_queue_loaded = False
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_states.clear()
    agents_graph_actions._agent_instances.clear()

    round_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        orchestration_actions,
        "run_attack_surface_orchestration_round",
        lambda agent_state, target, **kwargs: round_calls.append(
            {"agent_id": agent_state.agent_id, "target": target, **kwargs}
        )
        or {"success": True, "skipped": False, "round_number": 2},
    )

    flushed = orchestration_actions._flush_orchestration_autorun_queue("agent_root")

    assert flushed["success"] is True
    assert flushed["triggered"] is True
    assert flushed["queued"] is False
    assert round_calls[0]["agent_id"] == "agent_root"
    assert round_calls[0]["target"] == "web"
    assert agents_graph_actions._agent_graph["nodes"]["agent_root"]["recovered_from_snapshot"] is True
    assert agents_graph_actions._agent_graph["nodes"]["agent_root"]["status"] == "recovered"
    recovered_state = agents_graph_actions._agent_states["agent_root"]
    assert recovered_state.context["auto_loaded_framework_skills"] == ["httpx", "katana"]
    assert recovered_state.runtime_snapshot["runtime"]["scan_mode"] == "standard"
    assert recovered_state.runtime_snapshot["runtime"]["assessment_objective"] == "remediation"
    assert not (tmp_path / "autorun-queue.json").exists()


def test_create_agent_uses_recovered_runtime_snapshot_when_parent_agent_is_missing(
    monkeypatch: Any,
) -> None:
    captured: dict[str, Any] = {}

    class FakeAgentState:
        counter = 0

        def __init__(
            self,
            *,
            task: str,
            agent_name: str,
            parent_id: str | None,
            max_iterations: int,
            waiting_timeout: int,
        ) -> None:
            FakeAgentState.counter += 1
            self.agent_id = f"agent_fake_{FakeAgentState.counter}"
            self.task = task
            self.agent_name = agent_name
            self.parent_id = parent_id
            self.max_iterations = max_iterations
            self.waiting_timeout = waiting_timeout

    class FakeLLMConfig:
        def __init__(self, **kwargs: Any) -> None:
            captured["llm_config"] = dict(kwargs)
            self.timeout = kwargs.get("timeout")
            self.scan_mode = kwargs.get("scan_mode")
            self.assessment_objective = kwargs.get("assessment_objective")
            self.interactive = kwargs.get("interactive")
            self.system_prompt_context = kwargs.get("system_prompt_context")

    class FakeStrixAgent:
        def __init__(self, config: dict[str, Any]) -> None:
            captured["agent_config"] = config
            self.llm_config = config["llm_config"]

    class DummyThreadForCreate:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.args = args
            self.kwargs = kwargs
            self.started = False

        def start(self) -> None:
            self.started = True

    fake_agents_module = types.ModuleType("strix.agents")
    fake_agents_module.StrixAgent = FakeStrixAgent  # type: ignore[attr-defined]
    fake_agents_state_module = types.ModuleType("strix.agents.state")
    fake_agents_state_module.AgentState = FakeAgentState  # type: ignore[attr-defined]
    fake_llm_config_module = types.ModuleType("strix.llm.config")
    fake_llm_config_module.LLMConfig = FakeLLMConfig  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "strix.agents", fake_agents_module)
    monkeypatch.setitem(sys.modules, "strix.agents.state", fake_agents_state_module)
    monkeypatch.setitem(sys.modules, "strix.llm.config", fake_llm_config_module)
    monkeypatch.setattr(agents_graph_actions.threading, "Thread", DummyThreadForCreate)

    parent_state = orchestration_actions._PersistedAutorunState(
        agent_id="agent_root",
        agent_name="Recovered Root",
        task="Recovered orchestration root",
        runtime_snapshot={
            "agent_id": "agent_root",
            "agent_name": "Recovered Root",
            "task": "Recovered orchestration root",
            "context": {"auto_loaded_framework_skills": ["httpx", "nuclei"]},
            "runtime": {
                "timeout": 222,
                "scan_mode": "standard",
                "assessment_objective": "remediation",
                "interactive": True,
                "system_prompt_context": {
                    "assessment_objective": "remediation",
                    "authorized_targets": [
                        {"type": "web_application", "value": "https://app.test"}
                    ],
                },
            },
        },
    )

    result = agents_graph_actions.create_agent(
        agent_state=parent_state,
        task="validate recovered boundary",
        name="Recovered child",
        inherit_context=False,
    )

    assert result["success"] is True
    assert result["inherited_skills"] == ["httpx", "nuclei"]
    assert result["active_skills"] == ["httpx", "nuclei"]
    assert captured["llm_config"]["timeout"] == 222
    assert captured["llm_config"]["scan_mode"] == "standard"
    assert captured["llm_config"]["assessment_objective"] == "remediation"
    assert captured["llm_config"]["interactive"] is True
    assert captured["llm_config"]["system_prompt_context"]["assessment_objective"] == "remediation"
    assert captured["llm_config"]["system_prompt_context"]["authorized_targets"] == [
        {"type": "web_application", "value": "https://app.test"}
    ]


def test_run_agent_in_thread_auto_triggers_orchestration_followup(monkeypatch: Any) -> None:
    class FakeAgent:
        async def agent_loop(self, task: str) -> dict[str, Any]:
            return {"success": True, "task": task}

    state = ThreadState(
        agent_id="agent_child",
        agent_name="Child",
        parent_id="agent_root",
        task="validate target",
    )
    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }
    agents_graph_actions._agent_graph["nodes"][state.agent_id] = {
        "id": state.agent_id,
        "name": state.agent_name,
        "task": state.task,
        "status": "running",
        "parent_id": "agent_root",
        "created_at": state.start_time,
        "finished_at": None,
        "result": None,
        "state": state.model_dump(),
    }

    trigger_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        orchestration_actions,
        "trigger_attack_surface_orchestration_on_child_completion",
        lambda agent_state, completion_status=None, dry_run=False: trigger_calls.append(
            {
                "agent_id": agent_state.agent_id,
                "completion_status": completion_status,
                "dry_run": dry_run,
            }
        )
        or {"success": True, "triggered": True},
    )

    result = agents_graph_actions._run_agent_in_thread(FakeAgent(), state, [])

    assert result["result"]["success"] is True
    assert trigger_calls == [
        {
            "agent_id": state.agent_id,
            "completion_status": "completed",
            "dry_run": False,
        }
    ]
    assert (
        agents_graph_actions._agent_graph["nodes"][state.agent_id]["orchestration_autorun"][
            "triggered"
        ]
        is True
    )


def test_run_attack_surface_orchestration_round_from_child_uses_root_subtree(
    monkeypatch: Any,
) -> None:
    state = DummyState("agent_child", parent_id="agent_root")
    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }
    agents_graph_actions._agent_graph["nodes"]["agent_child"] = {
        "id": "agent_child",
        "name": "Child",
        "task": "child task",
        "status": "running",
        "parent_id": "agent_root",
    }

    build_calls: list[dict[str, Any]] = []
    review_calls: list[dict[str, Any]] = []
    signal_calls: list[dict[str, Any]] = []
    impact_calls: list[dict[str, Any]] = []

    def fake_build_attack_surface_review(
        agent_state: Any,
        target: str,
        scope_targets: list[str] | None = None,
        max_priorities: int = 16,
    ) -> dict[str, Any]:
        build_calls.append(
            {
                "agent_id": agent_state.agent_id,
                "target": target,
                "scope_targets": scope_targets,
                "max_priorities": max_priorities,
            }
        )
        surface_review_actions._surface_review_storage.setdefault("agent_root", {})["web"] = {
            "target": target,
            "updated_at": "2026-04-01T00:00:00+00:00",
            "report": {
                "summary": {"needs_more_data": True},
                "priorities": {
                    "top_targets_next": [],
                    "top_services_next": [],
                    "top_modules_next": [],
                    "top_endpoints_next": [],
                    "top_objects_next": [],
                    "top_params_objects": [],
                    "top_recon_value_exposures": [],
                    "top_reportable_hypotheses": [],
                    "top_chain_opportunities": [],
                    "top_role_boundaries_next": [],
                    "top_bug_class_gaps_next": [],
                    "top_blind_spots": [],
                },
            },
        }
        return {
            "success": True,
            "target": target,
            "report": surface_review_actions._surface_review_storage["agent_root"]["web"]["report"],
        }

    monkeypatch.setattr(surface_review_actions, "build_attack_surface_review", fake_build_attack_surface_review)
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_attack_surface_agents",
        lambda agent_state, **kwargs: review_calls.append({"agent_id": agent_state.agent_id, **kwargs})
        or {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_strong_signal_agents",
        lambda agent_state, **kwargs: signal_calls.append({"agent_id": agent_state.agent_id, **kwargs})
        or {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_impact_chain_agents",
        lambda agent_state, **kwargs: impact_calls.append({"agent_id": agent_state.agent_id, **kwargs})
        or {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )

    result = orchestration_actions.run_attack_surface_orchestration_round(
        agent_state=state,
        target="web",
        scope_targets=["app.test"],
        force=True,
        dry_run=True,
    )

    assert result["success"] is True
    assert result["root_agent_id"] == "agent_root"
    assert result["round_number"] == 1
    assert build_calls[0]["agent_id"] == "agent_root"
    assert review_calls[0]["agent_id"] == "agent_root"
    assert signal_calls[0]["agent_id"] == "agent_root"
    assert impact_calls[0]["agent_id"] == "agent_root"
    assert review_calls[0]["dry_run"] is True


def test_run_attack_surface_orchestration_round_skips_without_new_data(
    monkeypatch: Any,
) -> None:
    state = DummyState("agent_root")
    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }
    build_count = 0

    def fake_build_attack_surface_review(
        agent_state: Any,
        target: str,
        scope_targets: list[str] | None = None,
        max_priorities: int = 16,
    ) -> dict[str, Any]:
        nonlocal build_count
        build_count += 1
        surface_review_actions._surface_review_storage.setdefault("agent_root", {})["web"] = {
            "target": target,
            "updated_at": "2026-04-01T00:00:00+00:00",
            "report": {
                "summary": {"needs_more_data": False},
                "priorities": {
                    "top_targets_next": [],
                    "top_services_next": [],
                    "top_modules_next": [],
                    "top_endpoints_next": [],
                    "top_objects_next": [],
                    "top_params_objects": [],
                    "top_recon_value_exposures": [],
                    "top_reportable_hypotheses": [],
                    "top_chain_opportunities": [],
                    "top_role_boundaries_next": [],
                    "top_bug_class_gaps_next": [],
                    "top_blind_spots": [],
                },
            },
        }
        return {
            "success": True,
            "target": target,
            "report": surface_review_actions._surface_review_storage["agent_root"]["web"]["report"],
        }

    monkeypatch.setattr(surface_review_actions, "build_attack_surface_review", fake_build_attack_surface_review)
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_attack_surface_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_strong_signal_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_impact_chain_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )

    first = orchestration_actions.run_attack_surface_orchestration_round(
        agent_state=state,
        target="web",
        force=True,
        dry_run=True,
    )
    second = orchestration_actions.run_attack_surface_orchestration_round(
        agent_state=state,
        target="web",
        dry_run=True,
    )

    assert first["success"] is True
    assert second["success"] is True
    assert second["skipped"] is True
    assert build_count == 1


def test_run_attack_surface_orchestration_round_reruns_when_ledger_changes(
    monkeypatch: Any,
) -> None:
    state = DummyState("agent_root")
    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }
    build_count = 0

    def fake_build_attack_surface_review(
        agent_state: Any,
        target: str,
        scope_targets: list[str] | None = None,
        max_priorities: int = 16,
    ) -> dict[str, Any]:
        nonlocal build_count
        build_count += 1
        updated_at = f"2026-04-01T00:00:0{build_count}+00:00"
        surface_review_actions._surface_review_storage.setdefault("agent_root", {})["web"] = {
            "target": target,
            "updated_at": updated_at,
            "report": {
                "summary": {"needs_more_data": False},
                "priorities": {
                    "top_targets_next": [],
                    "top_services_next": [],
                    "top_modules_next": [],
                    "top_endpoints_next": [],
                    "top_objects_next": [],
                    "top_params_objects": [],
                    "top_recon_value_exposures": [],
                    "top_reportable_hypotheses": [],
                    "top_chain_opportunities": [],
                    "top_role_boundaries_next": [],
                    "top_bug_class_gaps_next": [],
                    "top_blind_spots": [],
                },
            },
        }
        return {
            "success": True,
            "target": target,
            "report": surface_review_actions._surface_review_storage["agent_root"]["web"]["report"],
        }

    monkeypatch.setattr(surface_review_actions, "build_attack_surface_review", fake_build_attack_surface_review)
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_attack_surface_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_strong_signal_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_impact_chain_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )

    first = orchestration_actions.run_attack_surface_orchestration_round(
        agent_state=state,
        target="web",
        force=True,
        dry_run=True,
    )
    assessment_actions.record_hypothesis(
        agent_state=state,
        hypothesis="New authz signal after child work",
        target="web",
        component="focus:authz:app.test/api/admin/users",
        vulnerability_type="authorization",
        priority="high",
    )
    second = orchestration_actions.run_attack_surface_orchestration_round(
        agent_state=state,
        target="web",
        dry_run=True,
    )

    assert first["success"] is True
    assert second["success"] is True
    assert second["skipped"] is False
    assert second["round_number"] == 2
    assert build_count == 2


def test_run_attack_surface_orchestration_round_suppresses_just_completed_duplicate_agent(
    monkeypatch: Any,
) -> None:
    state = DummyState("agent_root")
    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }

    def fake_build_attack_surface_review(
        agent_state: Any,
        target: str,
        scope_targets: list[str] | None = None,
        max_priorities: int = 16,
    ) -> dict[str, Any]:
        surface_review_actions._surface_review_storage.setdefault("agent_root", {})["web"] = {
            "target": target,
            "updated_at": "2026-04-01T00:00:10+00:00",
            "report": {
                "summary": {"needs_more_data": True},
                "priorities": {
                    "top_targets_next": [
                        {
                            "host": "api.app.test",
                            "preliminary_type": "api",
                            "coverage_status": "mapped",
                            "signal_classification": "confirmed",
                            "priority": "critical",
                        }
                    ],
                    "top_services_next": [],
                    "top_modules_next": [],
                    "top_endpoints_next": [],
                    "top_objects_next": [],
                    "top_params_objects": [],
                    "top_recon_value_exposures": [],
                    "top_reportable_hypotheses": [],
                    "top_chain_opportunities": [],
                    "top_role_boundaries_next": [],
                    "top_bug_class_gaps_next": [],
                    "top_blind_spots": [],
                },
            },
        }
        return {
            "success": True,
            "target": target,
            "report": surface_review_actions._surface_review_storage["agent_root"]["web"]["report"],
        }

    monkeypatch.setattr(surface_review_actions, "build_attack_surface_review", fake_build_attack_surface_review)
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_strong_signal_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_impact_chain_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )

    first = orchestration_actions.run_attack_surface_orchestration_round(
        agent_state=state,
        target="web",
        force=True,
        dry_run=True,
        max_review_agents=1,
        include_signal_swarm=False,
        include_impact_swarm=False,
    )

    agents_graph_actions._agent_graph["nodes"]["agent_child"] = {
        "id": "agent_child",
        "name": "P1 Recon api.app.test",
        "task": "Delegation key: recon-host|api.app.test\nPhase: Phase 1 layered reconnaissance and surface expansion",
        "status": "completed",
        "parent_id": "agent_root",
        "finished_at": "2026-04-01T00:00:30+00:00",
    }

    create_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        orchestration_actions,
        "create_agent",
        lambda agent_state, task, name, inherit_context=True, skills=None: create_calls.append(
            {"task": task, "name": name, "skills": skills}
        )
        or {"success": True, "agent_id": "agent_new", "active_skills": skills.split(",") if skills else []},
    )

    second = orchestration_actions.run_attack_surface_orchestration_round(
        agent_state=state,
        target="web",
        dry_run=False,
        max_review_agents=1,
        include_signal_swarm=False,
        include_impact_swarm=False,
    )

    assert first["success"] is True
    assert second["success"] is True
    assert second["skipped"] is False
    assert second["spawn_summary"]["review_created"] == 0
    assert "recon-host|api.app.test" in second["suppressed_completed_dedupe_keys"]
    assert create_calls == []
    assert second["attack_surface_agent_result"]["skipped_count"] == 1
    assert second["attack_surface_agent_result"]["skipped_agents"][0]["dedupe_key"] == "recon-host|api.app.test"
    assert (
        second["attack_surface_agent_result"]["skipped_agents"][0]["reason"]
        == "recent duplicate just completed in current agent subtree"
    )


def test_run_attack_surface_orchestration_round_blocks_previously_completed_duplicate_agents_during_completion_only_refresh(
    monkeypatch: Any,
) -> None:
    state = DummyState("agent_root")
    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }

    def fake_build_attack_surface_review(
        agent_state: Any,
        target: str,
        scope_targets: list[str] | None = None,
        max_priorities: int = 16,
    ) -> dict[str, Any]:
        surface_review_actions._surface_review_storage.setdefault("agent_root", {})["web"] = {
            "target": target,
            "updated_at": "2026-04-01T00:00:10+00:00",
            "report": {
                "summary": {"needs_more_data": True},
                "priorities": {
                    "top_targets_next": [
                        {
                            "host": "api.app.test",
                            "preliminary_type": "api",
                            "coverage_status": "mapped",
                            "signal_classification": "confirmed",
                            "priority": "critical",
                        }
                    ],
                    "top_services_next": [],
                    "top_modules_next": [],
                    "top_endpoints_next": [],
                    "top_objects_next": [],
                    "top_params_objects": [],
                    "top_recon_value_exposures": [],
                    "top_reportable_hypotheses": [],
                    "top_chain_opportunities": [],
                    "top_role_boundaries_next": [],
                    "top_bug_class_gaps_next": [],
                    "top_blind_spots": [],
                },
            },
        }
        return {
            "success": True,
            "target": target,
            "report": surface_review_actions._surface_review_storage["agent_root"]["web"]["report"],
        }

    monkeypatch.setattr(surface_review_actions, "build_attack_surface_review", fake_build_attack_surface_review)
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_strong_signal_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_impact_chain_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )

    first = orchestration_actions.run_attack_surface_orchestration_round(
        agent_state=state,
        target="web",
        force=True,
        dry_run=True,
        max_review_agents=1,
        include_signal_swarm=False,
        include_impact_swarm=False,
    )

    agents_graph_actions._agent_graph["nodes"]["agent_child_a"] = {
        "id": "agent_child_a",
        "name": "P1 Recon api.app.test",
        "task": "Delegation key: recon-host|api.app.test\nPhase: Phase 1 layered reconnaissance and surface expansion",
        "status": "completed",
        "parent_id": "agent_root",
        "finished_at": "2026-04-01T00:00:30+00:00",
    }

    create_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        orchestration_actions,
        "create_agent",
        lambda agent_state, task, name, inherit_context=True, skills=None: create_calls.append(
            {"task": task, "name": name, "skills": skills}
        )
        or {"success": True, "agent_id": f"agent_{len(create_calls)}", "active_skills": skills.split(",") if skills else []},
    )

    second = orchestration_actions.run_attack_surface_orchestration_round(
        agent_state=state,
        target="web",
        dry_run=False,
        max_review_agents=1,
        include_signal_swarm=False,
        include_impact_swarm=False,
    )

    agents_graph_actions._agent_graph["nodes"]["agent_child_b"] = {
        "id": "agent_child_b",
        "name": "Gap role guest",
        "task": "Delegation key: role-boundary|guest\nPhase: Coverage gap closure",
        "status": "completed",
        "parent_id": "agent_root",
        "finished_at": "2026-04-01T00:00:40+00:00",
    }

    third = orchestration_actions.run_attack_surface_orchestration_round(
        agent_state=state,
        target="web",
        dry_run=False,
        max_review_agents=1,
        include_signal_swarm=False,
        include_impact_swarm=False,
    )

    assert first["success"] is True
    assert second["success"] is True
    assert third["success"] is True
    assert create_calls == []
    assert "recon-host|api.app.test" in third["blocked_terminal_dedupe_keys"]
    assert third["attack_surface_agent_result"]["skipped_count"] == 1
    assert third["attack_surface_agent_result"]["skipped_agents"][0]["dedupe_key"] == "recon-host|api.app.test"
    assert (
        third["attack_surface_agent_result"]["skipped_agents"][0]["reason"]
        == "duplicate already completed earlier in current agent subtree and no new coverage/evidence/review was observed"
    )


def test_run_attack_surface_orchestration_round_reruns_when_completed_descendant_changes(
    monkeypatch: Any,
) -> None:
    state = DummyState("agent_root")
    agents_graph_actions._agent_graph["nodes"]["agent_root"] = {
        "id": "agent_root",
        "name": "Root",
        "task": "root orchestration",
        "status": "running",
        "parent_id": None,
    }
    build_count = 0

    def fake_build_attack_surface_review(
        agent_state: Any,
        target: str,
        scope_targets: list[str] | None = None,
        max_priorities: int = 16,
    ) -> dict[str, Any]:
        nonlocal build_count
        build_count += 1
        updated_at = f"2026-04-01T00:00:0{build_count}+00:00"
        surface_review_actions._surface_review_storage.setdefault("agent_root", {})["web"] = {
            "target": target,
            "updated_at": updated_at,
            "report": {
                "summary": {"needs_more_data": False},
                "priorities": {
                    "top_targets_next": [],
                    "top_services_next": [],
                    "top_modules_next": [],
                    "top_endpoints_next": [],
                    "top_objects_next": [],
                    "top_params_objects": [],
                    "top_recon_value_exposures": [],
                    "top_reportable_hypotheses": [],
                    "top_chain_opportunities": [],
                    "top_role_boundaries_next": [],
                    "top_bug_class_gaps_next": [],
                    "top_blind_spots": [],
                },
            },
        }
        return {
            "success": True,
            "target": target,
            "report": surface_review_actions._surface_review_storage["agent_root"]["web"]["report"],
        }

    monkeypatch.setattr(surface_review_actions, "build_attack_surface_review", fake_build_attack_surface_review)
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_attack_surface_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_strong_signal_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )
    monkeypatch.setattr(
        orchestration_actions,
        "spawn_impact_chain_agents",
        lambda *args, **kwargs: {"success": True, "created_count": 0, "recommended_count": 0, "skipped_count": 0},
    )

    first = orchestration_actions.run_attack_surface_orchestration_round(
        agent_state=state,
        target="web",
        force=True,
        dry_run=True,
    )
    agents_graph_actions._agent_graph["nodes"]["agent_child"] = {
        "id": "agent_child",
        "name": "Child",
        "task": "child validation task",
        "status": "completed",
        "parent_id": "agent_root",
        "finished_at": "2026-04-01T00:00:30+00:00",
    }
    second = orchestration_actions.run_attack_surface_orchestration_round(
        agent_state=state,
        target="web",
        dry_run=True,
    )

    assert first["success"] is True
    assert second["success"] is True
    assert second["skipped"] is False
    assert second["round_number"] == 2
    assert build_count == 2
