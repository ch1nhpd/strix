import importlib
import sys
from types import ModuleType
from typing import Any

fake_posthog = ModuleType("strix.telemetry.posthog")
fake_posthog.error = lambda *args, **kwargs: None  # type: ignore[attr-defined]

fake_telemetry = ModuleType("strix.telemetry")
fake_telemetry.__path__ = []  # type: ignore[attr-defined]
fake_telemetry.posthog = fake_posthog  # type: ignore[attr-defined]

sys.modules.setdefault("strix.telemetry", fake_telemetry)
sys.modules.setdefault("strix.telemetry.posthog", fake_posthog)

from strix.config import Config
from strix.tools.registry import clear_registry


def _empty_config_load(_cls: type[Config]) -> dict[str, dict[str, str]]:
    return {"env": {}}


def _reload_tools_module() -> ModuleType:
    clear_registry()

    for name in list(sys.modules):
        if name == "strix.tools" or name.startswith("strix.tools."):
            sys.modules.pop(name, None)

    return importlib.import_module("strix.tools")


def test_non_sandbox_registers_agents_graph_but_not_browser_or_web_search_when_disabled(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "false")
    monkeypatch.setenv("STRIX_DISABLE_BROWSER", "true")
    monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
    monkeypatch.setattr(Config, "load", classmethod(_empty_config_load))

    tools = _reload_tools_module()
    names = set(tools.get_tool_names())

    assert "record_coverage" in names
    assert "seed_coverage_from_targets" in names
    assert "map_runtime_surface" in names
    assert "list_runtime_inventory" in names
    assert "bootstrap_session_profile_from_browser" in names
    assert "map_browser_surface" in names
    assert "traverse_browser_surface" in names
    assert "confirm_active_artifact_in_browser" in names
    assert "synthesize_attack_hypotheses" in names
    assert "generate_contextual_payloads" in names
    assert "triage_attack_anomalies" in names
    assert "security_tool_doctor" in names
    assert "run_security_focus_pipeline" in names
    assert "run_security_tool_pipeline" in names
    assert "run_security_tool_scan" in names
    assert "list_security_tool_runs" in names
    assert "save_session_profile" in names
    assert "list_session_profiles" in names
    assert "extract_session_profiles_from_requests" in names
    assert "delete_session_profile" in names
    assert "mine_additional_attack_surface" in names
    assert "list_mined_attack_surface" in names
    assert "oob_interaction_harness" in names
    assert "discover_workflows_from_requests" in names
    assert "list_discovered_workflows" in names
    assert "run_inventory_differential_hunt" in names
    assert "role_matrix_test" in names
    assert "payload_probe_harness" in names
    assert "jwt_variant_harness" in names
    assert "race_condition_harness" in names
    assert "analyze_differential_access" in names
    assert "create_agent" in names
    assert "browser_action" not in names
    assert "web_search" not in names


def test_sandbox_registers_sandbox_tools_but_not_non_sandbox_tools(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "true")
    monkeypatch.setenv("STRIX_DISABLE_BROWSER", "true")
    monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
    monkeypatch.setattr(Config, "load", classmethod(_empty_config_load))

    tools = _reload_tools_module()
    names = set(tools.get_tool_names())

    assert "record_coverage" not in names
    assert "seed_coverage_from_targets" not in names
    assert "map_runtime_surface" not in names
    assert "list_runtime_inventory" not in names
    assert "bootstrap_session_profile_from_browser" not in names
    assert "map_browser_surface" not in names
    assert "traverse_browser_surface" not in names
    assert "confirm_active_artifact_in_browser" not in names
    assert "synthesize_attack_hypotheses" not in names
    assert "generate_contextual_payloads" not in names
    assert "triage_attack_anomalies" not in names
    assert "security_tool_doctor" not in names
    assert "run_security_focus_pipeline" not in names
    assert "run_security_tool_pipeline" not in names
    assert "run_security_tool_scan" not in names
    assert "list_security_tool_runs" not in names
    assert "save_session_profile" not in names
    assert "list_session_profiles" not in names
    assert "extract_session_profiles_from_requests" not in names
    assert "delete_session_profile" not in names
    assert "mine_additional_attack_surface" not in names
    assert "list_mined_attack_surface" not in names
    assert "oob_interaction_harness" not in names
    assert "discover_workflows_from_requests" not in names
    assert "list_discovered_workflows" not in names
    assert "run_inventory_differential_hunt" not in names
    assert "role_matrix_test" not in names
    assert "payload_probe_harness" not in names
    assert "jwt_variant_harness" not in names
    assert "race_condition_harness" not in names
    assert "analyze_differential_access" not in names
    assert "terminal_execute" in names
    assert "python_action" in names
    assert "list_requests" in names
    assert "create_agent" not in names
    assert "finish_scan" not in names
    assert "load_skill" not in names
    assert "browser_action" not in names
    assert "web_search" not in names


def test_load_skill_import_does_not_register_create_agent_in_sandbox(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "true")
    monkeypatch.setenv("STRIX_DISABLE_BROWSER", "true")
    monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
    monkeypatch.setattr(Config, "load", classmethod(_empty_config_load))

    clear_registry()
    for name in list(sys.modules):
        if name == "strix.tools" or name.startswith("strix.tools."):
            sys.modules.pop(name, None)

    load_skill_module = importlib.import_module("strix.tools.load_skill.load_skill_actions")
    registry = importlib.import_module("strix.tools.registry")

    names_before = set(registry.get_tool_names())
    assert "load_skill" not in names_before
    assert "create_agent" not in names_before

    state_type = type(
        "DummyState",
        (),
        {
            "agent_id": "agent_test",
            "context": {},
            "update_context": lambda self, key, value: self.context.__setitem__(key, value),
        },
    )
    result = load_skill_module.load_skill(state_type(), "nmap")

    names_after = set(registry.get_tool_names())
    assert "create_agent" not in names_after
    assert result["success"] is False
