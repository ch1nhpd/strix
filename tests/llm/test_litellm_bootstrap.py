import os

from strix.litellm_bootstrap import configure_litellm_environment, import_litellm


def test_configure_litellm_environment_sets_local_cost_map_default(
    monkeypatch,
) -> None:
    monkeypatch.delenv("LITELLM_LOCAL_MODEL_COST_MAP", raising=False)

    configure_litellm_environment()

    assert os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] == "True"


def test_configure_litellm_environment_preserves_explicit_value(
    monkeypatch,
) -> None:
    monkeypatch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "False")

    configure_litellm_environment()

    assert os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] == "False"


def test_import_litellm_returns_module_with_local_cost_map_enabled(
    monkeypatch,
) -> None:
    monkeypatch.delenv("LITELLM_LOCAL_MODEL_COST_MAP", raising=False)

    module = import_litellm()

    assert module is not None
    assert os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] == "True"
