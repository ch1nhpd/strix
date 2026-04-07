from strix.llm.config import LLMConfig
from strix.llm.utils import resolve_strix_model


def test_resolve_strix_model_normalizes_providerless_gpt_shorthand() -> None:
    api_model, canonical_model = resolve_strix_model("gpt-5.4")

    assert api_model == "openai/gpt-5.4"
    assert canonical_model == "openai/gpt-5.4"


def test_resolve_strix_model_preserves_providerless_shorthand_for_custom_api_base() -> None:
    api_model, canonical_model = resolve_strix_model(
        "gpt-5.4",
        api_base="http://10.5.48.71:8317/v1",
    )

    assert api_model == "gpt-5.4"
    assert canonical_model == "openai/gpt-5.4"


def test_resolve_strix_model_keeps_strix_prefix_semantics() -> None:
    api_model, canonical_model = resolve_strix_model("strix/gpt-5.4")

    assert api_model == "openai/gpt-5.4"
    assert canonical_model == "openai/gpt-5.4"


def test_llm_config_uses_providerless_gpt_shorthand_for_litellm() -> None:
    config = LLMConfig(model_name="gpt-5.4")

    assert config.model_name == "gpt-5.4"
    assert config.litellm_model == "openai/gpt-5.4"
    assert config.canonical_model == "openai/gpt-5.4"


def test_llm_config_preserves_providerless_gpt_shorthand_for_custom_api_base(
    monkeypatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", "gpt-5.4")
    monkeypatch.setenv("LLM_API_BASE", "http://10.5.48.71:8317/v1")

    config = LLMConfig()

    assert config.model_name == "gpt-5.4"
    assert config.api_base == "http://10.5.48.71:8317/v1"
    assert config.litellm_model == "gpt-5.4"
    assert config.canonical_model == "openai/gpt-5.4"
