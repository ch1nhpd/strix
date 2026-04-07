from strix.llm.config import LLMConfig
from strix.llm.llm import LLM


def test_llm_build_completion_args_preserves_raw_model_for_custom_api_base(
    monkeypatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", "gpt-5.4")
    monkeypatch.setenv("LLM_API_BASE", "http://10.5.48.71:8317/v1")

    llm = LLM(LLMConfig(), agent_name=None)

    args = llm._build_completion_args([{"role": "user", "content": "Reply with OK"}])

    assert args["model"] == "gpt-5.4"
    assert args["api_base"] == "http://10.5.48.71:8317/v1"
    assert args["custom_llm_provider"] == "openai"
