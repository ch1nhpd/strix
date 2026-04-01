import importlib.util
import sys
import types


def _ensure_fake_litellm() -> None:
    if importlib.util.find_spec("litellm") is not None:
        return

    fake_litellm = types.ModuleType("litellm")
    fake_litellm.drop_params = True
    fake_litellm.modify_params = True
    fake_litellm.callbacks = []
    fake_litellm.token_counter = lambda model, text: len(text)  # type: ignore[attr-defined]
    fake_litellm.completion = lambda **kwargs: None  # type: ignore[attr-defined]
    fake_litellm.acompletion = lambda **kwargs: None  # type: ignore[attr-defined]
    fake_litellm.completion_cost = lambda *args, **kwargs: 0.0  # type: ignore[attr-defined]
    fake_litellm.stream_chunk_builder = lambda chunks: None  # type: ignore[attr-defined]
    fake_litellm.supports_reasoning = lambda model=None: False  # type: ignore[attr-defined]
    fake_litellm._should_retry = lambda code: False  # type: ignore[attr-defined]
    fake_litellm._logging = types.SimpleNamespace(_disable_debugging=lambda: None)

    fake_litellm_utils = types.ModuleType("litellm.utils")
    fake_litellm_utils.supports_prompt_caching = lambda model=None: False  # type: ignore[attr-defined]
    fake_litellm_utils.supports_vision = lambda model=None: False  # type: ignore[attr-defined]

    sys.modules.setdefault("litellm", fake_litellm)
    sys.modules.setdefault("litellm.utils", fake_litellm_utils)


_ensure_fake_litellm()
