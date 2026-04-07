import html
import re
from typing import Any


_INVOKE_OPEN = re.compile(r'<invoke\s+name=["\']([^"\']+)["\']>')
_PARAM_NAME_ATTR = re.compile(r'<parameter\s+name=["\']([^"\']+)["\']>')
_FUNCTION_CALLS_TAG = re.compile(r"</?function_calls>")
_STRIP_TAG_QUOTES = re.compile(r"<(function|parameter)\s*=\s*([^>]*?)>")


def normalize_tool_format(content: str) -> str:
    """Convert alternative tool-call XML formats to the expected one.

    Handles:
      <function_calls>...</function_calls>  → stripped
      <invoke name="X">                     → <function=X>
      <parameter name="X">                  → <parameter=X>
      </invoke>                             → </function>
      <function="X">                        → <function=X>
      <parameter="X">                       → <parameter=X>
    """
    if "<invoke" in content or "<function_calls" in content:
        content = _FUNCTION_CALLS_TAG.sub("", content)
        content = _INVOKE_OPEN.sub(r"<function=\1>", content)
        content = _PARAM_NAME_ATTR.sub(r"<parameter=\1>", content)
        content = content.replace("</invoke>", "</function>")

    return _STRIP_TAG_QUOTES.sub(
        lambda m: f"<{m.group(1)}={m.group(2).strip().strip(chr(34) + chr(39))}>", content
    )


STRIX_MODEL_MAP: dict[str, str] = {
    "claude-sonnet-4.6": "anthropic/claude-sonnet-4-6",
    "claude-opus-4.6": "anthropic/claude-opus-4-6",
    "gpt-5.2": "openai/gpt-5.2",
    "gpt-5.1": "openai/gpt-5.1",
    "gpt-5.4": "openai/gpt-5.4",
    "gemini-3-pro-preview": "gemini/gemini-3-pro-preview",
    "gemini-3-flash-preview": "gemini/gemini-3-flash-preview",
    "glm-5": "openrouter/z-ai/glm-5",
    "glm-4.7": "openrouter/z-ai/glm-4.7",
}


def resolve_strix_model(
    model_name: str | None,
    *,
    api_base: str | None = None,
) -> tuple[str | None, str | None]:
    """Resolve a strix/ model into names for API calls and capability lookups.

    Returns (api_model, canonical_model):
    - api_model: openai/<base> for API calls (Strix API is OpenAI-compatible)
    - canonical_model: actual provider model name for litellm capability lookups
    Provider-less shorthand models that appear in STRIX_MODEL_MAP are normalized
    to provider-qualified names unless an explicit custom api_base is set, in which
    case the request model is preserved and only the canonical lookup model is mapped.
    Other non-strix models return the same name for both.
    """
    if not model_name:
        return None, None

    normalized_model = str(model_name).strip()
    if not normalized_model:
        return None, None

    direct_mapping = STRIX_MODEL_MAP.get(normalized_model)
    if direct_mapping:
        request_model = normalized_model if str(api_base or "").strip() else direct_mapping
        return request_model, direct_mapping

    if not normalized_model.startswith("strix/"):
        return normalized_model, normalized_model

    base_model = normalized_model[6:]
    api_model = f"openai/{base_model}"
    canonical_model = STRIX_MODEL_MAP.get(base_model, api_model)
    return api_model, canonical_model


def resolve_litellm_custom_provider(
    model_name: str | None,
    *,
    api_base: str | None = None,
) -> str | None:
    """Tell LiteLLM how to transport providerless models over a custom API base.

    Some OpenAI-compatible gateways expect raw model ids like `gpt-5.4`, but LiteLLM
    still needs an explicit provider hint to avoid rejecting the request before it is sent.
    """
    normalized_model = str(model_name or "").strip()
    if not normalized_model or not str(api_base or "").strip():
        return None
    if "/" in normalized_model:
        return None
    return "openai"


def resolve_litellm_request(
    model_name: str | None,
    *,
    api_base: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    api_model, canonical_model = resolve_strix_model(model_name, api_base=api_base)
    request_model = api_model or model_name
    custom_provider = resolve_litellm_custom_provider(request_model, api_base=api_base)
    return request_model, canonical_model, custom_provider


def _stringify_litellm_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            text = _stringify_litellm_content(item)
            if text.strip():
                parts.append(text)
        return "\n".join(parts)
    if isinstance(content, dict):
        item_type = str(content.get("type") or "").strip().lower()
        if item_type in {"text", "output_text"}:
            text_value = content.get("text")
            if isinstance(text_value, dict):
                text_value = text_value.get("value")
            return _stringify_litellm_content(text_value)
        for field in ("text", "value", "content", "output_text"):
            if field in content:
                text = _stringify_litellm_content(content.get(field))
                if text.strip():
                    return text
        return ""

    for field in ("text", "value", "content"):
        if hasattr(content, field):
            text = _stringify_litellm_content(getattr(content, field))
            if text.strip():
                return text
    return str(content)


def extract_litellm_response_text(response: Any) -> str:
    if response is None:
        return ""

    choices = response.get("choices") if isinstance(response, dict) else getattr(response, "choices", None)
    if not choices:
        return ""

    first_choice = choices[0] if isinstance(choices, list) and choices else None
    if first_choice is None:
        return ""

    message = (
        first_choice.get("message")
        if isinstance(first_choice, dict)
        else getattr(first_choice, "message", None)
    )
    if message is None:
        return ""

    if isinstance(message, dict):
        for field in ("content", "reasoning_content"):
            text = _stringify_litellm_content(message.get(field))
            if text.strip():
                return text.strip()
    else:
        for field in ("content", "reasoning_content"):
            text = _stringify_litellm_content(getattr(message, field, None))
            if text.strip():
                return text.strip()

    return ""


def extract_litellm_stream_chunk_text(chunk: Any) -> str:
    if chunk is None:
        return ""

    choices = chunk.get("choices") if isinstance(chunk, dict) else getattr(chunk, "choices", None)
    if not choices:
        return ""

    first_choice = choices[0] if isinstance(choices, list) and choices else None
    if first_choice is None:
        return ""

    delta = (
        first_choice.get("delta")
        if isinstance(first_choice, dict)
        else getattr(first_choice, "delta", None)
    )
    if delta is None:
        return ""

    if isinstance(delta, dict):
        for field in ("content", "reasoning_content", "text"):
            text = _stringify_litellm_content(delta.get(field))
            if text.strip():
                return text
    else:
        for field in ("content", "reasoning_content", "text"):
            text = _stringify_litellm_content(getattr(delta, field, None))
            if text.strip():
                return text

    return ""


def describe_litellm_response_shape(response: Any) -> str:
    if response is None:
        return "response=None"

    response_type = type(response).__name__
    choices = response.get("choices") if isinstance(response, dict) else getattr(response, "choices", None)
    if not choices:
        return f"type={response_type}, choices=missing-or-empty"

    first_choice = choices[0] if isinstance(choices, list) and choices else None
    if first_choice is None:
        return f"type={response_type}, choices=empty"

    message = (
        first_choice.get("message")
        if isinstance(first_choice, dict)
        else getattr(first_choice, "message", None)
    )
    if message is None:
        finish_reason = (
            first_choice.get("finish_reason")
            if isinstance(first_choice, dict)
            else getattr(first_choice, "finish_reason", None)
        )
        return f"type={response_type}, message=missing, finish_reason={finish_reason}"

    if isinstance(message, dict):
        content = message.get("content")
        reasoning_content = message.get("reasoning_content")
    else:
        content = getattr(message, "content", None)
        reasoning_content = getattr(message, "reasoning_content", None)

    return (
        f"type={response_type}, "
        f"content_type={type(content).__name__}, "
        f"content_present={bool(_stringify_litellm_content(content).strip())}, "
        f"reasoning_type={type(reasoning_content).__name__}, "
        f"reasoning_present={bool(_stringify_litellm_content(reasoning_content).strip())}"
    )


def _truncate_to_first_function(content: str) -> str:
    if not content:
        return content

    function_starts = [
        match.start() for match in re.finditer(r"<function=|<invoke\s+name=", content)
    ]

    if len(function_starts) >= 2:
        second_function_start = function_starts[1]

        return content[:second_function_start].rstrip()

    return content


def parse_tool_invocations(content: str) -> list[dict[str, Any]] | None:
    content = normalize_tool_format(content)
    content = fix_incomplete_tool_call(content)

    tool_invocations: list[dict[str, Any]] = []

    fn_regex_pattern = r"<function=([^>]+)>\n?(.*?)</function>"
    fn_param_regex_pattern = r"<parameter=([^>]+)>(.*?)</parameter>"

    fn_matches = re.finditer(fn_regex_pattern, content, re.DOTALL)

    for fn_match in fn_matches:
        fn_name = fn_match.group(1)
        fn_body = fn_match.group(2)

        param_matches = re.finditer(fn_param_regex_pattern, fn_body, re.DOTALL)

        args = {}
        for param_match in param_matches:
            param_name = param_match.group(1)
            param_value = param_match.group(2).strip()

            param_value = html.unescape(param_value)
            args[param_name] = param_value

        tool_invocations.append({"toolName": fn_name, "args": args})

    return tool_invocations if tool_invocations else None


def fix_incomplete_tool_call(content: str) -> str:
    """Fix incomplete tool calls by adding missing closing tag.

    Handles both ``<function=…>`` and ``<invoke name="…">`` formats.
    """
    has_open = "<function=" in content or "<invoke " in content
    count_open = content.count("<function=") + content.count("<invoke ")
    has_close = "</function>" in content or "</invoke>" in content
    if has_open and count_open == 1 and not has_close:
        content = content.rstrip()
        content = content + "function>" if content.endswith("</") else content + "\n</function>"
    return content


def format_tool_call(tool_name: str, args: dict[str, Any]) -> str:
    xml_parts = [f"<function={tool_name}>"]

    for key, value in args.items():
        xml_parts.append(f"<parameter={key}>{value}</parameter>")

    xml_parts.append("</function>")

    return "\n".join(xml_parts)


def clean_content(content: str) -> str:
    if not content:
        return ""

    content = normalize_tool_format(content)
    content = fix_incomplete_tool_call(content)

    tool_pattern = r"<function=[^>]+>.*?</function>"
    cleaned = re.sub(tool_pattern, "", content, flags=re.DOTALL)

    incomplete_tool_pattern = r"<function=[^>]+>.*$"
    cleaned = re.sub(incomplete_tool_pattern, "", cleaned, flags=re.DOTALL)

    partial_tag_pattern = r"<f(?:u(?:n(?:c(?:t(?:i(?:o(?:n(?:=(?:[^>]*)?)?)?)?)?)?)?)?)?$"
    cleaned = re.sub(partial_tag_pattern, "", cleaned)

    hidden_xml_patterns = [
        r"<inter_agent_message>.*?</inter_agent_message>",
        r"<agent_completion_report>.*?</agent_completion_report>",
    ]
    for pattern in hidden_xml_patterns:
        cleaned = re.sub(pattern, "", cleaned, flags=re.DOTALL | re.IGNORECASE)

    cleaned = re.sub(r"\n\s*\n", "\n\n", cleaned)

    return cleaned.strip()
