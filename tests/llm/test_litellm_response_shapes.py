from types import SimpleNamespace

from strix.llm.utils import (
    describe_litellm_response_shape,
    extract_litellm_response_text,
    extract_litellm_stream_chunk_text,
)


def test_extract_litellm_response_text_supports_object_message_shape() -> None:
    response = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content="OK",
                )
            )
        ]
    )

    assert extract_litellm_response_text(response) == "OK"


def test_extract_litellm_response_text_supports_dict_text_blocks() -> None:
    response = {
        "choices": [
            {
                "message": {
                    "content": [
                        {"type": "text", "text": "Hello"},
                        {"type": "output_text", "text": {"value": " world"}},
                    ]
                }
            }
        ]
    }

    assert extract_litellm_response_text(response) == "Hello\n world"


def test_extract_litellm_response_text_supports_dict_based_completion_payload() -> None:
    response = {
        "choices": [
            {
                "message": {
                    "content": [{"type": "text", "text": "OK"}]
                }
            }
        ]
    }

    assert extract_litellm_response_text(response) == "OK"


def test_describe_litellm_response_shape_reports_empty_content() -> None:
    response = {"choices": [{"message": {"content": ""}}]}

    description = describe_litellm_response_shape(response)

    assert "content_present=False" in description


def test_extract_litellm_stream_chunk_text_supports_object_delta_shape() -> None:
    chunk = SimpleNamespace(
        choices=[
            SimpleNamespace(
                delta=SimpleNamespace(
                    content="OK",
                )
            )
        ]
    )

    assert extract_litellm_stream_chunk_text(chunk) == "OK"


def test_extract_litellm_stream_chunk_text_supports_dict_text_blocks() -> None:
    chunk = {
        "choices": [
            {
                "delta": {
                    "content": [
                        {"type": "text", "text": "Hello"},
                        {"type": "output_text", "text": {"value": " world"}},
                    ]
                }
            }
        ]
    }

    assert extract_litellm_stream_chunk_text(chunk) == "Hello\n world"
