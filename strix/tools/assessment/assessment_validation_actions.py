import base64
import hashlib
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlparse, urlunparse

import httpx

from strix.tools.registry import register_tool

from .assessment_actions import record_coverage, record_evidence, record_hypothesis
from .assessment_session_actions import resolve_session_profile_reference


DEFAULT_SUCCESS_STATUSES = [200, 201, 202, 204, 206, 301, 302, 303, 307, 308]
AUTH_QUERY_MARKERS = ("token", "auth", "session", "jwt", "apikey", "api_key")
ROLE_KEYWORDS = [
    ("superadmin", 5),
    ("admin", 4),
    ("staff", 3),
    ("manager", 3),
    ("owner", 2),
    ("member", 1),
    ("user", 1),
    ("attacker", 1),
    ("other_user", 1),
    ("guest", 0),
    ("anonymous", 0),
    ("unauth", 0),
]


def _normalize_request_spec(
    item: dict[str, Any],
    *,
    field_name: str,
    agent_state: Any | None = None,
) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError(f"Each {field_name} item must be an object")

    label = str(item.get("name") or item.get("label") or "").strip()
    method = str(item.get("method") or "").strip().upper()
    profile = (
        resolve_session_profile_reference(agent_state, item)
        if agent_state is not None
        else None
    )
    base_url = (
        str(item.get("base_url") or profile.get("base_url") or "").strip()
        if profile
        else str(item.get("base_url") or "").strip()
    )
    path = str(item.get("path") or "").strip()
    url = str(item.get("url") or "").strip()

    if not label:
        raise ValueError(f"Each {field_name} item requires a non-empty name")
    if not method:
        raise ValueError(f"{field_name} '{label}' requires a method")
    if not url and path and base_url:
        url = urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))
    if not url:
        raise ValueError(f"{field_name} '{label}' requires a url")

    body = item.get("body")
    json_body = item.get("json_body")
    if body is not None and json_body is not None:
        raise ValueError(f"{field_name} '{label}' cannot include both body and json_body")

    profile_headers = profile.get("headers", {}) if profile else {}
    profile_cookies = profile.get("cookies", {}) if profile else {}
    profile_params = profile.get("params", {}) if profile else {}
    headers = {**profile_headers, **(item.get("headers") or {})}
    cookies = {**profile_cookies, **(item.get("cookies") or {})}
    params = {**profile_params, **(item.get("params") or {})}

    if not isinstance(headers, dict) or not isinstance(cookies, dict) or not isinstance(params, dict):
        raise ValueError(f"{field_name} '{label}' headers/cookies/params must be objects")

    delay_ms = int(item.get("delay_ms") or 0)
    if delay_ms < 0:
        raise ValueError(f"{field_name} '{label}' delay_ms must be >= 0")

    normalized: dict[str, Any] = {
        "name": label,
        "method": method,
        "url": url,
        "headers": {str(key): str(value) for key, value in headers.items()},
        "cookies": {str(key): str(value) for key, value in cookies.items()},
        "params": {str(key): str(value) for key, value in params.items()},
        "delay_ms": delay_ms,
    }

    if body is not None:
        normalized["body"] = str(body)
    if json_body is not None:
        if not isinstance(json_body, dict):
            raise ValueError(f"{field_name} '{label}' json_body must be an object")
        normalized["json_body"] = json_body
    if profile:
        normalized["session_profile_id"] = profile.get("profile_id")
        normalized["session_profile_name"] = profile.get("name")
        normalized["session_role"] = profile.get("role")
        normalized["session_tenant"] = profile.get("tenant")

    return normalized


def _normalize_success_statuses(success_statuses: list[int] | None) -> list[int]:
    if not success_statuses:
        return list(DEFAULT_SUCCESS_STATUSES)
    normalized: list[int] = []
    for status in success_statuses:
        if int(status) < 100:
            raise ValueError("success_statuses must contain valid HTTP status codes")
        normalized.append(int(status))
    return normalized


def _response_preview(response: httpx.Response) -> str:
    try:
        text = response.text
    except Exception:
        text = response.content.decode("utf-8", errors="ignore")
    return " ".join(text.split())[:400]


def _execute_request(
    spec: dict[str, Any],
    *,
    timeout: int,
    follow_redirects: bool,
) -> dict[str, Any]:
    if spec.get("delay_ms"):
        time.sleep(float(spec["delay_ms"]) / 1000)

    started = time.perf_counter()
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=follow_redirects,
            trust_env=False,
        ) as client:
            response = client.request(
                spec["method"],
                spec["url"],
                headers=spec.get("headers"),
                cookies=spec.get("cookies"),
                params=spec.get("params"),
                content=spec.get("body"),
                json=spec.get("json_body"),
            )
    except Exception as e:  # noqa: BLE001
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "error": str(e),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        }

    preview = _response_preview(response)
    content_bytes = response.content or b""
    return {
        "name": spec["name"],
        "method": spec["method"],
        "url": str(response.request.url),
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type", ""),
        "location": response.headers.get("location"),
        "body_length": len(content_bytes),
        "body_hash": hashlib.sha256(content_bytes).hexdigest()[:16],
        "body_preview": preview,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def _case_rank(name: str) -> int | None:
    lowered = name.lower()
    for keyword, rank in ROLE_KEYWORDS:
        if keyword in lowered:
            return rank
    return None


def _responses_match(left: dict[str, Any], right: dict[str, Any], threshold: float) -> tuple[bool, float]:
    if left.get("error") or right.get("error"):
        return False, 0.0
    if left.get("status_code") != right.get("status_code"):
        return False, 0.0
    if left.get("body_hash") == right.get("body_hash"):
        return True, 1.0

    left_preview = str(left.get("body_preview") or "")
    right_preview = str(right.get("body_preview") or "")
    if not left_preview or not right_preview:
        return False, 0.0

    ratio = SequenceMatcher(None, left_preview, right_preview).ratio()
    same_type = left.get("content_type") == right.get("content_type")
    return bool(same_type and ratio >= threshold), ratio


def _infer_authz_priority(method: str, suspicious_matches: list[dict[str, Any]]) -> str:
    if not suspicious_matches:
        return "normal"
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        return "critical"
    for match in suspicious_matches:
        lower_rank = match.get("lower_rank")
        higher_rank = match.get("higher_rank")
        if isinstance(lower_rank, int) and isinstance(higher_rank, int) and lower_rank == 0 and higher_rank >= 2:
            return "critical"
    return "high"


def _summarize_assessment(
    coverage_result: dict[str, Any] | None,
    hypothesis_result: dict[str, Any] | None = None,
    evidence_result: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    for result in [evidence_result, hypothesis_result, coverage_result]:
        if isinstance(result, dict) and isinstance(result.get("assessment_summary"), dict):
            return result["assessment_summary"]
    return None


def _normalize_injection_mode(injection_mode: str) -> str:
    normalized = str(injection_mode).strip().lower()
    if normalized not in {"query", "body", "json", "header", "raw_body"}:
        raise ValueError("injection_mode must be one of: query, body, json, header, raw_body")
    return normalized


def _normalize_jwt_token_location(token_location: str) -> str:
    normalized = str(token_location).strip().lower() or "auto"
    if normalized not in {"auto", "header", "cookie", "query"}:
        raise ValueError("token_location must be one of: auto, header, cookie, query")
    return normalized


def _safe_variant_fragment(value: str | None, fallback: str) -> str:
    candidate = "".join(
        char if char.isalnum() else "_"
        for char in str(value or "").strip().lower()
    ).strip("_")
    return candidate[:24] or fallback


def _normalize_payload_variants(
    payloads: list[Any] | None,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in payloads or []:
        if isinstance(item, dict):
            payload = str(item.get("payload") or "").strip()
            if not payload:
                continue
            normalized.append(
                {
                    "payload": payload,
                    "encoding": str(item.get("encoding") or "raw").strip() or "raw",
                    "strategy": str(item.get("strategy") or "manual").strip() or "manual",
                    "expected_markers": [
                        str(marker).strip()
                        for marker in list(item.get("expected_markers") or [])
                        if str(marker).strip()
                    ],
                    "expected_rejection": bool(item.get("expected_rejection")),
                }
            )
            continue

        payload = str(item).strip()
        if not payload:
            continue
        normalized.append(
            {
                "payload": payload,
                "encoding": "raw",
                "strategy": "manual",
                "expected_markers": [],
                "expected_rejection": False,
            }
        )
    return normalized


def _inject_query_value(url: str, parameter_name: str, payload: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    updated = False
    for index, (key, _) in enumerate(pairs):
        if key == parameter_name:
            pairs[index] = (key, payload)
            updated = True
    if not updated:
        pairs.append((parameter_name, payload))
    return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))


def _remove_query_value(url: str, parameter_name: str) -> str:
    parsed = urlparse(url)
    pairs = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key != parameter_name
    ]
    return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))


def _inject_form_value(body: str | None, parameter_name: str, payload: str) -> str:
    pairs = parse_qsl(str(body or ""), keep_blank_values=True)
    updated = False
    for index, (key, _) in enumerate(pairs):
        if key == parameter_name:
            pairs[index] = (key, payload)
            updated = True
    if not updated:
        pairs.append((parameter_name, payload))
    return urlencode(pairs, doseq=True)


def _flatten_json_scalar_paths(value: Any, prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(item, (dict, list)):
                flattened.update(_flatten_json_scalar_paths(item, path))
            else:
                flattened[path] = item
        return flattened
    if isinstance(value, list):
        for index, item in enumerate(value):
            path = f"{prefix}.{index}" if prefix else str(index)
            if isinstance(item, (dict, list)):
                flattened.update(_flatten_json_scalar_paths(item, path))
            else:
                flattened[path] = item
    return flattened


def _json_path_tokens(parameter_name: str) -> list[str]:
    return [token for token in str(parameter_name).split(".") if token]


def _json_parameter_path(json_body: dict[str, Any], parameter_name: str) -> list[str]:
    tokens = _json_path_tokens(parameter_name)
    if not tokens:
        return [str(parameter_name)]

    current: Any = json_body
    traversed = True
    for token in tokens:
        if isinstance(current, dict) and token in current:
            current = current[token]
            continue
        if isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
            continue
        traversed = False
        break
    if traversed:
        return tokens

    flattened = _flatten_json_scalar_paths(json_body)
    if parameter_name in flattened:
        return _json_path_tokens(parameter_name)

    matches = [path for path in flattened if path.rsplit(".", 1)[-1] == parameter_name]
    if len(matches) == 1:
        return _json_path_tokens(matches[0])
    return tokens


def _json_parameter_value(json_body: dict[str, Any], parameter_name: str) -> Any:
    tokens = _json_parameter_path(json_body, parameter_name)
    current: Any = json_body
    for token in tokens:
        if isinstance(current, dict) and token in current:
            current = current[token]
            continue
        if isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
            continue
        return None
    return current


def _set_json_parameter_value(json_body: dict[str, Any], parameter_name: str, payload: str) -> dict[str, Any]:
    tokens = _json_parameter_path(json_body, parameter_name)
    if not tokens:
        return json_body

    current: Any = json_body
    for index, token in enumerate(tokens[:-1]):
        next_token = tokens[index + 1]
        if isinstance(current, dict):
            if token not in current or not isinstance(current[token], (dict, list)):
                current[token] = [] if next_token.isdigit() else {}
            current = current[token]
            continue
        if isinstance(current, list) and token.isdigit():
            position = int(token)
            while len(current) <= position:
                current.append([] if next_token.isdigit() else {})
            if not isinstance(current[position], (dict, list)):
                current[position] = [] if next_token.isdigit() else {}
            current = current[position]
            continue
        return json_body

    final_token = tokens[-1]
    if isinstance(current, dict):
        current[final_token] = payload
    elif isinstance(current, list) and final_token.isdigit():
        position = int(final_token)
        while len(current) <= position:
            current.append(None)
        current[position] = payload
    else:
        json_body[parameter_name] = payload
    return json_body


def _looks_like_jwt(value: str | None) -> bool:
    candidate = str(value or "").strip()
    if candidate.count(".") != 2:
        return False
    return all(
        part and all(char.isalnum() or char in {"-", "_"} for char in part)
        for part in candidate.split(".")
    )


def _query_parameter_map(url: str, params: dict[str, Any] | None = None) -> dict[str, str]:
    normalized = {
        str(key): str(value)
        for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True)
    }
    for key, value in dict(params or {}).items():
        normalized[str(key)] = str(value)
    return normalized


def _jwt_token_locator(
    spec: dict[str, Any],
    jwt_token: str,
    *,
    token_location: str,
    header_name: str,
    cookie_name: str | None,
    query_parameter_name: str | None,
) -> dict[str, Any]:
    normalized_location = _normalize_jwt_token_location(token_location)
    headers = dict(spec.get("headers") or {})
    cookies = dict(spec.get("cookies") or {})
    query_params = _query_parameter_map(str(spec.get("url") or ""), spec.get("params"))

    if normalized_location == "header":
        return {
            "location": "header",
            "header_name": str(header_name).strip() or "Authorization",
            "header_prefix": (
                "Bearer"
                if str(header_name).strip().lower() == "authorization"
                else ""
            ),
        }
    if normalized_location == "cookie":
        resolved_cookie_name = str(cookie_name or "").strip()
        if not resolved_cookie_name:
            for name, value in cookies.items():
                if value == jwt_token or _looks_like_jwt(value):
                    resolved_cookie_name = str(name)
                    break
        return {
            "location": "cookie",
            "cookie_name": resolved_cookie_name or "token",
        }
    if normalized_location == "query":
        resolved_query_name = str(query_parameter_name or "").strip()
        if not resolved_query_name:
            for name, value in query_params.items():
                if value == jwt_token or _looks_like_jwt(value):
                    resolved_query_name = str(name)
                    break
        return {
            "location": "query",
            "query_parameter_name": resolved_query_name or "token",
        }

    preferred_header = str(header_name).strip() or "Authorization"
    auth_value = headers.get(preferred_header)
    if _jwt_from_authorization_header(auth_value) == jwt_token:
        return {
            "location": "header",
            "header_name": preferred_header,
            "header_prefix": (
                "Bearer" if preferred_header.lower() == "authorization" else ""
            ),
        }
    for name, value in headers.items():
        resolved = _jwt_from_authorization_header(value) if name.lower() == "authorization" else str(value)
        if resolved == jwt_token or _looks_like_jwt(resolved):
            return {
                "location": "header",
                "header_name": str(name),
                "header_prefix": (
                    "Bearer" if str(name).lower() == "authorization" else ""
                ),
            }
    for name, value in cookies.items():
        if value == jwt_token or _looks_like_jwt(value):
            return {
                "location": "cookie",
                "cookie_name": str(name),
            }
    for name, value in query_params.items():
        if value == jwt_token or _looks_like_jwt(value):
            return {
                "location": "query",
                "query_parameter_name": str(name),
            }
    return {
        "location": "header",
        "header_name": preferred_header,
        "header_prefix": "Bearer" if preferred_header.lower() == "authorization" else "",
    }


def _mutated_request_spec(
    spec: dict[str, Any],
    *,
    parameter_name: str,
    payload: str,
    injection_mode: str,
    header_name: str | None,
    name: str,
) -> dict[str, Any]:
    mutated = dict(spec)
    mutated["name"] = name
    if injection_mode == "query":
        existing_params = dict(spec.get("params") or {})
        if existing_params:
            existing_params[parameter_name] = payload
            mutated["params"] = existing_params
            if parameter_name in {
                key for key, _ in parse_qsl(urlparse(str(spec["url"])).query, keep_blank_values=True)
            }:
                mutated["url"] = _inject_query_value(str(spec["url"]), parameter_name, payload)
        else:
            mutated["url"] = _inject_query_value(str(spec["url"]), parameter_name, payload)
        return mutated
    if injection_mode == "body":
        mutated["body"] = _inject_form_value(spec.get("body"), parameter_name, payload)
        mutated.pop("json_body", None)
        return mutated
    if injection_mode == "raw_body":
        mutated["body"] = payload
        mutated.pop("json_body", None)
        return mutated
    if injection_mode == "json":
        json_body = json.loads(json.dumps(spec.get("json_body") or {}, ensure_ascii=False))
        if not isinstance(json_body, dict):
            raise ValueError("json injection requires base_request json_body to be an object")
        json_body = _set_json_parameter_value(json_body, parameter_name, payload)
        mutated["json_body"] = json_body
        mutated.pop("body", None)
        return mutated

    resolved_header_name = str(header_name or parameter_name).strip()
    if not resolved_header_name:
        raise ValueError("header_name or parameter_name is required for header injection")
    headers = dict(spec.get("headers") or {})
    headers[resolved_header_name] = payload
    mutated["headers"] = headers
    return mutated


def _observation_from_result(
    result: dict[str, Any],
    *,
    payload: str | None = None,
    strategy: str | None = None,
    encoding: str | None = None,
    expected_rejection: bool | None = None,
) -> dict[str, Any]:
    observation = dict(result)
    if payload is not None:
        observation["payload"] = payload
    if strategy is not None:
        observation["strategy"] = strategy
    if encoding is not None:
        observation["encoding"] = encoding
    if expected_rejection is not None:
        observation["expected_rejection"] = expected_rejection
    return observation


def _default_semantic_markers_for_type(vulnerability_type: str) -> list[str]:
    normalized = str(vulnerability_type or "").strip().lower()
    if normalized == "sqli":
        return [
            "sql syntax",
            "sqlstate",
            "mysql",
            "postgresql",
            "sqlite",
            "ora-",
            "syntax error at or near",
            "unclosed quotation mark",
            "odbc",
        ]
    if normalized == "ssti":
        return [
            "templatesyntaxerror",
            "jinja2",
            "twig\\error",
            "smarty",
            "freemarker",
            "liquid error",
            "el1008e",
            "template error",
        ]
    if normalized == "xss":
        return [
            "<svg",
            "onload=alert",
            "<img",
            "onerror=alert",
            "constructor.constructor",
            "alert(1)",
        ]
    if normalized == "open_redirect":
        return [
            "https://evil.example/landing",
            "//evil.example/landing",
            "/admin",
            "/internal/debug",
        ]
    if normalized == "xxe":
        return [
            "xml parser",
            "doctype",
            "external entity",
            "entity xxe",
            "entity not defined",
        ]
    return []


def _semantic_matcher_hits(
    result: dict[str, Any],
    *,
    vulnerability_type: str,
    expected_markers: list[str] | None = None,
    semantic_matchers: list[str] | None = None,
) -> list[str]:
    searchable_text = " ".join(
        [
            str(result.get("body_preview") or ""),
            str(result.get("location") or ""),
            str(result.get("error") or ""),
        ]
    ).lower()
    hits: list[str] = []
    seen: set[str] = set()
    for marker in [
        *_default_semantic_markers_for_type(vulnerability_type),
        *[str(item).strip() for item in list(expected_markers or []) if str(item).strip()],
        *[str(item).strip() for item in list(semantic_matchers or []) if str(item).strip()],
    ]:
        lowered = marker.lower()
        if lowered in seen or lowered not in searchable_text:
            continue
        seen.add(lowered)
        hits.append(marker)
    return hits


def _payload_reflection_detected(result: dict[str, Any], payload: str | None) -> bool:
    candidate = str(payload or "").strip()
    if not candidate:
        return False
    searchable_text = " ".join(
        [
            str(result.get("body_preview") or ""),
            str(result.get("location") or ""),
        ]
    )
    return candidate in searchable_text


def _augment_probe_observation(
    observation: dict[str, Any],
    *,
    vulnerability_type: str,
    payload: str | None = None,
    expected_markers: list[str] | None = None,
    semantic_matchers: list[str] | None = None,
) -> dict[str, Any]:
    augmented = dict(observation)
    matcher_hits = _semantic_matcher_hits(
        augmented,
        vulnerability_type=vulnerability_type,
        expected_markers=expected_markers,
        semantic_matchers=semantic_matchers,
    )
    if matcher_hits:
        augmented["matcher_hits"] = matcher_hits
    if _payload_reflection_detected(augmented, payload):
        augmented["reflection_detected"] = True
    return augmented


def _mark_oob_matches(
    observations: list[dict[str, Any]],
    interactions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not interactions:
        return observations

    serialized_interactions = [
        {
            "text": json.dumps(
                interaction.get("raw_event") or interaction,
                sort_keys=True,
                ensure_ascii=False,
            ).lower(),
            "protocol": str(interaction.get("protocol") or "").strip() or None,
        }
        for interaction in interactions
    ]

    for observation in observations:
        payload = str(observation.get("payload") or "").strip()
        if not payload:
            continue

        candidate_texts = [payload]
        decoded = payload
        for _ in range(2):
            decoded_once = unquote(decoded)
            if decoded_once == decoded:
                break
            candidate_texts.append(decoded_once)
            decoded = decoded_once

        indicators: list[str] = []
        seen_indicators: set[str] = set()
        for candidate in candidate_texts:
            for match in re.findall(r"https?://[^\s\"'<>]+", candidate, flags=re.IGNORECASE):
                normalized = str(match).rstrip(").,;\"'>").lower()
                if not normalized or normalized in seen_indicators:
                    continue
                seen_indicators.add(normalized)
                indicators.append(normalized)
        if not indicators:
            lowered_payload = payload.lower()
            if lowered_payload and len(lowered_payload) <= 200:
                indicators.append(lowered_payload)

        for interaction in serialized_interactions:
            if not any(indicator in interaction["text"] for indicator in indicators):
                continue
            observation["oob_interaction"] = True
            observation["callback_protocol"] = interaction["protocol"]
            break
    return observations


def _b64url_decode_json(value: str) -> dict[str, Any] | None:
    cleaned = str(value).strip()
    if not cleaned:
        return None
    padding = "=" * (-len(cleaned) % 4)
    try:
        decoded = base64.urlsafe_b64decode(f"{cleaned}{padding}".encode("ascii"))
        parsed = json.loads(decoded.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _b64url_encode_json(value: dict[str, Any]) -> str:
    encoded = base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    return encoded.decode("ascii").rstrip("=")


def _jwt_variants(
    jwt_token: str,
    *,
    claim_overrides: dict[str, Any] | None = None,
    include_admin_variants: bool = True,
) -> list[dict[str, Any]]:
    token = str(jwt_token).strip()
    parts = token.split(".")
    variants: list[dict[str, Any]] = []

    variants.append(
        {
            "name": "no_auth",
            "token": None,
            "strategy": "missing_token",
        }
    )
    variants.append(
        {
            "name": "invalid_signature",
            "token": f"{token}x",
            "strategy": "signature_mutation",
        }
    )

    if len(parts) != 3:
        variants.append(
            {
                "name": "malformed_token",
                "token": f"{token}.broken",
                "strategy": "malformed_structure",
            }
        )
        return variants

    header = _b64url_decode_json(parts[0])
    payload = _b64url_decode_json(parts[1])
    if header is None or payload is None:
        variants.append(
            {
                "name": "malformed_token",
                "token": f"{parts[0]}.{parts[1]}.",
                "strategy": "malformed_structure",
            }
        )
        return variants

    variants.append(
        {
            "name": "empty_signature",
            "token": f"{parts[0]}.{parts[1]}.",
            "strategy": "empty_signature",
        }
    )

    alg_none_header = dict(header)
    alg_none_header["alg"] = "none"
    variants.append(
        {
            "name": "alg_none_unsigned",
            "token": f"{_b64url_encode_json(alg_none_header)}.{parts[1]}.",
            "strategy": "alg_none",
        }
    )

    if include_admin_variants:
        elevated_payload = dict(payload)
        elevated_payload.update(
            {
                "role": "admin",
                "is_admin": True,
                "admin": True,
                **(claim_overrides or {}),
            }
        )
        variants.append(
            {
                "name": "alg_none_admin_claims",
                "token": (
                    f"{_b64url_encode_json(alg_none_header)}."
                    f"{_b64url_encode_json(elevated_payload)}."
                ),
                "strategy": "alg_none_claim_escalation",
            }
        )

    return variants


def _auth_header_value(
    token: str | None,
    *,
    header_prefix: str,
) -> str | None:
    if token is None:
        return None
    normalized_prefix = str(header_prefix).strip()
    if not normalized_prefix:
        return token
    return f"{normalized_prefix} {token}"


def _jwt_from_authorization_header(value: str | None) -> str | None:
    candidate = str(value or "").strip()
    if not candidate:
        return None
    parts = candidate.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() in {"bearer", "jwt"}:
        return parts[1].strip() or None
    return candidate


def _jwt_applied_request_spec(
    spec: dict[str, Any],
    *,
    location: dict[str, Any],
    token: str | None,
) -> dict[str, Any]:
    mutated = dict(spec)
    carrier = str(location.get("location") or "header")
    if carrier == "header":
        resolved_header_name = str(location.get("header_name") or "Authorization").strip() or "Authorization"
        header_prefix = str(location.get("header_prefix") or "").strip()
        headers_map = dict(mutated.get("headers") or {})
        header_value = _auth_header_value(token, header_prefix=header_prefix)
        if header_value is None:
            headers_map.pop(resolved_header_name, None)
        else:
            headers_map[resolved_header_name] = header_value
        mutated["headers"] = headers_map
        return mutated

    if carrier == "cookie":
        resolved_cookie_name = str(location.get("cookie_name") or "token").strip() or "token"
        headers_map = dict(mutated.get("headers") or {})
        headers_map.pop("Cookie", None)
        headers_map.pop("cookie", None)
        cookies_map = dict(mutated.get("cookies") or {})
        if token is None:
            cookies_map.pop(resolved_cookie_name, None)
        else:
            cookies_map[resolved_cookie_name] = token
        mutated["headers"] = headers_map
        mutated["cookies"] = cookies_map
        return mutated

    resolved_query_parameter_name = (
        str(location.get("query_parameter_name") or "token").strip() or "token"
    )
    params_map = dict(mutated.get("params") or {})
    if params_map:
        if token is None:
            params_map.pop(resolved_query_parameter_name, None)
        else:
            params_map[resolved_query_parameter_name] = token
        mutated["params"] = params_map
    if (
        not params_map
        or resolved_query_parameter_name
        in {key for key, _ in parse_qsl(urlparse(str(spec.get("url") or "")).query, keep_blank_values=True)}
    ):
        mutated["url"] = (
            _remove_query_value(str(spec.get("url") or ""), resolved_query_parameter_name)
            if token is None
            else _inject_query_value(
                str(spec.get("url") or ""),
                resolved_query_parameter_name,
                token,
            )
        )
    return mutated


@register_tool(sandbox_execution=False)
def role_matrix_test(
    agent_state: Any,
    target: str,
    component: str,
    surface: str,
    method: str,
    url: str,
    cases: list[dict[str, Any]],
    baseline_case: str | None = None,
    timeout: int = 15,
    follow_redirects: bool = False,
    similarity_threshold: float = 0.98,
    success_statuses: list[int] | None = None,
) -> dict[str, Any]:
    try:
        normalized_cases = [
            _normalize_request_spec(case, field_name="cases", agent_state=agent_state)
            for case in cases
        ]
        if len(normalized_cases) < 2:
            raise ValueError("cases must contain at least 2 request variants")

        normalized_method = method.strip().upper()
        normalized_url = url.strip()
        if not normalized_method or not normalized_url:
            raise ValueError("method and url are required")

        statuses = _normalize_success_statuses(success_statuses)
        results = [
            _execute_request(case, timeout=timeout, follow_redirects=follow_redirects)
            for case in normalized_cases
        ]

        baseline_result = None
        if baseline_case:
            for result in results:
                if result["name"] == baseline_case:
                    baseline_result = result
                    break
            if baseline_result is None:
                raise ValueError(f"baseline_case '{baseline_case}' was not found in cases")

        suspicious_matches: list[dict[str, Any]] = []
        if baseline_result is not None:
            for result in results:
                if result["name"] == baseline_result["name"]:
                    continue
                matches, ratio = _responses_match(result, baseline_result, similarity_threshold)
                if matches and int(result.get("status_code") or 0) in statuses:
                    suspicious_matches.append(
                        {
                            "case": result["name"],
                            "baseline_case": baseline_result["name"],
                            "status_code": result.get("status_code"),
                            "similarity": round(ratio, 3),
                            "body_hash": result.get("body_hash"),
                            "lower_rank": _case_rank(result["name"]),
                            "higher_rank": _case_rank(baseline_result["name"]),
                        }
                    )
        else:
            for index, left in enumerate(results):
                left_rank = _case_rank(left["name"])
                for right in results[index + 1 :]:
                    right_rank = _case_rank(right["name"])
                    if left_rank is None or right_rank is None or left_rank == right_rank:
                        continue
                    lower, higher = (left, right) if left_rank < right_rank else (right, left)
                    matches, ratio = _responses_match(lower, higher, similarity_threshold)
                    if matches and int(lower.get("status_code") or 0) in statuses:
                        suspicious_matches.append(
                            {
                                "case": lower["name"],
                                "baseline_case": higher["name"],
                                "status_code": lower.get("status_code"),
                                "similarity": round(ratio, 3),
                                "body_hash": lower.get("body_hash"),
                                "lower_rank": min(left_rank, right_rank),
                                "higher_rank": max(left_rank, right_rank),
                            }
                        )

        error_count = sum(1 for result in results if result.get("error"))
        if error_count == len(results):
            coverage_status = "blocked"
            coverage_priority = "high"
            coverage_rationale = (
                f"Role matrix test could not reach {normalized_method} {normalized_url}; all "
                "request variants failed."
            )
            next_step = "Restore connectivity or authentication context before concluding access control coverage"
        elif suspicious_matches:
            coverage_status = "in_progress"
            coverage_priority = _infer_authz_priority(normalized_method, suspicious_matches)
            coverage_rationale = (
                f"Role matrix testing found {len(suspicious_matches)} suspicious response-parity "
                f"match(es) on {normalized_method} {normalized_url}."
            )
            next_step = (
                "Validate whether lower-privilege cases can read or mutate data reserved for the "
                "baseline or higher-privilege case"
            )
        elif error_count > 0:
            coverage_status = "blocked"
            coverage_priority = "normal"
            coverage_rationale = (
                f"Role matrix test partially executed on {normalized_method} {normalized_url}, "
                "but some variants failed and coverage remains incomplete."
            )
            next_step = "Repair the failing variants and re-run the full privilege matrix"
        else:
            coverage_status = "covered"
            coverage_priority = "normal"
            coverage_rationale = (
                f"Role matrix test completed on {normalized_method} {normalized_url} without "
                "suspicious privilege-parity matches."
            )
            next_step = "Extend the matrix with additional tenants/roles only if new evidence appears"

        coverage_result = record_coverage(
            agent_state=agent_state,
            target=target,
            component=component,
            surface=surface,
            status=coverage_status,
            rationale=coverage_rationale,
            priority=coverage_priority,
            next_step=next_step,
        )

        hypothesis_result = None
        evidence_result = None
        if suspicious_matches:
            hypothesis_result = record_hypothesis(
                agent_state=agent_state,
                hypothesis=(
                    f"Lower-privilege access may match privileged behavior on "
                    f"{normalized_method} {normalized_url}"
                ),
                target=target,
                component=component,
                vulnerability_type="authorization",
                status="open",
                priority=coverage_priority,
                rationale=coverage_rationale,
            )
            evidence_result = record_evidence(
                agent_state=agent_state,
                title=f"Role-matrix parity on {normalized_method} {normalized_url}",
                details=json.dumps(
                    {
                        "url": normalized_url,
                        "method": normalized_method,
                        "suspicious_matches": suspicious_matches,
                        "case_summaries": results,
                    },
                    ensure_ascii=False,
                ),
                source="traffic",
                target=target,
                component=component,
                related_coverage_id=coverage_result.get("coverage_id"),
                related_hypothesis_id=(
                    hypothesis_result.get("hypothesis_id")
                    if isinstance(hypothesis_result, dict)
                    else None
                ),
            )
        elif error_count > 0:
            evidence_result = record_evidence(
                agent_state=agent_state,
                title=f"Role-matrix execution issue on {normalized_method} {normalized_url}",
                details=json.dumps(
                    {"url": normalized_url, "method": normalized_method, "case_summaries": results},
                    ensure_ascii=False,
                ),
                source="tool",
                target=target,
                component=component,
                related_coverage_id=coverage_result.get("coverage_id"),
            )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to run role_matrix_test: {e}"}
    else:
        return {
            "success": True,
            "url": normalized_url,
            "method": normalized_method,
            "cases": results,
            "suspicious_matches": suspicious_matches,
            "coverage_result": coverage_result,
            "hypothesis_result": hypothesis_result,
            "evidence_result": evidence_result,
            "assessment_summary": _summarize_assessment(
                coverage_result,
                hypothesis_result,
                evidence_result,
            ),
        }


@register_tool(sandbox_execution=False)
def payload_probe_harness(
    agent_state: Any,
    target: str,
    component: str,
    surface: str,
    vulnerability_type: str,
    parameter_name: str,
    base_request: dict[str, Any],
    payloads: list[Any] | None = None,
    callback_urls: list[str] | None = None,
    semantic_matchers: list[str] | None = None,
    baseline_value: str | None = None,
    injection_mode: str = "query",
    header_name: str | None = None,
    include_encodings: bool = True,
    max_payloads: int = 6,
    timeout: int = 15,
    follow_redirects: bool = False,
    oob_harness_id: str | None = None,
    poll_oob: bool = False,
    oob_wait_seconds: int = 5,
    oob_poll_interval: int = 5,
    min_anomaly_score: int = 4,
    persist_hypothesis: bool = True,
) -> dict[str, Any]:
    try:
        from .assessment_creative_actions import (
            generate_contextual_payloads,
            triage_attack_anomalies,
        )
        from .assessment_oob_actions import oob_interaction_harness

        normalized_target = str(target).strip()
        normalized_component = str(component).strip()
        normalized_surface = str(surface).strip()
        normalized_vulnerability_type = str(vulnerability_type).strip().lower()
        normalized_parameter_name = str(parameter_name).strip()
        normalized_injection_mode = _normalize_injection_mode(injection_mode)
        if not normalized_target or not normalized_component or not normalized_surface:
            raise ValueError("target, component, and surface are required")
        if not normalized_vulnerability_type:
            raise ValueError("vulnerability_type is required")
        if not normalized_parameter_name:
            raise ValueError("parameter_name is required")
        if max_payloads < 1:
            raise ValueError("max_payloads must be >= 1")

        base_request_spec = _normalize_request_spec(
            {"name": "baseline", **base_request},
            field_name="base_request",
            agent_state=agent_state,
        )

        normalized_payloads = _normalize_payload_variants(payloads)
        if not normalized_payloads:
            generated = generate_contextual_payloads(
                vulnerability_type=normalized_vulnerability_type,
                surface=normalized_surface,
                parameter_names=[normalized_parameter_name],
                callback_urls=callback_urls,
                include_encodings=include_encodings,
                max_variants=max_payloads * 3,
            )
            if not generated.get("success"):
                raise ValueError(generated.get("error") or "Failed to generate payload variants")
            normalized_payloads = _normalize_payload_variants(generated.get("variants"))

        selected_payloads = normalized_payloads[:max_payloads]
        if not selected_payloads:
            raise ValueError("No payload variants were available to probe")

        baseline_spec = dict(base_request_spec)
        if baseline_value is not None:
            baseline_spec = _mutated_request_spec(
                base_request_spec,
                parameter_name=normalized_parameter_name,
                payload=str(baseline_value),
                injection_mode=normalized_injection_mode,
                header_name=header_name,
                name="baseline",
            )

        observations: list[dict[str, Any]] = [
            _augment_probe_observation(
                _observation_from_result(
                    _execute_request(
                        baseline_spec,
                        timeout=timeout,
                        follow_redirects=follow_redirects,
                    )
                ),
                vulnerability_type=normalized_vulnerability_type,
                semantic_matchers=semantic_matchers,
            )
        ]
        request_variants: list[dict[str, Any]] = [
            {
                "name": "baseline",
                "request": baseline_spec,
                "payload": baseline_value,
                "strategy": "baseline",
                "encoding": "raw",
            }
        ]

        for index, variant in enumerate(selected_payloads, start=1):
            payload = str(variant["payload"])
            strategy = str(variant.get("strategy") or "manual")
            encoding = str(variant.get("encoding") or "raw")
            expected_rejection = bool(variant.get("expected_rejection"))
            expected_markers = [
                str(marker).strip()
                for marker in list(variant.get("expected_markers") or [])
                if str(marker).strip()
            ]
            variant_name = (
                f"variant_{index}_"
                f"{_safe_variant_fragment(strategy, 'strategy')}_"
                f"{_safe_variant_fragment(encoding, 'encoding')}"
            )
            mutated_spec = _mutated_request_spec(
                base_request_spec,
                parameter_name=normalized_parameter_name,
                payload=payload,
                injection_mode=normalized_injection_mode,
                header_name=header_name,
                name=variant_name,
            )
            request_variants.append(
                {
                    "name": variant_name,
                    "request": mutated_spec,
                        "payload": payload,
                        "strategy": strategy,
                        "encoding": encoding,
                        "expected_markers": expected_markers,
                        "expected_rejection": expected_rejection,
                    }
                )
            response = _execute_request(
                mutated_spec,
                timeout=timeout,
                follow_redirects=follow_redirects,
            )
            observations.append(
                _augment_probe_observation(
                    _observation_from_result(
                        response,
                        payload=payload,
                        strategy=strategy,
                        encoding=encoding,
                        expected_rejection=expected_rejection,
                    ),
                    vulnerability_type=normalized_vulnerability_type,
                    payload=payload,
                    expected_markers=expected_markers,
                    semantic_matchers=semantic_matchers,
                )
            )

        oob_result = None
        interactions: list[dict[str, Any]] = []
        if oob_harness_id and poll_oob:
            oob_result = oob_interaction_harness(
                agent_state=agent_state,
                action="poll",
                harness_id=oob_harness_id,
                wait_seconds=oob_wait_seconds,
                poll_interval=oob_poll_interval,
            )
            if oob_result.get("success"):
                interactions = list(oob_result.get("interactions") or [])
                observations = _mark_oob_matches(observations, interactions)

        triage_result = triage_attack_anomalies(
            agent_state=agent_state,
            target=normalized_target,
            component=normalized_component,
            surface=normalized_surface,
            observations=observations,
            baseline_name="baseline",
            min_score=min_anomaly_score,
            persist_hypothesis=persist_hypothesis,
        )
        targeted_hypothesis_result = None
        if (
            persist_hypothesis
            and isinstance(triage_result, dict)
            and triage_result.get("suspicious_observations")
        ):
            triage_priority = str(
                triage_result.get("coverage_result", {})
                .get("record", {})
                .get("priority", "normal")
            )
            targeted_hypothesis_result = record_hypothesis(
                agent_state=agent_state,
                hypothesis=(
                    f"Active payload probing suggests {normalized_vulnerability_type} behavior on "
                    f"{normalized_surface}"
                ),
                target=normalized_target,
                component=normalized_component,
                vulnerability_type=normalized_vulnerability_type,
                status="open",
                priority=triage_priority,
                rationale=(
                    f"Payload probe harness observed high-signal anomalies while mutating "
                    f"{normalized_parameter_name} for {normalized_vulnerability_type} validation."
                ),
            )

        evidence_result = record_evidence(
            agent_state=agent_state,
            title=f"Payload probe harness on {normalized_surface}",
            details=json.dumps(
                {
                    "vulnerability_type": normalized_vulnerability_type,
                    "parameter_name": normalized_parameter_name,
                    "injection_mode": normalized_injection_mode,
                    "request_variants": request_variants,
                    "observations": observations,
                    "oob_harness_id": oob_harness_id,
                    "oob_interactions": interactions,
                },
                ensure_ascii=False,
            ),
            source="tool",
            target=normalized_target,
            component=normalized_component,
            related_coverage_id=(
                triage_result.get("coverage_result", {}).get("coverage_id")
                if isinstance(triage_result, dict)
                else None
            ),
            related_hypothesis_id=(
                targeted_hypothesis_result.get("hypothesis_id")
                if isinstance(targeted_hypothesis_result, dict)
                else (
                    (triage_result.get("hypothesis_result") or {}).get("hypothesis_id")
                    if isinstance(triage_result, dict)
                    else None
                )
            ),
        )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to run payload_probe_harness: {e}"}
    else:
        return {
            "success": True,
            "tool_name": "payload_probe_harness",
            "vulnerability_type": normalized_vulnerability_type,
            "parameter_name": normalized_parameter_name,
            "injection_mode": normalized_injection_mode,
            "request_count": len(request_variants),
            "request_variants": request_variants,
            "observations": observations,
            "triage_result": triage_result,
            "targeted_hypothesis_result": targeted_hypothesis_result,
            "oob_result": oob_result,
            "evidence_result": evidence_result,
            "finding_count": len(
                triage_result.get("suspicious_observations", [])
                if isinstance(triage_result, dict)
                else []
            ),
        }


@register_tool(sandbox_execution=False)
def jwt_variant_harness(
    agent_state: Any,
    target: str,
    component: str,
    surface: str,
    base_request: dict[str, Any],
    jwt_token: str,
    token_location: str = "auto",
    header_name: str = "Authorization",
    header_prefix: str = "Bearer",
    cookie_name: str | None = None,
    query_parameter_name: str | None = None,
    claim_overrides: dict[str, Any] | None = None,
    include_admin_variants: bool = True,
    timeout: int = 15,
    follow_redirects: bool = False,
    similarity_threshold: float = 0.98,
    success_statuses: list[int] | None = None,
) -> dict[str, Any]:
    try:
        normalized_target = str(target).strip()
        normalized_component = str(component).strip()
        normalized_surface = str(surface).strip()
        normalized_token = str(jwt_token).strip()
        normalized_header_name = str(header_name).strip() or "Authorization"
        if not normalized_target or not normalized_component or not normalized_surface:
            raise ValueError("target, component, and surface are required")
        if not normalized_token:
            raise ValueError("jwt_token is required")

        statuses = _normalize_success_statuses(success_statuses)
        normalized_token_location = _normalize_jwt_token_location(token_location)
        baseline_spec = _normalize_request_spec(
            {"name": "baseline_valid", **base_request},
            field_name="base_request",
            agent_state=agent_state,
        )
        token_carrier = _jwt_token_locator(
            baseline_spec,
            normalized_token,
            token_location=normalized_token_location,
            header_name=normalized_header_name,
            cookie_name=cookie_name,
            query_parameter_name=query_parameter_name,
        )
        if token_carrier["location"] == "header" and "header_prefix" not in token_carrier:
            token_carrier["header_prefix"] = header_prefix
        baseline_spec = _jwt_applied_request_spec(
            baseline_spec,
            location=token_carrier,
            token=normalized_token,
        )
        baseline_result = _execute_request(
            baseline_spec,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )

        variant_results: list[dict[str, Any]] = []
        suspicious_variants: list[dict[str, Any]] = []
        for variant in _jwt_variants(
            normalized_token,
            claim_overrides=claim_overrides,
            include_admin_variants=include_admin_variants,
        ):
            variant_spec = dict(baseline_spec)
            variant_spec["name"] = str(variant["name"])
            variant_spec = _jwt_applied_request_spec(
                variant_spec,
                location=token_carrier,
                token=variant.get("token"),
            )

            result = _execute_request(
                variant_spec,
                timeout=timeout,
                follow_redirects=follow_redirects,
            )
            result["strategy"] = str(variant.get("strategy") or "jwt_variant")
            variant_results.append(result)

            matches, ratio = _responses_match(result, baseline_result, similarity_threshold)
            if (
                not result.get("error")
                and not baseline_result.get("error")
                and int(result.get("status_code") or 0) in statuses
                and int(baseline_result.get("status_code") or 0) in statuses
                and matches
            ):
                suspicious_variants.append(
                    {
                        "name": result["name"],
                        "strategy": result["strategy"],
                        "status_code": result.get("status_code"),
                        "similarity": round(ratio, 3),
                        "body_hash": result.get("body_hash"),
                    }
                )

        total_errors = int(bool(baseline_result.get("error"))) + sum(
            1 for item in variant_results if item.get("error")
        )
        total_results = 1 + len(variant_results)
        if total_errors == total_results:
            coverage_status = "blocked"
            coverage_priority = "high"
            coverage_rationale = "JWT variant harness could not compare any successful request variants."
            next_step = "Repair the authenticated request context before relying on JWT validation checks"
        elif suspicious_variants:
            coverage_status = "in_progress"
            coverage_priority = "critical"
            coverage_rationale = (
                f"JWT variant harness found {len(suspicious_variants)} forged or missing-token "
                f"variant(s) that matched the baseline response on {normalized_surface}."
            )
            next_step = (
                "Manually confirm the highest-signal forged token variant and determine whether "
                "signature, alg, or claim validation can be bypassed in a real attack flow"
            )
        elif total_errors > 0:
            coverage_status = "blocked"
            coverage_priority = "normal"
            coverage_rationale = (
                "JWT variant harness executed partially, but some request variants failed and the "
                "surface remains unresolved."
            )
            next_step = "Repair failing variants and retry the JWT validation harness"
        else:
            coverage_status = "covered"
            coverage_priority = "normal"
            coverage_rationale = (
                f"JWT variant harness completed on {normalized_surface} without forged-token "
                "parity against the baseline response."
            )
            next_step = "Revisit only if new signing keys, claim contexts, or alternate token sinks appear"

        coverage_result = record_coverage(
            agent_state=agent_state,
            target=normalized_target,
            component=normalized_component,
            surface=normalized_surface,
            status=coverage_status,
            rationale=coverage_rationale,
            priority=coverage_priority,
            next_step=next_step,
        )

        hypothesis_result = None
        if suspicious_variants:
            hypothesis_result = record_hypothesis(
                agent_state=agent_state,
                hypothesis=f"JWT validation may be bypassed on {normalized_surface}",
                target=normalized_target,
                component=normalized_component,
                vulnerability_type="jwt",
                status="open",
                priority=coverage_priority,
                rationale=coverage_rationale,
            )

        evidence_result = record_evidence(
            agent_state=agent_state,
            title=f"JWT variant harness on {normalized_surface}",
            details=json.dumps(
                {
                    "baseline_result": baseline_result,
                    "variant_results": variant_results,
                    "suspicious_variants": suspicious_variants,
                    "token_carrier": token_carrier,
                },
                ensure_ascii=False,
            ),
            source="traffic",
            target=normalized_target,
            component=normalized_component,
            related_coverage_id=coverage_result.get("coverage_id"),
            related_hypothesis_id=(
                hypothesis_result.get("hypothesis_id")
                if isinstance(hypothesis_result, dict)
                else None
            ),
        )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to run jwt_variant_harness: {e}"}
    else:
        return {
            "success": True,
            "tool_name": "jwt_variant_harness",
            "baseline_result": baseline_result,
            "variant_results": variant_results,
            "suspicious_variants": suspicious_variants,
            "token_carrier": token_carrier,
            "coverage_result": coverage_result,
            "hypothesis_result": hypothesis_result,
            "evidence_result": evidence_result,
            "assessment_summary": _summarize_assessment(
                coverage_result,
                hypothesis_result,
                evidence_result,
            ),
        }


@register_tool(sandbox_execution=False)
def race_condition_harness(
    agent_state: Any,
    target: str,
    component: str,
    surface: str,
    requests: list[dict[str, Any]],
    iterations: int = 5,
    timeout: int = 15,
    follow_redirects: bool = False,
    expect_single_success: bool = False,
    success_statuses: list[int] | None = None,
) -> dict[str, Any]:
    try:
        if iterations < 1:
            raise ValueError("iterations must be >= 1")

        normalized_requests = [
            _normalize_request_spec(item, field_name="requests", agent_state=agent_state)
            for item in requests
        ]
        if len(normalized_requests) < 2:
            raise ValueError("requests must contain at least 2 concurrent request definitions")

        statuses = _normalize_success_statuses(success_statuses)
        iteration_results: list[dict[str, Any]] = []

        for iteration in range(iterations):
            with ThreadPoolExecutor(max_workers=len(normalized_requests)) as executor:
                future_map = {
                    executor.submit(
                        _execute_request,
                        spec,
                        timeout=timeout,
                        follow_redirects=follow_redirects,
                    ): spec["name"]
                    for spec in normalized_requests
                }
                batch = []
                for future in as_completed(future_map):
                    batch.append(future.result())
            batch.sort(key=lambda item: item["name"])
            iteration_results.append({"iteration": iteration + 1, "responses": batch})

        anomalies: list[dict[str, Any]] = []
        if expect_single_success:
            for batch in iteration_results:
                successes = [
                    response
                    for response in batch["responses"]
                    if not response.get("error") and int(response.get("status_code") or 0) in statuses
                ]
                if len(successes) > 1:
                    anomalies.append(
                        {
                            "type": "multiple_successes",
                            "iteration": batch["iteration"],
                            "successes": [
                                {
                                    "name": response["name"],
                                    "status_code": response.get("status_code"),
                                    "body_hash": response.get("body_hash"),
                                }
                                for response in successes
                            ],
                        }
                    )

        label_fingerprints: dict[str, set[tuple[Any, Any]]] = {}
        for batch in iteration_results:
            for response in batch["responses"]:
                if response.get("error"):
                    continue
                label_fingerprints.setdefault(response["name"], set()).add(
                    (response.get("status_code"), response.get("body_hash"))
                )

        inconsistent_labels = [
            {"name": label, "fingerprints": sorted(fingerprints)}
            for label, fingerprints in label_fingerprints.items()
            if len(fingerprints) > 1
        ]
        if inconsistent_labels:
            anomalies.append({"type": "inconsistent_responses", "labels": inconsistent_labels})

        total_errors = sum(
            1
            for batch in iteration_results
            for response in batch["responses"]
            if response.get("error")
        )
        total_responses = len(iteration_results) * len(normalized_requests)

        if total_errors == total_responses:
            coverage_status = "blocked"
            coverage_priority = "high"
            coverage_rationale = (
                "Race harness could not execute any successful concurrent requests for this surface."
            )
            next_step = "Restore request prerequisites and re-run the concurrent harness"
        elif anomalies:
            coverage_status = "in_progress"
            coverage_priority = "critical" if expect_single_success else "high"
            coverage_rationale = (
                f"Race harness observed {len(anomalies)} anomaly group(s) across {iterations} "
                "concurrent iteration(s)."
            )
            next_step = (
                "Attempt exploit-specific validation around duplicate success, inconsistent state, "
                "or multi-step TOCTOU behavior"
            )
        elif total_errors > 0:
            coverage_status = "blocked"
            coverage_priority = "normal"
            coverage_rationale = (
                "Race harness executed partially, but some concurrent requests failed and the "
                "surface remains unresolved."
            )
            next_step = "Repair failing request variants and re-run the race harness"
        else:
            coverage_status = "covered"
            coverage_priority = "normal"
            coverage_rationale = (
                f"Race harness completed {iterations} concurrent iteration(s) without suspicious "
                "race indicators."
            )
            next_step = "Revisit only if the workflow semantics imply stronger single-use guarantees"

        coverage_result = record_coverage(
            agent_state=agent_state,
            target=target,
            component=component,
            surface=surface,
            status=coverage_status,
            rationale=coverage_rationale,
            priority=coverage_priority,
            next_step=next_step,
        )

        hypothesis_result = None
        evidence_result = None
        if anomalies:
            hypothesis_result = record_hypothesis(
                agent_state=agent_state,
                hypothesis=f"Concurrent execution may violate expected single-use or state consistency on {surface}",
                target=target,
                component=component,
                vulnerability_type="race_condition",
                status="open",
                priority=coverage_priority,
                rationale=coverage_rationale,
            )
            evidence_result = record_evidence(
                agent_state=agent_state,
                title=f"Race harness anomalies on {surface}",
                details=json.dumps(
                    {
                        "anomalies": anomalies,
                        "iterations": iteration_results,
                    },
                    ensure_ascii=False,
                ),
                source="traffic",
                target=target,
                component=component,
                related_coverage_id=coverage_result.get("coverage_id"),
                related_hypothesis_id=(
                    hypothesis_result.get("hypothesis_id")
                    if isinstance(hypothesis_result, dict)
                    else None
                ),
            )
        elif total_errors > 0:
            evidence_result = record_evidence(
                agent_state=agent_state,
                title=f"Race harness execution issue on {surface}",
                details=json.dumps({"iterations": iteration_results}, ensure_ascii=False),
                source="tool",
                target=target,
                component=component,
                related_coverage_id=coverage_result.get("coverage_id"),
            )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to run race_condition_harness: {e}"}
    else:
        return {
            "success": True,
            "iterations": iteration_results,
            "anomalies": anomalies,
            "coverage_result": coverage_result,
            "hypothesis_result": hypothesis_result,
            "evidence_result": evidence_result,
            "assessment_summary": _summarize_assessment(
                coverage_result,
                hypothesis_result,
                evidence_result,
            ),
        }
