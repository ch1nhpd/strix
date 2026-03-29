import json
from typing import Any
from urllib.parse import parse_qsl, urlparse

from strix.tools.registry import register_tool

from .assessment_actions import (
    _normalize_non_empty,
    _resolve_root_agent_id,
    _slug,
    _stable_id,
    _utc_now,
)


SessionProfile = dict[str, Any]
_session_profile_storage: dict[str, dict[str, SessionProfile]] = {}


def clear_session_profile_storage() -> None:
    _session_profile_storage.clear()


def get_proxy_manager() -> Any:
    from strix.tools.proxy.proxy_manager import get_proxy_manager as _get_proxy_manager

    return _get_proxy_manager()


def _get_session_store(agent_state: Any) -> tuple[str, dict[str, SessionProfile]]:
    root_agent_id = _resolve_root_agent_id(agent_state)
    if root_agent_id not in _session_profile_storage:
        _session_profile_storage[root_agent_id] = {}
    return root_agent_id, _session_profile_storage[root_agent_id]


def _update_agent_context(agent_state: Any, root_agent_id: str) -> None:
    if hasattr(agent_state, "update_context"):
        agent_state.update_context("session_profile_root_agent_id", root_agent_id)


def _normalize_mapping(
    value: dict[str, Any] | None,
    *,
    field_name: str,
) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object")
    return {str(key): str(item) for key, item in value.items()}


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = " ".join(str(value).strip().split())
    return normalized or None


def _normalize_base_url(base_url: str | None) -> str | None:
    normalized = _normalize_optional_text(base_url)
    if normalized is None:
        return None

    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base_url must be an absolute http(s) URL")

    return normalized.rstrip("/")


def _parse_cookie_header(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in cookie_header.split(";"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        cleaned_key = key.strip()
        cleaned_value = value.strip()
        if cleaned_key:
            cookies[cleaned_key] = cleaned_value
    return cookies


def _parse_raw_request(content: str) -> dict[str, Any]:
    lines = content.splitlines()
    if not lines:
        return {"headers": {}, "body": "", "query_params": {}}

    request_line = lines[0].strip().split(" ")
    method = request_line[0] if len(request_line) > 0 else ""
    request_target = request_line[1] if len(request_line) > 1 else ""

    headers: dict[str, str] = {}
    body_start = len(lines)
    for index, line in enumerate(lines[1:], 1):
        if line.strip() == "":
            body_start = index + 1
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()

    parsed_target = urlparse(request_target)
    body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""
    return {
        "method": method,
        "request_target": request_target,
        "path": parsed_target.path or request_target,
        "query_params": {
            str(key): str(value)
            for key, value in parse_qsl(parsed_target.query, keep_blank_values=True)
        },
        "headers": headers,
        "body": body,
    }


def _infer_base_url(headers: dict[str, str]) -> str | None:
    host = headers.get("Host") or headers.get("host")
    if not host:
        return None

    referer = (headers.get("Referer") or headers.get("referer") or "").lower()
    origin = (headers.get("Origin") or headers.get("origin") or "").lower()
    is_https = ":443" in host or referer.startswith("https://") or origin.startswith("https://")
    return f"{'https' if is_https else 'http'}://{host}".rstrip("/")


def _extract_session_headers(headers: dict[str, str]) -> dict[str, str]:
    allowed_exact = {
        "authorization",
        "x-api-key",
        "api-key",
        "x-csrf-token",
        "csrf-token",
        "x-xsrf-token",
        "x-auth-token",
        "x-session-id",
    }
    extracted: dict[str, str] = {}
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in allowed_exact or "token" in lowered or "auth" in lowered:
            extracted[key] = value
    return extracted


def _extract_session_params(params: dict[str, str]) -> dict[str, str]:
    extracted: dict[str, str] = {}
    for key, value in params.items():
        lowered = key.lower()
        if any(marker in lowered for marker in ["token", "session", "csrf", "auth", "apikey", "api_key"]):
            extracted[key] = value
    return extracted


def _infer_auth_hint(headers: dict[str, str], cookies: dict[str, str]) -> str:
    header_names = {key.lower() for key in headers}
    hints: list[str] = []

    if "authorization" in header_names:
        auth_value = headers.get("Authorization") or headers.get("authorization") or ""
        if auth_value.lower().startswith("bearer "):
            hints.append("bearer")
        else:
            hints.append("authorization")

    if cookies:
        hints.append("cookie")
    if "x-api-key" in header_names or "api-key" in header_names:
        hints.append("api_key")
    if "x-csrf-token" in header_names or "csrf-token" in header_names:
        hints.append("csrf")

    return "+".join(hints) if hints else "anonymous"


def _redact_mapping(mapping: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in mapping.items():
        if len(value) <= 4:
            redacted[key] = "*" * len(value)
        else:
            redacted[key] = f"{value[:2]}***{value[-2:]}"
    return redacted


def _profile_for_response(
    profile_id: str,
    record: SessionProfile,
    *,
    include_values: bool,
) -> SessionProfile:
    profile = dict(record)
    profile["profile_id"] = profile_id
    if not include_values:
        profile["headers"] = _redact_mapping(record.get("headers", {}))
        profile["cookies"] = _redact_mapping(record.get("cookies", {}))
        profile["params"] = dict(record.get("params", {}))
    return profile


def resolve_session_profile_reference(
    agent_state: Any,
    profile_reference: str | dict[str, Any] | None,
) -> SessionProfile | None:
    reference_value: str | None = None
    if isinstance(profile_reference, dict):
        for key in ["session_profile_id", "session_profile", "session_profile_name"]:
            candidate = profile_reference.get(key)
            if isinstance(candidate, str) and candidate.strip():
                reference_value = candidate.strip()
                break
    elif isinstance(profile_reference, str) and profile_reference.strip():
        reference_value = profile_reference.strip()

    if not reference_value:
        return None

    _, store = _get_session_store(agent_state)
    if reference_value in store:
        return _profile_for_response(reference_value, store[reference_value], include_values=True)

    slug_reference = _slug(reference_value)
    for profile_id, profile in store.items():
        if _slug(str(profile.get("name", ""))) == slug_reference:
            return _profile_for_response(profile_id, profile, include_values=True)

    raise ValueError(f"Session profile '{reference_value}' was not found")


@register_tool(sandbox_execution=False)
def save_session_profile(
    agent_state: Any,
    name: str,
    headers: dict[str, Any] | None = None,
    cookies: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    base_url: str | None = None,
    role: str | None = None,
    tenant: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    try:
        normalized_name = _normalize_non_empty(name, "name")
        normalized_headers = _normalize_mapping(headers, field_name="headers")
        normalized_cookies = _normalize_mapping(cookies, field_name="cookies")
        normalized_params = _normalize_mapping(params, field_name="params")
        normalized_base_url = _normalize_base_url(base_url)
        normalized_role = _normalize_optional_text(role)
        normalized_tenant = _normalize_optional_text(tenant)
        normalized_notes = _normalize_optional_text(notes)

        root_agent_id, store = _get_session_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        profile_id = _stable_id(
            "sess",
            normalized_name,
            normalized_role or "",
            normalized_tenant or "",
            normalized_base_url or "",
        )
        timestamp = _utc_now()
        existing = store.get(profile_id)

        record: SessionProfile = {
            "name": normalized_name,
            "headers": normalized_headers,
            "cookies": normalized_cookies,
            "params": normalized_params,
            "base_url": normalized_base_url,
            "role": normalized_role,
            "tenant": normalized_tenant,
            "notes": normalized_notes,
            "auth_hint": _infer_auth_hint(normalized_headers, normalized_cookies),
            "owner_agent_id": getattr(agent_state, "agent_id", None),
            "updated_at": timestamp,
        }
        if existing and "created_at" in existing:
            record["created_at"] = existing["created_at"]
        else:
            record["created_at"] = timestamp

        store[profile_id] = record

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to save session profile: {e}"}
    else:
        return {
            "success": True,
            "profile_id": profile_id,
            "updated_existing": existing is not None,
            "record": _profile_for_response(profile_id, record, include_values=False),
        }


@register_tool(sandbox_execution=False)
def list_session_profiles(
    agent_state: Any,
    include_values: bool = False,
    max_items: int = 50,
) -> dict[str, Any]:
    try:
        if max_items < 1:
            raise ValueError("max_items must be >= 1")

        root_agent_id, store = _get_session_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        profiles = [
            _profile_for_response(profile_id, profile, include_values=include_values)
            for profile_id, profile in store.items()
        ]
        profiles.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to list session profiles: {e}"}
    else:
        return {
            "success": True,
            "root_agent_id": root_agent_id,
            "profile_count": len(store),
            "profiles": profiles[:max_items],
        }


@register_tool(sandbox_execution=False)
def extract_session_profiles_from_requests(
    agent_state: Any,
    request_ids: list[str] | None = None,
    httpql_filter: str | None = None,
    start_page: int = 1,
    end_page: int = 1,
    page_size: int = 20,
    name_prefix: str = "traffic",
    include_unauthenticated: bool = False,
    default_role: str | None = None,
    default_tenant: str | None = None,
    max_profiles: int = 20,
) -> dict[str, Any]:
    try:
        normalized_prefix = _normalize_non_empty(name_prefix, "name_prefix")
        if start_page < 1 or end_page < start_page:
            raise ValueError("start_page/end_page must define a valid positive range")
        if page_size < 1:
            raise ValueError("page_size must be >= 1")
        if max_profiles < 1:
            raise ValueError("max_profiles must be >= 1")

        manager = get_proxy_manager()
        candidate_ids: list[str] = []
        if request_ids:
            for request_id in request_ids:
                if isinstance(request_id, str) and request_id.strip():
                    candidate_ids.append(request_id.strip())
        else:
            listing = manager.list_requests(
                httpql_filter=httpql_filter,
                start_page=start_page,
                end_page=end_page,
                page_size=page_size,
            )
            if listing.get("error"):
                raise ValueError(str(listing["error"]))
            for row in listing.get("requests", []):
                request_id = row.get("id")
                if request_id:
                    candidate_ids.append(str(request_id))

        extracted: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        seen_fingerprints: set[str] = set()
        for request_id in candidate_ids:
            if len(extracted) >= max_profiles:
                break

            raw_request = manager.view_request(
                request_id=request_id,
                part="request",
                page=1,
                page_size=120,
            )
            if raw_request.get("error") or not raw_request.get("content"):
                skipped.append(
                    {
                        "request_id": request_id,
                        "reason": raw_request.get("error", "raw_request_unavailable"),
                    }
                )
                continue

            parsed = _parse_raw_request(str(raw_request["content"]))
            headers = parsed.get("headers", {})
            cookies = _parse_cookie_header(headers.get("Cookie") or headers.get("cookie") or "")
            session_headers = _extract_session_headers(headers)
            session_params = _extract_session_params(parsed.get("query_params", {}))
            base_url = _infer_base_url(headers)
            auth_hint = _infer_auth_hint(session_headers, cookies)

            if auth_hint == "anonymous" and not include_unauthenticated:
                skipped.append({"request_id": request_id, "reason": "anonymous_request_skipped"})
                continue

            fingerprint = _stable_id(
                "sessfp",
                base_url or "",
                auth_hint,
                json.dumps(session_headers, sort_keys=True),
                json.dumps(cookies, sort_keys=True),
                json.dumps(session_params, sort_keys=True),
            )
            if fingerprint in seen_fingerprints:
                skipped.append({"request_id": request_id, "reason": "duplicate_session_material"})
                continue
            seen_fingerprints.add(fingerprint)

            host = urlparse(base_url).netloc if base_url else "unknown"
            profile_name = (
                f"{normalized_prefix}_{host.replace('.', '_').replace(':', '_')}_{auth_hint}_"
                f"{fingerprint[-4:]}"
            )
            save_result = save_session_profile(
                agent_state=agent_state,
                name=profile_name,
                headers=session_headers,
                cookies=cookies,
                params=session_params,
                base_url=base_url,
                role=default_role,
                tenant=default_tenant,
                notes=(
                    f"Extracted from request {request_id} "
                    f"{parsed.get('method', '').upper()} {parsed.get('path', '')}"
                ),
            )
            if not save_result.get("success"):
                skipped.append(
                    {
                        "request_id": request_id,
                        "reason": save_result.get("error", "save_failed"),
                    }
                )
                continue

            extracted.append(
                {
                    "request_id": request_id,
                    "auth_hint": auth_hint,
                    "base_url": base_url,
                    "profile": save_result.get("record"),
                }
            )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to extract session profiles: {e}"}
    else:
        return {
            "success": len(extracted) > 0,
            "extracted_count": len(extracted),
            "profiles": extracted,
            "skipped": skipped,
        }


@register_tool(sandbox_execution=False)
def delete_session_profile(
    agent_state: Any,
    profile_id: str | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    try:
        if not profile_id and not name:
            raise ValueError("profile_id or name is required")

        root_agent_id, store = _get_session_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        target_profile_id = None
        if isinstance(profile_id, str) and profile_id.strip() and profile_id.strip() in store:
            target_profile_id = profile_id.strip()
        elif isinstance(name, str) and name.strip():
            slug_name = _slug(name)
            for candidate_id, profile in store.items():
                if _slug(str(profile.get("name", ""))) == slug_name:
                    target_profile_id = candidate_id
                    break

        if target_profile_id is None:
            raise ValueError("Session profile was not found")

        removed = store.pop(target_profile_id)

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to delete session profile: {e}"}
    else:
        return {
            "success": True,
            "deleted_profile_id": target_profile_id,
            "deleted_name": removed.get("name"),
            "remaining_profiles": len(store),
        }
