import json
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool

from .assessment_actions import (
    _normalize_non_empty,
    _stable_id,
    record_coverage,
    record_evidence,
    record_hypothesis,
)
from .assessment_session_actions import (
    _parse_cookie_header,
    _redact_mapping,
    save_session_profile,
)
from .assessment_validation_actions import _spawn_followup_agents


SENSITIVE_KEYWORDS = ("token", "auth", "session", "jwt", "csrf", "xsrf", "api_key", "apikey")
BEARER_KEYWORDS = (
    "bearer",
    "access_token",
    "access-token",
    "accesstoken",
    "auth_token",
    "authtoken",
    "jwt",
)
CSRF_KEYWORDS = ("csrf", "xsrf")
API_KEY_KEYWORDS = ("api_key", "apikey", "x-api-key")
BROWSER_SIGNAL_PREFIX = "__strix_browser_signal__:"
ACTIVE_BROWSER_ATTRIBUTES = ("onload", "onerror", "onclick", "onmouseover", "href", "src")
SESSION_COOKIE_KEYWORDS = (
    "session",
    "sess",
    "sid",
    "auth",
    "token",
    "jwt",
    "remember",
    "refresh",
)
AUTHENTICATED_PATH_HINTS = (
    "dashboard",
    "account",
    "profile",
    "settings",
    "admin",
    "console",
    "portal",
    "workspace",
    "billing",
    "projects",
)
LOGIN_PATH_HINTS = (
    "login",
    "signin",
    "sign-in",
    "signup",
    "register",
    "forgot",
    "reset",
    "verify",
    "auth",
)
AUTO_BOOTSTRAP_BROWSER_STATE_ATTR = "_strix_auto_session_bootstrap_state"


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


def _looks_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(keyword in lowered for keyword in SENSITIVE_KEYWORDS)


def _collect_nested_candidates(
    value: Any,
    *,
    prefix: str,
    depth: int = 0,
) -> dict[str, str]:
    if depth > 4:
        return {}

    collected: dict[str, str] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(item, str) and _looks_sensitive_key(path):
                collected[path] = item
            elif isinstance(item, (dict, list)):
                collected.update(_collect_nested_candidates(item, prefix=path, depth=depth + 1))
    elif isinstance(value, list):
        for index, item in enumerate(value[:20]):
            path = f"{prefix}[{index}]"
            if isinstance(item, str) and _looks_sensitive_key(path):
                collected[path] = item
            elif isinstance(item, (dict, list)):
                collected.update(_collect_nested_candidates(item, prefix=path, depth=depth + 1))

    return collected


def _parse_json_value(key: str, raw_value: str) -> dict[str, str]:
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        return {}
    return _collect_nested_candidates(parsed, prefix=key)


def _string_candidates_from_browser_material(result: dict[str, Any]) -> dict[str, str]:
    candidates: dict[str, str] = {}
    for source_name in ["localStorage", "sessionStorage", "meta", "hiddenInputs"]:
        mapping = result.get(source_name) or {}
        if not isinstance(mapping, dict):
            continue
        for key, value in mapping.items():
            normalized_key = str(key)
            normalized_value = str(value)
            if _looks_sensitive_key(normalized_key):
                candidates[f"{source_name}.{normalized_key}"] = normalized_value
            candidates.update(_parse_json_value(f"{source_name}.{normalized_key}", normalized_value))

    next_data = result.get("nextData")
    if isinstance(next_data, (dict, list)):
        candidates.update(_collect_nested_candidates(next_data, prefix="nextData"))
    return candidates


def _choose_value(candidates: dict[str, str], keywords: tuple[str, ...]) -> str | None:
    prioritized: list[tuple[int, str]] = []
    for key, value in candidates.items():
        lowered = key.lower()
        score = sum(3 for keyword in keywords if keyword in lowered)
        if value.lower().startswith("bearer "):
            score += 4
        if "." in value and len(value) > 20:
            score += 2
        if len(value) >= 24:
            score += 1
        if score > 0:
            prioritized.append((score, key))

    if not prioritized:
        return None

    prioritized.sort(reverse=True)
    return candidates[prioritized[0][1]]


def _authorization_header(candidates: dict[str, str]) -> str | None:
    chosen = _choose_value(candidates, BEARER_KEYWORDS)
    if not chosen:
        return None
    if chosen.lower().startswith("bearer "):
        return chosen
    return f"Bearer {chosen}"


def _build_notes(
    existing_notes: str | None,
    *,
    page_url: str,
    tab_id: str,
    candidate_count: int,
) -> str:
    parts = []
    if existing_notes:
        parts.append(existing_notes)
    parts.append(
        f"Bootstrapped from browser tab {tab_id} at {page_url} with {candidate_count} sensitive key(s)"
    )
    return " ".join(parts)


def _browser_manager() -> Any:
    from strix.tools.browser.tab_manager import get_browser_tab_manager

    return get_browser_tab_manager()


async def _collect_browser_material(browser: Any, tab_id: str) -> dict[str, Any]:
    page = browser.pages[tab_id]
    page_url = page.url
    browser_result = await page.evaluate(
        """
        () => {
          const dumpStorage = (storage) => {
            const out = {};
            try {
              for (let i = 0; i < storage.length; i += 1) {
                const key = storage.key(i);
                out[key] = storage.getItem(key);
              }
            } catch (error) {}
            return out;
          };

          const meta = {};
          for (const element of document.querySelectorAll('meta[name], meta[property]')) {
            const key = element.getAttribute('name') || element.getAttribute('property');
            if (!key) {
              continue;
            }
            meta[key] = element.getAttribute('content') || '';
          }

          const hiddenInputs = {};
          for (const element of document.querySelectorAll('input[type="hidden"][name]')) {
            hiddenInputs[element.name] = element.value || '';
          }

          let nextData = null;
          try {
            const node = document.getElementById('__NEXT_DATA__');
            if (node && node.textContent) {
              nextData = JSON.parse(node.textContent);
            }
          } catch (error) {}

          return {
            href: window.location.href,
            origin: window.location.origin,
            title: document.title,
            cookie: document.cookie || '',
            localStorage: dumpStorage(window.localStorage),
            sessionStorage: dumpStorage(window.sessionStorage),
            meta,
            hiddenInputs,
            nextData,
          };
        }
        """
    )

    context_cookies = []
    if browser.context is not None and page_url:
        context_cookies = await browser.context.cookies([page_url])

    return {
        "page_url": page_url,
        "origin": browser_result.get("origin") or "",
        "title": browser_result.get("title") or "",
        "document_cookie": browser_result.get("cookie") or "",
        "localStorage": browser_result.get("localStorage") or {},
        "sessionStorage": browser_result.get("sessionStorage") or {},
        "meta": browser_result.get("meta") or {},
        "hiddenInputs": browser_result.get("hiddenInputs") or {},
        "nextData": browser_result.get("nextData"),
        "context_cookies": context_cookies,
    }


def _normalize_marker_values(values: list[str] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in list(values or []):
        candidate = str(value).strip()
        lowered = candidate.lower()
        if not candidate or lowered in seen:
            continue
        seen.add(lowered)
        normalized.append(candidate)
    return normalized


def _normalize_http_urls(values: list[str] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in list(values or []):
        candidate = str(value).strip()
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return normalized


def _extract_session_artifacts(
    material: dict[str, Any],
    *,
    base_url: str | None = None,
    allow_anonymous: bool = False,
) -> dict[str, Any]:
    page_url = str(material.get("page_url") or "")
    normalized_base_url = _normalize_base_url(base_url) or _normalize_base_url(
        str(material.get("origin") or "")
    )

    cookies = {
        str(item.get("name")): str(item.get("value"))
        for item in material.get("context_cookies", [])
        if item.get("name")
    }
    cookies.update(_parse_cookie_header(str(material.get("document_cookie") or "")))

    candidate_values = _string_candidates_from_browser_material(material)
    headers: dict[str, str] = {}
    authorization = _authorization_header(candidate_values)
    csrf_token = _choose_value(candidate_values, CSRF_KEYWORDS)
    api_key = _choose_value(candidate_values, API_KEY_KEYWORDS)
    if authorization:
        headers["Authorization"] = authorization
    if csrf_token:
        headers["X-CSRF-Token"] = csrf_token
    if api_key:
        headers["X-API-Key"] = api_key

    if not headers and not cookies and not allow_anonymous:
        raise ValueError("No reusable authentication material was found in browser state")

    return {
        "page_url": page_url,
        "base_url": normalized_base_url,
        "cookies": cookies,
        "headers": headers,
        "candidate_values": candidate_values,
        "page_title": str(material.get("title") or ""),
    }


def _has_session_cookie_signal(cookies: dict[str, str]) -> bool:
    for key, value in cookies.items():
        lowered_key = key.lower()
        lowered_value = str(value).lower()
        if any(keyword in lowered_key for keyword in SESSION_COOKIE_KEYWORDS):
            return True
        if lowered_value.startswith("eyj") and len(lowered_value) > 20:
            return True
    return False


def _has_path_hint(page_url: str, hints: tuple[str, ...]) -> bool:
    parsed = urlparse(page_url)
    path = f"{parsed.path}?{parsed.query}".lower()
    return any(hint in path for hint in hints)


def _auto_bootstrap_profile_name(page_url: str, base_url: str | None) -> str:
    parsed = urlparse(base_url or page_url)
    host = parsed.netloc or "browser"
    safe_host = host.replace(".", "-").replace(":", "-").replace("_", "-")
    return f"browser-auto-{safe_host}"


def maybe_auto_bootstrap_session_profile_from_browser(
    agent_state: Any,
    *,
    tab_id: str | None = None,
    source_action: str | None = None,
    browser: Any | None = None,
) -> dict[str, Any]:
    active_browser = browser
    if active_browser is None:
        manager = _browser_manager()
        active_browser = manager._get_agent_browser()
    if active_browser is None:
        return {
            "success": True,
            "auto_bootstrapped": False,
            "reason": "browser_not_launched",
        }

    resolved_tab_id = tab_id or active_browser.current_page_id
    if not resolved_tab_id or resolved_tab_id not in active_browser.pages:
        return {
            "success": True,
            "auto_bootstrapped": False,
            "reason": "tab_not_found",
            "tab_id": resolved_tab_id,
        }

    material = active_browser._run_async(_collect_browser_material(active_browser, resolved_tab_id))
    extracted = _extract_session_artifacts(material, allow_anonymous=True)
    headers = dict(extracted["headers"])
    cookies = dict(extracted["cookies"])
    candidate_values = dict(extracted["candidate_values"])
    page_url = str(extracted["page_url"] or "")
    base_url = extracted["base_url"]

    strong_auth_signal = bool(headers) or bool(candidate_values)
    session_cookie_signal = _has_session_cookie_signal(cookies)
    authenticated_path_signal = _has_path_hint(page_url, AUTHENTICATED_PATH_HINTS)
    login_path_signal = _has_path_hint(page_url, LOGIN_PATH_HINTS)
    if not (
        strong_auth_signal
        or session_cookie_signal
        or (bool(cookies) and authenticated_path_signal and not login_path_signal)
    ):
        return {
            "success": True,
            "auto_bootstrapped": False,
            "reason": "no_likely_authenticated_material",
            "tab_id": resolved_tab_id,
            "page_url": page_url,
        }

    fingerprint = _stable_id(
        "browserfp",
        resolved_tab_id,
        base_url or "",
        page_url,
        json.dumps(headers, sort_keys=True),
        json.dumps(cookies, sort_keys=True),
        json.dumps(sorted(candidate_values.keys())),
    )
    bootstrap_state = getattr(active_browser, AUTO_BOOTSTRAP_BROWSER_STATE_ATTR, None)
    if not isinstance(bootstrap_state, dict):
        bootstrap_state = {}
        setattr(active_browser, AUTO_BOOTSTRAP_BROWSER_STATE_ATTR, bootstrap_state)

    existing_entry = bootstrap_state.get(resolved_tab_id)
    if isinstance(existing_entry, dict) and existing_entry.get("fingerprint") == fingerprint:
        return {
            "success": True,
            "auto_bootstrapped": False,
            "reason": "unchanged_browser_auth_state",
            "tab_id": resolved_tab_id,
            "page_url": page_url,
            "profile_id": existing_entry.get("profile_id"),
        }

    save_result = save_session_profile(
        agent_state=agent_state,
        name=_auto_bootstrap_profile_name(page_url, base_url),
        headers=headers,
        cookies=cookies,
        base_url=base_url,
        role="authenticated",
        notes=_build_notes(
            _normalize_optional_text(
                f"Automatically bootstrapped after browser action '{source_action or 'unknown'}'."
            ),
            page_url=page_url,
            tab_id=resolved_tab_id,
            candidate_count=len(candidate_values),
        ),
    )
    if not save_result.get("success"):
        raise ValueError(str(save_result.get("error") or "session profile save failed"))

    bootstrap_state[resolved_tab_id] = {
        "fingerprint": fingerprint,
        "profile_id": save_result.get("profile_id"),
    }
    if hasattr(agent_state, "update_context"):
        agent_state.update_context(
            "last_auto_bootstrapped_session_profile",
            {
                "profile_id": save_result.get("profile_id"),
                "page_url": page_url,
                "tab_id": resolved_tab_id,
                "source_action": source_action,
            },
        )

    return {
        "success": True,
        "auto_bootstrapped": True,
        "tab_id": resolved_tab_id,
        "page_url": page_url,
        "profile_id": save_result.get("profile_id"),
        "record": save_result.get("record"),
        "extracted_material": {
            "headers": _redact_mapping(headers),
            "cookies": _redact_mapping(cookies),
            "sensitive_keys": sorted(candidate_values.keys())[:40],
        },
    }


def _browser_signal_init_script() -> str:
    return """
        () => {
          const pushSignal = (kind, value) => {
            const text = String(value ?? '');
            try {
              console.log(`${'__strix_browser_signal__:'}${kind}:${text}`);
            } catch (error) {}
            try {
              window.__strixBrowserSignals = window.__strixBrowserSignals || [];
              window.__strixBrowserSignals.push({ kind, value: text });
            } catch (error) {}
          };
          window.alert = (...args) => {
            pushSignal('alert', args.join(' '));
            return true;
          };
          window.confirm = (...args) => {
            pushSignal('confirm', args.join(' '));
            return true;
          };
          window.prompt = (...args) => {
            pushSignal('prompt', args.join(' '));
            return args.length > 1 ? String(args[1]) : '';
          };
          window.addEventListener('error', (event) => {
            pushSignal('pageerror', event && event.message ? event.message : '');
          });
          window.addEventListener('unhandledrejection', (event) => {
            const reason = event && event.reason;
            const message = reason && reason.message ? reason.message : String(reason || '');
            pushSignal('rejection', message);
          });
        }
    """


async def _probe_artifact_page(
    browser: Any,
    artifact_url: str,
    *,
    viewer_url: str | None = None,
    artifact_filename: str | None = None,
    wait_seconds: float,
) -> dict[str, Any]:
    if browser.context is None:
        raise ValueError("Browser context is not available")

    page = await browser.context.new_page()
    tab_id = f"tab_{browser._next_tab_id}"
    browser._next_tab_id += 1
    previous_tab_id = browser.current_page_id
    browser.pages[tab_id] = page
    browser.current_page_id = tab_id
    await browser._setup_console_logging(page, tab_id)
    navigation_url = str(viewer_url or artifact_url)

    try:
        await page.add_init_script(_browser_signal_init_script())
        await page.goto(navigation_url, wait_until="domcontentloaded")
        await page.wait_for_timeout(max(250, int(wait_seconds * 1000)))
        script = """
            () => {
              const artifactUrl = __STRIX_ARTIFACT_URL__;
              const artifactName = __STRIX_ARTIFACT_NAME__;
              const interesting = ['onload', 'onerror', 'onclick', 'onmouseover', 'href', 'src'];
              const activeNodes = [];
              for (const node of document.querySelectorAll('[onload],[onerror],[onclick],[onmouseover],[href^="javascript:"],[src^="javascript:"]')) {
                if (activeNodes.length >= 10) {
                  break;
                }
                const attrs = {};
                for (const attr of interesting) {
                  const value = node.getAttribute && node.getAttribute(attr);
                  if (value) {
                    attrs[attr] = value;
                  }
                }
                activeNodes.push({
                  tag: (node.tagName || '').toLowerCase(),
                  attrs,
                });
              }
              const artifactMarkers = [artifactUrl, artifactName].filter(Boolean).map((item) => String(item).toLowerCase());
              const matchedArtifactNodes = [];
              for (const node of document.querySelectorAll('img,iframe,object,embed,source,a,link,use,image')) {
                if (matchedArtifactNodes.length >= 10) {
                  break;
                }
                const attrs = {};
                let matched = false;
                for (const attr of ['href', 'src', 'data', 'poster', 'xlink:href']) {
                  const value = node.getAttribute && node.getAttribute(attr);
                  if (!value) {
                    continue;
                  }
                  attrs[attr] = value;
                  const loweredValue = String(value).toLowerCase();
                  if (artifactMarkers.some((marker) => marker && loweredValue.includes(marker))) {
                    matched = true;
                  }
                }
                if (matched) {
                  matchedArtifactNodes.push({
                    tag: (node.tagName || '').toLowerCase(),
                    attrs,
                  });
                }
              }
              const html = document.documentElement ? document.documentElement.outerHTML || '' : '';
              const text = document.body && document.body.innerText
                ? document.body.innerText
                : ((document.documentElement && document.documentElement.textContent) || '');
              return {
                href: window.location.href,
                title: document.title || '',
                readyState: document.readyState || '',
                htmlSnippet: html.slice(0, 1200),
                textSnippet: text.slice(0, 400),
                svgCount: document.querySelectorAll('svg').length,
                scriptCount: document.querySelectorAll('script').length,
                activeNodes,
                matchedArtifactNodes,
                matchedArtifactCount: matchedArtifactNodes.length,
                browserSignals: window.__strixBrowserSignals || [],
              };
            }
            """
        script = script.replace("__STRIX_ARTIFACT_URL__", json.dumps(artifact_url))
        script = script.replace("__STRIX_ARTIFACT_NAME__", json.dumps(str(artifact_filename or "")))
        page_result = await page.evaluate(
            script
        )
        console_logs = list(browser.console_logs.get(tab_id, []))
    finally:
        browser.pages.pop(tab_id, None)
        browser.console_logs.pop(tab_id, None)
        browser.current_page_id = previous_tab_id
        await page.close()

    return {
        "tab_id": tab_id,
        "navigation_url": navigation_url,
        "console_logs": console_logs,
        "page_result": page_result,
    }


@register_tool(sandbox_execution=False)
def bootstrap_session_profile_from_browser(
    agent_state: Any,
    name: str,
    role: str | None = None,
    tenant: str | None = None,
    tab_id: str | None = None,
    base_url: str | None = None,
    notes: str | None = None,
    allow_anonymous: bool = False,
) -> dict[str, Any]:
    try:
        normalized_name = _normalize_non_empty(name, "name")
        manager = _browser_manager()
        browser = manager._get_agent_browser()
        if browser is None:
            raise ValueError("Browser is not launched for the current agent")

        resolved_tab_id = tab_id or browser.current_page_id
        if not resolved_tab_id or resolved_tab_id not in browser.pages:
            raise ValueError(f"Tab '{resolved_tab_id}' was not found")

        material = browser._run_async(_collect_browser_material(browser, resolved_tab_id))
        extracted = _extract_session_artifacts(
            material,
            base_url=base_url,
            allow_anonymous=allow_anonymous,
        )
        page_url = str(extracted["page_url"] or "")
        normalized_base_url = extracted["base_url"]
        cookies = dict(extracted["cookies"])
        headers = dict(extracted["headers"])
        candidate_values = dict(extracted["candidate_values"])

        save_result = save_session_profile(
            agent_state=agent_state,
            name=normalized_name,
            headers=headers,
            cookies=cookies,
            base_url=normalized_base_url,
            role=role,
            tenant=tenant,
            notes=_build_notes(
                _normalize_optional_text(notes),
                page_url=page_url,
                tab_id=resolved_tab_id,
                candidate_count=len(candidate_values),
            ),
        )
        if not save_result.get("success"):
            raise ValueError(str(save_result.get("error") or "session profile save failed"))

    except (RuntimeError, TypeError, ValueError) as e:
        return {
            "success": False,
            "error": f"Failed to bootstrap session profile from browser: {e}",
        }
    else:
        return {
            "success": True,
            "tab_id": resolved_tab_id,
            "page_url": page_url,
            "profile_id": save_result.get("profile_id"),
            "record": save_result.get("record"),
            "extracted_material": {
                "headers": _redact_mapping(headers),
                "cookies": _redact_mapping(cookies),
                "sensitive_keys": sorted(candidate_values.keys())[:40],
            },
        }


@register_tool(sandbox_execution=False)
def confirm_active_artifact_in_browser(
    agent_state: Any,
    target: str,
    component: str,
    surface: str,
    url: str,
    viewer_urls: list[str] | None = None,
    artifact_filename: str | None = None,
    expected_console_markers: list[str] | None = None,
    expected_dom_markers: list[str] | None = None,
    wait_seconds: float = 1.5,
    open_artifact_directly_if_missing: bool = True,
    persist_hypothesis: bool = True,
    auto_spawn_impact_agents: bool = True,
) -> dict[str, Any]:
    try:
        normalized_target = _normalize_non_empty(target, "target")
        normalized_component = _normalize_non_empty(component, "component")
        normalized_surface = _normalize_non_empty(surface, "surface")
        normalized_url = _normalize_non_empty(url, "url")
        if urlparse(normalized_url).scheme not in {"http", "https"}:
            raise ValueError("url must be an absolute http(s) URL")
        if wait_seconds <= 0:
            raise ValueError("wait_seconds must be > 0")

        manager = _browser_manager()
        browser = manager._get_agent_browser()
        if browser is None:
            return {
                "success": True,
                "available": False,
                "confirmed_execution": False,
                "active_content_detected": False,
                "url": normalized_url,
                "reason": "Browser is not launched for the current agent",
            }

        console_markers = _normalize_marker_values(expected_console_markers)
        dom_markers = _normalize_marker_values(expected_dom_markers)
        normalized_viewer_urls = _normalize_http_urls(viewer_urls)

        def summarize_probe(probe: dict[str, Any], *, viewer_mode: bool) -> dict[str, Any]:
            page_result = dict(probe.get("page_result") or {})
            console_logs = list(probe.get("console_logs") or [])
            console_text = "\n".join(str(item.get("text") or "") for item in console_logs).lower()
            page_text = " ".join(
                [
                    str(page_result.get("htmlSnippet") or ""),
                    str(page_result.get("textSnippet") or ""),
                    json.dumps(page_result.get("activeNodes") or [], ensure_ascii=False),
                    json.dumps(page_result.get("matchedArtifactNodes") or [], ensure_ascii=False),
                ]
            ).lower()
            signal_logs = [
                str(item.get("text") or "")
                for item in console_logs
                if str(item.get("text") or "").startswith(BROWSER_SIGNAL_PREFIX)
            ]
            console_hits = [
                marker
                for marker in console_markers
                if marker.lower() in console_text
            ]
            dom_hits = [
                marker
                for marker in dom_markers
                if marker.lower() in page_text
            ]
            viewer_context_detected = bool(page_result.get("matchedArtifactCount") or 0)
            active_content_detected = bool(page_result.get("activeNodes") or page_result.get("scriptCount") or 0)
            confirmed_execution = (
                bool(signal_logs or console_hits)
                if not viewer_mode
                else bool(viewer_context_detected and (signal_logs or console_hits))
            )
            return {
                "probe": probe,
                "page_result": page_result,
                "console_logs": console_logs,
                "signal_logs": signal_logs,
                "console_hits": console_hits,
                "dom_hits": dom_hits,
                "viewer_context_detected": viewer_context_detected,
                "active_content_detected": active_content_detected,
                "confirmed_execution": confirmed_execution,
            }

        workflow_replay_results: list[dict[str, Any]] = []
        selected_summary: dict[str, Any] | None = None
        for viewer_url in normalized_viewer_urls:
            probe = browser._run_async(
                _probe_artifact_page(
                    browser,
                    normalized_url,
                    viewer_url=viewer_url,
                    artifact_filename=artifact_filename,
                    wait_seconds=wait_seconds,
                )
            )
            summary = summarize_probe(probe, viewer_mode=True)
            workflow_replay_results.append(
                {
                    "viewer_url": viewer_url,
                    "navigation_url": probe.get("navigation_url"),
                    "viewer_context_detected": summary["viewer_context_detected"],
                    "confirmed_execution": summary["confirmed_execution"],
                    "console_hits": summary["console_hits"],
                    "dom_hits": summary["dom_hits"],
                    "signal_logs": summary["signal_logs"],
                    "page_result": summary["page_result"],
                }
            )
            if summary["confirmed_execution"]:
                selected_summary = summary
                break
            if selected_summary is None and summary["viewer_context_detected"]:
                selected_summary = summary

        if selected_summary is None and open_artifact_directly_if_missing:
            direct_probe = browser._run_async(
                _probe_artifact_page(
                    browser,
                    normalized_url,
                    artifact_filename=artifact_filename,
                    wait_seconds=wait_seconds,
                )
            )
            selected_summary = summarize_probe(direct_probe, viewer_mode=False)

        if selected_summary is None:
            selected_summary = {
                "probe": {},
                "page_result": {},
                "console_logs": [],
                "signal_logs": [],
                "console_hits": [],
                "dom_hits": [],
                "viewer_context_detected": False,
                "active_content_detected": False,
                "confirmed_execution": False,
            }

        page_result = dict(selected_summary.get("page_result") or {})
        console_logs = list(selected_summary.get("console_logs") or [])
        signal_logs = list(selected_summary.get("signal_logs") or [])
        console_hits = list(selected_summary.get("console_hits") or [])
        dom_hits = list(selected_summary.get("dom_hits") or [])
        active_content_detected = bool(selected_summary.get("active_content_detected"))
        confirmed_execution = bool(selected_summary.get("confirmed_execution"))
        viewer_context_detected = bool(selected_summary.get("viewer_context_detected"))
        execution_context_url = str(
            page_result.get("href")
            or selected_summary.get("probe", {}).get("navigation_url")
            or normalized_url
        )

        coverage_result = None
        hypothesis_result = None
        evidence_result = None
        followup_agent_result = None
        if confirmed_execution:
            coverage_result = record_coverage(
                agent_state=agent_state,
                target=normalized_target,
                component=normalized_component,
                surface=normalized_surface,
                status="in_progress",
                rationale=(
                    f"Browser execution proof observed active client-side behavior while loading {execution_context_url}."
                ),
                priority="critical",
                next_step=(
                    "Capture the exact render path and authenticated viewer context, then confirm exploitability "
                    "in the business workflow that exposes this artifact."
                ),
            )
            if persist_hypothesis:
                hypothesis_result = record_hypothesis(
                    agent_state=agent_state,
                    hypothesis=f"Stored client-side execution is reachable at {normalized_url}",
                    target=normalized_target,
                    component=normalized_component,
                    vulnerability_type="xss",
                    status="validated",
                    priority="critical",
                    rationale=(
                        f"Browser instrumentation observed executable client-side behavior for {normalized_surface}."
                    ),
                )
            evidence_result = record_evidence(
                agent_state=agent_state,
                title=f"Browser execution proof for {normalized_surface}",
                details=json.dumps(
                    {
                        "url": normalized_url,
                        "execution_context_url": execution_context_url,
                        "viewer_context_detected": viewer_context_detected,
                        "workflow_replay_results": workflow_replay_results,
                        "console_hits": console_hits,
                        "dom_hits": dom_hits,
                        "signal_logs": signal_logs,
                        "console_logs": console_logs,
                        "page_result": page_result,
                    },
                    ensure_ascii=False,
                ),
                source="tool",
                target=normalized_target,
                component=normalized_component,
                related_coverage_id=(
                    coverage_result.get("coverage_id")
                    if isinstance(coverage_result, dict)
                    else None
                ),
                related_hypothesis_id=(
                    hypothesis_result.get("hypothesis_id")
                    if isinstance(hypothesis_result, dict)
                    else None
                ),
            )
            if auto_spawn_impact_agents:
                followup_agent_result = _spawn_followup_agents(
                    agent_state,
                    target=normalized_target,
                    hypothesis_result=hypothesis_result,
                    prefer_impact=True,
                )

    except (RuntimeError, TypeError, ValueError) as e:
        return {
            "success": False,
            "error": f"Failed to confirm active artifact in browser: {e}",
        }
    else:
        return {
            "success": True,
            "available": True,
            "url": normalized_url,
            "execution_context_url": execution_context_url,
            "confirmed_execution": confirmed_execution,
            "viewer_context_detected": viewer_context_detected,
            "active_content_detected": active_content_detected,
            "workflow_replay_results": workflow_replay_results,
            "console_hits": console_hits,
            "dom_hits": dom_hits,
            "signal_logs": signal_logs,
            "console_logs": console_logs,
            "page_result": page_result,
            "coverage_result": coverage_result,
            "hypothesis_result": hypothesis_result,
            "evidence_result": evidence_result,
            "followup_agent_result": followup_agent_result,
        }
