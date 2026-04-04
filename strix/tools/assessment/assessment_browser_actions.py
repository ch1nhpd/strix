import json
import re
from posixpath import splitext
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse

from strix.tools.registry import register_tool

from .assessment_actions import (
    _normalize_non_empty,
    _slug,
    _stable_id,
    _utc_now,
    bulk_record_coverage,
    list_assessment_state,
    record_coverage,
    record_evidence,
    record_hypothesis,
)
from .assessment_runtime_actions import (
    _get_inventory_store,
    _normalize_runtime_path,
    _priority_for_endpoint,
    _sort_inventory,
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
BROWSER_SURFACE_ROUTE_ATTRS = (
    "href",
    "action",
    "formaction",
    "data-href",
    "data-url",
    "data-endpoint",
    "data-api",
    "data-route",
    "data-path",
    "data-action",
    "data-link",
    "data-target",
    "hx-get",
    "hx-post",
    "hx-put",
    "hx-delete",
    "hx-patch",
    "ng-href",
    "onclick",
    "routerlink",
    "src",
)
BROWSER_SURFACE_STATIC_EXTENSIONS = {
    ".avif",
    ".bmp",
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".map",
    ".mp4",
    ".png",
    ".svg",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
}
BROWSER_SURFACE_HIGH_VALUE_PATH_MARKERS = (
    "/account",
    "/admin",
    "/api",
    "/auth",
    "/billing",
    "/checkout",
    "/dashboard",
    "/download",
    "/export",
    "/graphql",
    "/import",
    "/invite",
    "/login",
    "/oauth",
    "/orders",
    "/payment",
    "/profile",
    "/reset",
    "/search",
    "/settings",
    "/subscription",
    "/tenant",
    "/upload",
    "/users",
    "/verify",
    "/webhook",
    "/workspace",
)
BROWSER_TRAVERSAL_BLOCKED_MARKERS = (
    "delete",
    "disable",
    "logout",
    "remove",
    "revoke",
    "signout",
    "terminate",
)
BROWSER_TRAVERSAL_PRIORITY_MARKERS = (
    "admin",
    "billing",
    "dashboard",
    "invite",
    "order",
    "payment",
    "profile",
    "project",
    "report",
    "search",
    "setting",
    "subscription",
    "tenant",
    "user",
    "workspace",
)
BROWSER_CLICK_EXPLORATION_BLOCKED_MARKERS = (
    "add",
    "checkout",
    "create",
    "delete",
    "disable",
    "invite",
    "logout",
    "pay",
    "purchase",
    "remove",
    "reset",
    "revoke",
    "save",
    "signout",
    "submit",
    "terminate",
    "update",
    "upload",
)
BROWSER_CLICK_EXPLORATION_PRIORITY_MARKERS = (
    "activity",
    "advanced",
    "audit",
    "detail",
    "filter",
    "history",
    "member",
    "menu",
    "more",
    "notification",
    "panel",
    "permission",
    "profile",
    "report",
    "role",
    "security",
    "setting",
    "tab",
    "team",
    "user",
)
BROWSER_FORM_EXPLORATION_MARKERS = (
    "filter",
    "find",
    "lookup",
    "query",
    "search",
    "sort",
    "tab",
    "view",
)
BROWSER_FORM_EXPLORATION_PARAM_MARKERS = {
    "q": "security",
    "query": "security",
    "search": "security",
    "keyword": "security",
    "filter": "active",
    "status": "active",
    "type": "security",
    "role": "admin",
    "tab": "mfa",
    "view": "detail",
    "section": "security",
    "sort": "created_at",
    "order": "desc",
}
BROWSER_ROUTE_HINT_SCRIPT_ATTRS = {
    "onclick",
    "data-action",
    "hx-delete",
    "hx-get",
    "hx-patch",
    "hx-post",
    "hx-put",
    "ng-href",
    "routerlink",
}
SCRIPT_ROUTE_VALUE_MARKERS = (
    "axios",
    "fetch(",
    "location",
    "navigate(",
    "open(",
    "router.push",
    "window.open",
)
MATERIAL_ROUTE_KEYWORDS = (
    "action",
    "api",
    "callback",
    "endpoint",
    "href",
    "link",
    "location",
    "next",
    "path",
    "redirect",
    "return",
    "route",
    "target",
    "uri",
    "url",
    "viewer",
)
BROWSER_REVIEWABLE_ASSET_EXTENSIONS = {".js", ".mjs", ".cjs", ".map"}
SOURCE_MAP_DIRECTIVE_RE = re.compile(
    r"""sourceMappingURL\s*=\s*(?P<url>[^\s"'`*]+)""",
    re.IGNORECASE,
)
BROWSER_ASSET_FETCH_MARKER = "__STRIX_BROWSER_FETCH_ASSET__"
SCRIPT_ROUTE_LITERAL_RE = re.compile(
    r"""(?P<url>https?://[^\s"'`<>()]+|/[A-Za-z0-9._~%!$&'()*+,;=:@/\-?#[\]]+)"""
)
SOURCE_MAP_METADATA_KEYS = {"version", "sources", "sourcesContent", "names", "mappings"}
SOURCE_MAP_ROLE_HINT_MARKERS = (
    "admin",
    "owner",
    "permission",
    "privilege",
    "role",
    "scope",
    "staff",
    "moderator",
)
SOURCE_MAP_OBJECT_HINT_MARKERS = (
    "account",
    "attachment",
    "audit",
    "bucket",
    "file",
    "id",
    "invoice",
    "member",
    "object",
    "order",
    "organization",
    "org",
    "project",
    "report",
    "subscription",
    "team",
    "tenant",
    "user",
    "workspace",
)
SOURCE_MAP_SECRET_HINT_MARKERS = (
    "accesskey",
    "access_key",
    "api_key",
    "apikey",
    "auth",
    "clientsecret",
    "client_secret",
    "csrf",
    "jwt",
    "password",
    "privatekey",
    "private_key",
    "secret",
    "session",
    "token",
    "xsrf",
)
SOURCE_MAP_FEATURE_HINT_MARKERS = (
    "beta",
    "debug",
    "experiment",
    "feature",
    "flag",
    "internal",
    "preview",
    "toggle",
)
SOURCE_MAP_PARAM_HINT_MARKERS = (
    "callback",
    "file",
    "id",
    "path",
    "redirect",
    "return",
    "state",
    "target",
    "tenant",
    "token",
    "url",
    "uri",
)
SOURCE_MAP_SOURCE_PRIORITY_MARKERS = (
    "admin",
    "auth",
    "billing",
    "debug",
    "internal",
    "report",
    "security",
    "tenant",
)


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


def _decode_json_container(raw_value: str) -> dict[str, Any] | list[Any] | None:
    candidate = str(raw_value or "").strip()
    if len(candidate) < 2 or candidate[0] not in {"{", "["} or len(candidate) > 12000:
        return None
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, (dict, list)):
        return parsed
    return None


def _looks_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(keyword in lowered for keyword in SENSITIVE_KEYWORDS)


def _looks_material_route_key(key: str) -> bool:
    lowered = str(key or "").lower()
    return any(keyword in lowered for keyword in MATERIAL_ROUTE_KEYWORDS)


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


async def _collect_browser_surface(browser: Any, tab_id: str) -> dict[str, Any]:
    page = browser.pages[tab_id]
    return await page.evaluate(
        """
        () => {
          const LIMIT = 160;
          const trim = (value, limit = 120) =>
            String(value || '').replace(/\\s+/g, ' ').trim().slice(0, limit);
          const addUnique = (items, seen, key, value) => {
            if (!key || seen.has(key) || items.length >= LIMIT) {
              return;
            }
            seen.add(key);
            items.push(value);
          };

          const links = [];
          const forms = [];
          const routeHints = [];
          const scriptHints = [];
          const interactive = [];
          const headings = [];
          const linkSeen = new Set();
          const formSeen = new Set();
          const routeSeen = new Set();
          const scriptSeen = new Set();
          const interactiveSeen = new Set();
          const headingSeen = new Set();
          const routeAttrs = %ROUTE_ATTRS%;
          const routeSelector = Array.from(new Set(routeAttrs.map((attr) => `[${attr}]`))).join(',');
          const scriptMarkers = %SCRIPT_MARKERS%;

          for (const element of document.querySelectorAll('a[href]')) {
            const href = trim(element.getAttribute('href') || '', 500);
            const text = trim(
              element.innerText ||
              element.getAttribute('aria-label') ||
              element.getAttribute('title') ||
              element.getAttribute('data-testid') ||
              ''
            );
            const rel = trim(element.getAttribute('rel') || '');
            const nav = Boolean(element.closest('nav, header, aside, [role="navigation"], [role="menu"]'));
            addUnique(links, linkSeen, `${href}|${text}|${nav}`, { href, text, rel, nav });
          }

          for (const form of document.querySelectorAll('form')) {
            const action = trim(form.getAttribute('action') || window.location.href, 500);
            const method = trim(form.getAttribute('method') || 'GET').toUpperCase();
            const inputNames = Array.from(
              form.querySelectorAll('input[name], select[name], textarea[name]')
            )
              .map((element) => trim(element.getAttribute('name') || '', 80))
              .filter(Boolean)
              .slice(0, 40);
            const buttonLabels = Array.from(form.querySelectorAll('button, input[type="submit"]'))
              .map((element) =>
                trim(
                  element.innerText ||
                  element.getAttribute('value') ||
                  element.getAttribute('aria-label') ||
                  ''
                )
              )
              .filter(Boolean)
              .slice(0, 10);
            addUnique(
              forms,
              formSeen,
              `${action}|${method}|${inputNames.join(',')}`,
              { action, method, inputNames, buttonLabels }
            );
          }

          if (routeSelector) {
            for (const element of document.querySelectorAll(routeSelector)) {
              const tag = String((element.tagName || '')).toLowerCase();
              const label = trim(
                element.innerText ||
                element.getAttribute('aria-label') ||
                element.getAttribute('title') ||
                element.getAttribute('name') ||
                element.getAttribute('data-testid') ||
                ''
              );
              for (const attr of routeAttrs) {
                const value = trim(element.getAttribute(attr) || '', 500);
                if (!value) {
                  continue;
                }
                addUnique(
                  routeHints,
                  routeSeen,
                  `${attr}|${value}|${tag}|${label}`,
                  { attr, value, tag, label }
                );
              }
            }
          }

          for (const script of document.querySelectorAll('script')) {
            const inlineText = trim(script.textContent || '', 1600);
            if (!inlineText) {
              continue;
            }
            const loweredText = inlineText.toLowerCase();
            if (!scriptMarkers.some((marker) => loweredText.includes(marker))) {
              continue;
            }
            addUnique(
              scriptHints,
              scriptSeen,
              inlineText,
              {
                attr: 'inline-script',
                value: inlineText,
                tag: 'script',
                label: trim(
                  script.getAttribute('id') ||
                  script.getAttribute('type') ||
                  script.getAttribute('nonce') ||
                  '',
                  80
                ),
              }
            );
          }

          for (const script of document.querySelectorAll('script[src]')) {
            const src = trim(script.getAttribute('src') || '', 500);
            if (!src) {
              continue;
            }
            addUnique(
              routeHints,
              routeSeen,
              `script-src|${src}|script`,
              { attr: 'script-src', value: src, tag: 'script', label: '' }
            );
          }

          for (const element of document.querySelectorAll('button,[role="button"],[role="menuitem"],summary,[data-testid],[aria-label]')) {
            const label = trim(
              element.innerText ||
              element.getAttribute('aria-label') ||
              element.getAttribute('title') ||
              element.getAttribute('data-testid') ||
              ''
            );
            if (!label) {
              continue;
            }
            const target =
              trim(element.getAttribute('formaction') || '', 500) ||
              trim(element.getAttribute('data-url') || '', 500) ||
              trim(element.getAttribute('data-route') || '', 500) ||
              trim(element.getAttribute('data-endpoint') || '', 500);
            addUnique(
              interactive,
              interactiveSeen,
              `${label}|${target}`,
              { label, target, role: trim(element.getAttribute('role') || '') }
            );
          }

          for (const element of document.querySelectorAll('h1,h2,h3,[role="heading"],nav a,aside a')) {
            const text = trim(element.innerText || element.getAttribute('aria-label') || '');
            if (!text) {
              continue;
            }
            addUnique(headings, headingSeen, text, text);
          }

          return {
            page_url: window.location.href,
            origin: window.location.origin,
            title: document.title || '',
            links,
            forms,
            routeHints,
            scriptHints,
            interactive,
            headings,
          };
        }
        """.replace("%ROUTE_ATTRS%", json.dumps(list(BROWSER_SURFACE_ROUTE_ATTRS)))
        .replace("%SCRIPT_MARKERS%", json.dumps([marker.lower() for marker in SCRIPT_ROUTE_VALUE_MARKERS]))
    )


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


def _normalize_query_params(query: str) -> list[str]:
    if not query:
        return []
    return sorted({key for key, _ in parse_qsl(query, keep_blank_values=True) if key})


def _normalize_browser_target_hint(agent_state: Any) -> str | None:
    context = getattr(agent_state, "context", {})
    if isinstance(context, dict):
        candidate = str(context.get("last_assessment_target") or "").strip()
        if candidate:
            return candidate

    assessment_state = list_assessment_state(
        agent_state=agent_state,
        include_resolved_coverage=True,
        include_evidence=False,
        max_items=120,
    )
    if assessment_state.get("success"):
        targets: list[str] = []
        for key in ("coverage", "hypotheses"):
            for item in list(assessment_state.get(key) or []):
                if not isinstance(item, dict):
                    continue
                candidate = str(item.get("target") or "").strip()
                if candidate and candidate not in targets:
                    targets.append(candidate)
        if len(targets) == 1:
            return targets[0]

    _, inventory_store = _get_inventory_store(agent_state)
    targets = [
        str(record.get("target") or "").strip()
        for record in inventory_store.values()
        if isinstance(record, dict) and str(record.get("target") or "").strip()
    ]
    unique_targets = list(dict.fromkeys(targets))
    if len(unique_targets) == 1:
        return unique_targets[0]
    return None


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


def _normalize_browser_surface_url(candidate: str, page_url: str) -> dict[str, Any] | None:
    value = str(candidate or "").strip()
    if not value or value.lower().startswith(("javascript:", "mailto:", "tel:", "#")):
        return None
    absolute = urljoin(page_url, value)
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    normalized_path = _normalize_runtime_path(parsed.path or "/")
    return {
        "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        + (f"?{parsed.query}" if parsed.query else ""),
        "host": parsed.netloc,
        "path": normalized_path,
        "query_params": _normalize_query_params(parsed.query),
    }


def _clean_browser_route_hint_value(value: str) -> str:
    cleaned = str(value or "").strip().lstrip("\"'`")
    while cleaned and cleaned[-1] in "\"'`),;]}":
        cleaned = cleaned[:-1].rstrip()
    return cleaned.strip()


def _is_direct_browser_route_hint_value(value: str) -> bool:
    candidate = str(value or "").strip()
    if not candidate:
        return False
    if candidate.startswith(("http://", "https://", "/", "./", "../")):
        return True
    if " " in candidate or any(char in candidate for char in "\"'`(){};"):
        return False
    return "/" in candidate


def _expand_browser_route_hint_values(*, attr: str, value: str) -> list[str]:
    raw_value = _normalize_optional_text(value)
    if raw_value is None:
        return []

    normalized_attr = str(attr or "").strip().lower()
    raw_lower = raw_value.lower()
    script_like = normalized_attr in BROWSER_ROUTE_HINT_SCRIPT_ATTRS or any(
        marker in raw_lower for marker in SCRIPT_ROUTE_VALUE_MARKERS
    )
    direct_candidate = _is_direct_browser_route_hint_value(raw_value)

    expanded_values: list[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        cleaned = _clean_browser_route_hint_value(candidate)
        if not cleaned or cleaned in seen:
            return
        seen.add(cleaned)
        expanded_values.append(cleaned)

    if direct_candidate:
        add(raw_value)

    if script_like:
        for match in SCRIPT_ROUTE_LITERAL_RE.finditer(raw_value):
            add(str(match.group("url") or ""))
    elif not direct_candidate:
        add(raw_value)

    return expanded_values


def _expand_browser_asset_hint_values(*, attr: str, value: str) -> list[str]:
    raw_value = _normalize_optional_text(value)
    if raw_value is None:
        return []

    candidates = list(_expand_browser_route_hint_values(attr=attr, value=raw_value))
    if any(extension in raw_value.lower() for extension in BROWSER_REVIEWABLE_ASSET_EXTENSIONS):
        for match in SCRIPT_ROUTE_LITERAL_RE.finditer(raw_value):
            candidates.append(str(match.group("url") or ""))
    for match in SOURCE_MAP_DIRECTIVE_RE.finditer(raw_value):
        candidates.append(str(match.group("url") or ""))

    expanded_values: list[str] = []
    seen: set[str] = set()
    allowed_prefixes = ("http://", "https://", "ws://", "wss://", "/", "./", "../")
    for candidate in candidates:
        cleaned = _clean_browser_route_hint_value(candidate)
        if (
            not cleaned
            or cleaned in seen
            or len(cleaned) > 500
            or any(char.isspace() for char in cleaned)
            or any(char in cleaned for char in "\"'`(){}[];")
            or not cleaned.startswith(allowed_prefixes)
        ):
            continue
        seen.add(cleaned)
        expanded_values.append(cleaned)
    return expanded_values


def _normalize_source_map_hint_name(value: str) -> str | None:
    candidate = str(value or "").strip()
    if len(candidate) < 3 or len(candidate) > 64:
        return None
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$.-]{2,63}", candidate):
        return None
    lowered = candidate.lower()
    if lowered in {
        "arguments",
        "class",
        "const",
        "constructor",
        "default",
        "export",
        "extends",
        "false",
        "function",
        "import",
        "let",
        "module",
        "null",
        "prototype",
        "return",
        "static",
        "super",
        "this",
        "true",
        "undefined",
        "var",
        "window",
    }:
        return None
    return candidate


def _dedupe_source_map_hints(values: list[str], *, limit: int = 12) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = _normalize_source_map_hint_name(value)
        if normalized is None or normalized.lower() in seen:
            continue
        seen.add(normalized.lower())
        deduped.append(normalized)
        if len(deduped) >= limit:
            break
    return deduped


def _extract_source_map_metadata(body: str) -> dict[str, Any] | None:
    decoded = _decode_json_container(body)
    if not isinstance(decoded, dict):
        return None
    if not any(key in decoded for key in SOURCE_MAP_METADATA_KEYS):
        return None

    source_files = list(
        dict.fromkeys(
            str(item).strip()
            for item in list(decoded.get("sources") or [])
            if str(item).strip()
        )
    )[:20]
    embedded_sources = [
        str(item)
        for item in list(decoded.get("sourcesContent") or [])
        if isinstance(item, str) and item.strip()
    ][:10]
    names = _dedupe_source_map_hints(
        [
            str(item).strip()
            for item in list(decoded.get("names") or [])
            if str(item).strip()
        ],
        limit=24,
    )
    interesting_source_files = [
        item
        for item in source_files
        if any(marker in item.lower() for marker in SOURCE_MAP_SOURCE_PRIORITY_MARKERS)
    ][:10]
    role_hints = [
        item
        for item in names
        if any(marker in item.lower() for marker in SOURCE_MAP_ROLE_HINT_MARKERS)
    ][:12]
    object_hints = [
        item
        for item in names
        if any(marker in item.lower() for marker in SOURCE_MAP_OBJECT_HINT_MARKERS)
    ][:12]
    secret_hints = [
        item
        for item in names
        if any(marker in item.lower() for marker in SOURCE_MAP_SECRET_HINT_MARKERS)
    ][:12]
    feature_hints = [
        item
        for item in names
        if any(marker in item.lower() for marker in SOURCE_MAP_FEATURE_HINT_MARKERS)
    ][:12]
    param_hints = [
        item
        for item in names
        if any(marker in item.lower() for marker in SOURCE_MAP_PARAM_HINT_MARKERS)
    ][:12]

    return {
        "source_files": source_files,
        "interesting_source_files": interesting_source_files,
        "embedded_sources": embedded_sources,
        "embedded_source_count": len(embedded_sources),
        "hint_names": names,
        "role_hints": role_hints,
        "object_hints": object_hints,
        "secret_hints": secret_hints,
        "feature_hints": feature_hints,
        "param_hints": param_hints,
    }


def _browser_material_route_hints(material: dict[str, Any]) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add_hint(*, attr: str, label: str, value: str) -> None:
        raw_value = _normalize_optional_text(value)
        if raw_value is None:
            return
        lowered_value = raw_value.lower()
        absolute_or_root = raw_value.startswith(("http://", "https://", "/", "./", "../"))
        contains_path_fragment = "/" in raw_value and " " not in raw_value and not any(
            char in raw_value for char in "\"'`(){};"
        )
        script_like = any(marker in lowered_value for marker in SCRIPT_ROUTE_VALUE_MARKERS)
        if not (
            script_like
            or absolute_or_root
            or (_looks_material_route_key(label) and contains_path_fragment)
        ):
            return
        key = (attr, label, raw_value)
        if key in seen:
            return
        seen.add(key)
        hints.append(
            {
                "attr": attr,
                "label": label[:160],
                "value": raw_value,
            }
        )

    def walk(value: Any, *, prefix: str, attr: str, depth: int = 0) -> None:
        if depth > 5:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(item, (dict, list)):
                    walk(item, prefix=path, attr=attr, depth=depth + 1)
                    continue
                if isinstance(item, str):
                    add_hint(attr=attr, label=path, value=item)
                    decoded = _decode_json_container(item)
                    if decoded is not None:
                        walk(decoded, prefix=path, attr=attr, depth=depth + 1)
        elif isinstance(value, list):
            for index, item in enumerate(value[:30]):
                path = f"{prefix}[{index}]"
                if isinstance(item, (dict, list)):
                    walk(item, prefix=path, attr=attr, depth=depth + 1)
                    continue
                if isinstance(item, str):
                    add_hint(attr=attr, label=path, value=item)
                    decoded = _decode_json_container(item)
                    if decoded is not None:
                        walk(decoded, prefix=path, attr=attr, depth=depth + 1)
        elif isinstance(value, str):
            add_hint(attr=attr, label=prefix, value=value)
            decoded = _decode_json_container(value)
            if decoded is not None:
                walk(decoded, prefix=prefix, attr=attr, depth=depth + 1)

    for source_name in ("localStorage", "sessionStorage", "meta", "hiddenInputs"):
        mapping = material.get(source_name)
        if isinstance(mapping, dict):
            walk(mapping, prefix=source_name, attr=source_name)

    next_data = material.get("nextData")
    if isinstance(next_data, (dict, list)):
        walk(next_data, prefix="nextData", attr="nextData")

    return hints


def _browser_asset_artifacts_from_snapshot(
    *,
    material: dict[str, Any],
    surface: dict[str, Any],
    page_url: str,
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add_asset(
        *,
        raw_url: str,
        attr: str,
        label: str,
        inferred: bool = False,
        source_asset: str | None = None,
    ) -> None:
        normalized = _normalize_browser_surface_url(raw_url, page_url)
        if normalized is None:
            return
        normalized_path = str(normalized["path"])
        extension = splitext(normalized_path.lower())[1]
        if extension not in BROWSER_REVIEWABLE_ASSET_EXTENSIONS:
            return
        kind = "source_map" if extension == ".map" else "js_asset"
        key = (kind, str(normalized["host"]), normalized_path)
        if key in seen:
            return
        seen.add(key)
        artifacts.append(
            {
                "kind": kind,
                "host": str(normalized["host"]),
                "path": normalized_path,
                "method": "GET",
                "priority": "high" if kind == "source_map" else "normal",
                "sample_url": str(normalized["url"]),
                "source_attr": attr,
                "label": label[:160],
                "source_page_url": page_url,
                "inferred": bool(inferred),
                "source_asset": str(source_asset or "").strip(),
            }
        )

    def add_candidates(
        *,
        attr: str,
        value: str,
        label: str,
        source_asset: str | None = None,
    ) -> None:
        for candidate in _expand_browser_asset_hint_values(attr=attr, value=value):
            add_asset(
                raw_url=candidate,
                attr=attr,
                label=label,
                source_asset=source_asset,
            )

    for hint in list(surface.get("routeHints") or []):
        if not isinstance(hint, dict):
            continue
        attr = str(hint.get("attr") or "")
        raw_value = str(hint.get("value") or "")
        label = str(hint.get("label") or "")
        add_candidates(attr=attr, value=raw_value, label=label)
        lowered_attr = attr.lower()
        if lowered_attr == "script-src":
            normalized = _normalize_browser_surface_url(raw_value, page_url)
            if normalized is not None:
                normalized_url = str(normalized["url"])
                normalized_path = str(normalized["path"])
                extension = splitext(normalized_path.lower())[1]
                if extension in {".js", ".mjs", ".cjs"}:
                    add_asset(
                        raw_url=f"{normalized_url}.map",
                        attr="inferred-source-map",
                        label=label or normalized_path,
                        inferred=True,
                        source_asset=normalized_path,
                    )

    for hint in list(surface.get("scriptHints") or []):
        if not isinstance(hint, dict):
            continue
        add_candidates(
            attr=str(hint.get("attr") or "inline-script"),
            value=str(hint.get("value") or ""),
            label=str(hint.get("label") or ""),
        )

    for hint in _browser_material_route_hints(material):
        add_candidates(
            attr=str(hint.get("attr") or "material"),
            value=str(hint.get("value") or ""),
            label=str(hint.get("label") or ""),
        )

    return artifacts


def _browser_asset_fetch_script(asset_url: str) -> str:
    script = """
    async () => {
      const marker = "__STRIX_BROWSER_FETCH_ASSET__";
      const url = __STRIX_BROWSER_FETCH_ASSET_URL__;
      try {
        const response = await fetch(url, {
          credentials: 'include',
          redirect: 'follow',
          cache: 'no-store',
        });
        const text = await response.text();
        return {
          marker,
          ok: response.ok,
          status: response.status,
          content_type: response.headers.get('content-type') || '',
          final_url: response.url || url,
          body: String(text || '').slice(0, 250000),
        };
      } catch (error) {
        return {
          marker,
          ok: false,
          status: 0,
          content_type: '',
          final_url: url,
          body: '',
          error: String(error || ''),
        };
      }
    }
    """
    return script.replace("__STRIX_BROWSER_FETCH_ASSET_URL__", json.dumps(asset_url))


async def _fetch_browser_asset_body(
    browser: Any,
    *,
    tab_id: str,
    asset_url: str,
) -> dict[str, Any]:
    page = browser.pages[tab_id]
    result = await page.evaluate(_browser_asset_fetch_script(asset_url))
    if not isinstance(result, dict):
        return {
            "ok": False,
            "status": 0,
            "content_type": "",
            "final_url": asset_url,
            "body": "",
            "error": "invalid_browser_asset_fetch_result",
        }
    return {
        "ok": bool(result.get("ok")),
        "status": int(result.get("status") or 0),
        "content_type": str(result.get("content_type") or ""),
        "final_url": str(result.get("final_url") or asset_url),
        "body": str(result.get("body") or ""),
        "error": str(result.get("error") or ""),
    }


def _browser_asset_content_discovery(
    *,
    asset: dict[str, Any],
    body: str,
    page_url: str,
    auth_hint: str,
    source: str = "browser_asset",
    origin: str = "browser_asset",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    from .assessment_surface_actions import _extract_js_paths, _extract_ws_urls

    asset_url = str(
        (list(asset.get("sample_urls") or []) or [asset.get("sample_url") or ""])[0] or page_url
    ).strip()
    asset_path = str(asset.get("path") or "")
    derived_artifacts: list[dict[str, Any]] = []
    derived_inventory: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    seen_artifacts: set[tuple[str, str, str]] = set()
    seen_inventory: set[tuple[str, str, str]] = set()
    websocket_paths: set[tuple[str, str]] = set()

    def add_artifact(
        *,
        kind: str,
        host: str,
        path: str,
        method: str,
        sample_url: str,
        priority: str,
        source_files: list[str] | None = None,
        hint_names: list[str] | None = None,
        role_hints: list[str] | None = None,
        object_hints: list[str] | None = None,
        secret_hints: list[str] | None = None,
        feature_hints: list[str] | None = None,
        param_hints: list[str] | None = None,
    ) -> None:
        key = (kind, host, path)
        if key in seen_artifacts:
            return
        seen_artifacts.add(key)
        derived_artifacts.append(
            {
                "kind": kind,
                "host": host,
                "path": path,
                "method": method,
                "priority": priority,
                "sample_url": sample_url,
                "source_attr": "asset-content",
                "label": asset_path[:160],
                "source_page_url": page_url,
                "source_asset": asset_path,
                "inferred": True,
                "source_files": list(source_files or [])[:12],
                "hint_names": list(hint_names or [])[:12],
                "role_hints": list(role_hints or [])[:12],
                "object_hints": list(object_hints or [])[:12],
                "secret_hints": list(secret_hints or [])[:12],
                "feature_hints": list(feature_hints or [])[:12],
                "param_hints": list(param_hints or [])[:12],
            }
        )

    def add_inventory(
        *,
        host: str,
        path: str,
        method: str,
        sample_url: str,
        query_params: list[str],
    ) -> None:
        key = (host, path, method)
        if key in seen_inventory:
            return
        seen_inventory.add(key)
        derived_inventory.append(
            {
                "host": host,
                "normalized_path": path,
                "methods": [method],
                "status_codes": [],
                "query_params": query_params,
                "body_params": [],
                "content_types": [
                    "application/json" if path.startswith(("/api", "/graphql", "/graphiql")) else "text/html"
                ],
                "auth_hints": [auth_hint],
                "sources": [source],
                "origins": [origin],
                "sample_urls": [sample_url],
                "sample_request_ids": [],
                "observed_count": 1,
                "priority": _priority_for_endpoint(
                    path,
                    [method],
                    query_params=query_params,
                    body_params=[],
                    auth_hints=[auth_hint],
                ),
            }
        )

    asset_normalized = _normalize_browser_surface_url(asset_url or asset_path, page_url)
    source_map_metadata = _extract_source_map_metadata(body)
    if source_map_metadata and asset_normalized is not None:
        metadata_query_params = sorted(
            {
                str(item).strip()
                for item in [
                    *list(asset_normalized.get("query_params") or []),
                    *list(source_map_metadata.get("param_hints") or []),
                ]
                if str(item).strip()
            }
        )[:12]
        add_artifact(
            kind="source_map",
            host=str(asset_normalized["host"]),
            path=str(asset_normalized["path"]),
            method="GET",
            sample_url=str(asset_normalized["url"]),
            priority="high",
            source_files=list(source_map_metadata.get("interesting_source_files") or source_map_metadata.get("source_files") or [])[:12],
            hint_names=list(source_map_metadata.get("hint_names") or [])[:12],
            role_hints=list(source_map_metadata.get("role_hints") or [])[:12],
            object_hints=list(source_map_metadata.get("object_hints") or [])[:12],
            secret_hints=list(source_map_metadata.get("secret_hints") or [])[:12],
            feature_hints=list(source_map_metadata.get("feature_hints") or [])[:12],
            param_hints=metadata_query_params,
        )
        evidence_rows.append(
            {
                "kind": "source_map_metadata",
                "asset_path": asset_path,
                "source_count": len(list(source_map_metadata.get("source_files") or [])),
                "embedded_source_count": int(source_map_metadata.get("embedded_source_count") or 0),
                "interesting_source_files": list(source_map_metadata.get("interesting_source_files") or [])[:8],
                "role_hints": list(source_map_metadata.get("role_hints") or [])[:8],
                "object_hints": list(source_map_metadata.get("object_hints") or [])[:8],
                "secret_hints": list(source_map_metadata.get("secret_hints") or [])[:8],
                "feature_hints": list(source_map_metadata.get("feature_hints") or [])[:8],
                "param_hints": metadata_query_params[:8],
            }
        )

    text_blobs = [body]
    if source_map_metadata:
        text_blobs.extend(list(source_map_metadata.get("embedded_sources") or [])[:6])

    for ws_url in _extract_ws_urls(body):
        parsed = urlparse(ws_url)
        path = _normalize_runtime_path(parsed.path)
        host = parsed.netloc
        if not host:
            continue
        websocket_paths.add((host.lower(), path))
        add_artifact(
            kind="websocket_endpoint",
            host=host,
            path=path,
            method="GET",
            sample_url=ws_url,
            priority="high",
        )

    for blob in text_blobs:
        for candidate in _expand_browser_asset_hint_values(attr="inline-script", value=blob):
            normalized = _normalize_browser_surface_url(candidate, asset_url or page_url)
            if normalized is None:
                continue
            host = str(normalized["host"])
            path = str(normalized["path"])
            if (host.lower(), path) in websocket_paths:
                continue
            sample_url = str(normalized["url"])
            extension = splitext(path.lower())[1]
            if extension in BROWSER_REVIEWABLE_ASSET_EXTENSIONS:
                add_artifact(
                    kind="source_map" if extension == ".map" else "js_asset",
                    host=host,
                    path=path,
                    method="GET",
                    sample_url=sample_url,
                    priority="high" if extension == ".map" else "normal",
                )
                continue
            if extension and extension in BROWSER_SURFACE_STATIC_EXTENSIONS:
                continue
            if path.startswith(("/graphql", "/graphiql")):
                add_artifact(
                    kind="graphql_endpoint",
                    host=host,
                    path=path,
                    method="POST",
                    sample_url=sample_url,
                    priority="high",
                )
                add_inventory(
                    host=host,
                    path=path,
                    method="POST",
                    sample_url=sample_url,
                    query_params=list(normalized.get("query_params") or []),
                )
                continue
            add_artifact(
                kind="js_route",
                host=host,
                path=path,
                method="ANY",
                sample_url=sample_url,
                priority=_priority_for_endpoint(
                    path,
                    ["ANY"],
                    query_params=list(normalized.get("query_params") or []),
                    body_params=[],
                    auth_hints=[auth_hint],
                ),
            )
            add_inventory(
                host=host,
                path=path,
                method="ANY" if path.startswith("/api") else "GET",
                sample_url=sample_url,
                query_params=list(normalized.get("query_params") or []),
            )

        for path in _extract_js_paths(blob):
            normalized = _normalize_browser_surface_url(path, asset_url or page_url)
            if normalized is None:
                continue
            host = str(normalized["host"])
            normalized_path = str(normalized["path"])
            if (host.lower(), normalized_path) in websocket_paths:
                continue
            sample_url = str(normalized["url"])
            if normalized_path.startswith(("/graphql", "/graphiql")):
                add_artifact(
                    kind="graphql_endpoint",
                    host=host,
                    path=normalized_path,
                    method="POST",
                    sample_url=sample_url,
                    priority="high",
                )
                add_inventory(
                    host=host,
                    path=normalized_path,
                    method="POST",
                    sample_url=sample_url,
                    query_params=list(normalized.get("query_params") or []),
                )
                continue
            add_artifact(
                kind="js_route",
                host=host,
                path=normalized_path,
                method="ANY",
                sample_url=sample_url,
                priority=_priority_for_endpoint(
                    normalized_path,
                    ["ANY"],
                    query_params=list(normalized.get("query_params") or []),
                    body_params=[],
                    auth_hints=[auth_hint],
                ),
            )
            add_inventory(
                host=host,
                path=normalized_path,
                method="ANY" if normalized_path.startswith("/api") else "GET",
                sample_url=sample_url,
                query_params=list(normalized.get("query_params") or []),
            )

    if derived_artifacts or derived_inventory:
        evidence_rows.append(
            {
                "kind": "asset_content_mining",
                "asset_path": asset_path,
                "derived_artifact_count": len(derived_artifacts),
                "derived_inventory_count": len(derived_inventory),
            }
        )

    return derived_artifacts, derived_inventory, evidence_rows


def _browser_asset_navigation_candidates(
    *,
    page_url: str,
    inventory_rows: list[dict[str, Any]],
    source_asset: str | None = None,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen_urls: set[str] = set()

    for row in inventory_rows:
        if not isinstance(row, dict):
            continue
        methods = {
            str(item).strip().upper()
            for item in list(row.get("methods") or [])
            if str(item).strip()
        }
        if methods and "GET" not in methods:
            continue
        sample_urls = [
            str(value).strip() for value in list(row.get("sample_urls") or []) if str(value).strip()
        ]
        sample_url = sample_urls[0] if sample_urls else str(row.get("normalized_path") or "").strip()
        if not sample_url:
            continue
        normalized = _normalize_browser_surface_url(sample_url, page_url)
        if normalized is None:
            continue
        path = str(normalized["path"])
        lowered_path = path.lower()
        if (
            any(char in path for char in "{}\"'`")
            or any(marker in lowered_path for marker in ("/socket", "/ws", "/websocket", "/realtime"))
        ):
            continue
        url = str(normalized["url"])
        if url in seen_urls:
            continue
        seen_urls.add(url)
        candidates.append(
            {
                "url": url,
                "host": str(normalized["host"]),
                "path": path,
                "label": str(source_asset or row.get("normalized_path") or "").strip(),
                "attr": "asset-content",
                "nav": False,
                "source_kind": "asset_content",
                "source_asset": str(source_asset or "").strip(),
            }
        )

    return candidates


async def _expand_browser_assets(
    browser: Any,
    *,
    tab_id: str,
    page_url: str,
    material: dict[str, Any],
    browser_artifacts: list[dict[str, Any]],
    max_assets: int = 6,
) -> dict[str, Any]:
    if max_assets < 1:
        return {
            "artifacts": [],
            "inventory": [],
            "evidence_rows": [],
            "navigation_candidates": [],
        }

    auth_hint = _browser_surface_auth_hint(material, page_url)
    expanded_artifacts: list[dict[str, Any]] = []
    expanded_inventory: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    navigation_candidates: list[dict[str, Any]] = []
    fetched_urls: set[str] = set()

    for artifact in browser_artifacts:
        sample_urls = [str(value).strip() for value in list(artifact.get("sample_urls") or []) if str(value).strip()]
        sample_url = sample_urls[0] if sample_urls else str(artifact.get("sample_url") or "").strip()
        if not sample_url or sample_url in fetched_urls:
            continue
        fetched_urls.add(sample_url)
        fetch_result = await _fetch_browser_asset_body(browser, tab_id=tab_id, asset_url=sample_url)
        body = str(fetch_result.get("body") or "")
        if not body:
            continue
        derived_artifacts, derived_inventory, derived_evidence = _browser_asset_content_discovery(
            asset={**artifact, "sample_url": sample_url},
            body=body,
            page_url=page_url,
            auth_hint=auth_hint,
        )
        expanded_artifacts.extend(derived_artifacts)
        expanded_inventory.extend(derived_inventory)
        evidence_rows.extend(derived_evidence)
        navigation_candidates.extend(
            _browser_asset_navigation_candidates(
                page_url=page_url,
                inventory_rows=derived_inventory,
                source_asset=str(artifact.get("path") or ""),
            )
        )
        if len(fetched_urls) >= max_assets:
            break

    return {
        "artifacts": expanded_artifacts,
        "inventory": _merge_browser_runtime_inventory([], expanded_inventory),
        "evidence_rows": evidence_rows[:40],
        "navigation_candidates": navigation_candidates,
    }


def _browser_surface_candidate_allowed(
    *,
    attr: str,
    path: str,
    method: str,
) -> bool:
    lowered_path = str(path or "").lower()
    extension = splitext(lowered_path)[1]
    if extension and extension in BROWSER_SURFACE_STATIC_EXTENSIONS:
        return any(marker in lowered_path for marker in BROWSER_SURFACE_HIGH_VALUE_PATH_MARKERS)
    if method != "GET":
        return True
    if attr in {"action", "formaction", "data-endpoint", "data-api", "data-route", "data-path"}:
        return True
    return True


def _merge_browser_runtime_inventory(
    existing_items: list[dict[str, Any]],
    incoming_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for row in [*existing_items, *incoming_items]:
        if not isinstance(row, dict):
            continue
        host = str(row.get("host") or "").strip()
        normalized_path = _normalize_runtime_path(str(row.get("normalized_path") or "/"))
        if not host:
            continue
        key = (host, normalized_path)
        target = merged.setdefault(
            key,
            {
                "host": host,
                "normalized_path": normalized_path,
                "methods": set(),
                "status_codes": set(),
                "query_params": set(),
                "body_params": set(),
                "content_types": set(),
                "auth_hints": set(),
                "sources": set(),
                "origins": set(),
                "sample_urls": set(),
                "sample_request_ids": [],
                "observed_count": 0,
            },
        )
        target["methods"].update(
            str(item).strip().upper() for item in list(row.get("methods") or []) if str(item).strip()
        )
        target["status_codes"].update(
            int(item) for item in list(row.get("status_codes") or []) if str(item).strip()
        )
        target["query_params"].update(
            str(item).strip() for item in list(row.get("query_params") or []) if str(item).strip()
        )
        target["body_params"].update(
            str(item).strip() for item in list(row.get("body_params") or []) if str(item).strip()
        )
        target["content_types"].update(
            str(item).strip() for item in list(row.get("content_types") or []) if str(item).strip()
        )
        target["auth_hints"].update(
            str(item).strip() for item in list(row.get("auth_hints") or []) if str(item).strip()
        )
        target["sources"].update(
            str(item).strip() for item in list(row.get("sources") or []) if str(item).strip()
        )
        target["origins"].update(
            str(item).strip() for item in list(row.get("origins") or []) if str(item).strip()
        )
        target["sample_urls"].update(
            str(item).strip() for item in list(row.get("sample_urls") or []) if str(item).strip()
        )
        target["observed_count"] += max(1, int(row.get("observed_count") or 0))

    inventory: list[dict[str, Any]] = []
    for item in merged.values():
        methods = sorted(item["methods"]) or ["GET"]
        query_params = sorted(item["query_params"])
        body_params = sorted(item["body_params"])
        auth_hints = sorted(item["auth_hints"]) or ["anonymous"]
        inventory.append(
            {
                "host": item["host"],
                "normalized_path": item["normalized_path"],
                "methods": methods,
                "status_codes": sorted(item["status_codes"]),
                "query_params": query_params,
                "body_params": body_params,
                "content_types": sorted(item["content_types"]),
                "auth_hints": auth_hints,
                "sources": sorted(item["sources"]),
                "origins": sorted(item["origins"]),
                "sample_urls": sorted(item["sample_urls"])[:3],
                "sample_request_ids": list(item["sample_request_ids"])[:3],
                "observed_count": item["observed_count"],
                "priority": _priority_for_endpoint(
                    item["normalized_path"],
                    methods,
                    query_params=query_params,
                    body_params=body_params,
                    auth_hints=auth_hints,
                ),
            }
        )
    inventory.sort(key=_sort_inventory)
    return inventory


def _browser_surface_auth_hint(material: dict[str, Any], page_url: str) -> str:
    extracted = _extract_session_artifacts(material, allow_anonymous=True)
    return (
        "browser_authenticated"
        if (
            extracted.get("headers")
            or _has_session_cookie_signal(dict(extracted.get("cookies") or {}))
            or _has_path_hint(page_url, AUTHENTICATED_PATH_HINTS)
        )
        else "anonymous"
    )


def _browser_inventory_from_snapshot(
    *,
    material: dict[str, Any],
    surface: dict[str, Any],
    page_url: str,
    source: str = "browser_dom",
    origin: str = "browser",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    auth_hint = _browser_surface_auth_hint(material, page_url)
    browser_candidates: dict[tuple[str, str], dict[str, Any]] = {}
    evidence_rows: list[dict[str, Any]] = []
    navigation_candidates: list[dict[str, Any]] = []

    def add_candidate(
        *,
        raw_url: str,
        method: str,
        attr: str,
        label: str | None = None,
        query_params: list[str] | None = None,
        body_params: list[str] | None = None,
        nav_hint: bool = False,
    ) -> None:
        normalized = _normalize_browser_surface_url(raw_url, page_url)
        if normalized is None:
            return
        if not _browser_surface_candidate_allowed(
            attr=attr,
            path=str(normalized["path"]),
            method=method,
        ):
            return
        key = (str(normalized["host"]), str(normalized["path"]))
        entry = browser_candidates.setdefault(
            key,
            {
                "host": str(normalized["host"]),
                "normalized_path": str(normalized["path"]),
                "methods": set(),
                "status_codes": set(),
                "query_params": set(),
                "body_params": set(),
                "content_types": {"text/html"},
                "auth_hints": {auth_hint},
                "sources": {source},
                "origins": {origin},
                "sample_urls": set(),
                "sample_request_ids": [],
                "observed_count": 0,
                "labels": set(),
            },
        )
        entry["methods"].add(str(method or "GET").strip().upper() or "GET")
        entry["query_params"].update(list(query_params or []))
        entry["query_params"].update(list(normalized.get("query_params") or []))
        entry["body_params"].update(list(body_params or []))
        entry["sample_urls"].add(str(normalized["url"]))
        entry["observed_count"] += 1
        if label:
            entry["labels"].add(str(label).strip())

        if str(method or "GET").strip().upper() == "GET":
            navigation_candidates.append(
                {
                    "url": str(normalized["url"]),
                    "host": str(normalized["host"]),
                    "path": str(normalized["path"]),
                    "label": str(label or "").strip(),
                    "attr": attr,
                    "nav": bool(nav_hint),
                }
            )

    for link in list(surface.get("links") or []):
        if not isinstance(link, dict):
            continue
        add_candidate(
            raw_url=str(link.get("href") or ""),
            method="GET",
            attr="href",
            label=str(link.get("text") or ""),
            nav_hint=bool(link.get("nav")),
        )
        evidence_rows.append(
            {
                "kind": "link",
                "href": str(link.get("href") or ""),
                "label": str(link.get("text") or ""),
                "nav": bool(link.get("nav")),
            }
        )

    for form in list(surface.get("forms") or []):
        if not isinstance(form, dict):
            continue
        form_method = str(form.get("method") or "GET").strip().upper() or "GET"
        input_names = [
            str(item).strip() for item in list(form.get("inputNames") or []) if str(item).strip()
        ]
        add_candidate(
            raw_url=str(form.get("action") or ""),
            method=form_method,
            attr="action",
            label=", ".join(
                [
                    str(item)
                    for item in list(form.get("buttonLabels") or [])
                    if str(item).strip()
                ][:2]
            ),
            query_params=input_names if form_method == "GET" else [],
            body_params=input_names if form_method != "GET" else [],
        )
        evidence_rows.append(
            {
                "kind": "form",
                "action": str(form.get("action") or ""),
                "method": form_method,
                "input_names": input_names[:20],
                "button_labels": [
                    str(item)
                    for item in list(form.get("buttonLabels") or [])
                    if str(item).strip()
                ][:6],
            }
        )

    for hint in list(surface.get("routeHints") or []):
        if not isinstance(hint, dict):
            continue
        attr = str(hint.get("attr") or "")
        raw_value = str(hint.get("value") or "")
        expanded_values = _expand_browser_route_hint_values(attr=attr, value=raw_value)
        for candidate_value in expanded_values:
            add_candidate(
                raw_url=candidate_value,
                method="GET",
                attr=attr,
                label=str(hint.get("label") or ""),
            )
        evidence_row = {
            "kind": "route_hint",
            "attr": attr,
            "value": raw_value,
            "label": str(hint.get("label") or ""),
        }
        if expanded_values and expanded_values != [raw_value]:
            evidence_row["expanded_values"] = expanded_values[:8]
        evidence_rows.append(evidence_row)

    for hint in list(surface.get("scriptHints") or []):
        if not isinstance(hint, dict):
            continue
        attr = str(hint.get("attr") or "inline-script")
        raw_value = str(hint.get("value") or "")
        expanded_values = _expand_browser_route_hint_values(attr=attr, value=raw_value)
        for candidate_value in expanded_values:
            add_candidate(
                raw_url=candidate_value,
                method="GET",
                attr=attr,
                label=str(hint.get("label") or ""),
            )
        evidence_row = {
            "kind": "script_hint",
            "attr": attr,
            "value": raw_value,
            "label": str(hint.get("label") or ""),
        }
        if expanded_values:
            evidence_row["expanded_values"] = expanded_values[:8]
        evidence_rows.append(evidence_row)

    for hint in _browser_material_route_hints(material):
        attr = str(hint.get("attr") or "material")
        raw_value = str(hint.get("value") or "")
        expanded_values = _expand_browser_route_hint_values(attr=attr, value=raw_value)
        for candidate_value in expanded_values:
            add_candidate(
                raw_url=candidate_value,
                method="GET",
                attr=attr,
                label=str(hint.get("label") or ""),
            )
        evidence_row = {
            "kind": "material_route_hint",
            "attr": attr,
            "value": raw_value,
            "label": str(hint.get("label") or ""),
        }
        if expanded_values:
            evidence_row["expanded_values"] = expanded_values[:8]
        evidence_rows.append(evidence_row)

    for interactive in list(surface.get("interactive") or []):
        if not isinstance(interactive, dict):
            continue
        target = str(interactive.get("target") or "")
        label = str(interactive.get("label") or "")
        role = str(interactive.get("role") or "")
        if target:
            add_candidate(
                raw_url=target,
                method="GET",
                attr="interactive",
                label=label,
                nav_hint=role.lower() in {"menuitem", "tab", "link"},
            )
        evidence_rows.append(
            {
                "kind": "interactive",
                "label": label,
                "target": target,
                "role": role,
            }
        )

    browser_inventory = _merge_browser_runtime_inventory(
        [],
        [
            {
                "host": item["host"],
                "normalized_path": item["normalized_path"],
                "methods": sorted(item["methods"]),
                "status_codes": [],
                "query_params": sorted(item["query_params"]),
                "body_params": sorted(item["body_params"]),
                "content_types": sorted(item["content_types"]),
                "auth_hints": sorted(item["auth_hints"]),
                "sources": sorted(item["sources"]),
                "origins": sorted(item["origins"]),
                "sample_urls": sorted(item["sample_urls"])[:3],
                "sample_request_ids": [],
                "observed_count": item["observed_count"],
            }
            for item in browser_candidates.values()
        ],
    )
    return browser_inventory, evidence_rows, navigation_candidates


def _persist_browser_inventory(
    agent_state: Any,
    *,
    target: str,
    browser_inventory: list[dict[str, Any]],
    max_seed_items: int,
    evidence_title: str,
    evidence_details: dict[str, Any],
    review_surface: str,
    review_rationale: str,
    review_next_step: str,
    review_status: str = "in_progress",
    review_priority: str = "high",
) -> dict[str, Any]:
    normalized_target = _normalize_non_empty(target, "target")
    root_agent_id, inventory_store = _get_inventory_store(agent_state)
    existing_record = inventory_store.get(_slug(normalized_target)) or {}
    existing_inventory = [
        item
        for item in list(
            existing_record.get("inventory")
            or existing_record.get("selected_inventory")
            or []
        )
        if isinstance(item, dict)
    ]
    merged_inventory = _merge_browser_runtime_inventory(existing_inventory, browser_inventory)
    selected_inventory = merged_inventory[:max_seed_items]
    inventory_store[_slug(normalized_target)] = {
        "target": normalized_target,
        "inventory": merged_inventory,
        "selected_inventory": selected_inventory,
        "inventory_total": len(merged_inventory),
        "inventory_truncated": len(merged_inventory) > len(selected_inventory),
        "request_count": int(existing_record.get("request_count") or 0),
        "sitemap_hosts": list(existing_record.get("sitemap_hosts") or []),
        "request_errors": list(existing_record.get("request_errors") or []),
        "sitemap_errors": list(existing_record.get("sitemap_errors") or []),
        "mapped_at": _utc_now(),
    }
    if hasattr(agent_state, "update_context"):
        agent_state.update_context("runtime_inventory_root_agent_id", root_agent_id)

    coverage_items = []
    for item in browser_inventory[:max_seed_items]:
        params_summary = ", ".join(
            [*list(item.get("query_params") or []), *list(item.get("body_params") or [])]
        )
        auth_summary = ", ".join(list(item.get("auth_hints") or []))
        sample_urls = [str(value) for value in list(item.get("sample_urls") or []) if str(value).strip()]
        source_context = sample_urls[0] if sample_urls else "browser-visible surface"
        for method in list(item.get("methods") or ["GET"]):
            rationale = (
                f"Auto-seeded from browser traversal on {source_context} for {method} "
                f"{item['normalized_path']}. Auth hints: {auth_summary}."
            )
            if params_summary:
                rationale += f" Observed parameters: {params_summary}."
            coverage_items.append(
                {
                    "target": normalized_target,
                    "component": f"runtime:{item['host']}",
                    "surface": f"Runtime endpoint {method} {item['normalized_path']}",
                    "status": "uncovered",
                    "priority": str(item.get("priority") or "normal"),
                    "rationale": rationale,
                    "next_step": (
                        "Replay this browser-discovered flow directly, collect runtime requests, compare "
                        "roles/tenants, and test hidden params plus injection variants before treating the module as covered"
                    ),
                }
            )

    coverage_result = bulk_record_coverage(
        agent_state=agent_state,
        items=coverage_items,
        preserve_existing_status=True,
    )
    inventory_review_result = record_coverage(
        agent_state=agent_state,
        target=normalized_target,
        component="browser_surface",
        surface=review_surface,
        status=review_status,
        rationale=review_rationale,
        priority=review_priority,
        next_step=review_next_step,
    )
    evidence_result = record_evidence(
        agent_state=agent_state,
        title=evidence_title,
        details=json.dumps(evidence_details, ensure_ascii=False),
        source="browser",
        target=normalized_target,
        component="browser_surface_mapper",
    )
    discovered_modules = sorted(
        {
            item["normalized_path"].split("/", 2)[1]
            for item in browser_inventory
            if str(item.get("normalized_path") or "").startswith("/")
            and len(str(item.get("normalized_path") or "").split("/")) > 1
        }
    )
    return {
        "inventory_total": len(merged_inventory),
        "inventory_truncated": len(merged_inventory) > len(selected_inventory),
        "inventory": browser_inventory[:max_seed_items],
        "coverage_result": coverage_result,
        "inventory_review_result": inventory_review_result,
        "evidence_result": evidence_result,
        "discovered_modules": discovered_modules,
    }


def _persist_browser_surface_artifacts(
    agent_state: Any,
    *,
    target: str,
    browser_artifacts: list[dict[str, Any]],
    max_seed_items: int,
    evidence_title: str,
    evidence_details: dict[str, Any],
) -> dict[str, Any]:
    normalized_target = _normalize_non_empty(target, "target")
    if max_seed_items < 1:
        raise ValueError("max_seed_items must be >= 1")
    if not browser_artifacts:
        return {
            "artifacts_total": 0,
            "artifacts": [],
            "artifact_coverage_result": {
                "success": True,
                "updated_count": 0,
                "records": [],
            },
            "artifact_evidence_result": None,
        }

    from .assessment_surface_actions import _artifact_sort, _get_surface_store, _update_agent_context

    root_agent_id, store = _get_surface_store(agent_state)
    _update_agent_context(agent_state, root_agent_id)
    existing_record = dict(store.get(_slug(normalized_target)) or {})
    existing_artifacts = [
        item
        for item in list(
            existing_record.get("artifacts")
            or existing_record.get("selected_artifacts")
            or []
        )
        if isinstance(item, dict)
    ]

    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    existing_keys: set[tuple[str, str, str]] = set()

    def merge_rows(rows: list[dict[str, Any]], *, mark_existing: bool) -> None:
        for row in rows:
            kind = str(row.get("kind") or "artifact").strip().lower()
            host = str(row.get("host") or "").strip()
            path = _normalize_runtime_path(str(row.get("path") or "/"))
            if not kind or not host:
                continue
            key = (kind, host, path)
            if mark_existing:
                existing_keys.add(key)
            target_row = merged.setdefault(
                key,
                {
                    "kind": kind,
                    "host": host,
                    "path": path,
                    "method": str(row.get("method") or "GET").strip().upper() or "GET",
                    "priority": str(row.get("priority") or "normal"),
                    "sample_urls": set(),
                    "source_attrs": set(),
                    "labels": set(),
                    "source_page_urls": set(),
                    "source_assets": set(),
                    "source_files": set(),
                    "hint_names": set(),
                    "role_hints": set(),
                    "object_hints": set(),
                    "secret_hints": set(),
                    "feature_hints": set(),
                    "param_hints": set(),
                    "inferred": bool(row.get("inferred")),
                },
            )
            target_row["method"] = str(target_row.get("method") or row.get("method") or "GET").strip().upper() or "GET"
            if str(row.get("priority") or "").strip():
                target_row["priority"] = str(row.get("priority") or "").strip()
            sample_url = str(row.get("sample_url") or row.get("url") or "").strip()
            if sample_url:
                target_row["sample_urls"].add(sample_url)
            source_attr = str(row.get("source_attr") or "").strip()
            if source_attr:
                target_row["source_attrs"].add(source_attr)
            label = str(row.get("label") or "").strip()
            if label:
                target_row["labels"].add(label)
            source_page_url = str(row.get("source_page_url") or "").strip()
            if source_page_url:
                target_row["source_page_urls"].add(source_page_url)
            source_asset = str(row.get("source_asset") or "").strip()
            if source_asset:
                target_row["source_assets"].add(source_asset)
            target_row["source_files"].update(
                str(item).strip() for item in list(row.get("source_files") or []) if str(item).strip()
            )
            target_row["hint_names"].update(
                str(item).strip() for item in list(row.get("hint_names") or []) if str(item).strip()
            )
            target_row["role_hints"].update(
                str(item).strip() for item in list(row.get("role_hints") or []) if str(item).strip()
            )
            target_row["object_hints"].update(
                str(item).strip() for item in list(row.get("object_hints") or []) if str(item).strip()
            )
            target_row["secret_hints"].update(
                str(item).strip() for item in list(row.get("secret_hints") or []) if str(item).strip()
            )
            target_row["feature_hints"].update(
                str(item).strip() for item in list(row.get("feature_hints") or []) if str(item).strip()
            )
            target_row["param_hints"].update(
                str(item).strip() for item in list(row.get("param_hints") or []) if str(item).strip()
            )
            target_row["inferred"] = bool(target_row.get("inferred", True) and bool(row.get("inferred")))

    merge_rows(existing_artifacts, mark_existing=True)
    merge_rows(browser_artifacts, mark_existing=False)

    merged_artifacts = []
    for item in merged.values():
        merged_artifacts.append(
            {
                "kind": str(item["kind"]),
                "host": str(item["host"]),
                "path": str(item["path"]),
                "method": str(item["method"]),
                "priority": str(item["priority"]),
                "sample_urls": sorted(item["sample_urls"])[:4],
                "source_attrs": sorted(item["source_attrs"])[:6],
                "labels": sorted(item["labels"])[:6],
                "source_page_urls": sorted(item["source_page_urls"])[:4],
                "source_assets": sorted(item["source_assets"])[:4],
                "source_files": sorted(item["source_files"])[:12],
                "hint_names": sorted(item["hint_names"])[:12],
                "role_hints": sorted(item["role_hints"])[:12],
                "object_hints": sorted(item["object_hints"])[:12],
                "secret_hints": sorted(item["secret_hints"])[:12],
                "feature_hints": sorted(item["feature_hints"])[:12],
                "param_hints": sorted(item["param_hints"])[:12],
                "inferred": bool(item["inferred"]),
            }
        )
    merged_artifacts.sort(key=_artifact_sort)
    selected_artifacts = merged_artifacts[:max_seed_items]

    store[_slug(normalized_target)] = {
        "target": normalized_target,
        "artifacts": merged_artifacts,
        "selected_artifacts": selected_artifacts,
        "artifacts_total": len(merged_artifacts),
        "request_count": int(existing_record.get("request_count") or 0),
        "mined_at": _utc_now(),
    }

    coverage_items = []
    for artifact in merged_artifacts:
        key = (
            str(artifact.get("kind") or "").strip().lower(),
            str(artifact.get("host") or "").strip(),
            str(artifact.get("path") or "").strip(),
        )
        if key in existing_keys:
            continue
        kind = str(artifact.get("kind") or "artifact")
        path = str(artifact.get("path") or "/")
        source_assets = list(artifact.get("source_assets") or [])
        source_pages = list(artifact.get("source_page_urls") or [])
        source_files = list(artifact.get("source_files") or [])
        role_hints = list(artifact.get("role_hints") or [])
        object_hints = list(artifact.get("object_hints") or [])
        secret_hints = list(artifact.get("secret_hints") or [])
        feature_hints = list(artifact.get("feature_hints") or [])
        param_hints = list(artifact.get("param_hints") or [])
        if kind == "source_map":
            surface = f"Browser-discovered source map GET {path}"
            rationale = (
                f"Browser surface mining revealed source map candidate {path} on host "
                f"{artifact['host']}. Source maps often leak hidden routes, internal object names, "
                "and debug context that can enable deeper chaining."
            )
            if source_assets:
                rationale += f" Related asset: {source_assets[0]}."
            if source_files:
                rationale += f" Embedded source hints: {', '.join(source_files[:3])}."
            if role_hints or object_hints or secret_hints or feature_hints:
                rationale += (
                    " Exposed hint names: "
                    + ", ".join([*role_hints[:2], *object_hints[:2], *secret_hints[:2], *feature_hints[:2]][:6])
                    + "."
                )
            next_step = (
                "Retrieve and review the source map, enumerate exposed routes/objects/secrets, and "
                "compare them against runtime coverage plus privileged UI states"
            )
        elif kind == "js_asset":
            surface = f"Browser-discovered JavaScript asset GET {path}"
            rationale = (
                f"Browser surface mining revealed JavaScript bundle {path} on host {artifact['host']}; "
                "bundle review can expose hidden routes, feature flags, object models, and client-only "
                "authorization assumptions."
            )
            if source_files or role_hints or object_hints or feature_hints:
                rationale += " Browser asset metadata already exposed additional source/object/feature hints."
            next_step = (
                "Fetch the bundle, extract hidden routes and sink candidates, then reconcile them against "
                "runtime inventory, docs, and authenticated UI coverage"
            )
        elif kind == "js_route":
            surface = f"Browser-mined route ANY {path}"
            rationale = (
                f"Browser-fetched asset content referenced hidden route {path} on host {artifact['host']}. "
                "This route may not be visible in the UI and should be reconciled against auth boundaries "
                "and runtime behavior."
            )
            if source_assets:
                rationale += f" Source asset: {source_assets[0]}."
            if param_hints:
                rationale += f" Query or object hints observed: {', '.join(param_hints[:4])}."
            next_step = (
                "Request the route directly, compare authenticated and low-privilege behavior, and test "
                "whether the hidden route exposes undocumented objects, params, or state transitions"
            )
        elif kind == "graphql_endpoint":
            surface = f"Browser-mined GraphQL endpoint POST {path}"
            rationale = (
                f"Browser-fetched asset content referenced GraphQL endpoint {path} on host {artifact['host']}; "
                "resolver-level authorization and schema exposure can diverge from visible UI coverage."
            )
            next_step = (
                "Probe introspection, operation names, persisted queries, and resolver-level authz using the "
                "browser-derived endpoint as a seed"
            )
        elif kind == "websocket_endpoint":
            surface = f"Browser-mined WebSocket endpoint GET {path}"
            rationale = (
                f"Browser-fetched asset content referenced WebSocket endpoint {path} on host {artifact['host']}; "
                "channel auth and tenant isolation often drift from equivalent HTTP routes."
            )
            next_step = (
                "Test socket handshake auth, channel naming, message authorization, and cross-user or "
                "cross-tenant subscription isolation"
            )
        else:
            surface = f"Browser-discovered artifact GET {path}"
            rationale = (
                f"Browser surface mining revealed artifact {path} on host {artifact['host']}; "
                "it should be reconciled against hidden-route and auth coverage."
            )
            next_step = (
                "Review the artifact content and compare any hidden routes, configs, or object hints against "
                "runtime coverage and privileged UI states"
            )
        if source_pages:
            rationale += f" Observed from {source_pages[0]}."
        coverage_items.append(
            {
                "target": normalized_target,
                "component": f"surface:{artifact['host']}",
                "surface": surface,
                "status": "uncovered",
                "priority": str(artifact.get("priority") or "normal"),
                "rationale": rationale,
                "next_step": next_step,
            }
        )

    if coverage_items:
        artifact_coverage_result = bulk_record_coverage(
            agent_state=agent_state,
            items=coverage_items,
            preserve_existing_status=True,
        )
    else:
        artifact_coverage_result = {
            "success": True,
            "updated_count": 0,
            "records": [],
        }

    artifact_evidence_result = record_evidence(
        agent_state=agent_state,
        title=evidence_title,
        details=json.dumps(evidence_details, ensure_ascii=False),
        source="browser",
        target=normalized_target,
        component="browser_surface_artifact_mapper",
    )
    return {
        "artifacts_total": len(merged_artifacts),
        "artifacts": selected_artifacts,
        "artifact_coverage_result": artifact_coverage_result,
        "artifact_evidence_result": artifact_evidence_result,
    }


def _browser_traversal_candidate_score(candidate: dict[str, Any]) -> tuple[int, int, int, int, str]:
    path = str(candidate.get("path") or "").lower()
    label = str(candidate.get("label") or "").lower()
    attr = str(candidate.get("attr") or "").lower()
    source_kind = str(candidate.get("source_kind") or "").lower()
    nav = 1 if bool(candidate.get("nav")) else 0
    seed_score = 1 if source_kind == "seed_url" else 0
    marker_score = sum(1 for marker in BROWSER_TRAVERSAL_PRIORITY_MARKERS if marker in path or marker in label)
    attr_score = 1 if attr in {
        "href",
        "action",
        "asset-content",
        "form_get_explore",
        "formaction",
        "data-route",
        "data-path",
        "interactive",
        "onclick",
        "routerlink",
        "inline-script",
        "nextdata",
        "sessionstorage",
        "localstorage",
    } else 0
    return (-seed_score, -marker_score, -nav, -attr_score, path)


def _browser_traversal_candidates(
    *,
    page_url: str,
    navigation_candidates: list[dict[str, Any]],
    same_origin_only: bool,
) -> list[dict[str, Any]]:
    page_origin = urlparse(page_url).netloc.lower()
    selected: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for candidate in sorted(navigation_candidates, key=_browser_traversal_candidate_score):
        url = str(candidate.get("url") or "").strip()
        path = str(candidate.get("path") or "").strip().lower()
        if not url or url in seen_urls:
            continue
        parsed = urlparse(url)
        if same_origin_only and parsed.netloc.lower() != page_origin:
            continue
        if not path or path == "/" or path == urlparse(page_url).path.lower():
            continue
        if path.startswith(("/api", "/graphql", "/graphiql", "/socket", "/ws")):
            continue
        if any(marker in path for marker in BROWSER_TRAVERSAL_BLOCKED_MARKERS):
            continue
        extension = splitext(path)[1]
        if extension and extension in BROWSER_SURFACE_STATIC_EXTENSIONS:
            continue
        seen_urls.add(url)
        selected.append(dict(candidate))
    return selected


def _browser_seed_navigation_candidates(
    *,
    page_url: str,
    seed_urls: list[str] | None,
    same_origin_only: bool,
) -> list[dict[str, Any]]:
    page_origin = urlparse(page_url).netloc.lower()
    current_page_normalized = _normalize_browser_surface_url(page_url, page_url) or {}
    current_page_normalized_url = str(current_page_normalized.get("url") or "").strip()
    selected: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for seed_url in list(seed_urls or []):
        normalized = _normalize_browser_surface_url(str(seed_url), page_url)
        if normalized is None:
            continue
        url = str(normalized.get("url") or "").strip()
        path = str(normalized.get("path") or "").strip().lower()
        if not url or url in seen_urls:
            continue
        parsed = urlparse(url)
        if same_origin_only and parsed.netloc.lower() != page_origin:
            continue
        if current_page_normalized_url and url == current_page_normalized_url:
            continue
        if not path:
            continue
        if any(marker in path for marker in BROWSER_TRAVERSAL_BLOCKED_MARKERS):
            continue
        extension = splitext(path)[1]
        if extension and extension in BROWSER_SURFACE_STATIC_EXTENSIONS:
            continue
        seen_urls.add(url)
        selected.append(
            {
                "url": url,
                "host": str(normalized.get("host") or ""),
                "path": path,
                "label": "Priority seed",
                "attr": "seed-url",
                "nav": True,
                "source_kind": "seed_url",
                "source_value": str(seed_url).strip(),
            }
        )
    return sorted(selected, key=_browser_traversal_candidate_score)


def _browser_surface_signature(surface: dict[str, Any]) -> str:
    def normalize_dict_rows(rows: list[dict[str, Any]], fields: tuple[str, ...]) -> list[dict[str, Any]]:
        normalized_rows: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            normalized_rows.append({field: str(row.get(field) or "") for field in fields})
        normalized_rows.sort(key=lambda item: json.dumps(item, sort_keys=True))
        return normalized_rows

    payload = {
        "page_url": str(surface.get("page_url") or ""),
        "title": str(surface.get("title") or ""),
        "headings": sorted(str(item) for item in list(surface.get("headings") or []) if str(item).strip()),
        "links": normalize_dict_rows(list(surface.get("links") or []), ("href", "text", "rel", "nav")),
        "forms": normalize_dict_rows(
            list(surface.get("forms") or []),
            ("action", "method", "inputNames", "buttonLabels"),
        ),
        "routeHints": normalize_dict_rows(
            list(surface.get("routeHints") or []),
            ("attr", "value", "tag", "label"),
        ),
        "scriptHints": normalize_dict_rows(
            list(surface.get("scriptHints") or []),
            ("attr", "value", "tag", "label"),
        ),
        "interactive": normalize_dict_rows(
            list(surface.get("interactive") or []),
            ("label", "target", "role"),
        ),
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _inventory_item_identity(item: dict[str, Any]) -> str:
    return json.dumps(
        {
            "host": str(item.get("host") or ""),
            "normalized_path": str(item.get("normalized_path") or ""),
            "methods": sorted(str(value) for value in list(item.get("methods") or [])),
            "query_params": sorted(str(value) for value in list(item.get("query_params") or [])),
            "body_params": sorted(str(value) for value in list(item.get("body_params") or [])),
        },
        sort_keys=True,
        ensure_ascii=False,
    )


def _browser_click_candidate_score(candidate: dict[str, Any]) -> tuple[int, int, int, str]:
    label = str(candidate.get("label") or "").lower()
    role = str(candidate.get("role") or "").lower()
    marker_score = sum(1 for marker in BROWSER_CLICK_EXPLORATION_PRIORITY_MARKERS if marker in label)
    role_score = 1 if role in {"menuitem", "summary", "tab"} else 0
    target_score = 1 if str(candidate.get("target") or "").strip() else 0
    return (-marker_score, -role_score, target_score, label)


def _browser_form_exploration_value(input_name: str) -> str | None:
    lowered_name = str(input_name or "").strip().lower()
    for marker, value in BROWSER_FORM_EXPLORATION_PARAM_MARKERS.items():
        if marker == lowered_name or marker in lowered_name:
            return value
    return None


def _browser_form_navigation_candidates(
    *,
    page_url: str,
    surface: dict[str, Any],
    same_origin_only: bool,
    max_candidates: int = 2,
) -> list[dict[str, Any]]:
    if max_candidates < 1:
        return []

    page_origin = urlparse(page_url).netloc.lower()
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for form in list(surface.get("forms") or []):
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "GET").strip().upper() or "GET"
        if method != "GET":
            continue
        action = str(form.get("action") or "").strip() or page_url
        input_names = [
            str(item).strip() for item in list(form.get("inputNames") or []) if str(item).strip()
        ]
        button_labels = [
            str(item).strip() for item in list(form.get("buttonLabels") or []) if str(item).strip()
        ]
        searchable = " ".join([action, *input_names, *button_labels]).strip().lower()
        if not any(marker in searchable for marker in BROWSER_FORM_EXPLORATION_MARKERS):
            continue

        params: dict[str, str] = {}
        for input_name in input_names:
            value = _browser_form_exploration_value(input_name)
            if value is None:
                continue
            params[input_name] = value
        if not params:
            continue

        absolute = urljoin(page_url, action)
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        if same_origin_only and parsed.netloc.lower() != page_origin:
            continue

        path = _normalize_runtime_path(parsed.path or "/")
        if any(marker in path.lower() for marker in BROWSER_TRAVERSAL_BLOCKED_MARKERS):
            continue

        merged_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        merged_params.update(params)
        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        query = urlencode(merged_params)
        if query:
            url = f"{url}?{query}"
        lowered_url = url.lower()
        if lowered_url in seen:
            continue
        seen.add(lowered_url)
        candidates.append(
            {
                "url": url,
                "host": parsed.netloc,
                "path": path,
                "label": ", ".join(button_labels[:2]) or action or path,
                "attr": "form_get_explore",
                "nav": False,
                "source_kind": "form_get_explore",
                "source_page_url": page_url,
                "form_inputs": input_names[:8],
                "exploration_params": dict(params),
            }
        )
    return sorted(candidates, key=_browser_traversal_candidate_score)[:max_candidates]


def _browser_click_exploration_candidates(surface: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for interactive in list(surface.get("interactive") or []):
        if not isinstance(interactive, dict):
            continue
        label = str(interactive.get("label") or "").strip()
        role = str(interactive.get("role") or "").strip().lower()
        target = str(interactive.get("target") or "").strip()
        searchable = " ".join([label.lower(), role, target.lower()]).strip()
        if not label:
            continue
        if target:
            continue
        if any(marker in searchable for marker in BROWSER_TRAVERSAL_BLOCKED_MARKERS):
            continue
        if any(marker in searchable for marker in BROWSER_CLICK_EXPLORATION_BLOCKED_MARKERS):
            continue
        if role and role not in {"button", "menuitem", "summary", "tab"}:
            continue
        key = f"{label.lower()}|{role}|{target.lower()}"
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "label": label,
                "role": role,
                "target": target,
            }
        )
    return sorted(candidates, key=_browser_click_candidate_score)


def _browser_click_candidate_script(candidate: dict[str, Any]) -> str:
    script = """
        () => {
          /* __STRIX_CLICK_CANDIDATE_MARKER__ */
          const candidate = __STRIX_BROWSER_CLICK_CANDIDATE__;
          const trim = (value, limit = 160) =>
            String(value || '').replace(/\\s+/g, ' ').trim().slice(0, limit);
          const normalized = (value) => trim(value).toLowerCase();
          const desiredLabel = normalized(candidate.label || '');
          const desiredRole = normalized(candidate.role || '');
          const desiredTarget = trim(candidate.target || '', 500);
          const elements = document.querySelectorAll(
            'button,[role="button"],[role="menuitem"],[role="tab"],summary,[data-testid],[aria-label]'
          );
          let best = null;
          let bestScore = -1;

          for (const element of elements) {
            const label = trim(
              element.innerText ||
              element.getAttribute('aria-label') ||
              element.getAttribute('title') ||
              element.getAttribute('data-testid') ||
              ''
            );
            if (!label) {
              continue;
            }
            const role = trim(
              element.getAttribute('role') ||
              ((element.tagName || '').toLowerCase() === 'summary' ? 'summary' : '')
            ).toLowerCase();
            const target =
              trim(element.getAttribute('formaction') || '', 500) ||
              trim(element.getAttribute('data-url') || '', 500) ||
              trim(element.getAttribute('data-route') || '', 500) ||
              trim(element.getAttribute('data-endpoint') || '', 500);
            let score = 0;
            if (normalized(label) === desiredLabel) {
              score += 5;
            } else if (desiredLabel && normalized(label).includes(desiredLabel)) {
              score += 3;
            }
            if (desiredRole && role === desiredRole) {
              score += 2;
            }
            if (desiredTarget && target === desiredTarget) {
              score += 3;
            }
            if (!desiredTarget && !target) {
              score += 1;
            }
            if (score > bestScore) {
              bestScore = score;
              best = { element, label, role, target };
            }
          }

          if (!best || bestScore < 3) {
            return { matched: false, clicked: false };
          }

          best.element.scrollIntoView({ block: 'center', inline: 'center' });
          try {
            best.element.click();
          } catch (error) {
            try {
              best.element.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
            } catch (dispatchError) {}
          }
          return {
            matched: true,
            clicked: true,
            label: best.label,
            role: best.role,
            target: best.target,
          };
        }
    """
    return script.replace("__STRIX_BROWSER_CLICK_CANDIDATE__", json.dumps(candidate, ensure_ascii=False))


async def _visit_browser_surface_page(
    browser: Any,
    *,
    url: str,
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

    try:
        await page.goto(url, wait_until="domcontentloaded")
        await page.wait_for_timeout(max(250, int(wait_seconds * 1000)))
        material = await _collect_browser_material(browser, tab_id)
        surface = await _collect_browser_surface(browser, tab_id)
        console_logs = list(browser.console_logs.get(tab_id, []))
    finally:
        browser.pages.pop(tab_id, None)
        browser.console_logs.pop(tab_id, None)
        browser.current_page_id = previous_tab_id
        await page.close()

    return {
        "tab_id": tab_id,
        "url": url,
        "material": material,
        "surface": surface,
        "console_logs": console_logs,
    }


async def _click_browser_surface_candidate(
    browser: Any,
    *,
    page_url: str,
    candidate: dict[str, Any],
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

    try:
        await page.goto(page_url, wait_until="domcontentloaded")
        await page.wait_for_timeout(max(250, int(wait_seconds * 1000)))
        before_material = await _collect_browser_material(browser, tab_id)
        before_surface = await _collect_browser_surface(browser, tab_id)
        click_result = await page.evaluate(_browser_click_candidate_script(candidate))
        await page.wait_for_timeout(max(250, int(wait_seconds * 1000)))
        after_material = await _collect_browser_material(browser, tab_id)
        after_surface = await _collect_browser_surface(browser, tab_id)
        console_logs = list(browser.console_logs.get(tab_id, []))
    finally:
        browser.pages.pop(tab_id, None)
        browser.console_logs.pop(tab_id, None)
        browser.current_page_id = previous_tab_id
        await page.close()

    return {
        "tab_id": tab_id,
        "page_url": page_url,
        "candidate": dict(candidate),
        "click_result": click_result if isinstance(click_result, dict) else {},
        "before_material": before_material,
        "before_surface": before_surface,
        "after_material": after_material,
        "after_surface": after_surface,
        "console_logs": console_logs,
    }


def _map_browser_surface_from_tab(
    agent_state: Any,
    *,
    target: str,
    tab_id: str | None = None,
    max_seed_items: int = 40,
    browser: Any | None = None,
) -> dict[str, Any]:
    normalized_target = _normalize_non_empty(target, "target")
    if max_seed_items < 1:
        raise ValueError("max_seed_items must be >= 1")

    active_browser = browser
    if active_browser is None:
        manager = _browser_manager()
        active_browser = manager._get_agent_browser()
    if active_browser is None:
        return {
            "success": False,
            "available": False,
            "error": "Browser is not launched for the current agent",
        }

    resolved_tab_id = tab_id or active_browser.current_page_id
    if not resolved_tab_id or resolved_tab_id not in active_browser.pages:
        raise ValueError(f"Tab '{resolved_tab_id}' was not found")

    material = active_browser._run_async(_collect_browser_material(active_browser, resolved_tab_id))
    surface = active_browser._run_async(_collect_browser_surface(active_browser, resolved_tab_id))
    page_url = str(surface.get("page_url") or material.get("page_url") or "")
    if not page_url:
        raise ValueError("Active browser tab does not have a page URL")
    browser_inventory, evidence_rows, _ = _browser_inventory_from_snapshot(
        material=material,
        surface=surface,
        page_url=page_url,
    )
    browser_artifacts = _browser_asset_artifacts_from_snapshot(
        material=material,
        surface=surface,
        page_url=page_url,
    )
    if browser_artifacts:
        asset_expansion = active_browser._run_async(
            _expand_browser_assets(
                active_browser,
                tab_id=resolved_tab_id,
                page_url=page_url,
                material=material,
                browser_artifacts=browser_artifacts,
                max_assets=min(max_seed_items, 8),
            )
        )
        browser_inventory = _merge_browser_runtime_inventory(
            browser_inventory,
            list(asset_expansion.get("inventory") or []),
        )
        browser_artifacts = [*browser_artifacts, *list(asset_expansion.get("artifacts") or [])]
        evidence_rows.extend(list(asset_expansion.get("evidence_rows") or []))
    if not browser_inventory and not browser_artifacts:
        return {
            "success": False,
            "available": True,
            "tab_id": resolved_tab_id,
            "page_url": page_url,
            "error": (
                "No actionable browser-visible routes, forms, or JS/source-map artifacts were "
                "discovered on the active tab"
            ),
        }

    if browser_inventory:
        persisted = _persist_browser_inventory(
            agent_state,
            target=normalized_target,
            browser_inventory=browser_inventory,
            max_seed_items=max_seed_items,
            evidence_title=f"Browser-visible surface map for {normalized_target}",
            evidence_details={
                "page_url": page_url,
                "title": str(surface.get("title") or ""),
                "headings": [str(item) for item in list(surface.get("headings") or [])][:30],
                "interactive": [
                    item for item in list(surface.get("interactive") or []) if isinstance(item, dict)
                ][:40],
                "evidence_rows": evidence_rows[:80],
                "browser_inventory": browser_inventory[:max_seed_items],
            },
            review_surface=f"Browser-visible surface completeness for {normalized_target}",
            review_rationale=(
                f"Mapped {len(browser_inventory)} browser-visible route/form candidate(s) from {page_url}. "
                "This only covers the currently visited UI state; hidden routes, role-gated modules, and "
                "background APIs can still remain uncovered."
            ),
            review_next_step=(
                "Traverse additional menus and authenticated pages, rerun browser surface mapping, then reconcile "
                "browser-visible paths against proxy/runtime and hidden-route mining"
            ),
        )
    else:
        persisted = {
            "inventory_total": 0,
            "inventory_truncated": False,
            "inventory": [],
            "coverage_result": {"success": True, "updated_count": 0, "records": []},
            "inventory_review_result": None,
            "evidence_result": None,
            "discovered_modules": [],
        }
    artifact_persisted = _persist_browser_surface_artifacts(
        agent_state,
        target=normalized_target,
        browser_artifacts=browser_artifacts,
        max_seed_items=max_seed_items,
        evidence_title=f"Browser-discovered JS and source-map artifacts for {normalized_target}",
        evidence_details={
            "page_url": page_url,
            "title": str(surface.get("title") or ""),
            "browser_artifacts": browser_artifacts[:max_seed_items],
        },
    )
    return {
        "success": True,
        "available": True,
        "tab_id": resolved_tab_id,
        "page_url": page_url,
        "page_title": str(surface.get("title") or ""),
        "discovered_count": len(browser_inventory),
        "artifact_count": len(browser_artifacts),
        **persisted,
        **artifact_persisted,
    }


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

    surface_map_result = None
    target_hint = _normalize_browser_target_hint(agent_state)
    if target_hint:
        try:
            surface_map_result = _map_browser_surface_from_tab(
                agent_state,
                target=target_hint,
                tab_id=resolved_tab_id,
                browser=active_browser,
            )
        except (RuntimeError, TypeError, ValueError) as e:
            surface_map_result = {
                "success": False,
                "available": True,
                "error": f"Failed to auto-map browser surface: {e}",
            }

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
        "surface_map_result": surface_map_result,
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
def map_browser_surface(
    agent_state: Any,
    target: str,
    tab_id: str | None = None,
    max_seed_items: int = 40,
) -> dict[str, Any]:
    try:
        return _map_browser_surface_from_tab(
            agent_state,
            target=target,
            tab_id=tab_id,
            max_seed_items=max_seed_items,
        )
    except (RuntimeError, TypeError, ValueError) as e:
        return {
            "success": False,
            "available": True,
            "error": f"Failed to map browser surface: {e}",
        }


@register_tool(sandbox_execution=False)
def traverse_browser_surface(
    agent_state: Any,
    target: str,
    tab_id: str | None = None,
    max_pages: int = 6,
    max_depth: int = 2,
    max_clicks: int = 3,
    same_origin_only: bool = True,
    wait_seconds: float = 0.8,
    max_seed_items: int = 60,
    seed_urls: list[str] | None = None,
) -> dict[str, Any]:
    try:
        normalized_target = _normalize_non_empty(target, "target")
        if max_pages < 1:
            raise ValueError("max_pages must be >= 1")
        if max_depth < 0:
            raise ValueError("max_depth must be >= 0")
        if max_clicks < 0:
            raise ValueError("max_clicks must be >= 0")
        if max_seed_items < 1:
            raise ValueError("max_seed_items must be >= 1")

        manager = _browser_manager()
        browser = manager._get_agent_browser()
        if browser is None:
            return {
                "success": False,
                "available": False,
                "error": "Browser is not launched for the current agent",
            }

        resolved_tab_id = tab_id or browser.current_page_id
        if not resolved_tab_id or resolved_tab_id not in browser.pages:
            raise ValueError(f"Tab '{resolved_tab_id}' was not found")

        current_material = browser._run_async(_collect_browser_material(browser, resolved_tab_id))
        current_surface = browser._run_async(_collect_browser_surface(browser, resolved_tab_id))
        current_page_url = str(current_surface.get("page_url") or current_material.get("page_url") or "")
        if not current_page_url:
            raise ValueError("Active browser tab does not have a page URL")

        root_inventory, _, root_candidates = _browser_inventory_from_snapshot(
            material=current_material,
            surface=current_surface,
            page_url=current_page_url,
        )
        root_artifacts = _browser_asset_artifacts_from_snapshot(
            material=current_material,
            surface=current_surface,
            page_url=current_page_url,
        )
        if root_artifacts:
            root_asset_expansion = browser._run_async(
                _expand_browser_assets(
                    browser,
                    tab_id=resolved_tab_id,
                    page_url=current_page_url,
                    material=current_material,
                    browser_artifacts=root_artifacts,
                    max_assets=min(max_seed_items, 8),
                )
            )
            root_inventory = _merge_browser_runtime_inventory(
                root_inventory,
                list(root_asset_expansion.get("inventory") or []),
            )
            root_artifacts = [*root_artifacts, *list(root_asset_expansion.get("artifacts") or [])]
            root_candidates = [
                *root_candidates,
                *list(root_asset_expansion.get("navigation_candidates") or []),
            ]
        seed_candidates = _browser_seed_navigation_candidates(
            page_url=current_page_url,
            seed_urls=seed_urls,
            same_origin_only=same_origin_only,
        )
        queue = [{**candidate, "depth": 1} for candidate in seed_candidates]
        queue.extend(
            [
                {**candidate, "depth": 1}
                for candidate in _browser_traversal_candidates(
                    page_url=current_page_url,
                    navigation_candidates=root_candidates,
                    same_origin_only=same_origin_only,
                )
            ]
        )
        queue.extend(
            [
                {**candidate, "depth": 1}
                for candidate in _browser_form_navigation_candidates(
                    page_url=current_page_url,
                    surface=current_surface,
                    same_origin_only=same_origin_only,
                )
            ]
        )
        visited_urls = {current_page_url}
        traversed_pages: list[dict[str, Any]] = []
        click_states: list[dict[str, Any]] = []
        workflow_states: list[dict[str, Any]] = []
        aggregate_inventory = list(root_inventory)
        aggregate_artifacts = list(root_artifacts)
        remaining_clicks = max_clicks

        def expand_click_states(
            *,
            page_url: str,
            material: dict[str, Any],
            surface: dict[str, Any],
            current_depth: int,
        ) -> list[dict[str, Any]]:
            nonlocal remaining_clicks, aggregate_inventory

            queued_navigation_candidates: list[dict[str, Any]] = []
            if remaining_clicks <= 0:
                return queued_navigation_candidates

            before_signature = _browser_surface_signature(surface)
            before_inventory, _, _ = _browser_inventory_from_snapshot(
                material=material,
                surface=surface,
                page_url=page_url,
                source="browser_click_baseline",
                origin="browser_click_baseline",
            )
            before_inventory_keys = {_inventory_item_identity(item) for item in before_inventory}

            for candidate in _browser_click_exploration_candidates(surface)[:remaining_clicks]:
                click_probe = browser._run_async(
                    _click_browser_surface_candidate(
                        browser,
                        page_url=page_url,
                        candidate=candidate,
                        wait_seconds=wait_seconds,
                    )
                )
                click_result = (
                    click_probe.get("click_result")
                    if isinstance(click_probe.get("click_result"), dict)
                    else {}
                )
                after_surface = (
                    click_probe.get("after_surface")
                    if isinstance(click_probe.get("after_surface"), dict)
                    else {}
                )
                after_material = (
                    click_probe.get("after_material")
                    if isinstance(click_probe.get("after_material"), dict)
                    else {}
                )
                after_page_url = str(
                    after_surface.get("page_url") or after_material.get("page_url") or page_url
                )
                if same_origin_only and urlparse(after_page_url).netloc.lower() != urlparse(page_url).netloc.lower():
                    continue
                if not click_result.get("clicked"):
                    continue
                after_signature = _browser_surface_signature(after_surface)
                after_inventory, _, navigation_candidates = _browser_inventory_from_snapshot(
                    material=after_material,
                    surface=after_surface,
                    page_url=after_page_url,
                    source="browser_click",
                    origin="browser_click",
                )
                after_artifacts = _browser_asset_artifacts_from_snapshot(
                    material=after_material,
                    surface=after_surface,
                    page_url=after_page_url,
                )
                if after_artifacts:
                    after_asset_expansion = browser._run_async(
                        _expand_browser_assets(
                            browser,
                            tab_id=resolved_tab_id,
                            page_url=after_page_url,
                            material=after_material,
                            browser_artifacts=after_artifacts,
                            max_assets=min(max_seed_items, 6),
                        )
                    )
                    after_inventory = _merge_browser_runtime_inventory(
                        after_inventory,
                        list(after_asset_expansion.get("inventory") or []),
                    )
                    after_artifacts = [
                        *after_artifacts,
                        *list(after_asset_expansion.get("artifacts") or []),
                    ]
                    navigation_candidates = [
                        *navigation_candidates,
                        *list(after_asset_expansion.get("navigation_candidates") or []),
                    ]
                new_inventory = [
                    item for item in after_inventory if _inventory_item_identity(item) not in before_inventory_keys
                ]
                if after_signature == before_signature and not new_inventory and not after_artifacts:
                    continue

                remaining_clicks -= 1
                aggregate_inventory.extend(new_inventory or after_inventory)
                aggregate_artifacts.extend(after_artifacts)
                click_states.append(
                    {
                        "source_page_url": page_url,
                        "page_url": after_page_url,
                        "label": str(click_result.get("label") or candidate.get("label") or ""),
                        "role": str(click_result.get("role") or candidate.get("role") or ""),
                        "inventory_count": len(new_inventory or after_inventory),
                        "new_paths": [
                            str(item.get("normalized_path") or "")
                            for item in (new_inventory or after_inventory)[:12]
                            if str(item.get("normalized_path") or "").strip()
                        ],
                    }
                )

                if current_depth >= max_depth:
                    continue
                queued_navigation_candidates.extend(
                    [
                        {**candidate_row, "depth": current_depth + 1}
                        for candidate_row in _browser_traversal_candidates(
                            page_url=after_page_url,
                            navigation_candidates=navigation_candidates,
                            same_origin_only=same_origin_only,
                        )
                    ]
                )
                queued_navigation_candidates.extend(
                    [
                        {**candidate_row, "depth": current_depth + 1}
                        for candidate_row in _browser_form_navigation_candidates(
                            page_url=after_page_url,
                            surface=after_surface,
                            same_origin_only=same_origin_only,
                        )
                    ]
                )
                if remaining_clicks <= 0:
                    break
            return queued_navigation_candidates

        queue.extend(
            expand_click_states(
                page_url=current_page_url,
                material=current_material,
                surface=current_surface,
                current_depth=0,
            )
        )

        while queue and len(traversed_pages) < max_pages:
            current = queue.pop(0)
            candidate_url = str(current.get("url") or "").strip()
            current_depth = int(current.get("depth") or 1)
            if not candidate_url or candidate_url in visited_urls:
                continue
            visited_urls.add(candidate_url)

            visit_result = browser._run_async(
                _visit_browser_surface_page(
                    browser,
                    url=candidate_url,
                    wait_seconds=wait_seconds,
                )
            )
            surface = (
                visit_result.get("surface")
                if isinstance(visit_result.get("surface"), dict)
                else {}
            )
            material = (
                visit_result.get("material")
                if isinstance(visit_result.get("material"), dict)
                else {}
            )
            visited_page_url = str(surface.get("page_url") or material.get("page_url") or candidate_url)
            browser_inventory, _, navigation_candidates = _browser_inventory_from_snapshot(
                material=material,
                surface=surface,
                page_url=visited_page_url,
                source="browser_traversal",
                origin="browser_traversal",
            )
            browser_artifacts = _browser_asset_artifacts_from_snapshot(
                material=material,
                surface=surface,
                page_url=visited_page_url,
            )
            if browser_artifacts:
                asset_expansion = browser._run_async(
                    _expand_browser_assets(
                        browser,
                        tab_id=resolved_tab_id,
                        page_url=visited_page_url,
                        material=material,
                        browser_artifacts=browser_artifacts,
                        max_assets=min(max_seed_items, 6),
                    )
                )
                browser_inventory = _merge_browser_runtime_inventory(
                    browser_inventory,
                    list(asset_expansion.get("inventory") or []),
                )
                browser_artifacts = [
                    *browser_artifacts,
                    *list(asset_expansion.get("artifacts") or []),
                ]
                navigation_candidates = [
                    *navigation_candidates,
                    *list(asset_expansion.get("navigation_candidates") or []),
                ]
            aggregate_inventory.extend(browser_inventory)
            aggregate_artifacts.extend(browser_artifacts)
            traversed_pages.append(
                {
                    "url": visited_page_url,
                    "title": str(surface.get("title") or ""),
                    "depth": current_depth,
                    "headings": [str(item) for item in list(surface.get("headings") or [])][:15],
                    "inventory_count": len(browser_inventory),
                    "console_log_count": len(list(visit_result.get("console_logs") or [])),
                }
            )
            if str(current.get("source_kind") or "") == "form_get_explore":
                workflow_states.append(
                    {
                        "source_page_url": str(current.get("source_page_url") or ""),
                        "url": visited_page_url,
                        "input_names": [
                            str(item)
                            for item in list(current.get("form_inputs") or [])
                            if str(item).strip()
                        ][:8],
                        "submitted_params": {
                            str(key): str(value)
                            for key, value in dict(current.get("exploration_params") or {}).items()
                            if str(key).strip()
                        },
                        "inventory_count": len(browser_inventory),
                    }
                )
            if current_depth >= max_depth:
                continue
            for candidate in _browser_traversal_candidates(
                page_url=visited_page_url,
                navigation_candidates=navigation_candidates,
                same_origin_only=same_origin_only,
            ):
                if candidate.get("url") in visited_urls:
                    continue
                queue.append({**candidate, "depth": current_depth + 1})
            for candidate in _browser_form_navigation_candidates(
                page_url=visited_page_url,
                surface=surface,
                same_origin_only=same_origin_only,
            ):
                if candidate.get("url") in visited_urls:
                    continue
                queue.append({**candidate, "depth": current_depth + 1})
            queue.extend(
                expand_click_states(
                    page_url=visited_page_url,
                    material=material,
                    surface=surface,
                    current_depth=current_depth,
                )
            )

        if not aggregate_inventory and not aggregate_artifacts:
            return {
                "success": False,
                "available": True,
                "tab_id": resolved_tab_id,
                "page_url": current_page_url,
                "error": (
                    "No browser traversal candidates, runtime inventory, or JS/source-map artifacts "
                    "were discovered"
                ),
            }

        if aggregate_inventory:
            persisted = _persist_browser_inventory(
                agent_state,
                target=normalized_target,
                browser_inventory=aggregate_inventory,
                max_seed_items=max_seed_items,
                evidence_title=f"Browser traversal map for {normalized_target}",
                evidence_details={
                    "start_page_url": current_page_url,
                    "start_title": str(current_surface.get("title") or ""),
                    "same_origin_only": same_origin_only,
                    "max_pages": max_pages,
                    "max_depth": max_depth,
                    "max_clicks": max_clicks,
                    "seed_urls": [str(candidate.get("url") or "") for candidate in seed_candidates[:20]],
                    "traversed_pages": traversed_pages,
                    "click_states": click_states,
                    "workflow_states": workflow_states,
                    "aggregate_inventory": aggregate_inventory[:max_seed_items],
                },
                review_surface=f"Browser traversal coverage for {normalized_target}",
                review_rationale=(
                    f"Traversed {len(traversed_pages)} additional browser-visible page(s) and explored "
                    f"{len(click_states)} click-derived UI state(s) plus {len(workflow_states)} safe "
                    f"workflow state(s) from {current_page_url}, extracting "
                    f"{len(aggregate_inventory)} route/form candidate(s). Hidden role-gated flows, "
                    "JS-only transitions, and non-linked pages can still remain uncovered."
                ),
                review_next_step=(
                    "Drive additional roles/states through the UI, capture proxy/runtime differences, compare "
                    "browser-reached and click-opened states against hidden-route, workflow, and parameter mining, "
                    "and follow any newly revealed forms or modules with targeted authz and injection tests"
                ),
            )
        else:
            persisted = {
                "inventory_total": 0,
                "inventory_truncated": False,
                "inventory": [],
                "coverage_result": {"success": True, "updated_count": 0, "records": []},
                "inventory_review_result": None,
                "evidence_result": None,
                "discovered_modules": [],
            }
        artifact_persisted = _persist_browser_surface_artifacts(
            agent_state,
            target=normalized_target,
            browser_artifacts=aggregate_artifacts,
            max_seed_items=max_seed_items,
            evidence_title=f"Browser traversal JS and source-map artifacts for {normalized_target}",
            evidence_details={
                "start_page_url": current_page_url,
                "same_origin_only": same_origin_only,
                "seed_urls": [str(candidate.get("url") or "") for candidate in seed_candidates[:20]],
                "traversed_pages": traversed_pages,
                "browser_artifacts": aggregate_artifacts[:max_seed_items],
            },
        )
    except (RuntimeError, TypeError, ValueError) as e:
        return {
            "success": False,
            "available": True,
            "error": f"Failed to traverse browser surface: {e}",
        }
    else:
        return {
            "success": True,
            "available": True,
            "tab_id": resolved_tab_id,
            "page_url": current_page_url,
            "seed_url_count": len(seed_candidates),
            "pages_visited": len(traversed_pages),
            "clicks_performed": len(click_states),
            "traversed_pages": traversed_pages,
            "click_states": click_states,
            "workflow_states": workflow_states,
            "discovered_count": len(aggregate_inventory),
            "artifact_count": len(aggregate_artifacts),
            **persisted,
            **artifact_persisted,
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
