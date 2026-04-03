import ast
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from strix.tools.registry import register_tool

from .assessment_actions import (
    VALID_PRIORITIES,
    _normalize_non_empty,
    _resolve_root_agent_id,
    _stable_id,
    _utc_now,
    bulk_record_coverage,
    record_evidence,
    record_coverage,
    record_hypothesis,
)
from .assessment_validation_actions import _execute_request


SUPPORTED_SECURITY_TOOLS = {
    "arjun",
    "bandit",
    "dirsearch",
    "ffuf",
    "httpx",
    "jwt_tool",
    "katana",
    "naabu",
    "nuclei",
    "nmap",
    "semgrep",
    "sqlmap",
    "subfinder",
    "trivy",
    "trufflehog",
    "wapiti",
    "wafw00f",
    "zaproxy",
}
TOOL_PRIORITY = {"critical": "critical", "high": "high", "medium": "normal", "low": "low"}
TOOL_RUN = dict[str, Any]
_tool_scan_storage: dict[str, dict[str, TOOL_RUN]] = {}
SUPPORTED_FOCUS_PIPELINES = {
    "auth_jwt",
    "ssrf_oob",
    "sqli",
    "xss",
    "open_redirect",
    "ssti",
    "xxe",
    "file_upload",
    "path_traversal",
    "authz",
    "workflow_race",
}
SENSITIVE_PATH_KEYWORDS = [
    "admin",
    "auth",
    "login",
    "graphql",
    "openapi",
    "swagger",
    "debug",
    "internal",
    "export",
    "import",
    "invoice",
    "order",
    "payment",
    "checkout",
]
SENSITIVE_PARAMETER_KEYWORDS = {
    "admin": ("authorization", "high"),
    "redirect": ("open_redirect", "high"),
    "return": ("open_redirect", "high"),
    "next": ("open_redirect", "high"),
    "continue": ("open_redirect", "high"),
    "callback": ("ssrf", "critical"),
    "webhook": ("ssrf", "critical"),
    "url": ("ssrf", "critical"),
    "uri": ("ssrf", "high"),
    "endpoint": ("ssrf", "high"),
    "file": ("path_traversal", "high"),
    "path": ("path_traversal", "high"),
    "template": ("ssti", "high"),
    "cmd": ("rce", "critical"),
    "command": ("rce", "critical"),
    "exec": ("rce", "critical"),
    "query": ("sqli", "normal"),
    "filter": ("sqli", "normal"),
    "search": ("sqli", "normal"),
    "sort": ("sqli", "normal"),
    "id": ("idor", "critical"),
    "user": ("idor", "high"),
    "account": ("idor", "high"),
    "tenant": ("idor", "critical"),
    "order": ("idor", "high"),
    "invoice": ("idor", "high"),
    "amount": ("business_logic", "high"),
    "price": ("business_logic", "high"),
    "discount": ("business_logic", "high"),
    "coupon": ("business_logic", "high"),
    "token": ("authentication", "high"),
    "jwt": ("authentication", "high"),
    "role": ("authorization", "high"),
    "html": ("xss", "normal"),
    "content": ("xss", "normal"),
    "message": ("xss", "normal"),
}
TOOL_VERSION_ARGS = {
    "arjun": ["--help"],
    "bandit": ["--version"],
    "dirsearch": ["--help"],
    "httpx": ["-version"],
    "jwt_tool": ["-h"],
    "katana": ["-version"],
    "naabu": ["-version"],
    "nuclei": ["-version"],
    "nmap": ["--version"],
    "ffuf": ["-V"],
    "semgrep": ["--version"],
    "sqlmap": ["--version"],
    "subfinder": ["-version"],
    "trivy": ["--version"],
    "trufflehog": ["--version"],
    "wapiti": ["--version"],
    "wafw00f": ["--version"],
    "zaproxy": ["-version"],
}
TOOL_OUTPUT_SUFFIXES = {
    "arjun": ".json",
    "bandit": ".json",
    "dirsearch": ".json",
    "httpx": ".jsonl",
    "jwt_tool": ".txt",
    "katana": ".jsonl",
    "naabu": ".jsonl",
    "nuclei": ".jsonl",
    "nmap": ".xml",
    "ffuf": ".json",
    "semgrep": ".json",
    "sqlmap": ".txt",
    "subfinder": ".jsonl",
    "trivy": ".json",
    "trufflehog": ".jsonl",
    "wapiti": ".json",
    "wafw00f": ".json",
    "zaproxy": ".json",
}
PROJECTDISCOVERY_TOOLS = {"httpx", "katana", "naabu", "nuclei", "subfinder"}
INCOMPATIBLE_TOOL_PATTERNS = (
    "no such option",
    "unknown option",
    "unknown flag",
    "unrecognized arguments",
    "is not a valid option",
)
DEFAULT_HTTPX_PATHS = [
    "/",
    "/login",
    "/admin",
    "/dashboard",
    "/graphql",
    "/openapi.json",
    "/swagger.json",
    "/robots.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/sitemap.xml",
]
DEFAULT_FUZZ_WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "C:\\SecLists\\Discovery\\Web-Content\\common.txt",
    "C:\\SecLists\\Discovery\\Web-Content\\raft-small-directories.txt",
]
FINDING_VULNERABILITY_KEYWORDS = {
    "authorization": "authorization",
    "idor": "idor",
    "sqli": "sqli",
    "sql injection": "sqli",
    "xss": "xss",
    "csrf": "csrf",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "rce": "rce",
    "command injection": "rce",
    "ssti": "ssti",
    "template injection": "ssti",
    "jwt": "jwt",
    "authentication": "authentication",
    "auth": "authentication",
    "deserialization": "deserialization",
    "path traversal": "path_traversal",
    "traversal": "path_traversal",
    "lfi": "lfi",
    "open redirect": "open_redirect",
    "redirect": "open_redirect",
    "secret": "secret_exposure",
    "credential": "secret_exposure",
    "hardcoded password": "secret_exposure",
    "alg:none": "jwt",
    "weak hmac secret": "jwt",
    "key confusion": "jwt",
    "jwks": "jwt",
    "expired token": "authentication",
    "immortal token": "authentication",
    "subprocess": "rce",
    "shell": "rce",
    "yaml load": "deserialization",
    "x-frame-options": "misconfiguration",
    "missing anti-csrf": "csrf",
    "cross domain": "cors",
}
JWT_FINDING_PATTERNS = [
    ("alg:none", "JWT alg:none acceptance", "critical"),
    ("none algorithm", "JWT alg:none acceptance", "critical"),
    ("cve-2015-9235", "JWT alg:none acceptance", "critical"),
    ("key confusion", "JWT RSA key confusion", "critical"),
    ("cve-2016-5431", "JWT RSA key confusion", "critical"),
    ("jwks injection", "JWT JWKS injection", "critical"),
    ("cve-2018-0114", "JWT JWKS injection", "critical"),
    ("null signature", "JWT null-signature acceptance", "critical"),
    ("cve-2020-28042", "JWT null-signature acceptance", "critical"),
    ("weak secret", "Weak JWT HMAC secret", "critical"),
    ("dictionary attack successful", "Weak JWT HMAC secret", "critical"),
    ("signature not checked", "JWT signature validation bypass", "critical"),
    ("claim processed before", "JWT claims processed before signature validation", "high"),
    ("claims processed before", "JWT claims processed before signature validation", "high"),
    ("token persists after logout", "JWT persistence after logout", "high"),
    ("never expires", "JWT token expiry not enforced", "high"),
    ("immortal token", "JWT token expiry not enforced", "high"),
    ("exp not checked", "JWT token expiry not enforced", "high"),
]
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
FOCUS_PARAMETER_HINTS = {
    "ssrf_oob": ["callback", "webhook", "url", "uri", "endpoint"],
    "sqli": ["id", "query", "search", "filter", "sort"],
    "xss": [
        "q",
        "query",
        "search",
        "comment",
        "message",
        "content",
        "html",
        "bio",
        "description",
        "feedback",
        "title",
        "name",
    ],
    "open_redirect": [
        "redirect",
        "return",
        "next",
        "continue",
        "dest",
        "destination",
        "target",
        "url",
        "uri",
        "link",
    ],
    "ssti": ["template", "view", "render", "html", "content", "message"],
    "path_traversal": ["file", "path", "filename", "document", "download"],
}
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
VERIFICATION_ORDER = {"raw": 0, "correlated": 1, "validated": 2}
AUTO_FOCUS_PRIORITY = {
    "authz": 0,
    "workflow_race": 1,
    "ssrf_oob": 2,
    "sqli": 3,
    "auth_jwt": 4,
    "xss": 5,
    "open_redirect": 6,
    "path_traversal": 7,
    "ssti": 8,
    "xxe": 9,
    "file_upload": 10,
}
AUTO_FOCUS_SIGNAL_KEYWORDS = {
    "authz": [
        "account",
        "admin",
        "invoice",
        "member",
        "order",
        "profile",
        "project",
        "tenant",
        "user",
        "workspace",
    ],
    "workflow_race": [
        "amount",
        "balance",
        "cart",
        "checkout",
        "coupon",
        "credit",
        "discount",
        "inventory",
        "invoice",
        "limit",
        "payment",
        "price",
        "quantity",
        "redeem",
        "refund",
        "stock",
        "transfer",
        "wallet",
    ],
    "xss": [
        "bio",
        "comment",
        "content",
        "feedback",
        "html",
        "message",
        "preview",
        "q",
        "query",
        "search",
    ],
    "open_redirect": [
        "bounce",
        "continue",
        "dest",
        "destination",
        "link",
        "next",
        "out",
        "redirect",
        "return",
        "target",
        "url",
    ],
}
HIGH_SIGNAL_FINDING_KEYWORDS = (
    "alg:none",
    "blind sql",
    "command injection",
    "default credential",
    "default password",
    "deserialization",
    "graphql introspection",
    "key confusion",
    "path traversal",
    "remote code execution",
    "server-side request forgery",
    "sql injection",
    "ssrf",
    "ssti",
    "template injection",
    "token disclosure",
    "weak secret",
    "xml external entity",
    "xxe",
)
LOW_SIGNAL_FINDING_KEYWORDS = (
    "application error disclosure",
    "cookie no httponly",
    "cookie without httponly",
    "cookie without secure",
    "cross-domain javascript source file inclusion",
    "missing anti-csrf",
    "missing x-frame-options",
    "modern web application",
    "server leaks version information",
    "strict-transport-security",
    "tech detect",
    "timestamp disclosure",
    "x-content-type-options",
)
XML_CONTENT_TYPE_MARKERS = ("application/xml", "text/xml", "soap", "svg+xml")
XML_PATH_KEYWORDS = ("xml", "soap", "feed", "import", "saml")
UPLOAD_PATH_KEYWORDS = ("upload", "avatar", "attachment", "document", "file", "image", "import")
UPLOAD_PUBLIC_PATH_HINTS = (
    "upload",
    "uploads",
    "file",
    "files",
    "media",
    "static",
    "static/uploads",
    "assets",
    "avatars",
    "images",
    "attachments",
    "documents",
)
EXECUTABLE_UPLOAD_EXTENSIONS = (".php", ".phtml", ".phar", ".php3", ".php4", ".php5", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl")
ACTIVE_UPLOAD_EXTENSIONS = (".svg", ".html", ".htm", ".js", ".mjs")
CODE_SCAN_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".cs", ".go", ".rb"}
CODE_SCAN_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".idea",
    ".next",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "venv",
}
SINK_PRIORITY_RANK = {"critical": 4, "high": 3, "normal": 2, "low": 1}
FOCUS_SOURCE_HINTS = {
    "xss": ["html", "content", "message", "comment", "bio", "description"],
    "open_redirect": ["redirect", "return", "next", "continue", "target", "url"],
    "ssti": ["template", "view", "render", "html", "content", "message"],
    "xxe": ["xml", "body", "payload", "document", "feed", "svg"],
    "file_upload": ["file", "upload", "image", "avatar", "attachment", "document"],
    "path_traversal": ["file", "path", "filename", "document", "download", "name"],
}
GENERIC_REQUEST_SOURCE_MARKERS = (
    "request",
    "query",
    "query_params",
    "params",
    "form",
    "files",
    "json",
    "body",
    "data",
    "args",
    "values",
)
VIEWER_PATH_KEYWORDS = ("view", "preview", "profile", "account", "avatar", "image", "media", "file", "document", "attachment", "download")
UPLOAD_SKIP_SEGMENTS = {"upload", "uploads", "file", "files", "image", "images", "attachment", "attachments", "document", "documents", "avatar", "import"}
FOCUS_CODE_SINK_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "xss": [
        {
            "regex": r"(dangerouslySetInnerHTML|innerHTML\s*=|outerHTML\s*=|v-html|mark_safe\s*\(|Markup\s*\()",
            "kind": "html_render_sink",
            "summary": "User-controlled HTML rendering sink",
            "priority": "critical",
        },
        {
            "regex": r"(render\(.*unescaped|unsafeHTML|bypassSecurityTrustHtml|RawHtml|HtmlString)",
            "kind": "unsafe_html_bypass",
            "summary": "Explicit unsafe HTML trust bypass",
            "priority": "high",
        },
    ],
    "open_redirect": [
        {
            "regex": r"(redirect\s*\(|RedirectResponse\s*\(|res\.redirect\s*\(|response\.redirect\s*\(|HttpResponseRedirect\s*\()",
            "kind": "redirect_sink",
            "summary": "Dynamic redirect sink",
            "priority": "high",
        },
        {
            "regex": r"(window\.location|location\.href|location\.assign|location\.replace)",
            "kind": "client_redirect_sink",
            "summary": "Client-side redirect sink",
            "priority": "normal",
        },
    ],
    "ssti": [
        {
            "regex": r"render_template_string\s*\(",
            "kind": "dynamic_template_render",
            "summary": "Dynamic template rendering sink",
            "priority": "critical",
        },
        {
            "regex": r"(jinja2\.)?Template\s*\(",
            "kind": "template_constructor",
            "summary": "Template object construction sink",
            "priority": "high",
        },
        {
            "regex": r"(TemplateResponse|Jinja2Templates|render_template|res\.render|twig\.render|nunjucks\.render)",
            "kind": "template_response",
            "summary": "Template response rendering sink",
            "priority": "high",
        },
    ],
    "xxe": [
        {
            "regex": r"XMLParser\s*\([^)]*resolve_entities\s*=\s*True",
            "kind": "unsafe_entity_resolution",
            "summary": "XML parser explicitly enables entity resolution",
            "priority": "critical",
        },
        {
            "regex": r"(lxml\.etree\.(parse|fromstring|XML)|minidom\.(parse|parseString)|DocumentBuilderFactory|SAXBuilder|xml2js|libxmljs)",
            "kind": "xml_parser_sink",
            "summary": "Server-side XML parsing sink",
            "priority": "high",
        },
    ],
    "file_upload": [
        {
            "regex": r"(UploadFile\b|IFormFile\b|MultipartFile\b|multer\s*\(|formidable\b|express-fileupload\b|request\.files\b|files\.createReadStream\b)",
            "kind": "upload_handler",
            "summary": "File upload entrypoint",
            "priority": "high",
        },
        {
            "regex": r"mount\(\s*[\"']([^\"']+)[\"']\s*,\s*StaticFiles\([^)]*directory\s*=\s*[\"']([^\"']+)[\"']",
            "kind": "public_artifact_mount",
            "summary": "Static artifact mount path",
            "priority": "critical",
            "path_hint_group": 1,
        },
        {
            "regex": r"app\.use\(\s*[\"']([^\"']+)[\"']\s*,\s*express\.static\(\s*[\"']([^\"']+)[\"']",
            "kind": "public_artifact_mount",
            "summary": "Express static artifact mount path",
            "priority": "critical",
            "path_hint_group": 1,
        },
        {
            "regex": r"(StaticFiles\([^)]*directory\s*=\s*[\"']([^\"']+)[\"']|express\.static\(\s*[\"']([^\"']+)[\"'])",
            "kind": "public_artifact_storage",
            "summary": "Publicly served artifact storage hint",
            "priority": "high",
        },
        {
            "regex": r"(FileResponse\s*\(|send_file\s*\(|sendFromDirectory\s*\()",
            "kind": "artifact_retrieval",
            "summary": "Artifact retrieval sink",
            "priority": "high",
        },
    ],
    "path_traversal": [
        {
            "regex": r"(send_file\s*\(|sendFromDirectory\s*\(|FileResponse\s*\(|fs\.(readFile|readFileSync)\s*\(|open\s*\()",
            "kind": "file_access_sink",
            "summary": "User-reachable file access sink",
            "priority": "high",
        }
    ],
}
SESSION_ROLE_KEYWORDS = [
    ("superadmin", 5),
    ("admin", 4),
    ("staff", 3),
    ("manager", 3),
    ("owner", 2),
    ("member", 1),
    ("user", 1),
    ("other_user", 1),
    ("guest", 0),
    ("anonymous", 0),
]
AUTH_FIELD_MARKERS = ("token", "auth", "session", "jwt", "apikey", "api_key")
RACE_SINGLE_USE_TYPES = {
    "checkout",
    "coupon",
    "invite",
    "invitation",
    "inventory",
    "otp",
    "password_reset",
    "payment",
    "redeem",
    "reset",
    "transfer",
    "wallet",
}


def clear_tool_scan_storage() -> None:
    _tool_scan_storage.clear()


def _get_tool_store(agent_state: Any) -> tuple[str, dict[str, TOOL_RUN]]:
    root_agent_id = _resolve_root_agent_id(agent_state)
    if root_agent_id not in _tool_scan_storage:
        _tool_scan_storage[root_agent_id] = {}
    return root_agent_id, _tool_scan_storage[root_agent_id]


def _update_agent_context(agent_state: Any, root_agent_id: str) -> None:
    if hasattr(agent_state, "update_context"):
        agent_state.update_context("tool_scan_root_agent_id", root_agent_id)


def _normalize_tool_name(tool_name: str) -> str:
    normalized = str(tool_name).strip().lower()
    if normalized not in SUPPORTED_SECURITY_TOOLS:
        raise ValueError(
            f"tool_name must be one of: {', '.join(sorted(SUPPORTED_SECURITY_TOOLS))}"
        )
    return normalized


def _resolve_tool_executable(tool_name: str) -> str | None:
    if tool_name == "jwt_tool":
        for candidate in ["jwt_tool", "jwt_tool.py"]:
            resolved = shutil.which(candidate) or shutil.which(f"{candidate}.exe")
            if resolved is not None:
                return resolved
    return shutil.which(tool_name) or shutil.which(f"{tool_name}.exe")


def _bundled_fuzz_wordlist_path() -> str | None:
    candidate = Path(__file__).resolve().parents[2] / "wordlists" / "common-web.txt"
    return str(candidate) if candidate.exists() else None


def _resolve_effective_wordlist_path(tool_name: str, wordlist_path: str | None) -> str | None:
    explicit = str(wordlist_path or "").strip()
    if explicit:
        return explicit
    if tool_name != "ffuf":
        return None
    for candidate in [*DEFAULT_FUZZ_WORDLIST_CANDIDATES, _bundled_fuzz_wordlist_path()]:
        if not candidate:
            continue
        candidate_path = Path(candidate)
        if candidate_path.exists():
            return str(candidate_path)
    return None


def _tool_incompatibility_reason(tool_name: str, output: str, exit_code: int | None = None) -> str | None:
    lowered = str(output or "").strip().lower()
    if not lowered:
        return None
    if any(pattern in lowered for pattern in INCOMPATIBLE_TOOL_PATTERNS):
        return (
            f"{tool_name} executable on PATH appears to be an incompatible command with the same name"
        )
    if tool_name in PROJECTDISCOVERY_TOOLS and exit_code not in {None, 0} and "usage:" in lowered:
        return (
            f"{tool_name} executable on PATH appears to be an incompatible command with the same name"
        )
    return None


def _normalize_focus_pipeline_name(focus: str) -> str:
    normalized = str(focus).strip().lower()
    if normalized not in SUPPORTED_FOCUS_PIPELINES:
        raise ValueError(
            f"focus must be one of: {', '.join(sorted(SUPPORTED_FOCUS_PIPELINES))}"
        )
    return normalized


def _write_lines_file(lines: list[str], suffix: str = ".txt") -> str:
    fd, path = tempfile.mkstemp(prefix="strix_tool_", suffix=suffix)
    os.close(fd)
    Path(path).write_text("\n".join(lines), encoding="utf-8")
    Path(path).chmod(0o600)
    return path


def _execute_tool_command(command: list[str], *, timeout: int) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=max(timeout, 1) * 10,
        check=False,
    )
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
    }


def _parse_json_lines(content: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in content.splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
    return records


def _parse_json_payload(content: str) -> Any:
    cleaned = content.strip()
    if not cleaned:
        return None
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def _iter_nested_dicts(value: Any) -> list[dict[str, Any]]:
    nested: list[dict[str, Any]] = []
    if isinstance(value, dict):
        nested.append(value)
        for item in value.values():
            nested.extend(_iter_nested_dicts(item))
    elif isinstance(value, list):
        for item in value:
            nested.extend(_iter_nested_dicts(item))
    return nested


def _read_output_file(path: str) -> str:
    output_path = Path(path)
    if not output_path.exists():
        return ""
    try:
        return output_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return output_path.read_text(encoding="utf-8", errors="ignore")


def _base_url(value: str) -> str | None:
    parsed = urlparse(str(value).strip())
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _jwt_from_authorization_header(value: str | None) -> str | None:
    candidate = str(value or "").strip()
    if not candidate:
        return None
    parts = candidate.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() in {"bearer", "jwt"}:
        return parts[1].strip() or None
    return candidate


def _looks_like_jwt(value: str | None) -> bool:
    candidate = str(value or "").strip()
    if candidate.count(".") != 2:
        return False
    return all(
        part and all(char.isalnum() or char in {"-", "_"} for char in part)
        for part in candidate.split(".")
    )


def _priority_for_path(path: str) -> str:
    lowered = path.lower()
    score = 0
    for keyword in SENSITIVE_PATH_KEYWORDS:
        if keyword in lowered:
            score += 2
    if ":" in path:
        score += 2
    if score >= 6:
        return "critical"
    if score >= 3:
        return "high"
    return "normal"


def _looks_sensitive_path(path: str) -> bool:
    lowered = path.lower()
    return any(keyword in lowered for keyword in SENSITIVE_PATH_KEYWORDS) or ":" in lowered


def _priority_for_host(host: str) -> str:
    lowered = host.lower()
    if any(keyword in lowered for keyword in ["admin", "internal", "auth", "api", "vpn"]):
        return "high"
    return "normal"


def _priority_for_port(port: int | None, service: str | None = None) -> str:
    if port in {22, 3389, 5432, 6379, 9200, 9300, 2375, 2376, 5000, 5601, 27017, 11211}:
        return "critical"
    if port in {21, 25, 53, 80, 110, 143, 443, 445, 8080, 8443, 8888}:
        return "high"
    if service and any(keyword in service.lower() for keyword in ["admin", "db", "redis", "mongo"]):
        return "high"
    return "normal"


def _priority_for_parameter(parameter_name: str) -> str:
    lowered = parameter_name.lower()
    for keyword, (_, priority) in SENSITIVE_PARAMETER_KEYWORDS.items():
        if keyword in lowered:
            return priority
    return "normal"


def _infer_parameter_vulnerability_type(parameter_name: str) -> str | None:
    lowered = parameter_name.lower()
    for keyword, (vulnerability_type, _) in SENSITIVE_PARAMETER_KEYWORDS.items():
        if keyword in lowered:
            return vulnerability_type
    return None


def _record_for_response(record: TOOL_RUN, *, include_findings: bool) -> TOOL_RUN:
    response = dict(record)
    if not include_findings:
        response.pop("findings", None)
    return response


def _normalize_targets(targets: list[str] | None) -> list[str]:
    normalized: list[str] = []
    for item in targets or []:
        candidate = str(item).strip()
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return normalized


def _normalize_paths(paths: list[str] | None) -> list[str]:
    normalized: list[str] = []
    for item in paths or []:
        candidate = str(item).strip()
        if not candidate:
            continue
        if not candidate.startswith("/"):
            candidate = f"/{candidate}"
        if candidate not in normalized:
            normalized.append(candidate)
    return normalized


def _normalize_headers(headers: dict[str, str] | None) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in (headers or {}).items():
        name = str(key).strip()
        body = str(value).strip()
        if name and body:
            normalized[name] = body
    return normalized


def _build_scope_payload(
    *,
    tool_name: str,
    target: str,
    component: str,
    targets: list[str],
    target_path: str | None,
    url: str | None,
    raw_request_path: str | None,
    paths: list[str],
    headers: dict[str, str],
    data: str | None,
    request_method: str,
    ports: str | None,
    top_ports: int | None,
    parameter: str | None,
    configs: list[str],
    tags: list[str],
    severities: list[str],
    automatic_scan: bool,
    active_only: bool,
    collect_sources: bool,
    no_interactsh: bool,
    use_js_crawl: bool,
    headless: bool,
    known_files: str,
    recursion: bool,
    recursion_depth: int,
    scan_type: str | None,
    service_detection: bool,
    default_scripts: bool,
    flush_session: bool,
    level: int,
    risk: int,
    zapit: bool,
    jwt_token: str | None,
    canary_value: str | None,
    public_key_path: str | None,
    dictionary_path: str | None,
) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "target": target,
        "component": component,
        "targets": targets,
        "target_path": target_path,
        "url": url,
        "raw_request_path": raw_request_path,
        "paths": paths,
        "headers": headers,
        "data": data,
        "request_method": request_method,
        "ports": ports,
        "top_ports": top_ports,
        "parameter": parameter,
        "configs": configs,
        "tags": tags,
        "severities": severities,
        "automatic_scan": automatic_scan,
        "active_only": active_only,
        "collect_sources": collect_sources,
        "no_interactsh": no_interactsh,
        "use_js_crawl": use_js_crawl,
        "headless": headless,
        "known_files": known_files,
        "recursion": recursion,
        "recursion_depth": recursion_depth,
        "scan_type": scan_type,
        "service_detection": service_detection,
        "default_scripts": default_scripts,
        "flush_session": flush_session,
        "level": level,
        "risk": risk,
        "zapit": zapit,
        "jwt_token": jwt_token,
        "canary_value": canary_value,
        "public_key_path": public_key_path,
        "dictionary_path": dictionary_path,
    }


def _scope_key(scope_payload: dict[str, Any]) -> str:
    return _stable_id("scope", json.dumps(scope_payload, sort_keys=True, ensure_ascii=False))


def _tool_run_matches_scope(
    record: TOOL_RUN,
    *,
    tool_name: str,
    target: str,
    scope_key: str,
) -> bool:
    return (
        str(record.get("tool_name") or "") == tool_name
        and str(record.get("target") or "") == target
        and str(record.get("scope_key") or "") == scope_key
        and int(record.get("exit_code") or 0) == 0
    )


def _reusable_tool_run(
    store: dict[str, TOOL_RUN],
    *,
    tool_name: str,
    target: str,
    scope_key: str,
) -> TOOL_RUN | None:
    matches = [
        record
        for record in store.values()
        if _tool_run_matches_scope(
            record,
            tool_name=tool_name,
            target=target,
            scope_key=scope_key,
        )
    ]
    matches.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
    return matches[0] if matches else None


def _tool_run_response(
    record: TOOL_RUN,
    *,
    include_findings: bool,
    reused_existing_run: bool = True,
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "success": True,
        "root_agent_id": record.get("root_agent_id"),
        "run_id": record.get("run_id"),
        "tool_name": record.get("tool_name"),
        "target": record.get("target"),
        "component": record.get("component"),
        "command": record.get("command"),
        "tool_exit_code": record.get("exit_code"),
        "finding_count": int(record.get("finding_count") or 0),
        "discovery_seed_count": int(record.get("discovery_seed_count") or 0),
        "hypothesis_seed_count": int(record.get("hypothesis_seed_count") or 0),
        "stdout_preview": record.get("stdout_preview"),
        "stderr_preview": record.get("stderr_preview"),
        "scope_key": record.get("scope_key"),
        "scope": record.get("scope"),
        "reused_existing_run": reused_existing_run,
        "skipped": bool(record.get("skipped")),
        "skip_reason": record.get("skip_reason"),
        "availability": record.get("availability"),
        "needs_more_data": bool(record.get("needs_more_data")),
    }
    if include_findings:
        response["findings"] = list(record.get("findings") or [])
    return response


def _priority_from_severity(severity: str | None) -> str:
    candidate = str(severity or "medium").strip().lower()
    if candidate in TOOL_PRIORITY:
        return TOOL_PRIORITY[candidate]
    return {
        "info": "low",
        "informational": "low",
        "warning": "normal",
        "medium": "normal",
        "moderate": "normal",
        "error": "high",
    }.get(candidate, "normal")


def _dedupe_preserve_order(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        fingerprint = json.dumps(item, sort_keys=True, ensure_ascii=False)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduped.append(item)
    return deduped


def _truncate(value: str, limit: int = 300) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: limit - 3]}..."


def _ensure_output_path(tool_name: str, output_path: str | None) -> str:
    if output_path:
        return output_path
    fd, generated = tempfile.mkstemp(
        prefix=f"strix_{tool_name}_",
        suffix=TOOL_OUTPUT_SUFFIXES.get(tool_name, ".out"),
    )
    os.close(fd)
    return generated


def _parse_findings(tool_name: str, *, stdout: str, output_content: str) -> list[dict[str, Any]]:
    if tool_name == "arjun":
        return _parse_arjun(output_content)
    if tool_name == "dirsearch":
        return _parse_dirsearch(output_content)
    if tool_name == "httpx":
        return _parse_httpx(output_content)
    if tool_name == "jwt_tool":
        return _parse_jwt_tool(stdout or output_content)
    if tool_name == "katana":
        return _parse_katana(output_content)
    if tool_name == "naabu":
        return _parse_naabu(output_content)
    if tool_name == "nuclei":
        return _parse_nuclei(output_content)
    if tool_name == "nmap":
        return _parse_nmap(output_content)
    if tool_name == "ffuf":
        return _parse_ffuf(output_content)
    if tool_name == "bandit":
        return _parse_bandit(output_content)
    if tool_name == "semgrep":
        return _parse_semgrep(output_content)
    if tool_name == "subfinder":
        return _parse_subfinder(output_content)
    if tool_name == "trivy":
        return _parse_trivy(output_content)
    if tool_name == "trufflehog":
        return _parse_trufflehog(output_content or stdout)
    if tool_name == "wapiti":
        return _parse_wapiti(output_content)
    if tool_name == "wafw00f":
        return _parse_wafw00f(output_content or stdout)
    if tool_name == "zaproxy":
        return _parse_zaproxy(output_content)
    if tool_name == "sqlmap":
        return _parse_sqlmap(stdout)
    return []


def _host_for_finding(tool_name: str, finding: dict[str, Any]) -> str:
    for field in ["url", "matched_at", "host"]:
        value = str(finding.get(field) or "").strip()
        if not value:
            continue
        parsed = urlparse(value)
        if parsed.netloc:
            return parsed.netloc
        if field == "host":
            return value
    return tool_name


def _path_for_finding(finding: dict[str, Any]) -> str:
    direct = str(finding.get("path") or "").strip()
    if direct:
        return direct if direct.startswith("/") else f"/{direct}"
    for field in ["url", "matched_at"]:
        value = str(finding.get(field) or "").strip()
        if value:
            parsed = urlparse(value)
            if parsed.path:
                return parsed.path
    return "/"


def _component_for_host(host: str) -> str:
    return f"surface:{host}"


def _scanner_component(tool_name: str, host: str, finding: dict[str, Any]) -> str:
    if tool_name == "nuclei":
        return _component_for_host(host)
    if tool_name in {"semgrep", "bandit", "trivy", "trufflehog"}:
        path = str(finding.get("path") or "").strip()
        return f"code:{path}" if path else f"code:{tool_name}"
    if tool_name == "nmap":
        return f"service:{host}"
    if tool_name == "jwt_tool":
        return f"auth:{host}"
    if tool_name in {"wapiti", "zaproxy"}:
        path = _path_for_finding(finding)
        return f"surface:{host}{path}"
    return f"{tool_name}:{host}"


def _infer_vulnerability_type(tool_name: str, finding: dict[str, Any]) -> str:
    if tool_name == "sqlmap":
        return "sqli"
    if tool_name == "trufflehog":
        return "secret_exposure"
    if tool_name == "jwt_tool":
        return "jwt"
    if tool_name == "trivy":
        finding_class = str(finding.get("finding_class") or "").strip().lower()
        if finding_class == "secret":
            return "secret_exposure"
        if finding_class == "misconfig":
            return "misconfiguration"
    if tool_name == "wapiti":
        category = str(finding.get("name") or "").strip().lower()
        mapped = {
            "sql": "sqli",
            "blindsql": "sqli",
            "xss": "xss",
            "permanentxss": "xss",
            "ssrf": "ssrf",
            "xxe": "xxe",
            "csrf": "csrf",
            "file": "path_traversal",
            "exec": "rce",
        }.get(category)
        if mapped:
            return mapped

    signals = [
        str(finding.get("finding_id") or ""),
        str(finding.get("script_id") or ""),
        str(finding.get("template_id") or ""),
        str(finding.get("check_id") or ""),
        str(finding.get("detector") or ""),
        str(finding.get("parameter") or ""),
        str(finding.get("message") or ""),
        str(finding.get("name") or ""),
        " ".join(str(tag) for tag in finding.get("tags", [])),
    ]
    joined = " ".join(signal.lower() for signal in signals if signal)
    for keyword, vulnerability_type in FINDING_VULNERABILITY_KEYWORDS.items():
        if keyword in joined:
            return vulnerability_type
    return "scanner_finding"


def _priority_rank(priority: str | None) -> int:
    candidate = str(priority or "").strip().lower()
    if candidate in VALID_PRIORITIES:
        return VALID_PRIORITIES.index(candidate)
    return 0


def _highest_priority(*priorities: str | None) -> str:
    selected = "low"
    for priority in priorities:
        if _priority_rank(priority) > _priority_rank(selected):
            selected = str(priority or "").strip().lower()
    return selected if selected in VALID_PRIORITIES else "low"


def _confidence_rank(confidence: str | None) -> int:
    return CONFIDENCE_ORDER.get(str(confidence or "").strip().lower(), 0)


def _verification_rank(state: str | None) -> int:
    return VERIFICATION_ORDER.get(str(state or "").strip().lower(), 0)


def _finding_signal_text(finding: dict[str, Any]) -> str:
    values = [
        finding.get("template_id"),
        finding.get("matched_at"),
        finding.get("finding_id"),
        finding.get("check_id"),
        finding.get("script_id"),
        finding.get("detector"),
        finding.get("parameter"),
        finding.get("message"),
        finding.get("name"),
        finding.get("path"),
        finding.get("url"),
        " ".join(str(tag) for tag in finding.get("tags", [])),
    ]
    return " ".join(str(value).strip().lower() for value in values if str(value or "").strip())


def _map_vulnerability_type_to_focus(vulnerability_type: str, *, text: str) -> str | None:
    if vulnerability_type in {"authorization", "idor"}:
        return "authz"
    if vulnerability_type == "ssrf":
        return "ssrf_oob"
    if vulnerability_type == "sqli":
        return "sqli"
    if vulnerability_type == "xss":
        return "xss"
    if vulnerability_type == "open_redirect":
        return "open_redirect"
    if vulnerability_type == "ssti":
        return "ssti"
    if vulnerability_type in {"path_traversal", "lfi"}:
        return "path_traversal"
    if vulnerability_type == "xxe":
        return "xxe"
    if vulnerability_type == "file_upload":
        return "file_upload"
    if vulnerability_type == "jwt":
        return "auth_jwt"
    if vulnerability_type == "business_logic":
        return "workflow_race"
    if vulnerability_type == "authentication" and any(
        marker in text for marker in ("jwt", "token", "bearer", "authorization", "session")
    ):
        return "auth_jwt"
    return None


def _focus_signal_boost(
    focus: str,
    *,
    path: str,
    parameter_name: str,
    text: str,
) -> int:
    keywords = list(AUTO_FOCUS_SIGNAL_KEYWORDS.get(focus, []))
    if not keywords:
        return 0
    searchable = " ".join(
        [
            str(path or "").strip().lower(),
            str(parameter_name or "").strip().lower(),
            str(text or "").strip().lower(),
        ]
    )
    matches = sum(1 for keyword in keywords if keyword in searchable)
    if matches >= 2:
        return 2
    if matches == 1:
        return 1
    return 0


def _focus_candidates_for_finding(
    tool_name: str,
    finding: dict[str, Any],
    *,
    vulnerability_type: str | None = None,
) -> list[str]:
    effective_vulnerability_type = vulnerability_type or _infer_vulnerability_type(tool_name, finding)
    text = _finding_signal_text(finding)
    path = _path_for_finding(finding).lower()
    parameter_name = str(finding.get("parameter") or "").strip().lower()
    candidates: list[str] = []

    mapped_focus = _map_vulnerability_type_to_focus(effective_vulnerability_type, text=text)
    if mapped_focus:
        candidates.append(mapped_focus)

    if effective_vulnerability_type in {
        "authentication",
        "authorization",
        "business_logic",
        "cors",
        "csrf",
        "idor",
        "misconfiguration",
        "scanner_finding",
        "xss",
    }:
        parameter_vulnerability = (
            _infer_parameter_vulnerability_type(parameter_name) if parameter_name else None
        )
        parameter_focus = (
            _map_vulnerability_type_to_focus(parameter_vulnerability, text=text)
            if parameter_vulnerability
            else None
        )
        if parameter_focus:
            candidates.append(parameter_focus)

        if any(keyword in path for keyword in XML_PATH_KEYWORDS):
            candidates.append("xxe")
        if any(keyword in path for keyword in UPLOAD_PATH_KEYWORDS):
            candidates.append("file_upload")
        if any(keyword in path for keyword in ("download", "document", "attachment", "file")):
            candidates.append("path_traversal")
        if any(keyword in path for keyword in ("search", "comment", "feedback", "message", "preview")):
            candidates.append("xss")
        if any(keyword in path for keyword in ("redirect", "bounce", "out")):
            candidates.append("open_redirect")
        if any(
            keyword in path
            for keyword in ("admin", "account", "profile", "tenant", "order", "invoice", "payment", "checkout", "export")
        ):
            candidates.append("authz")
        if any(
            keyword in path for keyword in ("cart", "checkout", "coupon", "invoice", "payment", "redeem")
        ):
            candidates.append("workflow_race")
        if any(marker in text for marker in ("jwt", "token", "bearer", "authorization", "session")):
            candidates.append("auth_jwt")

    return _unique_strings(
        [candidate for candidate in candidates if candidate in SUPPORTED_FOCUS_PIPELINES]
    )


def _finding_candidate_url(tool_name: str, finding: dict[str, Any]) -> str | None:
    for field in ["url", "matched_at"]:
        value = str(finding.get(field) or "").strip()
        if _is_http_url(value):
            return value
    host = _host_for_finding(tool_name, finding)
    path = _path_for_finding(finding)
    if host and host != tool_name:
        return f"https://{host}{path}"
    return None


def _scanner_finding_verified(tool_name: str, finding: dict[str, Any], *, signal_text: str) -> bool:
    if tool_name in {"sqlmap", "jwt_tool"}:
        return True
    if tool_name == "trufflehog":
        return bool(finding.get("verified"))
    if tool_name == "nmap":
        return "vulnerable" in signal_text
    return False


def _triage_scanner_finding(tool_name: str, finding: dict[str, Any]) -> dict[str, Any]:
    vulnerability_type = str(
        finding.get("vulnerability_type") or _infer_vulnerability_type(tool_name, finding)
    )
    path = _path_for_finding(finding)
    parameter_name = str(finding.get("parameter") or "").strip()
    severity_priority = _priority_from_severity(
        str(finding.get("severity") or finding.get("priority") or "medium")
    )
    path_priority = _priority_for_path(path)
    parameter_priority = _priority_for_parameter(parameter_name) if parameter_name else "low"
    effective_priority = _highest_priority(severity_priority, path_priority, parameter_priority)
    signal_text = _finding_signal_text(finding)
    focus_candidates = _focus_candidates_for_finding(
        tool_name,
        finding,
        vulnerability_type=vulnerability_type,
    )
    verified = _scanner_finding_verified(tool_name, finding, signal_text=signal_text)
    raw_only_vulnerability = vulnerability_type in {"misconfiguration", "scanner_finding"}
    low_signal = any(keyword in signal_text for keyword in LOW_SIGNAL_FINDING_KEYWORDS)
    explicit_exploit_signal = raw_only_vulnerability is False or any(
        keyword in signal_text for keyword in HIGH_SIGNAL_FINDING_KEYWORDS
    )

    score = 1 + _priority_rank(effective_priority)
    if explicit_exploit_signal:
        score += 2
    if focus_candidates:
        score += 1
    if _looks_sensitive_path(path):
        score += 1
    if parameter_name and _priority_rank(parameter_priority) >= _priority_rank("high"):
        score += 1
    if tool_name in {"sqlmap", "jwt_tool"}:
        score += 2
    elif tool_name in {"bandit", "nmap", "semgrep", "trivy", "trufflehog"}:
        score += 1
    if raw_only_vulnerability and tool_name in {"nuclei", "wapiti", "zaproxy"}:
        score -= 1
    if low_signal:
        score -= 2
    if raw_only_vulnerability and not focus_candidates and _priority_rank(effective_priority) <= _priority_rank("normal"):
        score -= 1
    if verified:
        score += 2

    if score >= 6:
        confidence = "high"
    elif score >= 4:
        confidence = "medium"
    else:
        confidence = "low"

    verification_state = "validated" if verified else "raw"
    should_record_hypothesis = confidence != "low"
    if raw_only_vulnerability and not verified and not focus_candidates:
        should_record_hypothesis = _priority_rank(effective_priority) >= _priority_rank("high")
    if (
        raw_only_vulnerability
        and tool_name in {"nuclei", "wapiti", "zaproxy"}
        and confidence == "medium"
        and not (
            _looks_sensitive_path(path)
            or _priority_rank(parameter_priority) >= _priority_rank("high")
        )
    ):
        should_record_hypothesis = False
    if tool_name in {"nuclei", "wapiti", "zaproxy"} and low_signal and not verified:
        should_record_hypothesis = False

    rationale_bits: list[str] = [f"scanner confidence={confidence}", f"verification={verification_state}"]
    if focus_candidates:
        rationale_bits.append(f"follow-up focus={', '.join(focus_candidates)}")
    if low_signal:
        rationale_bits.append("generic scanner wording lowers trust")
    if verified:
        rationale_bits.append(f"{tool_name} output looks directly confirmatory")

    return {
        "vulnerability_type": vulnerability_type,
        "priority": effective_priority,
        "confidence": confidence,
        "verification_state": verification_state,
        "requires_manual_confirmation": verification_state != "validated",
        "requires_runtime_context": any(
            focus in {"authz", "workflow_race"} for focus in focus_candidates
        ),
        "focus_candidates": focus_candidates,
        "primary_focus": focus_candidates[0] if focus_candidates else None,
        "should_record_hypothesis": should_record_hypothesis,
        "score": score,
        "rationale": "; ".join(rationale_bits),
    }


def _annotate_scanner_findings(tool_name: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    annotated: list[dict[str, Any]] = []
    for finding in findings:
        triage = _triage_scanner_finding(tool_name, finding)
        annotated.append(
            {
                **finding,
                "vulnerability_type": triage["vulnerability_type"],
                "triage": triage,
            }
        )
    return annotated


def _next_step_for_path(path: str) -> str:
    if _looks_sensitive_path(path):
        return (
            "Validate authentication, authorization, state-changing behavior, and hidden input "
            "handling on this path before concluding coverage"
        )
    return "Probe this discovered path for parameter handling, access control, and workflow relevance"


def _record_run_evidence(
    agent_state: Any,
    *,
    tool_name: str,
    logical_target: str,
    component: str,
    run_id: str,
    command: list[str],
    execution: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    detail_payload = {
        "run_id": run_id,
        "tool_name": tool_name,
        "command": command,
        "exit_code": execution.get("exit_code"),
        "stdout_preview": _truncate(str(execution.get("stdout") or ""), 600),
        "stderr_preview": _truncate(str(execution.get("stderr") or ""), 600),
        "finding_count": len(findings),
        "findings_preview": findings[:10],
    }
    return record_evidence(
        agent_state=agent_state,
        title=f"{tool_name} scan run for {logical_target}",
        details=json.dumps(detail_payload, ensure_ascii=False),
        source="tool",
        target=logical_target,
        component=component,
    )


def _missing_tool_skip_reason(tool_name: str, error: BaseException) -> str | None:
    normalized_tool = str(tool_name).strip().lower()
    message = str(error).strip()
    lowered = message.lower()
    if f"{normalized_tool} is not available on path" in lowered:
        return message or f"{tool_name} is not available on PATH"
    if isinstance(error, FileNotFoundError):
        return message or f"{tool_name} is not available on PATH"
    if isinstance(error, OSError):
        if getattr(error, "errno", None) == 2 or getattr(error, "winerror", None) == 2:
            return message or f"{tool_name} is not available on PATH"
    if "no such file or directory" in lowered:
        return message or f"{tool_name} is not available on PATH"
    if "the system cannot find the file specified" in lowered:
        return message or f"{tool_name} is not available on PATH"
    return None


def _record_skipped_tool_run(
    agent_state: Any,
    *,
    store: dict[str, TOOL_RUN],
    root_agent_id: str,
    tool_name: str,
    logical_target: str,
    logical_component: str,
    scope_key: str,
    scope_payload: dict[str, Any],
    resolved_output_path: str,
    include_findings: bool,
    reason: str,
    availability: str = "missing_tool",
    command: list[str] | None = None,
) -> dict[str, Any]:
    started_at = _utc_now()
    attempted_command = list(command or [tool_name])
    run_id = _stable_id(
        "scan",
        logical_target,
        logical_component,
        tool_name,
        started_at,
    )
    execution = {
        "exit_code": 127,
        "stdout": "",
        "stderr": reason,
    }
    evidence_result = _record_run_evidence(
        agent_state,
        tool_name=tool_name,
        logical_target=logical_target,
        component=logical_component,
        run_id=run_id,
        command=attempted_command,
        execution=execution,
        findings=[],
    )
    run_record: TOOL_RUN = {
        "root_agent_id": root_agent_id,
        "run_id": run_id,
        "tool_name": tool_name,
        "target": logical_target,
        "component": logical_component,
        "command": attempted_command,
        "exit_code": execution["exit_code"],
        "stdout_preview": "",
        "stderr_preview": _truncate(reason, 400),
        "finding_count": 0,
        "findings": [],
        "output_path": resolved_output_path,
        "created_at": started_at,
        "updated_at": _utc_now(),
        "scope_key": scope_key,
        "scope": scope_payload,
        "discovery_seed_count": 0,
        "hypothesis_seed_count": 0,
        "evidence_id": evidence_result.get("evidence_id"),
        "skipped": True,
        "skip_reason": reason,
        "availability": availability,
        "needs_more_data": True,
    }
    store[run_id] = run_record

    response = _tool_run_response(
        run_record,
        include_findings=include_findings,
        reused_existing_run=False,
    )
    response["evidence_result"] = evidence_result
    return response


def _unique_strings(items: list[str]) -> list[str]:
    normalized: list[str] = []
    for item in items:
        candidate = str(item).strip()
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return normalized


def _is_http_url(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered.startswith("http://") or lowered.startswith("https://")


def _extract_host_targets(findings: list[dict[str, Any]]) -> list[str]:
    hosts: list[str] = []
    for finding in findings:
        for key in ["host", "hostname", "ip", "url"]:
            value = str(finding.get(key) or "").strip()
            if not value:
                continue
            if key == "url":
                parsed = urlparse(value)
                if parsed.netloc:
                    hosts.append(parsed.netloc)
            else:
                hosts.append(value)
    return _unique_strings(hosts)


def _extract_live_urls(findings: list[dict[str, Any]]) -> list[str]:
    urls: list[str] = []
    for finding in findings:
        value = str(finding.get("url") or "").strip()
        if _is_http_url(value):
            urls.append(value)
    return _unique_strings(urls)


def _extract_open_ports_by_host(findings: list[dict[str, Any]]) -> dict[str, list[int]]:
    ports_by_host: dict[str, list[int]] = {}
    for finding in findings:
        try:
            port = int(finding.get("port"))
        except (TypeError, ValueError):
            continue
        host = str(finding.get("host") or finding.get("hostname") or "").strip()
        if not host:
            continue
        host_ports = ports_by_host.setdefault(host, [])
        if port not in host_ports:
            host_ports.append(port)
    for host, ports in ports_by_host.items():
        ports.sort()
        ports_by_host[host] = ports
    return ports_by_host


def _ffuf_seed_urls(urls: list[str], *, limit: int) -> list[str]:
    candidates: list[str] = []
    for raw_url in urls:
        parsed = urlparse(str(raw_url).strip())
        if not parsed.scheme or not parsed.netloc:
            continue
        base = f"{parsed.scheme}://{parsed.netloc}"
        if f"{base}/FUZZ" not in candidates:
            candidates.append(f"{base}/FUZZ")
        path_segments = [segment for segment in (parsed.path or "/").split("/") if segment]
        if not path_segments:
            continue
        first_segment = path_segments[0]
        first_candidate = f"{base}/{first_segment}/FUZZ"
        if first_candidate not in candidates:
            candidates.append(first_candidate)
        parent_segments = path_segments[:-1]
        if parent_segments:
            parent_candidate = f"{base}/{'/'.join(parent_segments)}/FUZZ"
            if parent_candidate not in candidates:
                candidates.append(parent_candidate)
        if len(candidates) >= limit:
            break
    return candidates[:limit]


def _seed_discovery_coverage(
    agent_state: Any,
    *,
    logical_target: str,
    tool_name: str,
    findings: list[dict[str, Any]],
    max_seed_items: int,
) -> dict[str, Any] | None:
    coverage_items: list[dict[str, Any]] = []
    for finding in findings:
        path = _path_for_finding(finding)
        host = _host_for_finding(tool_name, finding)
        status_code = finding.get("status_code")
        coverage_items.append(
            {
                "target": logical_target,
                "component": _component_for_host(host),
                "surface": f"Discovered path {path}",
                "status": "uncovered",
                "priority": _priority_for_path(path),
                "rationale": (
                    f"{tool_name} discovered {path} on {host}"
                    + (
                        f" with status {status_code}"
                        if status_code is not None
                        else ""
                    )
                ),
                "next_step": _next_step_for_path(path),
            }
        )
        if len(coverage_items) >= max_seed_items:
            break

    deduped = _dedupe_preserve_order(coverage_items)
    if not deduped:
        return None
    return bulk_record_coverage(
        agent_state=agent_state,
        items=deduped,
        preserve_existing_status=True,
    )


def _seed_parameter_discovery(
    agent_state: Any,
    *,
    logical_target: str,
    findings: list[dict[str, Any]],
    max_seed_items: int,
    max_hypotheses: int,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    coverage_items: list[dict[str, Any]] = []
    hypothesis_updates: list[dict[str, Any]] = []

    for finding in findings[:max_seed_items]:
        parameter_name = str(finding.get("parameter") or "").strip()
        if not parameter_name:
            continue

        host = _host_for_finding("arjun", finding)
        path = _path_for_finding(finding)
        component = f"params:{host}:{path}"
        coverage_items.append(
            {
                "target": logical_target,
                "component": component,
                "surface": f"Discovered parameter {parameter_name} on {path}",
                "status": "uncovered",
                "priority": _priority_for_parameter(parameter_name),
                "rationale": f"arjun discovered parameter {parameter_name} on {path} at {host}",
                "next_step": (
                    "Probe the new parameter with contextual payloads and compare behavior across roles, "
                    "objects, and edge-case encodings"
                ),
            }
        )

    deduped_coverage = _dedupe_preserve_order(coverage_items)
    coverage_result = None
    if deduped_coverage:
        coverage_result = bulk_record_coverage(
            agent_state=agent_state,
            items=deduped_coverage,
            preserve_existing_status=True,
        )

    for finding in findings[:max_hypotheses]:
        parameter_name = str(finding.get("parameter") or "").strip()
        vulnerability_type = _infer_parameter_vulnerability_type(parameter_name)
        if not vulnerability_type:
            continue

        host = _host_for_finding("arjun", finding)
        path = _path_for_finding(finding)
        component = f"params:{host}:{path}"
        rationale = (
            f"arjun discovered high-signal parameter {parameter_name} on {path}; the parameter name "
            f"matches common {vulnerability_type} attack surface patterns."
        )
        hypothesis_result = record_hypothesis(
            agent_state=agent_state,
            hypothesis=(
                f"Parameter {parameter_name} on {path} may expose {vulnerability_type} behavior"
            ),
            target=logical_target,
            component=component,
            vulnerability_type=vulnerability_type,
            status="open",
            priority=_priority_for_parameter(parameter_name),
            rationale=rationale,
        )
        hypothesis_updates.append({"finding": finding, "hypothesis_result": hypothesis_result})

    return coverage_result, hypothesis_updates


def _seed_host_discovery_coverage(
    agent_state: Any,
    *,
    logical_target: str,
    tool_name: str,
    findings: list[dict[str, Any]],
    max_seed_items: int,
) -> dict[str, Any] | None:
    coverage_items: list[dict[str, Any]] = []
    for finding in findings[:max_seed_items]:
        host = str(finding.get("host") or "").strip()
        if not host:
            continue
        source_count = len(finding.get("sources", []) or [])
        coverage_items.append(
            {
                "target": logical_target,
                "component": f"host:{host}",
                "surface": f"Discovered host {host}",
                "status": "uncovered",
                "priority": _priority_for_host(host),
                "rationale": (
                    f"{tool_name} discovered host {host}"
                    + (
                        f" from {source_count} source(s)"
                        if source_count
                        else ""
                    )
                ),
                "next_step": (
                    "Probe the host with httpx and follow-on scanners, then compare whether it exposes "
                    "distinct auth, admin, or legacy surface"
                ),
            }
        )

    deduped = _dedupe_preserve_order(coverage_items)
    if not deduped:
        return None
    return bulk_record_coverage(
        agent_state=agent_state,
        items=deduped,
        preserve_existing_status=True,
    )


def _seed_service_discovery_coverage(
    agent_state: Any,
    *,
    logical_target: str,
    tool_name: str,
    findings: list[dict[str, Any]],
    max_seed_items: int,
) -> dict[str, Any] | None:
    coverage_items: list[dict[str, Any]] = []
    for finding in findings[:max_seed_items]:
        if str(finding.get("kind") or "port") != "port":
            continue
        host = str(finding.get("host") or finding.get("ip") or "").strip()
        port = finding.get("port")
        if not host or port is None:
            continue
        protocol = str(finding.get("protocol") or "tcp").strip() or "tcp"
        service = str(finding.get("service") or "").strip()
        service_suffix = f" ({service})" if service else ""
        coverage_items.append(
            {
                "target": logical_target,
                "component": f"service:{host}",
                "surface": f"Open {protocol} port {port}{service_suffix} on {host}",
                "status": "uncovered",
                "priority": _priority_for_port(int(port), service),
                "rationale": (
                    f"{tool_name} observed open {protocol} port {port} on {host}"
                    + (
                        f" with service fingerprint {service}"
                        if service
                        else ""
                    )
                ),
                "next_step": (
                    "Verify the service banner, auth posture, and reachable attack surface before closing this "
                    "service discovery item"
                ),
            }
        )

    deduped = _dedupe_preserve_order(coverage_items)
    if not deduped:
        return None
    return bulk_record_coverage(
        agent_state=agent_state,
        items=deduped,
        preserve_existing_status=True,
    )


def _seed_waf_observations(
    agent_state: Any,
    *,
    logical_target: str,
    findings: list[dict[str, Any]],
    max_seed_items: int,
) -> dict[str, Any] | None:
    coverage_items: list[dict[str, Any]] = []
    for finding in findings[:max_seed_items]:
        host = _host_for_finding("wafw00f", finding)
        waf_name = str(finding.get("name") or "unknown-waf").strip()
        manufacturer = str(finding.get("manufacturer") or "").strip()
        descriptor = waf_name if not manufacturer else f"{waf_name} ({manufacturer})"
        coverage_items.append(
            {
                "target": logical_target,
                "component": f"defense:{host}",
                "surface": f"WAF detected on {host}: {descriptor}",
                "status": "covered",
                "priority": "normal",
                "rationale": (
                    f"wafw00f detected a likely defensive layer on {host}: {descriptor}."
                ),
                "next_step": (
                    "Treat hard blocks, CAPTCHAs, and shaped 403/406 responses as possible WAF behavior "
                    "and validate suspicious cases with slower or authenticated follow-up requests"
                ),
            }
        )

    deduped = _dedupe_preserve_order(coverage_items)
    if not deduped:
        return None
    return bulk_record_coverage(
        agent_state=agent_state,
        items=deduped,
        preserve_existing_status=True,
    )


def _record_scanner_findings(
    agent_state: Any,
    *,
    logical_target: str,
    tool_name: str,
    findings: list[dict[str, Any]],
    max_findings: int,
) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = []
    for finding in findings[:max_findings]:
        host = _host_for_finding(tool_name, finding)
        path = _path_for_finding(finding)
        component = _scanner_component(tool_name, host, finding)
        triage = (
            dict(finding.get("triage") or {})
            if isinstance(finding.get("triage"), dict)
            else _triage_scanner_finding(tool_name, finding)
        )
        priority = str(triage.get("priority") or "normal")
        vulnerability_type = str(
            triage.get("vulnerability_type") or _infer_vulnerability_type(tool_name, finding)
        )
        confidence = str(triage.get("confidence") or "low")
        verification_state = str(triage.get("verification_state") or "raw")
        focus_candidates = [
            str(item).strip()
            for item in list(triage.get("focus_candidates") or [])
            if str(item).strip()
        ]

        if tool_name == "nuclei":
            template_id = str(finding.get("template_id") or "unknown-template")
            surface = f"Nuclei finding {template_id} on {path}"
            rationale = (
                f"nuclei matched template {template_id} on {finding.get('matched_at') or host}; "
                f"name={finding.get('name') or 'unknown'} severity={finding.get('severity') or 'medium'}."
            )
        elif tool_name == "semgrep":
            check_id = str(finding.get("check_id") or "unknown-check")
            line = finding.get("line")
            line_suffix = f":{line}" if line is not None else ""
            surface = f"Semgrep finding {check_id} at {finding.get('path') or '<unknown>'}{line_suffix}"
            rationale = (
                f"semgrep flagged {check_id} in {finding.get('path') or '<unknown>'}"
                f" with severity {finding.get('severity') or 'medium'}: "
                f"{finding.get('message') or 'no message'}"
            )
        elif tool_name == "bandit":
            test_id = str(finding.get("check_id") or "unknown-test")
            line = finding.get("line")
            line_suffix = f":{line}" if line is not None else ""
            surface = f"Bandit finding {test_id} at {finding.get('path') or '<unknown>'}{line_suffix}"
            rationale = (
                f"bandit flagged {test_id} in {finding.get('path') or '<unknown>'}"
                f" with severity {finding.get('severity') or 'medium'}: "
                f"{finding.get('message') or 'no message'}"
            )
        elif tool_name == "trivy":
            finding_id = str(
                finding.get("finding_id")
                or finding.get("check_id")
                or finding.get("name")
                or "unknown-finding"
            )
            surface = f"Trivy finding {finding_id} at {finding.get('path') or '<unknown>'}"
            rationale = (
                f"trivy flagged {finding_id} in {finding.get('path') or '<unknown>'}"
                f" with severity {finding.get('severity') or 'medium'}: "
                f"{finding.get('message') or finding.get('name') or 'no message'}"
            )
        elif tool_name == "trufflehog":
            detector = str(finding.get("detector") or "unknown-detector")
            surface = f"Potential secret exposure via {detector} in {finding.get('path') or '<unknown>'}"
            rationale = (
                f"trufflehog detected {detector} in {finding.get('path') or '<unknown>'}"
                + (
                    " and marked it verified."
                    if finding.get("verified")
                    else "."
                )
            )
        elif tool_name == "nmap":
            script_id = str(finding.get("script_id") or "unknown-script")
            port = finding.get("port")
            port_suffix = f" on port {port}" if port is not None else ""
            surface = f"Nmap script finding {script_id}{port_suffix} at {host}"
            rationale = (
                f"nmap script {script_id} reported {finding.get('message') or 'a suspicious service signal'}"
            )
        elif tool_name == "wapiti":
            category = str(finding.get("name") or "unknown-category")
            parameter_name = str(finding.get("parameter") or "").strip()
            parameter_suffix = f" via {parameter_name}" if parameter_name else ""
            surface = f"Wapiti finding {category}{parameter_suffix} on {path}"
            rationale = (
                f"wapiti reported {category} on {finding.get('url') or path}: "
                f"{finding.get('message') or 'scanner-reported vulnerability'}"
            )
        elif tool_name == "zaproxy":
            alert_name = str(finding.get("name") or "unknown-alert")
            parameter_name = str(finding.get("parameter") or "").strip()
            parameter_suffix = f" via {parameter_name}" if parameter_name else ""
            surface = f"ZAP finding {alert_name}{parameter_suffix} on {path}"
            rationale = (
                f"zaproxy reported {alert_name} on {finding.get('url') or path}: "
                f"{finding.get('message') or 'scanner-reported issue'}"
            )
        elif tool_name == "jwt_tool":
            finding_name = str(finding.get("name") or "JWT weakness")
            surface = f"JWT finding {finding_name} on {host}"
            rationale = (
                f"jwt_tool reported {finding_name} against {host}: "
                f"{finding.get('message') or 'scanner-reported JWT weakness'}"
            )
        else:
            parameter = str(finding.get("parameter") or "<unknown>")
            surface = f"Potential SQL injection in parameter {parameter}"
            rationale = (
                f"sqlmap reported injectable parameter {parameter}: "
                f"{finding.get('message') or 'possible SQL injection'}"
            )

        rationale = f"{rationale} Triage: {triage.get('rationale') or 'scanner finding pending verification'}."
        coverage_result = record_coverage(
            agent_state=agent_state,
            target=logical_target,
            component=component,
            surface=surface,
            status="in_progress",
            rationale=rationale,
            priority=priority,
            next_step=(
                "Reproduce the scanner signal manually, verify exploitability, and capture targeted proof "
                "before resolving this item"
                if bool(triage.get("should_record_hypothesis"))
                else (
                    "Treat this as an unverified scanner signal; only escalate it if another tool, runtime "
                    "context, or manual reproduction confirms the same behavior"
                )
            ),
        )
        hypothesis_result = None
        if bool(triage.get("should_record_hypothesis")):
            focus_suffix = (
                f" follow-up={', '.join(focus_candidates)}"
                if focus_candidates
                else ""
            )
            hypothesis_result = record_hypothesis(
                agent_state=agent_state,
                hypothesis=(
                    f"{tool_name} indicates possible {vulnerability_type} on {surface.lower()}"
                ),
                target=logical_target,
                component=str(coverage_result.get("record", {}).get("component") or component),
                vulnerability_type=vulnerability_type,
                status="open",
                priority=priority,
                rationale=(
                    f"{rationale} Confidence={confidence}; verification_state={verification_state}."
                    f"{focus_suffix}"
                ),
            )
        updates.append(
            {
                "finding": finding,
                "triage": triage,
                "coverage_result": coverage_result,
                "hypothesis_result": hypothesis_result,
            }
        )
    return updates


def _version_probe_command(tool_name: str, executable: str) -> list[str]:
    return [executable, *TOOL_VERSION_ARGS.get(tool_name, ["--version"])]


def _build_command(
    tool_name: str,
    *,
    targets: list[str],
    target_path: str | None,
    url: str | None,
    wordlist_path: str | None,
    raw_request_path: str | None,
    paths: list[str],
    headers: dict[str, str],
    data: str | None,
    request_method: str,
    ports: str | None,
    top_ports: int | None,
    parameter: str | None,
    configs: list[str],
    tags: list[str],
    severities: list[str],
    proxy_url: str | None,
    automatic_scan: bool,
    active_only: bool,
    collect_sources: bool,
    no_interactsh: bool,
    use_js_crawl: bool,
    headless: bool,
    known_files: str,
    recursion: bool,
    recursion_depth: int,
    scan_type: str | None,
    host_discovery_disabled: bool,
    service_detection: bool,
    default_scripts: bool,
    store_response: bool,
    flush_session: bool,
    threads: int,
    rate_limit: int,
    concurrency: int,
    bulk_size: int,
    depth: int,
    timeout: int,
    retries: int,
    max_time_minutes: int | None,
    host_timeout: str | None,
    script_timeout: str | None,
    level: int,
    risk: int,
    zapit: bool,
    jwt_token: str | None,
    canary_value: str | None,
    public_key_path: str | None,
    dictionary_path: str | None,
    output_path: str,
    httpx_rich_metadata: bool = True,
) -> list[str]:
    executable = _resolve_tool_executable(tool_name)
    if executable is None:
        raise ValueError(f"{tool_name} is not available on PATH")

    if tool_name in {"httpx", "katana", "naabu", "nuclei", "subfinder"}:
        if not targets:
            raise ValueError(f"{tool_name} requires non-empty targets")
        target_file = _write_lines_file(targets)
    else:
        target_file = None

    if tool_name == "subfinder":
        if not targets:
            raise ValueError("subfinder requires non-empty targets")
        command = [
            executable,
            "-all",
            "-rl",
            str(rate_limit),
            "-timeout",
            str(timeout),
            "-silent",
            "-oJ",
            "-o",
            output_path,
        ]
        if len(targets) == 1:
            command.extend(["-d", targets[0]])
        else:
            command.extend(["-dL", str(target_file)])
        if recursion:
            command.append("-recursive")
        if collect_sources:
            command.append("-cs")
        if active_only:
            command.append("-nW")
        if proxy_url:
            command.extend(["-proxy", proxy_url])
        if max_time_minutes is not None:
            command.extend(["-max-time", str(max_time_minutes)])
        return command

    if tool_name == "naabu":
        if not targets:
            raise ValueError("naabu requires non-empty targets")
        resolved_scan_type = str(scan_type or "connect").strip().lower()
        command = [
            executable,
            "-list",
            str(target_file),
            "-scan-type",
            resolved_scan_type,
            "-rate",
            str(rate_limit),
            "-c",
            str(max(1, concurrency)),
            "-timeout",
            str(max(1, timeout) * 1000),
            "-retries",
            str(retries),
            "-silent",
            "-j",
            "-o",
            output_path,
        ]
        if ports:
            command.extend(["-p", ports])
        elif top_ports is not None:
            command.extend(["-top-ports", str(top_ports)])
        else:
            command.extend(["-top-ports", "100"])
        if host_discovery_disabled:
            command.append("-Pn")
        command.append("-verify")
        if proxy_url:
            command.extend(["-proxy", proxy_url])
        return command

    if tool_name == "nmap":
        if not targets:
            raise ValueError("nmap requires non-empty targets")
        resolved_scan_type = str(scan_type or "sT").strip()
        command = [
            executable,
            "-n",
            "--open",
            resolved_scan_type,
            f"-T{min(max(1, concurrency // 5), 4)}",
            "--max-retries",
            str(retries),
            "--host-timeout",
            str(host_timeout or "90s"),
            "-oX",
            output_path,
        ]
        if host_discovery_disabled:
            command.append("-Pn")
        if ports:
            command.extend(["-p", ports])
        elif top_ports is not None:
            command.extend(["--top-ports", str(top_ports)])
        else:
            command.extend(["--top-ports", "100"])
        if service_detection:
            command.append("-sV")
        if default_scripts:
            command.append("-sC")
            command.extend(["--script-timeout", str(script_timeout or "30s")])
        command.extend(targets)
        return command

    if tool_name == "httpx":
        command = [
            executable,
            "-l",
            str(target_file),
            "-sc",
            "-title",
            "-server",
            "-td",
            "-fr",
            "-timeout",
            str(timeout),
            "-retries",
            str(retries),
            "-rl",
            str(rate_limit),
            "-t",
            str(threads),
            "-silent",
            "-j",
            "-o",
            output_path,
        ]
        if httpx_rich_metadata:
            command.extend(["-cname", "-asn", "-cdn", "-tls-grab"])
        if paths:
            path_file = _write_lines_file(paths)
            command.extend(["-path", path_file])
        if proxy_url:
            command.extend(["-proxy", proxy_url])
        if store_response:
            response_dir = str(Path(output_path).with_suffix(""))
            command.extend(["-sr", "-srd", response_dir])
        return command

    if tool_name == "wafw00f":
        if not url:
            raise ValueError("wafw00f requires url")
        return [
            executable,
            url,
            "-o",
            output_path,
        ]

    if tool_name == "katana":
        command = [
            executable,
            "-list",
            str(target_file),
            "-d",
            str(depth),
            "-kf",
            known_files,
            "-c",
            str(concurrency),
            "-p",
            str(max(1, min(threads, 20))),
            "-rl",
            str(rate_limit),
            "-timeout",
            str(timeout),
            "-retry",
            str(retries),
            "-silent",
            "-j",
            "-o",
            output_path,
        ]
        if use_js_crawl:
            command.append("-jc")
        if headless:
            command.extend(["-hl", "-nos"])
        if proxy_url:
            command.extend(["-proxy", proxy_url])
        return command

    if tool_name == "nuclei":
        command = [
            executable,
            "-l",
            str(target_file),
            "-timeout",
            str(timeout),
            "-retries",
            str(retries),
            "-rl",
            str(rate_limit),
            "-c",
            str(concurrency),
            "-bs",
            str(bulk_size),
            "-silent",
            "-j",
            "-o",
            output_path,
        ]
        if tags:
            command.extend(["-tags", ",".join(tags)])
        elif automatic_scan:
            command.append("-as")
        if severities:
            command.extend(["-s", ",".join(severities)])
        if no_interactsh:
            command.append("-ni")
        return command

    if tool_name == "arjun":
        if not url and not raw_request_path and not targets:
            raise ValueError("arjun requires url, targets, or raw_request_path")
        command = [
            executable,
            "-t",
            str(threads),
            "-T",
            str(timeout),
            "--ratelimit",
            str(rate_limit),
            "-oJ",
            output_path,
        ]
        if url:
            command.extend(["-u", url])
        elif raw_request_path:
            command.extend(["-i", raw_request_path])
        elif targets:
            arjun_target_file = _write_lines_file(targets)
            command.extend(["-i", arjun_target_file])
        if wordlist_path:
            command.extend(["-w", wordlist_path])
        normalized_method = request_method.strip().upper()
        if normalized_method and normalized_method != "GET":
            command.extend(["-m", normalized_method])
        if data:
            command.extend(["--include", data])
        if headers:
            command.extend(
                [
                    "--headers",
                    "\n".join(f"{key}: {value}" for key, value in headers.items()),
                ]
            )
        return command

    if tool_name == "dirsearch":
        if not url:
            raise ValueError("dirsearch requires url")
        command = [
            executable,
            "-u",
            url,
            "--format=json",
            "-o",
            output_path,
            "-t",
            str(max(1, threads)),
            "--timeout",
            str(timeout),
            "--retries",
            str(retries),
            "-q",
        ]
        if wordlist_path:
            command.extend(["-w", wordlist_path])
        if proxy_url:
            command.extend(["-p", proxy_url])
        if recursion:
            command.extend(["-r", "--max-recursion-depth", str(recursion_depth)])
        if paths:
            subdirs = [item.strip("/") for item in paths if item.strip("/")]
            if subdirs:
                command.extend(["--subdirs", ",".join(subdirs)])
        return command

    if tool_name == "wapiti":
        if not url:
            raise ValueError("wapiti requires url")
        command = [
            executable,
            "-u",
            url,
            "-f",
            "json",
            "-o",
            output_path,
            "-d",
            str(depth),
        ]
        if flush_session:
            command.append("--flush-session")
        if proxy_url:
            command.extend(["-p", proxy_url])
        return command

    if tool_name == "ffuf":
        if not url or not wordlist_path:
            raise ValueError("ffuf requires url and wordlist_path")
        command = [
            executable,
            "-w",
            wordlist_path,
            "-u",
            url,
            "-ac",
            "-t",
            str(threads),
            "-rate",
            str(rate_limit),
            "-timeout",
            str(timeout),
            "-noninteractive",
            "-of",
            "json",
            "-o",
            output_path,
        ]
        if recursion:
            command.extend(["-recursion", "-recursion-depth", str(recursion_depth)])
        if proxy_url:
            command.extend(["-x", proxy_url])
        if data:
            command.extend(["-d", data])
        for key, value in headers.items():
            command.extend(["-H", f"{key}: {value}"])
        return command

    if tool_name == "jwt_tool":
        header_map = {str(key).lower(): value for key, value in headers.items()}
        mode = str(scan_type or ("playbook" if url or raw_request_path else "decode")).strip().lower()
        if not jwt_token and not raw_request_path and not url and not headers:
            raise ValueError("jwt_tool requires jwt_token, url/raw_request_path, or headers")
        if mode != "decode" and not (url or raw_request_path):
            raise ValueError("jwt_tool exploit and playbook modes require url or raw_request_path")
        command = [executable]
        if jwt_token:
            command.append(jwt_token)
        if raw_request_path:
            command.extend(["-r", raw_request_path])
        elif url:
            command.extend(["-t", url])

        cookie_header = header_map.get("cookie")
        if cookie_header:
            command.extend(["-rc", cookie_header])
        for key, value in headers.items():
            if key.lower() == "cookie":
                continue
            command.extend(["-rh", f"{key}: {value}"])

        if mode == "playbook":
            command.extend(["-M", "pb"])
        elif mode == "alg_none":
            command.extend(["-X", "a"])
        elif mode == "key_confusion":
            command.extend(["-X", "k"])
        elif mode == "jwks_injection":
            command.extend(["-X", "i"])
        elif mode == "null_signature":
            command.extend(["-X", "n"])
        elif mode == "verify":
            command.append("-V")
        elif mode == "crack":
            command.append("-C")
            if dictionary_path:
                command.extend(["-d", dictionary_path])
        elif mode != "decode":
            raise ValueError(
                "jwt_tool scan_type must be one of: decode, playbook, alg_none, "
                "key_confusion, jwks_injection, null_signature, verify, crack"
            )

        if canary_value:
            command.extend(["-cv", canary_value])
        if public_key_path:
            command.extend(["-pk", public_key_path])
        return command

    if tool_name == "semgrep":
        if not target_path:
            raise ValueError("semgrep requires target_path")
        command = [
            executable,
            "scan",
            "--metrics=off",
            "--json",
            "--output",
            output_path,
            "--quiet",
            "--jobs",
            str(max(1, concurrency)),
            "--timeout",
            str(timeout),
        ]
        for config in configs or ["p/default"]:
            command.extend(["--config", config])
        if severities:
            for severity in severities:
                command.extend(["--severity", severity])
        command.append(target_path)
        return command

    if tool_name == "trivy":
        if not target_path:
            raise ValueError("trivy requires target_path")
        command = [
            executable,
            "fs",
            "--format",
            "json",
            "--output",
            output_path,
            "--quiet",
            "--scanners",
            "vuln,misconfig,secret",
        ]
        if severities:
            command.extend(["--severity", ",".join(str(item).upper() for item in severities)])
        command.append(target_path)
        return command

    if tool_name == "bandit":
        if not target_path:
            raise ValueError("bandit requires target_path")
        command = [
            executable,
            "-r",
            target_path,
            "-f",
            "json",
            "-o",
            output_path,
            "-q",
        ]
        return command

    if tool_name == "sqlmap":
        if not url and not raw_request_path:
            raise ValueError("sqlmap requires url or raw_request_path")
        command = [
            executable,
            "--batch",
            "--level",
            str(level),
            "--risk",
            str(risk),
            "--threads",
            str(max(1, threads)),
            "--timeout",
            str(timeout),
            "--retries",
            str(retries),
            "--random-agent",
        ]
        if url:
            command.extend(["-u", url])
        if raw_request_path:
            command.extend(["-r", raw_request_path])
        if parameter:
            command.extend(["-p", parameter])
        if data:
            command.extend(["--data", data])
        if flush_session:
            command.append("--flush-session")
        extra_headers: list[str] = []
        for key, value in headers.items():
            if key.lower() == "cookie":
                command.extend(["--cookie", value])
            else:
                extra_headers.append(f"{key}: {value}")
        if extra_headers:
            command.extend(["--headers", "\n".join(extra_headers)])
        return command

    if tool_name == "zaproxy":
        if not url:
            raise ValueError("zaproxy requires url")
        command = [
            executable,
            "-cmd",
            "-quickurl",
            url,
            "-quickout",
            output_path,
            "-quickprogress",
        ]
        if zapit:
            command.append("-zapit")
        return command

    if tool_name == "trufflehog":
        if not target_path:
            raise ValueError("trufflehog requires target_path")
        return [
            executable,
            "filesystem",
            target_path,
            "--json",
            "--no-verification",
        ]

    raise ValueError(f"Unsupported tool_name '{tool_name}'")


def _string_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        values: list[str] = []
        for item in value:
            values.extend(_string_list(item))
        return _unique_strings(values)
    if value is None:
        return []
    candidate = str(value).strip()
    if not candidate or candidate.lower() in {"false", "none", "null"}:
        return []
    return [candidate]


def _string_values_for_keys(value: Any, keys: tuple[str, ...]) -> list[str]:
    if isinstance(value, dict):
        values: list[str] = []
        for key in keys:
            if key in value:
                values.extend(_string_list(value.get(key)))
        return _unique_strings(values)
    return []


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _httpx_asn_details(item: dict[str, Any]) -> tuple[list[str], list[str]]:
    details = item.get("asn")
    if not isinstance(details, dict):
        details = {}
    asn_numbers = _unique_strings(
        [
            *_string_values_for_keys(details, ("asn", "as_number", "number", "id")),
            *_string_list(item.get("asn_number")),
            *_string_list(item.get("as_number")),
        ]
    )
    asn_names = _unique_strings(
        [
            *_string_values_for_keys(
                details,
                ("as_name", "name", "org", "organization", "as_org", "description"),
            ),
            *_string_list(item.get("asn_name")),
            *_string_list(item.get("as_name")),
        ]
    )
    return asn_numbers, asn_names


def _httpx_tls_subject_names(item: dict[str, Any]) -> list[str]:
    tls = item.get("tls-grab") or item.get("tls_grab") or item.get("tls")
    if not isinstance(tls, dict):
        return []
    return _unique_strings(
        [
            *_string_values_for_keys(
                tls,
                (
                    "dns_names",
                    "subject_an",
                    "subject_alt_name",
                    "subjectAltName",
                    "subject_cn",
                    "subject_common_name",
                    "common_name",
                    "cn",
                ),
            ),
            *_string_values_for_keys(tls.get("subject_dn"), ("cn",)),
            *_string_values_for_keys(tls.get("subject"), ("cn", "common_name", "dns_names")),
        ]
    )


def _httpx_cdn_names(item: dict[str, Any]) -> list[str]:
    cdn_names = _unique_strings(
        [
            *_string_list(item.get("cdn_name")),
            *_string_list(item.get("cdn-name")),
            *_string_list(item.get("provider")),
        ]
    )
    if cdn_names:
        return cdn_names
    if bool(item.get("cdn")):
        return ["detected"]
    return []


def _parse_httpx(content: str) -> list[dict[str, Any]]:
    findings = []
    for item in _parse_json_lines(content):
        url = str(item.get("url") or item.get("final_url") or "")
        parsed = urlparse(url)
        path = parsed.path or str(item.get("path") or "/") or "/"
        port = _coerce_int(item.get("port")) or parsed.port
        if port is None:
            port = 80 if parsed.scheme == "http" else 443
        asn_numbers, asn_names = _httpx_asn_details(item)
        cdn_names = _httpx_cdn_names(item)
        findings.append(
            {
                "url": url,
                "host": str(item.get("host") or parsed.hostname or "").strip() or None,
                "scheme": str(item.get("scheme") or parsed.scheme or "").strip() or None,
                "port": port,
                "path": path if str(path).startswith("/") else f"/{path}",
                "status_code": item.get("status_code"),
                "title": item.get("title"),
                "webserver": item.get("webserver"),
                "tech": _string_list(item.get("tech") or []),
                "ip": _unique_strings(
                    [
                        *_string_list(item.get("ip")),
                        *_string_list(item.get("a")),
                        *_string_list(item.get("ips")),
                    ]
                ),
                "cname": _unique_strings(
                    [
                        *_string_list(item.get("cname")),
                        *_string_list(item.get("cnames")),
                    ]
                ),
                "asn": asn_numbers,
                "asn_name": asn_names,
                "provider": _unique_strings([*cdn_names, *asn_names])[:12],
                "cdn": cdn_names,
                "tls_subject_names": _httpx_tls_subject_names(item),
                "redirect_location": str(
                    item.get("location") or item.get("redirect_location") or ""
                ).strip()
                or None,
            }
        )
    return _dedupe_preserve_order(findings)


def _should_retry_httpx_with_basic_flags(execution: dict[str, Any], output_content: str) -> bool:
    if str(output_content or "").strip():
        return False
    if int(execution.get("exit_code") or 0) == 0:
        return False
    stderr = str(execution.get("stderr") or "").lower()
    return any(
        marker in stderr
        for marker in [
            "flag provided but not defined",
            "invalid argument",
            "no such option",
            "unknown flag",
            "unknown shorthand flag",
            "unknown option",
        ]
    )


def _parse_subfinder(content: str) -> list[dict[str, Any]]:
    findings = []
    for item in _parse_json_lines(content):
        host = str(item.get("host") or item.get("hostname") or "").strip()
        if not host:
            continue
        sources = item.get("sources") or item.get("source") or []
        if isinstance(sources, str):
            normalized_sources = [sources]
        elif isinstance(sources, list):
            normalized_sources = [str(source) for source in sources if str(source).strip()]
        else:
            normalized_sources = []
        findings.append(
            {
                "host": host,
                "input": str(item.get("input") or "").strip() or None,
                "sources": normalized_sources,
            }
        )
    return _dedupe_preserve_order(findings)


def _parse_naabu(content: str) -> list[dict[str, Any]]:
    findings = []
    for item in _parse_json_lines(content):
        host = str(item.get("host") or item.get("ip") or "").strip()
        port = item.get("port")
        if not host or port is None:
            continue
        findings.append(
            {
                "kind": "port",
                "host": host,
                "ip": str(item.get("ip") or "").strip() or None,
                "port": int(port),
                "protocol": str(item.get("protocol") or "tcp").strip() or "tcp",
            }
        )
    return _dedupe_preserve_order(findings)


def _parse_nmap(content: str) -> list[dict[str, Any]]:
    cleaned = content.strip()
    if not cleaned:
        return []
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        return []

    findings: list[dict[str, Any]] = []
    for host_node in root.findall("host"):
        status = host_node.find("status")
        if status is not None and status.attrib.get("state") == "down":
            continue

        address = host_node.find("address")
        hostname_node = host_node.find("hostnames/hostname")
        host = ""
        if hostname_node is not None:
            host = str(hostname_node.attrib.get("name") or "").strip()
        if not host and address is not None:
            host = str(address.attrib.get("addr") or "").strip()
        if not host:
            continue

        for port_node in host_node.findall("ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.attrib.get("state") != "open":
                continue

            port_value = port_node.attrib.get("portid")
            if not port_value:
                continue
            protocol = str(port_node.attrib.get("protocol") or "tcp").strip() or "tcp"
            service_node = port_node.find("service")
            service_name = ""
            if service_node is not None:
                parts = [
                    str(service_node.attrib.get("name") or "").strip(),
                    str(service_node.attrib.get("product") or "").strip(),
                    str(service_node.attrib.get("version") or "").strip(),
                ]
                service_name = " ".join(part for part in parts if part)
            findings.append(
                {
                    "kind": "port",
                    "host": host,
                    "port": int(port_value),
                    "protocol": protocol,
                    "service": service_name or None,
                }
            )

            for script_node in port_node.findall("script"):
                script_id = str(script_node.attrib.get("id") or "").strip()
                output = str(script_node.attrib.get("output") or "").strip()
                lowered = f"{script_id} {output}".lower()
                if not script_id:
                    continue
                if "vulnerable" not in lowered and "vuln" not in lowered and "default" not in lowered:
                    continue
                findings.append(
                    {
                        "kind": "script",
                        "host": host,
                        "port": int(port_value),
                        "protocol": protocol,
                        "script_id": script_id,
                        "message": output or script_id,
                        "severity": "high" if "vulnerable" in lowered or "vuln" in lowered else "normal",
                    }
                )
    return findings


def _parse_katana(content: str) -> list[dict[str, Any]]:
    findings = []
    for item in _parse_json_lines(content):
        url = str(item.get("url") or item.get("endpoint") or "")
        path = urlparse(url).path or "/"
        if not url:
            continue
        findings.append(
            {
                "url": url,
                "path": path,
                "source": item.get("source"),
                "method": item.get("method"),
            }
        )
    return findings


def _parse_nuclei(content: str) -> list[dict[str, Any]]:
    findings = []
    for item in _parse_json_lines(content):
        info = item.get("info") or {}
        severity = str(info.get("severity") or "medium").lower()
        findings.append(
            {
                "template_id": item.get("template-id"),
                "matched_at": item.get("matched-at"),
                "host": item.get("host"),
                "severity": severity,
                "name": info.get("name"),
                "tags": info.get("tags", []),
            }
        )
    return findings


def _parse_arjun(content: str) -> list[dict[str, Any]]:
    payload = _parse_json_payload(content)
    findings: list[dict[str, Any]] = []
    if payload is None:
        return findings

    def add_parameters(url: str, parameters: list[Any]) -> None:
        normalized_url = str(url).strip()
        path = urlparse(normalized_url).path or "/"
        for parameter in parameters:
            if isinstance(parameter, dict):
                name = str(
                    parameter.get("name")
                    or parameter.get("parameter")
                    or parameter.get("param")
                    or ""
                ).strip()
            else:
                name = str(parameter).strip()
            if not name:
                continue
            findings.append({"url": normalized_url, "path": path, "parameter": name})

    if isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(key, str) and key.startswith(("http://", "https://")) and isinstance(
                value, list
            ):
                add_parameters(key, value)

    for item in _iter_nested_dicts(payload):
        target_url = str(item.get("url") or item.get("endpoint") or item.get("target") or "").strip()
        parameters = item.get("params") or item.get("parameters") or item.get("stable_params")
        if target_url and isinstance(parameters, list):
            add_parameters(target_url, parameters)

    return _dedupe_preserve_order(findings)


def _parse_dirsearch(content: str) -> list[dict[str, Any]]:
    payload = _parse_json_payload(content)
    findings: list[dict[str, Any]] = []

    if payload is not None:
        for item in _iter_nested_dicts(payload):
            url = str(
                item.get("url")
                or item.get("target")
                or item.get("full_url")
                or item.get("uri")
                or ""
            ).strip()
            path = str(item.get("path") or "").strip()
            status_code = item.get("status") or item.get("status_code")
            if not url and not path:
                continue
            if not path and url:
                path = urlparse(url).path or "/"
            findings.append(
                {
                    "url": url,
                    "path": path or "/",
                    "status_code": status_code,
                    "length": item.get("content-length") or item.get("length"),
                }
            )
        return _dedupe_preserve_order(findings)

    for line in content.splitlines():
        match = re.search(
            r"(?P<status>\d{3})\s+[-|]\s+.*?(?P<path>/\S+)",
            line.strip(),
        )
        if not match:
            continue
        findings.append(
            {
                "url": "",
                "path": match.group("path"),
                "status_code": int(match.group("status")),
            }
        )
    return _dedupe_preserve_order(findings)


def _parse_wapiti(content: str) -> list[dict[str, Any]]:
    payload = _parse_json_payload(content)
    if not isinstance(payload, dict):
        return []

    findings: list[dict[str, Any]] = []
    vulnerability_groups = payload.get("vulnerabilities") or {}
    if isinstance(vulnerability_groups, dict):
        for category, items in vulnerability_groups.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                target_url = str(
                    item.get("url")
                    or item.get("path")
                    or item.get("request")
                    or item.get("target")
                    or ""
                ).strip()
                path = urlparse(target_url).path or str(item.get("path") or "/")
                findings.append(
                    {
                        "url": target_url,
                        "path": path or "/",
                        "name": str(category),
                        "parameter": str(item.get("parameter") or item.get("param") or "").strip() or None,
                        "message": str(
                            item.get("info")
                            or item.get("details")
                            or item.get("message")
                            or item.get("evil_request")
                            or ""
                        ).strip()
                        or None,
                        "severity": str(item.get("level") or item.get("severity") or "medium").lower(),
                    }
                )

    return _dedupe_preserve_order(findings)


def _parse_ffuf(content: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return []
    findings = []
    for item in payload.get("results", []):
        url = str(item.get("url") or "")
        findings.append(
            {
                "url": url,
                "path": urlparse(url).path or "/",
                "status_code": item.get("status"),
                "length": item.get("length"),
                "words": item.get("words"),
            }
        )
    return findings


def _parse_bandit(content: str) -> list[dict[str, Any]]:
    payload = _parse_json_payload(content)
    if not isinstance(payload, dict):
        return []

    findings = []
    for item in payload.get("results", []):
        findings.append(
            {
                "check_id": item.get("test_id"),
                "path": item.get("filename"),
                "message": item.get("issue_text"),
                "severity": str(item.get("issue_severity") or "medium").lower(),
                "confidence": str(item.get("issue_confidence") or "medium").lower(),
                "line": item.get("line_number"),
            }
        )
    return findings


def _parse_semgrep(content: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return []
    findings = []
    for item in payload.get("results", []):
        extra = item.get("extra") or {}
        findings.append(
            {
                "check_id": item.get("check_id"),
                "path": item.get("path"),
                "message": extra.get("message"),
                "severity": str(extra.get("severity") or "medium").lower(),
                "line": (item.get("start") or {}).get("line"),
            }
        )
    return findings


def _extract_file_path(value: Any) -> str | None:
    candidates: list[str] = []
    for item in _iter_nested_dicts(value):
        for key, entry in item.items():
            if not isinstance(entry, str):
                continue
            lowered = str(key).lower()
            if lowered in {"path", "file", "filepath", "fullpath", "filename", "fullfilepath"}:
                candidates.append(entry)
    for candidate in candidates:
        normalized = candidate.strip()
        if normalized:
            return normalized
    return None


def _parse_trufflehog(content: str) -> list[dict[str, Any]]:
    records = _parse_json_lines(content)
    payload = _parse_json_payload(content)
    if isinstance(payload, list):
        records.extend(item for item in payload if isinstance(item, dict))
    elif isinstance(payload, dict):
        records.append(payload)

    findings = []
    for item in records:
        detector = str(
            item.get("DetectorName") or item.get("DetectorType") or item.get("SourceType") or ""
        ).strip()
        path = _extract_file_path(item) or "<unknown>"
        redacted = str(item.get("Redacted") or "").strip()
        if not detector and not redacted:
            continue
        findings.append(
            {
                "path": path,
                "detector": detector or "secret-detector",
                "verified": bool(item.get("Verified")),
                "message": redacted or "Potential secret exposure",
                "severity": "high" if item.get("Verified") else "medium",
            }
        )
    return _dedupe_preserve_order(findings)


def _parse_trivy(content: str) -> list[dict[str, Any]]:
    payload = _parse_json_payload(content)
    if not isinstance(payload, dict):
        return []

    findings: list[dict[str, Any]] = []
    for result in payload.get("Results", []):
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "<unknown>").strip()
        finding_class = str(result.get("Class") or result.get("Type") or "").strip().lower()

        for vulnerability in result.get("Vulnerabilities", []) or []:
            if not isinstance(vulnerability, dict):
                continue
            findings.append(
                {
                    "finding_id": str(vulnerability.get("VulnerabilityID") or "").strip() or None,
                    "path": target,
                    "name": str(
                        vulnerability.get("Title")
                        or vulnerability.get("PkgName")
                        or vulnerability.get("PrimaryURL")
                        or ""
                    ).strip()
                    or None,
                    "message": str(
                        vulnerability.get("Description")
                        or vulnerability.get("Title")
                        or vulnerability.get("PrimaryURL")
                        or ""
                    ).strip()
                    or None,
                    "severity": str(vulnerability.get("Severity") or "medium").lower(),
                    "finding_class": "vulnerability",
                    "package_name": str(vulnerability.get("PkgName") or "").strip() or None,
                }
            )

        for misconfiguration in result.get("Misconfigurations", []) or []:
            if not isinstance(misconfiguration, dict):
                continue
            findings.append(
                {
                    "finding_id": str(misconfiguration.get("ID") or "").strip() or None,
                    "path": target,
                    "name": str(
                        misconfiguration.get("Title")
                        or misconfiguration.get("Type")
                        or ""
                    ).strip()
                    or None,
                    "message": str(
                        misconfiguration.get("Description")
                        or misconfiguration.get("Message")
                        or misconfiguration.get("Resolution")
                        or ""
                    ).strip()
                    or None,
                    "severity": str(misconfiguration.get("Severity") or "medium").lower(),
                    "finding_class": "misconfig",
                }
            )

        for secret in result.get("Secrets", []) or []:
            if not isinstance(secret, dict):
                continue
            findings.append(
                {
                    "finding_id": str(secret.get("RuleID") or secret.get("Category") or "").strip()
                    or None,
                    "path": target,
                    "name": str(secret.get("Title") or secret.get("Category") or "").strip() or None,
                    "message": str(secret.get("Match") or secret.get("Title") or "").strip() or None,
                    "severity": str(secret.get("Severity") or "high").lower(),
                    "finding_class": "secret",
                }
            )

    return _dedupe_preserve_order(findings)


def _parse_jwt_tool(content: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw_line in content.splitlines():
        line = raw_line.strip()
        lowered = line.lower()
        if not line:
            continue
        for keyword, name, severity in JWT_FINDING_PATTERNS:
            if keyword not in lowered:
                continue
            key = (name, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "name": name,
                    "message": _truncate(line, 220),
                    "severity": severity,
                }
            )
            break
    return findings


def _parse_wafw00f(content: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    payload = _parse_json_payload(content)
    if isinstance(payload, dict):
        records.append(payload)
        records.extend(_iter_nested_dicts(payload))
    elif isinstance(payload, list):
        records.extend(item for item in payload if isinstance(item, dict))

    findings: list[dict[str, Any]] = []
    for item in records:
        detected = item.get("detected")
        if detected is False:
            continue
        name = str(
            item.get("firewall")
            or item.get("waf")
            or item.get("name")
            or item.get("product")
            or ""
        ).strip()
        manufacturer = str(item.get("manufacturer") or item.get("vendor") or "").strip() or None
        url = str(item.get("url") or item.get("target") or item.get("site") or "").strip() or None
        if not name and not manufacturer:
            continue
        findings.append(
            {
                "url": url,
                "name": name or "unknown-waf",
                "manufacturer": manufacturer,
                "severity": "info",
            }
        )

    if findings:
        return _dedupe_preserve_order(findings)

    for raw_line in content.splitlines():
        line = raw_line.strip()
        match = re.search(
            r"(?P<url>https?://\S+).*?behind (?P<name>.+?)(?: WAF|$)",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        findings.append(
            {
                "url": match.group("url"),
                "name": match.group("name").strip(),
                "manufacturer": None,
                "severity": "info",
            }
        )
    return _dedupe_preserve_order(findings)


def _parse_zaproxy(content: str) -> list[dict[str, Any]]:
    payload = _parse_json_payload(content)
    if not isinstance(payload, dict):
        return []

    findings: list[dict[str, Any]] = []
    for site in payload.get("site", []):
        if not isinstance(site, dict):
            continue
        site_name = str(site.get("@name") or site.get("name") or "").strip()
        for alert in site.get("alerts", []):
            if not isinstance(alert, dict):
                continue
            alert_name = str(alert.get("alert") or alert.get("name") or "").strip()
            riskcode = str(alert.get("riskcode") or alert.get("risk") or "").strip()
            severity = {
                "3": "critical",
                "2": "high",
                "1": "medium",
                "0": "low",
            }.get(riskcode, str(alert.get("riskdesc") or "medium").split(" ", 1)[0].lower())
            instances = alert.get("instances") or []
            if not isinstance(instances, list) or not instances:
                findings.append(
                    {
                        "url": site_name,
                        "path": urlparse(site_name).path or "/",
                        "name": alert_name or "unknown-alert",
                        "parameter": None,
                        "message": str(alert.get("desc") or "").strip() or None,
                        "severity": severity,
                    }
                )
                continue

            for instance in instances:
                if not isinstance(instance, dict):
                    continue
                target_url = str(
                    instance.get("uri")
                    or instance.get("url")
                    or instance.get("endpoint")
                    or site_name
                ).strip()
                findings.append(
                    {
                        "url": target_url,
                        "path": urlparse(target_url).path or "/",
                        "name": alert_name or "unknown-alert",
                        "parameter": str(instance.get("param") or "").strip() or None,
                        "message": str(alert.get("desc") or instance.get("attack") or "").strip() or None,
                        "severity": severity,
                    }
                )

    return _dedupe_preserve_order(findings)


def _parse_sqlmap(stdout: str) -> list[dict[str, Any]]:
    findings = []
    vulnerable = re.findall(
        r"Parameter: (?P<parameter>.+?) .*? is vulnerable",
        stdout,
        re.IGNORECASE | re.DOTALL,
    )
    if vulnerable:
        for parameter in vulnerable:
            findings.append(
                {
                    "parameter": " ".join(parameter.split())[:120],
                    "severity": "high",
                    "message": "sqlmap reported injectable parameter",
                }
            )
    elif "is vulnerable" in stdout.lower():
        findings.append(
            {
                "parameter": "<unknown>",
                "severity": "high",
                "message": "sqlmap reported injectable surface",
            }
        )
    return findings


@register_tool(sandbox_execution=False)
def security_tool_doctor(
    agent_state: Any,
    tool_names: list[str] | None = None,
) -> dict[str, Any]:
    try:
        root_agent_id, _ = _get_tool_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        normalized_tools = [
            _normalize_tool_name(tool_name)
            for tool_name in (
                tool_names if tool_names is not None else sorted(SUPPORTED_SECURITY_TOOLS)
            )
        ]
        diagnostics: list[dict[str, Any]] = []
        for tool_name in normalized_tools:
            executable = _resolve_tool_executable(tool_name)
            version_output = None
            compatible = executable is not None
            compatibility_reason = None
            probe_exit_code = None
            if executable is not None:
                version_result = _execute_tool_command(
                    _version_probe_command(tool_name, executable),
                    timeout=5,
                )
                probe_exit_code = version_result.get("exit_code")
                version_output = _truncate(
                    str(version_result.get("stdout") or version_result.get("stderr") or "").strip(),
                    200,
                ) or None
                compatibility_reason = _tool_incompatibility_reason(
                    tool_name,
                    "\n".join(
                        [
                            str(version_result.get("stdout") or ""),
                            str(version_result.get("stderr") or ""),
                        ]
                    ),
                    exit_code=int(version_result.get("exit_code") or 0),
                )
                compatible = compatibility_reason is None

            diagnostics.append(
                {
                    "tool_name": tool_name,
                    "available": executable is not None and compatible,
                    "executable": executable,
                    "version_output": version_output,
                    "compatible": compatible,
                    "compatibility_reason": compatibility_reason,
                    "probe_exit_code": probe_exit_code,
                    "recommended_usage": (
                        "Use run_security_tool_scan so results are normalized into the assessment ledger"
                        if executable is not None and compatible
                        else (
                            "Point PATH at the intended tool binary; the current executable appears incompatible"
                            if executable is not None
                            else "Install or expose this executable on PATH before relying on it"
                        )
                    ),
                }
            )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to run security tool doctor: {e}"}
    else:
        return {
            "success": True,
            "root_agent_id": root_agent_id,
            "available_count": sum(1 for item in diagnostics if item["available"]),
            "tool_count": len(diagnostics),
            "tools": diagnostics,
        }


def _normalize_pipeline_mode(mode: str) -> str:
    normalized = str(mode).strip().lower()
    if normalized not in {"blackbox", "repo", "hybrid"}:
        raise ValueError("mode must be one of: blackbox, repo, hybrid")
    return normalized


def _append_pipeline_step(
    steps: list[dict[str, Any]],
    *,
    step_name: str,
    result: dict[str, Any],
    metadata: dict[str, Any] | None = None,
) -> None:
    steps.append(
        {
            "step": step_name,
            "success": bool(result.get("success")),
            "tool_name": result.get("tool_name"),
            "run_id": result.get("run_id"),
            "finding_count": int(result.get("finding_count") or 0),
            "discovery_seed_count": int(result.get("discovery_seed_count") or 0),
            "hypothesis_seed_count": int(result.get("hypothesis_seed_count") or 0),
            "error": result.get("error"),
            "metadata": metadata or {},
        }
    )


def _execute_or_reuse_tool_scan(
    agent_state: Any,
    *,
    store: dict[str, TOOL_RUN],
    reuse_previous_runs: bool,
    tool_name: str,
    target: str,
    include_findings: bool = False,
    **scan_kwargs: Any,
) -> dict[str, Any]:
    logical_component = str(scan_kwargs.get("component") or f"toolchain:{tool_name}")
    normalized_targets = _normalize_targets(scan_kwargs.get("targets"))
    normalized_paths = _normalize_paths(scan_kwargs.get("paths"))
    normalized_headers = _normalize_headers(scan_kwargs.get("headers"))
    normalized_configs = [
        str(item).strip() for item in (scan_kwargs.get("configs") or []) if str(item).strip()
    ]
    normalized_tags = [
        str(item).strip() for item in (scan_kwargs.get("tags") or []) if str(item).strip()
    ]
    normalized_severities = [
        str(item).strip() for item in (scan_kwargs.get("severities") or []) if str(item).strip()
    ]
    scope_payload = _build_scope_payload(
        tool_name=tool_name,
        target=target,
        component=logical_component,
        targets=normalized_targets,
        target_path=scan_kwargs.get("target_path"),
        url=scan_kwargs.get("url"),
        raw_request_path=scan_kwargs.get("raw_request_path"),
        paths=normalized_paths,
        headers=normalized_headers,
        data=scan_kwargs.get("data"),
        request_method=str(scan_kwargs.get("request_method") or "GET").strip().upper() or "GET",
        ports=scan_kwargs.get("ports"),
        top_ports=scan_kwargs.get("top_ports"),
        parameter=scan_kwargs.get("parameter"),
        configs=normalized_configs,
        tags=normalized_tags,
        severities=normalized_severities,
        automatic_scan=bool(scan_kwargs.get("automatic_scan", False)),
        active_only=bool(scan_kwargs.get("active_only", False)),
        collect_sources=bool(scan_kwargs.get("collect_sources", False)),
        no_interactsh=bool(scan_kwargs.get("no_interactsh", False)),
        use_js_crawl=bool(scan_kwargs.get("use_js_crawl", True)),
        headless=bool(scan_kwargs.get("headless", False)),
        known_files=str(scan_kwargs.get("known_files") or "robotstxt"),
        recursion=bool(scan_kwargs.get("recursion", False)),
        recursion_depth=int(scan_kwargs.get("recursion_depth") or 2),
        scan_type=scan_kwargs.get("scan_type"),
        service_detection=bool(scan_kwargs.get("service_detection", False)),
        default_scripts=bool(scan_kwargs.get("default_scripts", False)),
        flush_session=bool(scan_kwargs.get("flush_session", False)),
        level=int(scan_kwargs.get("level") or 2),
        risk=int(scan_kwargs.get("risk") or 1),
        zapit=bool(scan_kwargs.get("zapit", False)),
        jwt_token=(
            str(scan_kwargs.get("jwt_token")).strip()
            if scan_kwargs.get("jwt_token") is not None
            else None
        ),
        canary_value=(
            str(scan_kwargs.get("canary_value")).strip()
            if scan_kwargs.get("canary_value") is not None
            else None
        ),
        public_key_path=(
            str(scan_kwargs.get("public_key_path")).strip()
            if scan_kwargs.get("public_key_path") is not None
            else None
        ),
        dictionary_path=(
            str(scan_kwargs.get("dictionary_path")).strip()
            if scan_kwargs.get("dictionary_path") is not None
            else None
        ),
    )
    current_scope_key = _scope_key(scope_payload)
    if reuse_previous_runs:
        existing = _reusable_tool_run(
            store,
            tool_name=tool_name,
            target=target,
            scope_key=current_scope_key,
        )
        if existing is not None:
            return _tool_run_response(existing, include_findings=include_findings)

    return run_security_tool_scan(
        agent_state=agent_state,
        tool_name=tool_name,
        target=target,
        include_findings=include_findings,
        **scan_kwargs,
    )


def _attack_surface_review_scope_targets(*groups: list[str]) -> list[str]:
    scope_targets: list[str] = []
    for group in groups:
        for item in group:
            candidate = str(item).strip()
            if candidate:
                scope_targets.append(candidate)
    return _unique_strings(scope_targets)


def _attack_surface_review_snapshot(result: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(result, dict):
        return None

    snapshot: dict[str, Any] = {"success": bool(result.get("success"))}
    if not result.get("success"):
        snapshot["error"] = result.get("error")
        return snapshot

    report = result.get("report") if isinstance(result.get("report"), dict) else {}
    priorities = report.get("priorities") if isinstance(report.get("priorities"), dict) else {}
    snapshot["target"] = result.get("target")
    snapshot["summary"] = dict(report.get("summary") or {})
    snapshot["top_targets_next"] = list(priorities.get("top_targets_next") or [])[:5]
    snapshot["top_endpoints_next"] = list(priorities.get("top_endpoints_next") or [])[:5]
    snapshot["top_blind_spots"] = list(priorities.get("top_blind_spots") or [])[:5]
    return snapshot


def _build_pipeline_attack_surface_review(
    agent_state: Any,
    *,
    target: str,
    scope_targets: list[str],
    max_priorities: int,
) -> dict[str, Any]:
    from .assessment_surface_review_actions import build_attack_surface_review

    return build_attack_surface_review(
        agent_state=agent_state,
        target=target,
        scope_targets=scope_targets or None,
        max_priorities=max_priorities,
    )


def _persist_pipeline_attack_surface_review(
    agent_state: Any,
    result: dict[str, Any] | None,
) -> None:
    if not isinstance(result, dict) or not result.get("success"):
        return
    target = str(result.get("target") or "").strip()
    report = result.get("report")
    if not target or not isinstance(report, dict):
        return

    from . import assessment_surface_review_actions as surface_review_actions

    root_agent_id, store = surface_review_actions._get_surface_review_store(agent_state)
    surface_review_actions._update_agent_context(agent_state, root_agent_id)
    store[target] = {
        "target": target,
        "updated_at": _utc_now(),
        "report": report,
    }


def _pipeline_review_agent_limit(max_active_targets: int) -> int:
    return max(6, min(10, (max_active_targets * 2) + 2))


def _pipeline_signal_agent_limit(max_active_targets: int) -> int:
    return max(2, min(4, max_active_targets + 1))


def _pipeline_impact_agent_limit(max_active_targets: int) -> int:
    return max(1, min(3, max_active_targets))


def _spawn_pipeline_attack_surface_agents(
    agent_state: Any,
    *,
    target: str,
    max_active_targets: int,
    strategy: str,
) -> dict[str, Any]:
    from .assessment_orchestration_actions import spawn_attack_surface_agents

    return spawn_attack_surface_agents(
        agent_state=agent_state,
        target=target,
        max_agents=_pipeline_review_agent_limit(max_active_targets),
        strategy=strategy,
        inherit_context=True,
    )


def _spawn_pipeline_strong_signal_agents(
    agent_state: Any,
    *,
    target: str,
    max_active_targets: int,
) -> dict[str, Any]:
    from .assessment_orchestration_actions import spawn_strong_signal_agents

    return spawn_strong_signal_agents(
        agent_state=agent_state,
        target=target,
        max_agents=_pipeline_signal_agent_limit(max_active_targets),
        inherit_context=True,
    )


def _spawn_pipeline_impact_chain_agents(
    agent_state: Any,
    *,
    target: str,
    max_active_targets: int,
) -> dict[str, Any]:
    from .assessment_orchestration_actions import spawn_impact_chain_agents

    return spawn_impact_chain_agents(
        agent_state=agent_state,
        target=target,
        max_agents=_pipeline_impact_agent_limit(max_active_targets),
        inherit_context=True,
    )


def _sqlmap_candidate_url(url: str, parameter_name: str) -> str:
    parsed = urlparse(url)
    existing_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if parameter_name and not any(key == parameter_name for key, _ in existing_pairs):
        existing_pairs.append((parameter_name, "1"))
    if not existing_pairs and parameter_name:
        existing_pairs = [(parameter_name, "1")]
    updated_query = urlencode(existing_pairs, doseq=True)
    return urlunparse(parsed._replace(query=updated_query))


def _query_parameter_value(url: str, parameter_name: str) -> str | None:
    for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if key == parameter_name:
            return value
    return None


def _merge_query_params_into_url(url: str, params: dict[str, str]) -> str:
    if not params:
        return url
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    existing = {key for key, _ in pairs}
    for key, value in params.items():
        if key not in existing:
            pairs.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))


def _load_runtime_inventory_entries(agent_state: Any, target: str) -> list[dict[str, Any]]:
    try:
        from .assessment_runtime_actions import list_runtime_inventory

        result = list_runtime_inventory(
            agent_state=agent_state,
            target=target,
            include_inventory=True,
            max_items=1,
        )
    except Exception:  # noqa: BLE001
        return []

    if not result.get("success"):
        return []
    records = list(result.get("records") or [])
    if not records:
        return []
    record = records[0]
    inventory = record.get("inventory") or record.get("selected_inventory") or []
    return [item for item in inventory if isinstance(item, dict)]


def _load_discovered_workflows(agent_state: Any, target: str) -> list[dict[str, Any]]:
    try:
        from .assessment_workflow_actions import list_discovered_workflows

        result = list_discovered_workflows(
            agent_state=agent_state,
            target=target,
            include_workflows=True,
            max_items=1,
        )
    except Exception:  # noqa: BLE001
        return []

    if not result.get("success"):
        return []
    records = list(result.get("records") or [])
    if not records:
        return []
    workflows = records[0].get("workflows") or records[0].get("selected_workflows") or []
    return [item for item in workflows if isinstance(item, dict)]


def _load_mined_surface_artifacts(agent_state: Any, target: str) -> list[dict[str, Any]]:
    try:
        from .assessment_surface_actions import list_mined_attack_surface

        result = list_mined_attack_surface(
            agent_state=agent_state,
            target=target,
            include_artifacts=True,
            max_items=1,
        )
    except Exception:  # noqa: BLE001
        return []

    if not result.get("success"):
        return []
    records = list(result.get("records") or [])
    if not records:
        return []
    artifacts = records[0].get("artifacts") or records[0].get("selected_artifacts") or []
    return [item for item in artifacts if isinstance(item, dict)]


def _load_session_profiles(agent_state: Any) -> list[dict[str, Any]]:
    try:
        from .assessment_session_actions import list_session_profiles

        result = list_session_profiles(
            agent_state=agent_state,
            include_values=True,
            max_items=25,
        )
    except Exception:  # noqa: BLE001
        return []

    if not result.get("success"):
        return []
    return [item for item in list(result.get("profiles") or []) if isinstance(item, dict)]


def _get_focus_proxy_manager() -> Any | None:
    try:
        from .assessment_session_actions import get_proxy_manager

        return get_proxy_manager()
    except Exception:  # noqa: BLE001
        return None


def _get_focus_browser_manager() -> Any | None:
    try:
        from strix.tools.browser.tab_manager import get_browser_tab_manager

        return get_browser_tab_manager()
    except Exception:  # noqa: BLE001
        return None


def _candidate_urls_from_runtime_entries(runtime_entries: list[dict[str, Any]]) -> list[str]:
    candidate_urls: list[str] = []
    for entry in runtime_entries:
        if not isinstance(entry, dict):
            continue
        for sample_url in list(entry.get("sample_urls") or []):
            candidate = str(sample_url).strip()
            if _is_http_url(candidate):
                candidate_urls.append(candidate)
        host = str(entry.get("host") or "").strip()
        path = str(entry.get("normalized_path") or "").strip()
        if host and path:
            candidate_urls.append(f"https://{host}{path}")
    return _unique_strings(candidate_urls)


def _candidate_urls_from_surface_artifacts(surface_artifacts: list[dict[str, Any]]) -> list[str]:
    candidate_urls: list[str] = []
    for artifact in surface_artifacts:
        if not isinstance(artifact, dict):
            continue
        kind = str(artifact.get("kind") or "").strip().lower()
        if kind == "websocket_endpoint":
            continue
        host = str(artifact.get("host") or "").strip()
        path = str(artifact.get("path") or "").strip()
        if host and path:
            candidate_urls.append(f"https://{host}{path}")
    return _unique_strings(candidate_urls)


def _run_inventory_enrichment(
    agent_state: Any,
    *,
    target: str,
    steps: list[dict[str, Any]],
    max_seed_items: int,
    max_hypotheses: int,
    include_workflows: bool,
) -> dict[str, Any]:
    from .assessment_runtime_actions import map_runtime_surface
    from .assessment_surface_actions import mine_additional_attack_surface
    from .assessment_workflow_actions import discover_workflows_from_requests

    runtime_entries = _load_runtime_inventory_entries(agent_state, target)
    surface_artifacts = _load_mined_surface_artifacts(agent_state, target)
    workflows = _load_discovered_workflows(agent_state, target)
    proxy_manager = _get_focus_proxy_manager()

    runtime_result = None
    surface_result = None
    workflow_result = None
    if proxy_manager is None:
        return {
            "runtime_entries": runtime_entries,
            "surface_artifacts": surface_artifacts,
            "workflows": workflows,
            "runtime_result": runtime_result,
            "surface_result": surface_result,
            "workflow_result": workflow_result,
        }

    enrichment_seed_cap = max(max_seed_items, max_hypotheses * 2, 20)
    if not runtime_entries:
        try:
            runtime_result = map_runtime_surface(
                agent_state=agent_state,
                target=target,
                max_seed_items=enrichment_seed_cap,
            )
        except Exception as e:  # noqa: BLE001
            runtime_result = {
                "success": False,
                "error": f"Failed to map runtime surface during enrichment: {e}",
            }
        _append_pipeline_step(
            steps,
            step_name="map_runtime_surface",
            result=runtime_result,
            metadata={"source": "inventory_enrichment"},
        )
        if runtime_result.get("success"):
            runtime_entries = _load_runtime_inventory_entries(agent_state, target)

    if not surface_artifacts:
        try:
            surface_result = mine_additional_attack_surface(
                agent_state=agent_state,
                target=target,
                max_seed_items=enrichment_seed_cap,
            )
        except Exception as e:  # noqa: BLE001
            surface_result = {
                "success": False,
                "error": f"Failed to mine additional attack surface during enrichment: {e}",
            }
        _append_pipeline_step(
            steps,
            step_name="mine_additional_attack_surface",
            result=surface_result,
            metadata={"source": "inventory_enrichment"},
        )
        if surface_result.get("success"):
            surface_artifacts = _load_mined_surface_artifacts(agent_state, target)

    if include_workflows and not workflows:
        try:
            workflow_result = discover_workflows_from_requests(
                agent_state=agent_state,
                target=target,
                max_workflows=max(4, max_hypotheses),
            )
        except Exception as e:  # noqa: BLE001
            workflow_result = {
                "success": False,
                "error": f"Failed to discover workflows during enrichment: {e}",
            }
        _append_pipeline_step(
            steps,
            step_name="discover_workflows_from_requests",
            result=workflow_result,
            metadata={"source": "inventory_enrichment"},
        )
        if workflow_result.get("success"):
            workflows = _load_discovered_workflows(agent_state, target)

    return {
        "runtime_entries": runtime_entries,
        "surface_artifacts": surface_artifacts,
        "workflows": workflows,
        "runtime_result": runtime_result,
        "surface_result": surface_result,
        "workflow_result": workflow_result,
    }


def _read_code_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _iter_focus_source_files(root: Path) -> list[Path]:
    source_files: list[Path] = []
    if root.is_file():
        return [root] if root.suffix.lower() in CODE_SCAN_EXTENSIONS else []

    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [item for item in dirnames if item not in CODE_SCAN_IGNORED_DIRS]
        for filename in filenames:
            path = Path(current_root) / filename
            if path.suffix.lower() not in CODE_SCAN_EXTENSIONS:
                continue
            source_files.append(path)
    return source_files


def _relative_code_path(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return path.name


def _focus_source_keywords(focus: str) -> list[str]:
    return list(FOCUS_SOURCE_HINTS.get(focus, FOCUS_PARAMETER_HINTS.get(focus, [])))


def _ast_name_chain(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _ast_name_chain(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _ast_name_chain(node.func)
    if isinstance(node, ast.Subscript):
        return _ast_name_chain(node.value)
    return ""


def _ast_string_literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _ast_route_decorator_info(decorator: ast.AST) -> tuple[str | None, str | None]:
    if not isinstance(decorator, ast.Call):
        return None, None
    callee = _ast_name_chain(decorator.func).split(".")[-1].lower()
    route_method = {
        "get": "GET",
        "post": "POST",
        "put": "PUT",
        "patch": "PATCH",
        "delete": "DELETE",
        "api_route": "ANY",
        "route": "ANY",
    }.get(callee)
    if route_method is None:
        return None, None
    if decorator.args:
        path = _ast_string_literal(decorator.args[0])
    else:
        path = None
        for keyword in decorator.keywords:
            if str(keyword.arg or "") in {"path", "url"}:
                path = _ast_string_literal(keyword.value)
                break
    return route_method, path


def _ast_source_text(node: ast.AST, content: str) -> str:
    segment = ast.get_source_segment(content, node)
    if segment:
        return str(segment)
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001
        return ""


def _python_focus_scopes(content: str, focus: str) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    source_keywords = _focus_source_keywords(focus)
    scopes: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        route_methods: list[str] = []
        route_paths: list[str] = []
        for decorator in node.decorator_list:
            route_method, route_path = _ast_route_decorator_info(decorator)
            if route_method and route_method not in route_methods:
                route_methods.append(route_method)
            if route_path and route_path not in route_paths:
                route_paths.append(route_path)

        parameters: list[str] = []
        source_parameters: list[str] = []
        tainted_names: set[str] = set()
        for parameter in [
            *list(node.args.posonlyargs),
            *list(node.args.args),
            *list(node.args.kwonlyargs),
        ]:
            name = str(parameter.arg or "").strip()
            if not name or name == "self":
                continue
            parameters.append(name)
            annotation_text = _ast_name_chain(parameter.annotation).lower()
            lowered_name = name.lower()
            if any(keyword in lowered_name for keyword in source_keywords) or any(
                marker in annotation_text
                for marker in [
                    "uploadfile",
                    "request",
                    "file",
                    "body",
                    "form",
                    "query",
                    "path",
                ]
            ):
                tainted_names.add(name)
                source_parameters.append(name)

        body_nodes = list(ast.walk(node))
        body_nodes.sort(key=lambda item: (int(getattr(item, "lineno", 0) or 0), int(getattr(item, "col_offset", 0) or 0)))

        for child in body_nodes:
            targets: list[str] = []
            value_node: ast.AST | None = None
            if isinstance(child, ast.Assign):
                value_node = child.value
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        targets.append(target.id)
            elif isinstance(child, ast.AnnAssign):
                value_node = child.value
                if isinstance(child.target, ast.Name):
                    targets.append(child.target.id)
            if not value_node or not targets:
                continue

            value_text = _ast_source_text(value_node, content).lower()
            source_like = any(name.lower() in value_text for name in tainted_names) or (
                any(marker in value_text for marker in GENERIC_REQUEST_SOURCE_MARKERS)
                and any(keyword in value_text for keyword in source_keywords)
            )
            if not source_like:
                continue
            for target_name in targets:
                tainted_names.add(target_name)

        scopes.append(
            {
                "function_name": node.name,
                "start_line": int(getattr(node, "lineno", 0) or 0),
                "end_line": int(getattr(node, "end_lineno", getattr(node, "lineno", 0)) or 0),
                "parameters": parameters,
                "source_parameters": source_parameters,
                "tainted_names": sorted(tainted_names),
                "route_methods": route_methods,
                "route_paths": route_paths,
            }
        )

    return scopes


def _scope_for_line(scopes: list[dict[str, Any]], line_number: int) -> dict[str, Any] | None:
    matched: dict[str, Any] | None = None
    for scope in scopes:
        if int(scope.get("start_line") or 0) <= line_number <= int(scope.get("end_line") or 0):
            if matched is None or int(scope.get("start_line") or 0) >= int(matched.get("start_line") or 0):
                matched = scope
    return matched


def _discover_focus_code_sinks(
    agent_state: Any,
    *,
    target: str,
    focus: str,
    target_path: str,
    max_items: int,
) -> dict[str, Any]:
    normalized_focus = _normalize_focus_pipeline_name(focus)
    root = Path(str(target_path)).expanduser()
    if not root.exists():
        raise ValueError(f"target_path '{target_path}' does not exist")

    patterns = list(FOCUS_CODE_SINK_PATTERNS.get(normalized_focus, []))
    if not patterns:
        return {
            "success": True,
            "tool_name": "whitebox_sink_discovery",
            "focus": normalized_focus,
            "finding_count": 0,
            "findings": [],
            "public_path_hints": [],
        }

    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, int, str]] = set()
    public_path_hints: list[str] = []
    seen_path_hints: set[str] = set()

    for file_path in _iter_focus_source_files(root):
        content = _read_code_text(file_path)
        if not content:
            continue
        relative_path = _relative_code_path(root, file_path)
        python_scopes = (
            _python_focus_scopes(content, normalized_focus)
            if file_path.suffix.lower() == ".py"
            else []
        )
        for line_number, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            for pattern in patterns:
                match = re.search(str(pattern["regex"]), line, flags=re.IGNORECASE)
                if not match:
                    continue
                kind = str(pattern["kind"])
                finding_key = (relative_path, line_number, kind)
                if finding_key in seen_findings:
                    continue
                seen_findings.add(finding_key)
                finding = {
                    "path": relative_path,
                    "line": line_number,
                    "kind": kind,
                    "summary": str(pattern["summary"]),
                    "priority": str(pattern["priority"]),
                    "line_text": stripped[:240],
                }
                scope = _scope_for_line(python_scopes, line_number)
                if scope is not None:
                    tainted_hits = [
                        name
                        for name in list(scope.get("tainted_names") or [])
                        if re.search(rf"\b{re.escape(str(name))}\b", stripped)
                    ]
                    if scope.get("function_name"):
                        finding["function_name"] = scope.get("function_name")
                    if scope.get("route_paths"):
                        finding["route_paths"] = list(scope.get("route_paths") or [])
                    if scope.get("route_methods"):
                        finding["route_methods"] = list(scope.get("route_methods") or [])
                    if scope.get("source_parameters"):
                        finding["source_parameters"] = list(scope.get("source_parameters") or [])
                    if tainted_hits:
                        finding["tainted_symbols"] = tainted_hits
                        finding["source_to_sink"] = True
                        if finding["priority"] == "high":
                            finding["priority"] = "critical"
                findings.append(finding)
                path_hint_group = pattern.get("path_hint_group")
                if path_hint_group:
                    try:
                        raw_hint = str(match.group(int(path_hint_group))).strip()
                    except (IndexError, ValueError):
                        raw_hint = ""
                    if raw_hint and raw_hint not in seen_path_hints:
                        seen_path_hints.add(raw_hint)
                        public_path_hints.append(raw_hint)

    findings.sort(
        key=lambda item: (
            -SINK_PRIORITY_RANK.get(str(item.get("priority") or "low"), 0),
            str(item.get("path") or ""),
            int(item.get("line") or 0),
        )
    )
    selected_findings = findings[:max(1, max_items)]

    coverage_result = None
    hypothesis_result = None
    evidence_result = None
    if selected_findings:
        highest_priority = str(selected_findings[0].get("priority") or "high")
        sink_names = ", ".join(
            sorted({str(item.get("kind") or "") for item in selected_findings[:5] if str(item.get("kind") or "")})
        )
        coverage_result = record_coverage(
            agent_state=agent_state,
            target=target,
            component=f"whitebox:{normalized_focus}",
            surface=f"Whitebox sink discovery for {normalized_focus} under {root.name}",
            status="in_progress",
            rationale=(
                f"Static code inspection found {len(selected_findings)} {normalized_focus}-relevant sink clue(s)"
                f"{f' including {sink_names}' if sink_names else ''}."
            ),
            priority=highest_priority,
            next_step=(
                "Align these sink locations with captured requests, reachable routes, and artifact URLs so "
                "blackbox probes hit the highest-value parser or renderer paths first."
            ),
        )
        hypothesis_result = record_hypothesis(
            agent_state=agent_state,
            hypothesis=f"Codebase contains {normalized_focus}-relevant sink clues under {root.name}",
            target=target,
            component=f"whitebox:{normalized_focus}",
            vulnerability_type=normalized_focus if normalized_focus != "file_upload" else "file_upload",
            status="open",
            priority=highest_priority,
            rationale=(
                f"Whitebox sink discovery found {len(selected_findings)} clue(s) for {normalized_focus} in "
                f"{root.name}, which should bias deeper validation toward the matching parser or renderer paths."
            ),
        )
        evidence_result = record_evidence(
            agent_state=agent_state,
            title=f"Whitebox sink discovery for {normalized_focus}",
            details=json.dumps(
                {
                    "target_path": str(root),
                    "focus": normalized_focus,
                    "findings": selected_findings,
                    "public_path_hints": public_path_hints[:20],
                },
                ensure_ascii=False,
            ),
            source="tool",
            target=target,
            component=f"whitebox:{normalized_focus}",
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

    return {
        "success": True,
        "tool_name": "whitebox_sink_discovery",
        "focus": normalized_focus,
        "target_path": str(root),
        "finding_count": len(selected_findings),
        "findings": selected_findings,
        "public_path_hints": public_path_hints[:20],
        "coverage_result": coverage_result,
        "hypothesis_result": hypothesis_result,
        "evidence_result": evidence_result,
    }


def _parse_cookie_header(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in str(cookie_header or "").split(";"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        cleaned_key = key.strip()
        cleaned_value = value.strip()
        if cleaned_key:
            cookies[cleaned_key] = cleaned_value
    return cookies


def _infer_base_url_from_headers(headers: dict[str, str]) -> str | None:
    host = headers.get("Host") or headers.get("host")
    if not host:
        return None
    referer = str(headers.get("Referer") or headers.get("referer") or "").lower()
    origin = str(headers.get("Origin") or headers.get("origin") or "").lower()
    is_https = ":443" in host or referer.startswith("https://") or origin.startswith("https://")
    return f"{'https' if is_https else 'http'}://{host}".rstrip("/")


def _request_has_auth_material(base_request: dict[str, Any]) -> bool:
    headers = {
        str(key).lower(): str(value)
        for key, value in dict(base_request.get("headers") or {}).items()
    }
    if "authorization" in headers:
        return True
    if any("token" in key or "auth" in key for key in headers):
        return True
    query_params = {
        str(key).lower(): str(value)
        for key, value in parse_qsl(str(urlparse(str(base_request.get("url") or "")).query), keep_blank_values=True)
    }
    if any(any(marker in key for marker in AUTH_FIELD_MARKERS) for key in query_params):
        return True
    if any(_looks_like_jwt(value) for value in query_params.values()):
        return True
    if any(_looks_like_jwt(str(value)) for value in dict(base_request.get("params") or {}).values()):
        return True
    if any(
        any(marker in str(key).lower() for marker in AUTH_FIELD_MARKERS)
        for key in dict(base_request.get("params") or {})
    ):
        return True
    cookies = dict(base_request.get("cookies") or {})
    if any(_looks_like_jwt(str(value)) for value in cookies.values()):
        return True
    return bool(base_request.get("cookies"))


def _flatten_json_scalar_values(value: Any, prefix: str = "") -> dict[str, str]:
    flattened: dict[str, str] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(item, (dict, list)):
                flattened.update(_flatten_json_scalar_values(item, path))
            elif item is not None:
                flattened[path] = str(item)
                flattened.setdefault(str(key), str(item))
        return flattened
    if isinstance(value, list):
        for index, item in enumerate(value):
            path = f"{prefix}.{index}" if prefix else str(index)
            if isinstance(item, (dict, list)):
                flattened.update(_flatten_json_scalar_values(item, path))
            elif item is not None:
                flattened[path] = str(item)
    return flattened


def _jwt_from_cookie_map(cookies: dict[str, str]) -> tuple[str | None, str | None]:
    for key, value in cookies.items():
        candidate = str(value).strip()
        if _looks_like_jwt(candidate):
            return candidate, str(key)
    return None, None


def _jwt_from_query_map(params: dict[str, str]) -> tuple[str | None, str | None]:
    for key, value in params.items():
        candidate = str(value).strip()
        lowered_key = str(key).lower()
        if candidate and (_looks_like_jwt(candidate) or any(marker in lowered_key for marker in AUTH_FIELD_MARKERS)):
            return candidate, str(key)
    return None, None


def _jwt_from_request_context(context: dict[str, Any]) -> dict[str, Any] | None:
    base_request = dict(context.get("base_request") or {})
    headers = dict(base_request.get("headers") or {})
    for key, value in headers.items():
        resolved = _jwt_from_authorization_header(value) if str(key).lower() == "authorization" else str(value).strip()
        if not resolved or not _looks_like_jwt(resolved):
            continue
        return {
            "token": resolved,
            "token_location": "header",
            "header_name": str(key),
            "header_prefix": (
                str(value).split(" ", 1)[0].strip()
                if str(key).lower() == "authorization" and " " in str(value)
                else ""
            ),
        }

    cookie_token, cookie_name = _jwt_from_cookie_map(
        {str(key): str(value) for key, value in dict(base_request.get("cookies") or {}).items()}
    )
    if cookie_token and cookie_name:
        return {
            "token": cookie_token,
            "token_location": "cookie",
            "cookie_name": cookie_name,
        }

    query_token, query_parameter_name = _jwt_from_query_map(
        {
            str(key): str(value)
            for key, value in parse_qsl(urlparse(str(base_request.get("url") or "")).query, keep_blank_values=True)
        }
    )
    if query_token and query_parameter_name:
        return {
            "token": query_token,
            "token_location": "query",
            "query_parameter_name": query_parameter_name,
        }

    query_token, query_parameter_name = _jwt_from_query_map(
        {str(key): str(value) for key, value in dict(base_request.get("params") or {}).items()}
    )
    if query_token and query_parameter_name:
        return {
            "token": query_token,
            "token_location": "query",
            "query_parameter_name": query_parameter_name,
        }
    return None


def _request_context_from_raw_request(
    raw_request: str,
    *,
    request_id: str,
    source: str,
) -> dict[str, Any] | None:
    lines = str(raw_request or "").splitlines()
    if not lines:
        return None

    parts = lines[0].strip().split(" ")
    method = str(parts[0] if len(parts) > 0 else "").strip().upper()
    request_target = str(parts[1] if len(parts) > 1 else "").strip()
    if not method or not request_target:
        return None

    raw_headers: dict[str, str] = {}
    body_start = len(lines)
    for index, line in enumerate(lines[1:], 1):
        if line.strip() == "":
            body_start = index + 1
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        raw_headers[key.strip()] = value.strip()

    base_url = _infer_base_url_from_headers(raw_headers)
    url = (
        request_target
        if _is_http_url(request_target)
        else (
            urljoin(f"{base_url.rstrip('/')}/", request_target.lstrip("/"))
            if base_url
            else None
        )
    )
    if not url:
        return None

    headers = {
        str(key): str(value)
        for key, value in raw_headers.items()
        if str(key).lower() not in {"host", "cookie", "content-length", "connection"}
    }
    cookies = _parse_cookie_header(raw_headers.get("Cookie") or raw_headers.get("cookie") or "")
    body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""
    content_type = str(headers.get("Content-Type") or headers.get("content-type") or "")
    lowered_content_type = content_type.lower()

    base_request: dict[str, Any] = {
        "name": f"{source}_{request_id}",
        "method": method,
        "url": url,
        "headers": headers,
        "cookies": cookies,
    }
    query_params = {
        str(key): str(value)
        for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True)
    }
    body_params: dict[str, str] = {}
    json_params: dict[str, str] = {}

    if body:
        parsed_json = (
            _parse_json_payload(body)
            if "json" in lowered_content_type or body.lstrip().startswith("{")
            else None
        )
        if isinstance(parsed_json, dict):
            base_request["json_body"] = parsed_json
            json_params = _flatten_json_scalar_values(parsed_json)
        else:
            base_request["body"] = body
            if "x-www-form-urlencoded" in lowered_content_type or "=" in body:
                body_params = {
                    str(key): str(value)
                    for key, value in parse_qsl(body, keep_blank_values=True)
                }

    return {
        "request_id": request_id,
        "source": source,
        "url": url,
        "method": method,
        "content_type": content_type,
        "base_request": base_request,
        "query_params": query_params,
        "body_params": body_params,
        "json_params": json_params,
        "raw_request": raw_request,
    }


def _request_context_with_session_profile(
    context: dict[str, Any],
    session_profiles: list[dict[str, Any]],
) -> dict[str, Any]:
    base_request = dict(context.get("base_request") or {})
    if _request_has_auth_material(base_request):
        return context

    host = urlparse(str(base_request.get("url") or context.get("url") or "")).netloc
    matching_profile = None
    for profile in session_profiles:
        profile_base_url = str(profile.get("base_url") or "").strip()
        profile_host = urlparse(profile_base_url).netloc if profile_base_url else ""
        if host and not profile_host:
            continue
        if profile_host and host and profile_host != host:
            continue
        matching_profile = profile
        break

    if matching_profile is None:
        return context

    merged_headers = {
        **dict(matching_profile.get("headers") or {}),
        **dict(base_request.get("headers") or {}),
    }
    merged_cookies = {
        **dict(matching_profile.get("cookies") or {}),
        **dict(base_request.get("cookies") or {}),
    }
    merged_url = _merge_query_params_into_url(
        str(base_request.get("url") or context.get("url") or ""),
        {
            str(key): str(value)
            for key, value in dict(matching_profile.get("params") or {}).items()
        },
    )

    updated = dict(context)
    updated_base_request = dict(base_request)
    updated_base_request["headers"] = merged_headers
    updated_base_request["cookies"] = merged_cookies
    updated_base_request["url"] = merged_url
    updated["base_request"] = updated_base_request
    updated["url"] = merged_url
    updated["query_params"] = {
        str(key): str(value)
        for key, value in parse_qsl(urlparse(merged_url).query, keep_blank_values=True)
    }
    updated["session_profile_id"] = matching_profile.get("profile_id")
    updated["session_profile_name"] = matching_profile.get("name")
    return updated


def _request_context_match_score(
    context: dict[str, Any],
    *,
    parameter_name: str | None,
    focus: str | None,
) -> int:
    score = int(context.get("selection_score") or 0)
    normalized_parameter = str(parameter_name or "").strip()
    if normalized_parameter:
        if normalized_parameter in dict(context.get("query_params") or {}):
            score += 4
        if normalized_parameter in dict(context.get("body_params") or {}):
            score += 7
        if normalized_parameter in dict(context.get("json_params") or {}):
            score += 8
    if focus == "auth_jwt":
        if _jwt_from_request_context(context):
            score += 10
    if focus == "authz" and _request_has_auth_material(dict(context.get("base_request") or {})):
        score += 6
    if focus == "workflow_race" and str(context.get("method") or "").upper() in STATE_CHANGING_METHODS:
        score += 5
    if str(context.get("method") or "").upper() in STATE_CHANGING_METHODS:
        score += 3
    if context.get("base_request", {}).get("json_body") is not None:
        score += 2
    elif context.get("base_request", {}).get("body") is not None:
        score += 1
    return score


def _focus_request_contexts(
    agent_state: Any,
    target: str,
    *,
    candidate_url: str | None,
    parameter_name: str | None = None,
    focus: str | None = None,
    max_items: int = 3,
    runtime_entries: list[dict[str, Any]] | None = None,
    workflows: list[dict[str, Any]] | None = None,
    session_profiles: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    proxy_manager = _get_focus_proxy_manager()
    if proxy_manager is None:
        return []

    normalized_parameter = str(parameter_name or "").strip()
    candidate_host = urlparse(str(candidate_url or "")).netloc if candidate_url else ""
    candidate_path = urlparse(str(candidate_url or "")).path if candidate_url else ""
    inventory = runtime_entries if runtime_entries is not None else _load_runtime_inventory_entries(
        agent_state,
        target,
    )
    known_workflows = workflows if workflows is not None else _load_discovered_workflows(
        agent_state,
        target,
    )
    profiles = session_profiles if session_profiles is not None else _load_session_profiles(
        agent_state,
    )

    request_candidates: dict[str, dict[str, Any]] = {}

    def remember(request_id: str, *, score: int, source: str) -> None:
        normalized_request_id = str(request_id).strip()
        if not normalized_request_id or score < 1:
            return
        current = request_candidates.get(normalized_request_id)
        if current is None or score > int(current.get("score") or 0):
            request_candidates[normalized_request_id] = {
                "score": score,
                "source": source,
            }

    for entry in inventory:
        sample_request_ids = [str(item).strip() for item in list(entry.get("sample_request_ids") or [])]
        if not sample_request_ids:
            continue
        score = 0
        host = str(entry.get("host") or "").strip()
        sample_paths = [
            urlparse(str(item)).path
            for item in list(entry.get("sample_urls") or [])
            if _is_http_url(str(item))
        ]
        parameters = {
            str(item).strip()
            for item in [
                *list(entry.get("query_params") or []),
                *list(entry.get("body_params") or []),
            ]
            if str(item).strip()
        }
        if candidate_host and host == candidate_host:
            score += 3
        if candidate_path and candidate_path in sample_paths:
            score += 4
        if normalized_parameter and normalized_parameter in parameters:
            score += 6
        if focus in {"auth_jwt", "authz"} and any(
            str(item).strip().lower() != "anonymous"
            for item in list(entry.get("auth_hints") or [])
        ):
            score += 5
        if focus == "authz" and str(entry.get("priority") or "").strip().lower() in {"high", "critical"}:
            score += 3
        if any(
            str(method).strip().upper() in STATE_CHANGING_METHODS
            for method in list(entry.get("methods") or [])
        ):
            score += 2
        if focus == "workflow_race" and any(
            str(method).strip().upper() in STATE_CHANGING_METHODS
            for method in list(entry.get("methods") or [])
        ):
            score += 4
        if focus in {"ssrf_oob", "sqli"} and any(
            "json" in str(item).lower() for item in list(entry.get("content_types") or [])
        ):
            score += 1
        if score == 0 and not candidate_host and focus in {"auth_jwt", "authz", "workflow_race"}:
            score = 1
        for request_id in sample_request_ids:
            remember(request_id, score=score, source="runtime_inventory")

    for workflow in known_workflows:
        base_score = 0
        if candidate_host and str(workflow.get("host") or "").strip() == candidate_host:
            base_score += 2
        if str(workflow.get("priority") or "").strip().lower() == "critical":
            base_score += 2
        if bool(workflow.get("repeated_write")):
            base_score += 1
        for step in list(workflow.get("sequence") or []):
            request_id = str(step.get("request_id") or "").strip()
            if not request_id:
                continue
            score = base_score
            if candidate_path and str(step.get("path") or "").strip() == candidate_path:
                score += 4
            if (
                normalized_parameter
                and str(step.get("method") or "").strip().upper() in STATE_CHANGING_METHODS
            ):
                score += 1
            if focus == "workflow_race" and str(step.get("method") or "").strip().upper() in STATE_CHANGING_METHODS:
                score += 5
            if score == 0 and not candidate_host and focus in {"auth_jwt", "authz", "workflow_race"}:
                score = 1
            remember(request_id, score=score, source="workflow")

    contexts: list[dict[str, Any]] = []
    ordered_candidates = sorted(
        request_candidates.items(),
        key=lambda item: (int(item[1].get("score") or 0), item[0]),
        reverse=True,
    )
    for request_id, metadata in ordered_candidates[: max(1, max_items * 4)]:
        raw_request = proxy_manager.view_request(
            request_id=request_id,
            part="request",
            page=1,
            page_size=120,
        )
        if raw_request.get("error") or not raw_request.get("content"):
            continue
        context = _request_context_from_raw_request(
            str(raw_request["content"]),
            request_id=request_id,
            source=str(metadata.get("source") or "proxy"),
        )
        if context is None:
            continue
        context["selection_score"] = int(metadata.get("score") or 0)
        contexts.append(_request_context_with_session_profile(context, profiles))

    contexts.sort(
        key=lambda item: _request_context_match_score(
            item,
            parameter_name=normalized_parameter or None,
            focus=focus,
        ),
        reverse=True,
    )
    return contexts[:max_items]


def _request_contexts_from_request_ids(
    request_ids: list[str],
    *,
    session_profiles: list[dict[str, Any]] | None = None,
    source: str = "proxy",
) -> list[dict[str, Any]]:
    proxy_manager = _get_focus_proxy_manager()
    if proxy_manager is None:
        return []

    profiles = session_profiles or []
    contexts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for request_id in request_ids:
        normalized_request_id = str(request_id).strip()
        if not normalized_request_id or normalized_request_id in seen:
            continue
        seen.add(normalized_request_id)
        raw_request = proxy_manager.view_request(
            request_id=normalized_request_id,
            part="request",
            page=1,
            page_size=120,
        )
        if raw_request.get("error") or not raw_request.get("content"):
            continue
        context = _request_context_from_raw_request(
            str(raw_request["content"]),
            request_id=normalized_request_id,
            source=source,
        )
        if context is None:
            continue
        contexts.append(_request_context_with_session_profile(context, profiles))
    return contexts


def _session_profile_rank(profile: dict[str, Any]) -> int:
    lowered = " ".join(
        [
            str(profile.get("role") or "").strip().lower(),
            str(profile.get("name") or "").strip().lower(),
        ]
    )
    for keyword, rank in SESSION_ROLE_KEYWORDS:
        if keyword in lowered:
            return rank
    return 1 if profile.get("profile_id") else 0


def _session_case_name(profile: dict[str, Any]) -> str:
    candidate = str(profile.get("role") or profile.get("name") or "session").strip().lower()
    normalized = "".join(char if char.isalnum() else "_" for char in candidate).strip("_")
    return normalized or "session"


def _strip_auth_query_params(url: str) -> str:
    parsed = urlparse(url)
    filtered_pairs = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered_key = str(key).lower()
        candidate_value = str(value).strip()
        if any(marker in lowered_key for marker in AUTH_FIELD_MARKERS):
            continue
        if _looks_like_jwt(candidate_value):
            continue
        filtered_pairs.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(filtered_pairs, doseq=True)))


def _strip_auth_headers(headers: dict[str, Any]) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    for key, value in dict(headers or {}).items():
        lowered_key = str(key).lower()
        if lowered_key in {"authorization", "cookie", "x-api-key", "api-key", "x-auth-token"}:
            continue
        if any(marker in lowered_key for marker in AUTH_FIELD_MARKERS):
            continue
        sanitized[str(key)] = str(value)
    return sanitized


def _strip_auth_json_fields(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            lowered_key = str(key).lower()
            if lowered_key in {"csrf", "xsrf"} or any(
                marker in lowered_key for marker in AUTH_FIELD_MARKERS
            ):
                continue
            sanitized[str(key)] = _strip_auth_json_fields(item)
        return sanitized
    if isinstance(value, list):
        return [_strip_auth_json_fields(item) for item in value]
    return value


def _strip_auth_form_fields(body: str | None) -> str | None:
    if body is None:
        return None
    pairs = [
        (key, value)
        for key, value in parse_qsl(str(body), keep_blank_values=True)
        if str(key).lower() not in {"csrf", "xsrf"}
        and not any(marker in str(key).lower() for marker in AUTH_FIELD_MARKERS)
    ]
    return urlencode(pairs, doseq=True) if pairs else ""


def _sanitize_request_for_session_case(context: dict[str, Any]) -> dict[str, Any]:
    base_request = dict(context.get("base_request") or {})
    sanitized: dict[str, Any] = {
        "method": str(base_request.get("method") or context.get("method") or "GET").strip().upper(),
        "url": _strip_auth_query_params(str(base_request.get("url") or context.get("url") or "")),
    }

    headers = _strip_auth_headers(dict(base_request.get("headers") or {}))
    if headers:
        sanitized["headers"] = headers
    if base_request.get("json_body") is not None:
        sanitized_json = _strip_auth_json_fields(
            json.loads(json.dumps(base_request.get("json_body"), ensure_ascii=False))
        )
        if isinstance(sanitized_json, dict):
            sanitized["json_body"] = sanitized_json
    elif base_request.get("body") is not None:
        sanitized["body"] = _strip_auth_form_fields(str(base_request.get("body")))
    return sanitized


def _authz_focus_contexts(
    runtime_entries: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    *,
    session_profiles: list[dict[str, Any]],
    max_items: int,
) -> list[dict[str, Any]]:
    candidate_scores: dict[str, int] = {}

    def remember(request_id: str, score: int) -> None:
        normalized_request_id = str(request_id).strip()
        if not normalized_request_id or score < 1:
            return
        current = candidate_scores.get(normalized_request_id, 0)
        if score > current:
            candidate_scores[normalized_request_id] = score

    for entry in runtime_entries:
        score = {"critical": 8, "high": 6, "normal": 3, "low": 1}.get(
            str(entry.get("priority") or "normal").strip().lower(),
            2,
        )
        if any(
            str(item).strip().lower() != "anonymous"
            for item in list(entry.get("auth_hints") or [])
        ):
            score += 5
        if any(
            str(method).strip().upper() in STATE_CHANGING_METHODS
            for method in list(entry.get("methods") or [])
        ):
            score += 4
        if any(
            keyword in str(parameter).lower()
            for parameter in [*list(entry.get("query_params") or []), *list(entry.get("body_params") or [])]
            for keyword in ["id", "user", "account", "tenant", "order", "invoice", "role"]
        ):
            score += 3
        for request_id in list(entry.get("sample_request_ids") or [])[:2]:
            remember(str(request_id), score)

    for workflow in workflows:
        workflow_score = {"critical": 9, "high": 7, "normal": 4}.get(
            str(workflow.get("priority") or "normal").strip().lower(),
            3,
        )
        if bool(workflow.get("repeated_write")):
            workflow_score += 2
        for step in list(workflow.get("sequence") or []):
            step_score = workflow_score
            if str(step.get("method") or "").strip().upper() in STATE_CHANGING_METHODS:
                step_score += 3
            remember(str(step.get("request_id") or ""), step_score)

    ordered_request_ids = [
        item[0]
        for item in sorted(candidate_scores.items(), key=lambda item: (item[1], item[0]), reverse=True)
    ]
    contexts = _request_contexts_from_request_ids(
        ordered_request_ids[: max(1, max_items * 3)],
        session_profiles=session_profiles,
        source="authz",
    )
    contexts.sort(key=lambda item: _request_context_match_score(item, parameter_name=None, focus="authz"), reverse=True)
    return contexts[:max_items]


def _authz_cases_for_context(
    context: dict[str, Any],
    session_profiles: list[dict[str, Any]],
    *,
    max_profiles: int = 3,
) -> tuple[list[dict[str, Any]], str | None]:
    sanitized_request = _sanitize_request_for_session_case(context)
    request_host = urlparse(str(sanitized_request.get("url") or "")).netloc
    cases: list[dict[str, Any]] = [{"name": "guest", **sanitized_request}]
    baseline_case = None
    baseline_rank = -1
    seen_case_names = {"guest"}

    sorted_profiles = sorted(
        session_profiles,
        key=lambda item: (_session_profile_rank(item), str(item.get("updated_at") or "")),
        reverse=True,
    )
    for profile in sorted_profiles:
        if len(cases) >= max_profiles + 1:
            break
        profile_host = urlparse(str(profile.get("base_url") or "")).netloc
        if request_host and profile_host and profile_host != request_host:
            continue
        case_name = _session_case_name(profile)
        if case_name in seen_case_names:
            continue
        seen_case_names.add(case_name)
        cases.append(
            {
                "name": case_name,
                **sanitized_request,
                "session_profile_id": profile.get("profile_id"),
            }
        )
        profile_rank = _session_profile_rank(profile)
        if profile_rank >= baseline_rank:
            baseline_case = case_name
            baseline_rank = profile_rank

    return cases, baseline_case


def _workflow_race_expect_single_success(workflow: dict[str, Any], request_context: dict[str, Any]) -> bool:
    if bool(workflow.get("repeated_write")):
        return True
    workflow_type = str(workflow.get("type") or "").strip().lower()
    if workflow_type in RACE_SINGLE_USE_TYPES:
        return True
    request_path = urlparse(str(request_context.get("url") or "")).path.lower()
    return any(keyword in request_path for keyword in RACE_SINGLE_USE_TYPES)


def _workflow_race_plans(
    workflows: list[dict[str, Any]],
    runtime_entries: list[dict[str, Any]],
    *,
    session_profiles: list[dict[str, Any]],
    max_items: int,
) -> list[dict[str, Any]]:
    candidate_metadata: dict[str, dict[str, Any]] = {}

    def remember(request_id: str, metadata: dict[str, Any]) -> None:
        normalized_request_id = str(request_id).strip()
        if not normalized_request_id:
            return
        existing = candidate_metadata.get(normalized_request_id)
        if existing is None or int(metadata.get("score") or 0) > int(existing.get("score") or 0):
            candidate_metadata[normalized_request_id] = metadata

    for workflow in workflows:
        state_steps = [
            step
            for step in list(workflow.get("sequence") or [])
            if str(step.get("method") or "").strip().upper() in STATE_CHANGING_METHODS
        ]
        if not state_steps:
            continue
        selected_step = state_steps[-1]
        if bool(workflow.get("repeated_write")):
            grouped_steps: dict[tuple[str, str], list[dict[str, Any]]] = {}
            for step in state_steps:
                key = (
                    str(step.get("method") or "").strip().upper(),
                    str(step.get("normalized_path") or step.get("path") or "").strip(),
                )
                grouped_steps.setdefault(key, []).append(step)
            repeated_group = max(grouped_steps.values(), key=len)
            if len(repeated_group) > 1:
                selected_step = repeated_group[-1]
        score = {"critical": 10, "high": 7, "normal": 4}.get(
            str(workflow.get("priority") or "normal").strip().lower(),
            3,
        )
        if bool(workflow.get("repeated_write")):
            score += 4
        if str(workflow.get("type") or "").strip().lower() in RACE_SINGLE_USE_TYPES:
            score += 4
        remember(
            str(selected_step.get("request_id") or ""),
            {"score": score, "workflow": workflow, "step": selected_step},
        )

    if not candidate_metadata:
        for entry in runtime_entries:
            if not any(
                str(method).strip().upper() in STATE_CHANGING_METHODS
                for method in list(entry.get("methods") or [])
            ):
                continue
            score = {"critical": 7, "high": 5, "normal": 3}.get(
                str(entry.get("priority") or "normal").strip().lower(),
                2,
            )
            for request_id in list(entry.get("sample_request_ids") or [])[:1]:
                remember(
                    str(request_id),
                    {"score": score, "workflow": None, "step": None},
                )

    ordered_request_ids = [
        item[0]
        for item in sorted(
            candidate_metadata.items(),
            key=lambda item: (int(item[1].get("score") or 0), item[0]),
            reverse=True,
        )
    ]
    contexts = _request_contexts_from_request_ids(
        ordered_request_ids[: max(1, max_items * 2)],
        session_profiles=session_profiles,
        source="workflow_race",
    )
    context_map = {str(item.get("request_id") or ""): item for item in contexts}

    plans: list[dict[str, Any]] = []
    for request_id in ordered_request_ids:
        context = context_map.get(request_id)
        if context is None:
            continue
        metadata = candidate_metadata[request_id]
        plans.append(
            {
                "workflow": metadata.get("workflow"),
                "step": metadata.get("step"),
                "request_context": context,
                "score": metadata.get("score"),
            }
        )
        if len(plans) >= max_items:
            break
    return plans


def _request_context_parameter_candidates(
    runtime_entries: list[dict[str, Any]],
    *,
    focus: str,
) -> list[dict[str, Any]]:
    keywords = list(FOCUS_PARAMETER_HINTS.get(focus, []))
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in runtime_entries:
        sample_urls = [str(item).strip() for item in list(entry.get("sample_urls") or []) if str(item).strip()]
        sample_url = sample_urls[0] if sample_urls else ""
        path = str(entry.get("normalized_path") or "").strip() or "/"
        for parameter_name in _unique_strings(
            [
                *[str(item) for item in list(entry.get("query_params") or [])],
                *[str(item) for item in list(entry.get("body_params") or [])],
            ]
        ):
            lowered_parameter = parameter_name.lower()
            if not any(keyword in lowered_parameter for keyword in keywords):
                continue
            key = (sample_url, path, parameter_name)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    "url": sample_url,
                    "path": path,
                    "parameter": parameter_name,
                    "source": "runtime_inventory",
                    "sample_request_ids": list(entry.get("sample_request_ids") or []),
                }
            )
    return candidates


def _request_context_injection_mode(context: dict[str, Any], parameter_name: str) -> str:
    normalized_parameter = str(parameter_name).strip()
    if normalized_parameter in dict(context.get("json_params") or {}):
        return "json"
    if normalized_parameter in dict(context.get("body_params") or {}):
        return "body"
    if normalized_parameter in dict(context.get("query_params") or {}):
        return "query"

    base_request = dict(context.get("base_request") or {})
    content_type = str(context.get("content_type") or "").lower()
    if base_request.get("json_body") is not None or "json" in content_type:
        return "json"
    if base_request.get("body") is not None or "x-www-form-urlencoded" in content_type:
        return "body"
    return "query"


def _request_context_baseline_value(
    context: dict[str, Any],
    parameter_name: str,
    injection_mode: str,
) -> str | None:
    normalized_parameter = str(parameter_name).strip()
    if injection_mode == "raw_body":
        return str(dict(context.get("base_request") or {}).get("body") or "") or None
    if injection_mode == "json":
        return dict(context.get("json_params") or {}).get(normalized_parameter)
    if injection_mode == "body":
        return dict(context.get("body_params") or {}).get(normalized_parameter)
    return dict(context.get("query_params") or {}).get(normalized_parameter)


def _fallback_request_context(url: str, headers: dict[str, str]) -> dict[str, Any]:
    return {
        "request_id": None,
        "source": "synthetic",
        "url": url,
        "method": "GET",
        "content_type": "",
        "base_request": {
            "name": "synthetic_focus_request",
            "method": "GET",
            "url": url,
            "headers": dict(headers),
            "cookies": {},
        },
        "query_params": {
            str(key): str(value)
            for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True)
        },
        "body_params": {},
        "json_params": {},
        "raw_request": None,
        "selection_score": 0,
    }


def _fallback_body_request_context(
    url: str,
    headers: dict[str, str],
    *,
    method: str = "POST",
    body: str,
    content_type: str,
) -> dict[str, Any]:
    request_headers = dict(headers)
    if content_type and not any(str(key).lower() == "content-type" for key in request_headers):
        request_headers["Content-Type"] = content_type
    return {
        "request_id": None,
        "source": "synthetic",
        "url": url,
        "method": method,
        "content_type": content_type,
        "base_request": {
            "name": "synthetic_focus_body_request",
            "method": method,
            "url": url,
            "headers": request_headers,
            "cookies": {},
            "body": body,
        },
        "query_params": {
            str(key): str(value)
            for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True)
        },
        "body_params": {},
        "json_params": {},
        "raw_request": None,
        "selection_score": 0,
    }


def _path_or_url_contains_keyword(value: str, keywords: tuple[str, ...] | list[str]) -> bool:
    lowered = str(value or "").lower()
    return any(keyword in lowered for keyword in keywords)


def _request_context_has_xml_body(context: dict[str, Any]) -> bool:
    base_request = dict(context.get("base_request") or {})
    content_type = str(context.get("content_type") or base_request.get("headers", {}).get("Content-Type") or "").lower()
    body = str(base_request.get("body") or "").strip()
    return bool(body) and (
        any(marker in content_type for marker in XML_CONTENT_TYPE_MARKERS)
        or body.startswith("<?xml")
        or body.startswith("<")
    )


def _request_context_has_multipart_upload(context: dict[str, Any]) -> bool:
    base_request = dict(context.get("base_request") or {})
    content_type = str(context.get("content_type") or base_request.get("headers", {}).get("Content-Type") or "").lower()
    body = str(base_request.get("body") or "")
    return "multipart/form-data" in content_type and 'filename="' in body.lower()


def _collect_focus_request_ids(
    runtime_entries: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    *,
    entry_score_fn: Any,
    step_score_fn: Any | None = None,
    max_items: int,
) -> list[str]:
    candidate_scores: dict[str, int] = {}

    def remember(request_id: str, score: int) -> None:
        normalized_request_id = str(request_id).strip()
        if not normalized_request_id or score < 1:
            return
        current = candidate_scores.get(normalized_request_id, 0)
        if score > current:
            candidate_scores[normalized_request_id] = score

    for entry in runtime_entries:
        score = int(entry_score_fn(entry) or 0)
        if score < 1:
            continue
        for request_id in list(entry.get("sample_request_ids") or [])[:2]:
            remember(str(request_id), score)

    if step_score_fn is not None:
        for workflow in workflows:
            for step in list(workflow.get("sequence") or []):
                score = int(step_score_fn(workflow, step) or 0)
                if score < 1:
                    continue
                remember(str(step.get("request_id") or ""), score)

    return [
        item[0]
        for item in sorted(candidate_scores.items(), key=lambda item: (item[1], item[0]), reverse=True)
    ][: max(1, max_items * 3)]


def _xml_focus_contexts(
    runtime_entries: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    *,
    session_profiles: list[dict[str, Any]],
    max_items: int,
) -> list[dict[str, Any]]:
    request_ids = _collect_focus_request_ids(
        runtime_entries,
        workflows,
        entry_score_fn=lambda entry: (
            (8 if any("xml" in str(item).lower() or "soap" in str(item).lower() for item in list(entry.get("content_types") or [])) else 0)
            + (4 if _path_or_url_contains_keyword(" ".join(str(item) for item in list(entry.get("sample_urls") or [])), XML_PATH_KEYWORDS) else 0)
            + (3 if any(str(method).strip().upper() in STATE_CHANGING_METHODS for method in list(entry.get("methods") or [])) else 0)
        ),
        step_score_fn=lambda workflow, step: (
            (6 if _path_or_url_contains_keyword(str(step.get("path") or ""), XML_PATH_KEYWORDS) else 0)
            + (3 if str(step.get("method") or "").strip().upper() in STATE_CHANGING_METHODS else 0)
        ),
        max_items=max_items,
    )
    contexts = _request_contexts_from_request_ids(
        request_ids,
        session_profiles=session_profiles,
        source="xxe",
    )
    contexts = [item for item in contexts if _request_context_has_xml_body(item)]
    contexts.sort(key=lambda item: _request_context_match_score(item, parameter_name=None, focus=None), reverse=True)
    return contexts[:max_items]


def _upload_focus_contexts(
    runtime_entries: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    *,
    session_profiles: list[dict[str, Any]],
    max_items: int,
) -> list[dict[str, Any]]:
    request_ids = _collect_focus_request_ids(
        runtime_entries,
        workflows,
        entry_score_fn=lambda entry: (
            (8 if any("multipart/form-data" in str(item).lower() for item in list(entry.get("content_types") or [])) else 0)
            + (4 if _path_or_url_contains_keyword(" ".join(str(item) for item in list(entry.get("sample_urls") or [])), UPLOAD_PATH_KEYWORDS) else 0)
            + (3 if any(str(method).strip().upper() in STATE_CHANGING_METHODS for method in list(entry.get("methods") or [])) else 0)
        ),
        step_score_fn=lambda workflow, step: (
            (5 if _path_or_url_contains_keyword(str(step.get("path") or ""), UPLOAD_PATH_KEYWORDS) else 0)
            + (3 if str(step.get("method") or "").strip().upper() in STATE_CHANGING_METHODS else 0)
        ),
        max_items=max_items,
    )
    contexts = _request_contexts_from_request_ids(
        request_ids,
        session_profiles=session_profiles,
        source="file_upload",
    )
    contexts = [item for item in contexts if _request_context_has_multipart_upload(item)]
    contexts.sort(key=lambda item: _request_context_match_score(item, parameter_name=None, focus=None), reverse=True)
    return contexts[:max_items]


def _multipart_boundary(content_type: str) -> str | None:
    match = re.search(r'boundary="?([^";]+)"?', str(content_type), flags=re.IGNORECASE)
    return str(match.group(1)).strip() if match else None


def _replace_first_multipart_content(segment: str, file_content: str) -> str:
    separator = "\r\n\r\n" if "\r\n\r\n" in segment else "\n\n"
    if separator not in segment:
        return segment
    headers, content = segment.split(separator, 1)
    suffix = ""
    if content.endswith("\r\n"):
        content = content[:-2]
        suffix = "\r\n"
    elif content.endswith("\n"):
        content = content[:-1]
        suffix = "\n"
    return f"{headers}{separator}{file_content}{suffix}"


def _mutate_first_multipart_file_part(
    body: str,
    content_type: str,
    *,
    filename: str | None = None,
    part_content_type: str | None = None,
    file_content: str | None = None,
) -> str | None:
    boundary = _multipart_boundary(content_type)
    if not boundary:
        return None
    marker = f"--{boundary}"
    segments = body.split(marker)
    for index, segment in enumerate(segments):
        if 'filename="' not in segment.lower():
            continue
        mutated = segment
        if filename is not None:
            mutated = re.sub(
                r'(?i)filename="[^"]*"',
                f'filename="{filename}"',
                mutated,
                count=1,
            )
        if part_content_type is not None:
            if re.search(r"(?im)^Content-Type:\s*[^\r\n]+", mutated):
                mutated = re.sub(
                    r"(?im)^Content-Type:\s*[^\r\n]+",
                    f"Content-Type: {part_content_type}",
                    mutated,
                    count=1,
                )
            else:
                separator = "\r\n\r\n" if "\r\n\r\n" in mutated else "\n\n"
                mutated = mutated.replace(separator, f"\r\nContent-Type: {part_content_type}{separator}", 1)
        if file_content is not None:
            mutated = _replace_first_multipart_content(mutated, file_content)
        segments[index] = mutated
        return marker.join(segments)
    return None


def _multipart_upload_payloads_from_context(
    context: dict[str, Any],
    *,
    callback_urls: list[str] | None = None,
) -> list[dict[str, Any]]:
    base_request = dict(context.get("base_request") or {})
    body = str(base_request.get("body") or "")
    content_type = str(context.get("content_type") or base_request.get("headers", {}).get("Content-Type") or "")
    if not body or not content_type:
        return []

    variants: list[dict[str, Any]] = []
    seen_payloads: set[str] = set()

    def add_variant(
        *,
        strategy: str,
        filename: str | None = None,
        part_content_type: str | None = None,
        file_content: str | None = None,
        expected_markers: list[str] | None = None,
    ) -> None:
        payload = _mutate_first_multipart_file_part(
            body,
            content_type,
            filename=filename,
            part_content_type=part_content_type,
            file_content=file_content,
        )
        if not payload or payload in seen_payloads:
            return
        seen_payloads.add(payload)
        variants.append(
            {
                "payload": payload,
                "encoding": "raw",
                "strategy": strategy,
                "expected_rejection": True,
                "expected_markers": expected_markers or [],
            }
        )

    add_variant(
        strategy="php_extension_swap",
        filename="shell.php",
        part_content_type="application/x-php",
        expected_markers=["shell.php", ".php", "application/x-php"],
    )
    add_variant(
        strategy="double_extension_polyglot",
        filename="shell.php.jpg",
        part_content_type="image/jpeg",
        file_content="GIF89a\n<?php echo 49; ?>",
        expected_markers=["shell.php.jpg", "49"],
    )
    add_variant(
        strategy="svg_active_content",
        filename="avatar.svg",
        part_content_type="image/svg+xml",
        file_content=(
            '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" '
            'onload="alert(1)"></svg>'
        ),
        expected_markers=["avatar.svg", "image/svg+xml", ".svg"],
    )
    for callback_url in [str(item).strip() for item in list(callback_urls or []) if str(item).strip()][:1]:
        add_variant(
            strategy="svg_xxe_oob",
            filename="avatar-oob.svg",
            part_content_type="image/svg+xml",
            file_content=(
                '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM '
                f'"{callback_url}">]><svg xmlns="http://www.w3.org/2000/svg">'
                "<text>&xxe;</text></svg>"
            ),
            expected_markers=["avatar-oob.svg", "image/svg+xml", ".svg"],
        )
    return variants


def _multipart_payload_filename(payload: str) -> str | None:
    match = re.search(r'filename="([^"\r\n]+)"', str(payload), flags=re.IGNORECASE)
    if not match:
        return None
    candidate = str(match.group(1)).strip()
    return candidate or None


def _normalized_same_origin_url(candidate_url: str, request_url: str) -> str | None:
    candidate = str(candidate_url or "").strip().strip(" \t\r\n\"'`)>],")
    if not candidate:
        return None
    resolved = urljoin(request_url, candidate)
    parsed_candidate = urlparse(resolved)
    parsed_request = urlparse(request_url)
    if parsed_candidate.scheme not in {"http", "https"}:
        return None
    if parsed_candidate.netloc != parsed_request.netloc:
        return None
    return urlunparse(
        (
            parsed_candidate.scheme,
            parsed_candidate.netloc,
            parsed_candidate.path or "/",
            "",
            parsed_candidate.query,
            "",
        )
    )


def _extract_upload_artifact_urls_from_text(
    text: str,
    *,
    request_url: str,
    filenames: list[str],
) -> list[str]:
    candidates: list[str] = []
    raw_text = str(text or "")
    if not raw_text:
        return candidates

    seen: set[str] = set()

    def remember(value: str) -> None:
        normalized = _normalized_same_origin_url(value, request_url)
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        candidates.append(normalized)

    for match in re.findall(r"https?://[^\s\"'<>]+", raw_text, flags=re.IGNORECASE):
        remember(match)

    for filename in filenames:
        escaped = re.escape(filename)
        for pattern in [
            rf"/[A-Za-z0-9._~%/\-]*{escaped}(?:\?[^\s\"'<>]*)?",
            rf"[A-Za-z0-9._~%/\-]+/{escaped}(?:\?[^\s\"'<>]*)?",
        ]:
            for match in re.findall(pattern, raw_text, flags=re.IGNORECASE):
                remember(match)

    return candidates


def _heuristic_upload_artifact_urls(
    request_url: str,
    *,
    request_path: str,
    filenames: list[str],
    public_path_hints: list[str] | None = None,
) -> list[str]:
    if not filenames:
        return []

    parsed_request = urlparse(request_url)
    origin = urlunparse((parsed_request.scheme, parsed_request.netloc, "/", "", "", ""))
    base_path = PurePosixPath(request_path or "/")
    parent = str(base_path.parent)
    directories: list[str] = []
    for candidate in [
        request_path or "/",
        parent,
        f"/{str(base_path).strip('/').split('/')[0]}" if str(base_path).strip("/") else "/",
        *[f"/{hint.strip('/')}" for hint in UPLOAD_PUBLIC_PATH_HINTS],
        *[
            f"/{str(item).strip('/')}"
            for item in list(public_path_hints or [])
            if str(item).strip()
        ],
    ]:
        normalized = "/" if not candidate else str(candidate)
        if normalized not in directories:
            directories.append(normalized)

    candidates: list[str] = []
    seen: set[str] = set()
    for filename in filenames:
        filename_path = PurePosixPath(filename).name
        for raw_candidate in [
            urljoin(request_url, filename_path),
            urljoin(origin, filename_path),
            *[
                urljoin(origin, f"{directory.strip('/')}/{filename_path}")
                if directory != "/"
                else urljoin(origin, filename_path)
                for directory in directories
            ],
        ]:
            normalized = _normalized_same_origin_url(raw_candidate, request_url)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            candidates.append(normalized)
    return candidates


def _upload_retrieval_marker_hits(
    response: dict[str, Any],
    *,
    candidate_url: str,
    markers: list[str],
) -> list[str]:
    searchable = " ".join(
        [
            candidate_url,
            str(response.get("url") or ""),
            str(response.get("location") or ""),
            str(response.get("content_type") or ""),
            str(response.get("body_preview") or ""),
        ]
    ).lower()
    hits: list[str] = []
    seen: set[str] = set()
    for marker in [str(item).strip() for item in markers if str(item).strip()]:
        lowered = marker.lower()
        if lowered in searchable and lowered not in seen:
            seen.add(lowered)
            hits.append(marker)
    return hits


def _candidate_viewer_urls_for_artifact(
    request_context: dict[str, Any],
    *,
    artifact_url: str,
    artifact_filename: str,
    workflows: list[dict[str, Any]] | None = None,
    runtime_entries: list[dict[str, Any]] | None = None,
) -> list[str]:
    request_url = str(request_context.get("url") or "").strip()
    base = _base_url(request_url)
    if not base:
        return []
    normalized_request_url = _normalized_same_origin_url(request_url, request_url) or request_url
    request_host = urlparse(request_url).netloc
    request_path = urlparse(request_url).path or "/"
    request_id = str(request_context.get("request_id") or "").strip()
    artifact_name = PurePosixPath(str(artifact_filename or "")).name.lower()
    request_segments = {
        segment
        for segment in PurePosixPath(request_path).parts
        if segment and segment not in {"/", "."} and segment.lower() not in UPLOAD_SKIP_SEGMENTS
    }

    candidates: dict[str, int] = {}

    def remember(candidate_url: str, score: int) -> None:
        normalized = _normalized_same_origin_url(candidate_url, request_url)
        if (
            not normalized
            or normalized == artifact_url
            or normalized == normalized_request_url
            or score < 1
        ):
            return
        current = candidates.get(normalized, 0)
        if score > current:
            candidates[normalized] = score

    for workflow in list(workflows or []):
        sequence = [item for item in list(workflow.get("sequence") or []) if isinstance(item, dict)]
        request_positions = [
            index
            for index, step in enumerate(sequence)
            if str(step.get("request_id") or "").strip() == request_id
        ]
        for request_position in request_positions:
            for step in sequence[request_position + 1 :]:
                if str(step.get("method") or "").strip().upper() != "GET":
                    continue
                step_path = str(step.get("path") or "").strip()
                if not step_path:
                    continue
                candidate_url = urljoin(f"{base.rstrip('/')}/", step_path.lstrip("/"))
                score = 10
                if _path_or_url_contains_keyword(step_path, VIEWER_PATH_KEYWORDS):
                    score += 3
                remember(candidate_url, score)

        if request_positions:
            continue

        workflow_host = str(workflow.get("host") or "").strip()
        if workflow_host and workflow_host != request_host:
            continue
        for step in sequence:
            if str(step.get("method") or "").strip().upper() != "GET":
                continue
            step_path = str(step.get("path") or "").strip()
            if not step_path:
                continue
            candidate_segments = {
                segment
                for segment in PurePosixPath(step_path).parts
                if segment and segment not in {"/", "."}
            }
            overlap = len(request_segments & candidate_segments)
            score = overlap * 2
            if _path_or_url_contains_keyword(step_path, VIEWER_PATH_KEYWORDS):
                score += 4
            if score:
                remember(urljoin(f"{base.rstrip('/')}/", step_path.lstrip("/")), score)

    for entry in list(runtime_entries or []):
        entry_host = str(entry.get("host") or "").strip()
        if entry_host and entry_host != request_host:
            continue
        methods = {str(item).strip().upper() for item in list(entry.get("methods") or []) if str(item).strip()}
        for sample_url in list(entry.get("sample_urls") or []):
            candidate_url = str(sample_url or "").strip()
            if not _is_http_url(candidate_url):
                continue
            sample_path = urlparse(candidate_url).path or "/"
            has_get_method = "GET" in methods
            has_viewer_keyword = _path_or_url_contains_keyword(sample_path, VIEWER_PATH_KEYWORDS)
            has_artifact_hint = bool(
                artifact_name and artifact_name.rsplit(".", 1)[0] in sample_path.lower()
            )
            if not (has_get_method or has_viewer_keyword or has_artifact_hint):
                continue
            sample_segments = {
                segment
                for segment in PurePosixPath(sample_path).parts
                if segment and segment not in {"/", "."}
            }
            overlap = len(request_segments & sample_segments)
            score = overlap * 2
            if has_get_method:
                score += 2
            if has_viewer_keyword:
                score += 3
            if has_artifact_hint:
                score += 2
            remember(candidate_url, score)

    return [
        item[0]
        for item in sorted(candidates.items(), key=lambda item: (-item[1], item[0]))
    ][:5]


def _upload_followup_findings(
    agent_state: Any,
    *,
    target: str,
    request_context: dict[str, Any],
    active_probe_result: dict[str, Any],
    workflows: list[dict[str, Any]] | None = None,
    runtime_entries: list[dict[str, Any]] | None = None,
    public_path_hints: list[str] | None = None,
    timeout: int = 15,
) -> dict[str, Any]:
    request_url = str(request_context.get("url") or "").strip()
    request_path = urlparse(request_url).path or "/"
    suspicious_observations = list(
        (
            active_probe_result.get("triage_result", {}) if isinstance(active_probe_result, dict) else {}
        ).get("suspicious_observations", [])
        or []
    )
    request_variants = list(active_probe_result.get("request_variants") or [])
    variant_by_name = {
        str(item.get("name") or "").strip(): item
        for item in request_variants
        if str(item.get("name") or "").strip() and str(item.get("name") or "").strip() != "baseline"
    }
    base_request = dict(request_context.get("base_request") or {})
    headers = {
        str(key): str(value)
        for key, value in dict(base_request.get("headers") or {}).items()
        if str(key).lower() not in {"content-type", "content-length"}
    }
    cookies = {
        str(key): str(value)
        for key, value in dict(base_request.get("cookies") or {}).items()
    }

    retrieval_attempts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    browser_confirmation_results: list[dict[str, Any]] = []
    seen_attempts: set[tuple[str, str]] = set()
    seen_findings: set[tuple[str, str, str]] = set()

    def add_finding(finding: dict[str, Any]) -> None:
        key = (
            str(finding.get("issue_type") or ""),
            str(finding.get("variant_name") or ""),
            str(finding.get("artifact_url") or ""),
        )
        if key in seen_findings:
            return
        seen_findings.add(key)
        findings.append(finding)

    for observation in suspicious_observations:
        variant_name = str(observation.get("name") or "").strip()
        if not variant_name or variant_name == "baseline":
            continue
        variant = variant_by_name.get(variant_name)
        if variant is None:
            continue
        filename = _multipart_payload_filename(str(variant.get("payload") or ""))
        expected_markers = [str(item).strip() for item in list(variant.get("expected_markers") or []) if str(item).strip()]
        if not filename:
            continue

        if observation.get("oob_interaction"):
            callback_protocol = str(observation.get("callback_protocol") or "unknown").strip() or "unknown"
            add_finding(
                {
                    "issue_type": "uploaded_parser_oob",
                    "variant_name": variant_name,
                    "artifact_url": "",
                    "filename": filename,
                    "vulnerability_type": "xxe",
                    "priority": "critical",
                    "surface": f"Uploaded file {filename} triggered an out-of-band {callback_protocol} callback",
                    "rationale": (
                        f"Variant {variant_name} caused an out-of-band {callback_protocol} interaction after upload, "
                        "which suggests server-side parsing or fetch behavior on uploaded content."
                    ),
                    "next_step": (
                        "Confirm the parser or processor that handled the uploaded artifact and capture the exact "
                        "callback metadata for reporting."
                    ),
                    "details": {
                        "request_url": request_url,
                        "request_id": request_context.get("request_id"),
                        "callback_protocol": callback_protocol,
                        "top_issue_type": observation.get("top_issue_type"),
                    },
                }
            )

        candidate_urls = _extract_upload_artifact_urls_from_text(
            str(observation.get("location") or ""),
            request_url=request_url,
            filenames=[filename],
        )
        candidate_urls.extend(
            _extract_upload_artifact_urls_from_text(
                str(observation.get("body_preview") or ""),
                request_url=request_url,
                filenames=[filename],
            )
        )
        candidate_urls.extend(
            _heuristic_upload_artifact_urls(
                request_url,
                request_path=request_path,
                filenames=[filename],
                public_path_hints=public_path_hints,
            )
        )

        deduped_urls: list[str] = []
        seen_urls: set[str] = set()
        for candidate_url in candidate_urls:
            if candidate_url in seen_urls:
                continue
            seen_urls.add(candidate_url)
            deduped_urls.append(candidate_url)

        for candidate_url in deduped_urls[:8]:
            attempt_key = (variant_name, candidate_url)
            if attempt_key in seen_attempts:
                continue
            seen_attempts.add(attempt_key)

            response = _execute_request(
                {
                    "name": f"artifact_{variant_name}",
                    "method": "GET",
                    "url": candidate_url,
                    "headers": headers,
                    "cookies": cookies,
                },
                timeout=timeout,
                follow_redirects=True,
            )
            marker_hits = _upload_retrieval_marker_hits(
                response,
                candidate_url=candidate_url,
                markers=expected_markers,
            )
            retrieval_attempts.append(
                {
                    "variant_name": variant_name,
                    "filename": filename,
                    "artifact_url": candidate_url,
                    "response": response,
                    "marker_hits": marker_hits,
                }
            )

            if response.get("error"):
                continue
            status_code = int(response.get("status_code") or 0)
            if status_code not in {200, 206}:
                continue

            content_type = str(response.get("content_type") or "").lower()
            body_preview = str(response.get("body_preview") or "")
            body_preview_lower = body_preview.lower()
            filename_lower = filename.lower()

            if "49" in body_preview or "49" in marker_hits:
                add_finding(
                    {
                        "issue_type": "uploaded_code_execution",
                        "variant_name": variant_name,
                        "artifact_url": candidate_url,
                        "filename": filename,
                        "vulnerability_type": "rce",
                        "priority": "critical",
                        "surface": f"Uploaded artifact {filename} appears executable at {candidate_url}",
                        "rationale": (
                            f"Retrieving {candidate_url} returned the execution marker associated with the uploaded "
                            f"variant {variant_name}, indicating probable server-side code execution."
                        ),
                        "next_step": (
                            "Verify the execution primitive with a harmless secondary command and confirm the exact "
                            "runtime handling path before reporting."
                        ),
                        "details": {
                            "request_url": request_url,
                            "request_id": request_context.get("request_id"),
                            "status_code": status_code,
                            "content_type": response.get("content_type"),
                            "marker_hits": marker_hits,
                        },
                    }
                )
                continue

            if filename_lower.endswith(EXECUTABLE_UPLOAD_EXTENSIONS) and "<?php" in body_preview_lower:
                add_finding(
                    {
                        "issue_type": "uploaded_server_source_disclosure",
                        "variant_name": variant_name,
                        "artifact_url": candidate_url,
                        "filename": filename,
                        "vulnerability_type": "file_upload",
                        "priority": "high",
                        "surface": f"Uploaded server-side file {filename} is directly retrievable at {candidate_url}",
                        "rationale": (
                            f"The uploaded server-side file {filename} was fetched back from {candidate_url} and "
                            "its source content was exposed instead of being rejected."
                        ),
                        "next_step": (
                            "Check whether the same storage path can host executable content or be served under a "
                            "dangerous content-type elsewhere in the application."
                        ),
                        "details": {
                            "request_url": request_url,
                            "request_id": request_context.get("request_id"),
                            "status_code": status_code,
                            "content_type": response.get("content_type"),
                            "marker_hits": marker_hits,
                        },
                    }
                )

            if (
                filename_lower.endswith(".svg")
                and "svg+xml" in content_type
                and "<svg" in body_preview_lower
                and any(marker in body_preview_lower for marker in ["onload=", "<script", "javascript:"])
            ):
                add_finding(
                    {
                        "issue_type": "uploaded_svg_active_content",
                        "variant_name": variant_name,
                        "artifact_url": candidate_url,
                        "filename": filename,
                        "vulnerability_type": "xss",
                        "priority": "high",
                        "surface": f"Uploaded SVG {filename} is served back with active content at {candidate_url}",
                        "rationale": (
                            f"Retrieving {candidate_url} returned active SVG content from uploaded variant "
                            f"{variant_name}, which may enable stored XSS when the artifact is viewed in-origin."
                        ),
                        "next_step": (
                            "Confirm the rendering context where the SVG is embedded or opened and verify same-origin "
                            "script execution impact."
                        ),
                        "details": {
                            "request_url": request_url,
                            "request_id": request_context.get("request_id"),
                            "status_code": status_code,
                            "content_type": response.get("content_type"),
                            "marker_hits": marker_hits,
                        },
                    }
                )

    confirm_active_artifact_in_browser = None
    if any(item.get("issue_type") == "uploaded_svg_active_content" for item in findings):
        try:
            from .assessment_browser_actions import confirm_active_artifact_in_browser
        except Exception:  # noqa: BLE001
            confirm_active_artifact_in_browser = None

    recorded_findings: list[dict[str, Any]] = []
    component = f"focus:file_upload:{urlparse(request_url).netloc}{request_path}:followup"
    for finding in findings:
        coverage_result = record_coverage(
            agent_state=agent_state,
            target=target,
            component=component,
            surface=str(finding["surface"]),
            status="in_progress",
            rationale=str(finding["rationale"]),
            priority=str(finding["priority"]),
            next_step=str(finding["next_step"]),
        )
        hypothesis_result = record_hypothesis(
            agent_state=agent_state,
            hypothesis=str(finding["surface"]),
            target=target,
            component=component,
            vulnerability_type=str(finding["vulnerability_type"]),
            status="open",
            priority=str(finding["priority"]),
            rationale=str(finding["rationale"]),
        )
        evidence_result = record_evidence(
            agent_state=agent_state,
            title=f"Upload follow-up finding for {request_path}",
            details=json.dumps(
                {
                    **finding,
                    "request_context": {
                        "url": request_url,
                        "method": request_context.get("method"),
                        "request_id": request_context.get("request_id"),
                    },
                },
                ensure_ascii=False,
            ),
            source="tool",
            target=target,
            component=component,
            related_coverage_id=coverage_result.get("coverage_id"),
            related_hypothesis_id=(
                hypothesis_result.get("hypothesis_id")
                if isinstance(hypothesis_result, dict)
                else None
            ),
        )
        recorded_findings.append(
            {
                **finding,
                "coverage_result": coverage_result,
                "hypothesis_result": hypothesis_result,
                "evidence_result": evidence_result,
            }
        )
        if (
            finding.get("issue_type") == "uploaded_svg_active_content"
            and confirm_active_artifact_in_browser is not None
        ):
            viewer_urls = _candidate_viewer_urls_for_artifact(
                request_context,
                artifact_url=str(finding["artifact_url"]),
                artifact_filename=str(finding["filename"]),
                workflows=workflows,
                runtime_entries=runtime_entries,
            )
            browser_result = confirm_active_artifact_in_browser(
                agent_state=agent_state,
                target=target,
                component=f"{component}:browser",
                surface=f"Browser execution proof for {finding['filename']} at {finding['artifact_url']}",
                url=str(finding["artifact_url"]),
                viewer_urls=viewer_urls,
                artifact_filename=str(finding["filename"]),
                expected_dom_markers=["<svg", "onload="],
                wait_seconds=1.5,
            )
            browser_confirmation_results.append(browser_result)
            if browser_result.get("success") and browser_result.get("confirmed_execution"):
                recorded_findings.append(
                    {
                        "issue_type": "stored_xss_browser_confirmed",
                        "variant_name": finding.get("variant_name"),
                        "artifact_url": finding.get("artifact_url"),
                        "filename": finding.get("filename"),
                        "vulnerability_type": "xss",
                        "priority": "critical",
                        "surface": f"Stored browser execution confirmed for {finding['artifact_url']}",
                        "rationale": (
                            f"Browser instrumentation confirmed active client-side execution when loading "
                            f"{finding['artifact_url']} after the dangerous upload was accepted."
                        ),
                        "next_step": (
                            "Capture the viewer workflow that exposes this artifact and confirm whether untrusted "
                            "actors can force privileged users to load it."
                        ),
                        "browser_confirmation_result": browser_result,
                        "coverage_result": browser_result.get("coverage_result"),
                        "hypothesis_result": browser_result.get("hypothesis_result"),
                        "evidence_result": browser_result.get("evidence_result"),
                    }
                )

    return {
        "success": True,
        "tool_name": "upload_artifact_followup",
        "finding_count": len(recorded_findings),
        "oob_signal_count": sum(1 for item in recorded_findings if item.get("issue_type") == "uploaded_parser_oob"),
        "retrieval_attempt_count": len(retrieval_attempts),
        "retrieval_attempts": retrieval_attempts,
        "browser_confirmation_count": sum(
            1
            for item in browser_confirmation_results
            if item.get("success") and item.get("confirmed_execution")
        ),
        "browser_confirmation_results": browser_confirmation_results,
        "findings": recorded_findings,
    }

def _sqlmap_scan_kwargs_from_context(
    context: dict[str, Any],
    *,
    parameter_name: str,
) -> dict[str, Any]:
    base_request = dict(context.get("base_request") or {})
    headers = dict(base_request.get("headers") or {})
    cookies = dict(base_request.get("cookies") or {})
    if cookies and "Cookie" not in headers and "cookie" not in headers:
        headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())

    data = None
    if base_request.get("json_body") is not None:
        data = json.dumps(base_request["json_body"], ensure_ascii=False)
    elif base_request.get("body") is not None:
        data = str(base_request.get("body"))

    return {
        "url": str(base_request.get("url") or context.get("url") or ""),
        "headers": headers,
        "data": data,
        "parameter": parameter_name,
    }


def _tool_findings_for_runs(
    store: dict[str, TOOL_RUN],
    run_ids: list[str],
) -> list[tuple[str, dict[str, Any]]]:
    findings: list[tuple[str, dict[str, Any]]] = []
    for run_id in run_ids:
        record = store.get(str(run_id))
        if record is None:
            continue
        tool_name = str(record.get("tool_name") or "")
        for finding in list(record.get("findings") or []):
            if isinstance(finding, dict):
                findings.append((tool_name, finding))
    return findings


def _stored_tool_runs(
    store: dict[str, TOOL_RUN],
    *,
    target: str,
    tool_name: str | None = None,
) -> list[TOOL_RUN]:
    runs = [
        record
        for record in store.values()
        if str(record.get("target") or "") == target
        and (tool_name is None or str(record.get("tool_name") or "") == tool_name)
    ]
    runs.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
    return runs


def _stored_findings(
    store: dict[str, TOOL_RUN],
    *,
    target: str,
    tool_name: str | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for record in _stored_tool_runs(store, target=target, tool_name=tool_name):
        for finding in list(record.get("findings") or []):
            if isinstance(finding, dict):
                findings.append(finding)
    return findings


def _correlate_tool_run_signals(
    agent_state: Any,
    *,
    logical_target: str,
    store: dict[str, TOOL_RUN],
    run_ids: list[str],
    max_hypotheses: int,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for tool_name, finding in _tool_findings_for_runs(store, run_ids):
        triage = (
            dict(finding.get("triage") or {})
            if isinstance(finding.get("triage"), dict)
            else _triage_scanner_finding(tool_name, finding)
        )
        vulnerability_type = str(
            triage.get("vulnerability_type") or _infer_vulnerability_type(tool_name, finding)
        )
        if vulnerability_type in {"scanner_finding", "misconfiguration"} and tool_name not in {
            "trivy",
        }:
            continue
        host = _host_for_finding(tool_name, finding)
        path = _path_for_finding(finding)
        key = (host, path, vulnerability_type)
        bucket = grouped.setdefault(
            key,
            {
                "host": host,
                "path": path,
                "vulnerability_type": vulnerability_type,
                "tools": [],
                "signals": [],
                "max_priority": "low",
                "max_confidence": "low",
                "verification_state": "raw",
                "focus_candidates": [],
                "score": 0,
            },
        )
        if tool_name not in bucket["tools"]:
            bucket["tools"].append(tool_name)
        bucket["signals"].append(finding)
        finding_priority = str(triage.get("priority") or _priority_from_severity(
            str(finding.get("severity") or finding.get("priority") or "medium")
        ))
        if VALID_PRIORITIES.index(finding_priority) > VALID_PRIORITIES.index(bucket["max_priority"]):
            bucket["max_priority"] = finding_priority
        confidence = str(triage.get("confidence") or "low")
        if _confidence_rank(confidence) > _confidence_rank(str(bucket["max_confidence"])):
            bucket["max_confidence"] = confidence
        verification_state = str(triage.get("verification_state") or "raw")
        if _verification_rank(verification_state) > _verification_rank(str(bucket["verification_state"])):
            bucket["verification_state"] = verification_state
        bucket["focus_candidates"] = _unique_strings(
            [
                *list(bucket["focus_candidates"]),
                *[
                    str(item).strip()
                    for item in list(triage.get("focus_candidates") or [])
                    if str(item).strip()
                ],
            ]
        )
        bucket["score"] += 1 + _confidence_rank(confidence)

    correlated: list[dict[str, Any]] = []
    for bucket in grouped.values():
        tool_count = len(bucket["tools"])
        if tool_count < 2:
            continue
        if int(bucket["score"]) < 4 and str(bucket["max_priority"]) not in {"high", "critical"}:
            continue
        path_priority = _priority_for_path(str(bucket["path"]))
        priority = bucket["max_priority"]
        if VALID_PRIORITIES.index(path_priority) > VALID_PRIORITIES.index(priority):
            priority = path_priority
        confidence = (
            "high"
            if int(bucket["score"]) >= 6 or str(bucket["verification_state"]) == "validated"
            else "medium"
        )
        hypothesis_result = record_hypothesis(
            agent_state=agent_state,
            hypothesis=(
                f"Correlated tool signals suggest {bucket['vulnerability_type']} exposure "
                f"on {bucket['host']}{bucket['path']}"
            ),
            target=logical_target,
            component=f"correlated:{bucket['host']}{bucket['path']}",
            vulnerability_type=str(bucket["vulnerability_type"]),
            status="open",
            priority=priority,
            rationale=(
                f"Multiple tools reported consistent signals on {bucket['host']}{bucket['path']}: "
                f"{', '.join(bucket['tools'])}. Confidence={confidence}; "
                f"verification_state=correlated."
            ),
        )
        correlated.append(
            {
                "host": bucket["host"],
                "path": bucket["path"],
                "vulnerability_type": bucket["vulnerability_type"],
                "tools": bucket["tools"],
                "signal_count": len(bucket["signals"]),
                "confidence": confidence,
                "verification_state": "correlated",
                "focus_candidates": list(bucket["focus_candidates"]),
                "hypothesis_result": hypothesis_result,
            }
        )
        if len(correlated) >= max_hypotheses:
            break
    return correlated


def _auto_followup_score(
    tool_name: str,
    finding: dict[str, Any],
    *,
    confidence: str,
    verification_state: str,
    focus: str,
) -> int:
    path = _path_for_finding(finding)
    parameter_name = str(finding.get("parameter") or "").strip()
    signal_text = _finding_signal_text(finding)
    score = 1 + _confidence_rank(confidence)
    if verification_state == "validated":
        score += 2
    elif verification_state == "correlated":
        score += 1
    if tool_name == "arjun":
        score += 1
    if _looks_sensitive_path(path):
        score += 1
    if parameter_name and _priority_rank(_priority_for_parameter(parameter_name)) >= _priority_rank("high"):
        score += 1
    if focus in {"authz", "workflow_race"} and any(
        keyword in path.lower()
        for keyword in ("account", "admin", "checkout", "invoice", "order", "payment", "tenant")
    ):
        score += 1
    score += _focus_signal_boost(
        focus,
        path=path,
        parameter_name=parameter_name,
        text=signal_text,
    )
    return score


def _collect_auto_followup_focuses(
    *,
    store: dict[str, TOOL_RUN],
    run_ids: list[str],
    correlated_hypotheses: list[dict[str, Any]],
    deep: bool,
    max_followups: int,
) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for tool_name, finding in _tool_findings_for_runs(store, run_ids):
        triage = finding.get("triage") if isinstance(finding.get("triage"), dict) else {}
        focus_candidates = [
            str(item).strip()
            for item in list(triage.get("focus_candidates") or _focus_candidates_for_finding(tool_name, finding))
            if str(item).strip()
        ]
        if not focus_candidates:
            continue
        path = _path_for_finding(finding)
        confidence = str(triage.get("confidence") or "")
        if not confidence:
            confidence = "medium" if tool_name == "arjun" or _looks_sensitive_path(path) else "low"
        verification_state = str(triage.get("verification_state") or "raw")
        candidate_url = _finding_candidate_url(tool_name, finding)
        reason = str(
            finding.get("name")
            or finding.get("template_id")
            or finding.get("parameter")
            or finding.get("path")
            or tool_name
        )

        for focus in focus_candidates:
            score = _auto_followup_score(
                tool_name,
                finding,
                confidence=confidence,
                verification_state=verification_state,
                focus=focus,
            )
            bucket = buckets.setdefault(
                focus,
                {
                    "focus": focus,
                    "confidence": "low",
                    "verification_state": "raw",
                    "score": 0,
                    "tools": [],
                    "reasons": [],
                    "candidate_urls": [],
                },
            )
            bucket["score"] += score
            if _confidence_rank(confidence) > _confidence_rank(str(bucket["confidence"])):
                bucket["confidence"] = confidence
            if _verification_rank(verification_state) > _verification_rank(
                str(bucket["verification_state"])
            ):
                bucket["verification_state"] = verification_state
            if tool_name not in bucket["tools"]:
                bucket["tools"].append(tool_name)
            if reason not in bucket["reasons"]:
                bucket["reasons"].append(reason)
            if candidate_url and candidate_url not in bucket["candidate_urls"]:
                bucket["candidate_urls"].append(candidate_url)

    for item in correlated_hypotheses:
        focus_candidates = [
            str(candidate).strip()
            for candidate in list(item.get("focus_candidates") or [])
            if str(candidate).strip()
        ]
        if not focus_candidates:
            mapped_focus = _map_vulnerability_type_to_focus(
                str(item.get("vulnerability_type") or ""),
                text=str(item.get("vulnerability_type") or ""),
            )
            if mapped_focus:
                focus_candidates = [mapped_focus]
        for focus in focus_candidates:
            bucket = buckets.setdefault(
                focus,
                {
                    "focus": focus,
                    "confidence": "low",
                    "verification_state": "raw",
                    "score": 0,
                    "tools": [],
                    "reasons": [],
                    "candidate_urls": [],
                },
            )
            bucket["score"] += 2 + min(int(item.get("signal_count") or 0), 2)
            if _confidence_rank(str(item.get("confidence") or "medium")) > _confidence_rank(
                str(bucket["confidence"])
            ):
                bucket["confidence"] = str(item.get("confidence") or "medium")
            if _verification_rank("correlated") > _verification_rank(str(bucket["verification_state"])):
                bucket["verification_state"] = "correlated"
            for tool_name in list(item.get("tools") or []):
                if tool_name not in bucket["tools"]:
                    bucket["tools"].append(tool_name)
            reason = f"correlated {item.get('vulnerability_type')} on {item.get('path') or '/'}"
            if reason not in bucket["reasons"]:
                bucket["reasons"].append(reason)
            host = str(item.get("host") or "").strip()
            path = str(item.get("path") or "/").strip() or "/"
            if host:
                candidate_url = f"https://{host}{path}"
                if candidate_url not in bucket["candidate_urls"]:
                    bucket["candidate_urls"].append(candidate_url)

    minimum_score = 4 if deep else 5
    candidates = [
        {
            **bucket,
            "primary_url": (
                str(bucket["candidate_urls"][0]).strip() if list(bucket["candidate_urls"]) else None
            ),
        }
        for bucket in buckets.values()
        if int(bucket.get("score") or 0) >= minimum_score
        or str(bucket.get("verification_state") or "") == "validated"
    ]
    candidates.sort(
        key=lambda item: (
            -int(item.get("score") or 0),
            AUTO_FOCUS_PRIORITY.get(str(item.get("focus") or ""), 99),
            str(item.get("focus") or ""),
        )
    )
    return candidates[:max_followups]


def _run_pipeline_auto_followups(
    agent_state: Any,
    *,
    logical_target: str,
    steps: list[dict[str, Any]],
    store: dict[str, TOOL_RUN],
    run_ids: list[str],
    correlated_hypotheses: list[dict[str, Any]],
    deep: bool,
    max_active_targets: int,
    max_hypotheses: int,
    reuse_previous_runs: bool,
) -> list[dict[str, Any]]:
    from .assessment_hunt_actions import run_inventory_differential_hunt
    from .assessment_runtime_actions import map_runtime_surface
    from .assessment_workflow_actions import discover_workflows_from_requests

    candidate_focuses = _collect_auto_followup_focuses(
        store=store,
        run_ids=run_ids,
        correlated_hypotheses=correlated_hypotheses,
        deep=deep,
        max_followups=2 if deep else 1,
    )
    if not candidate_focuses:
        return []

    followup_results: list[dict[str, Any]] = []
    runtime_inventory_available = bool(_load_runtime_inventory_entries(agent_state, logical_target))
    workflow_inventory_available = bool(_load_discovered_workflows(agent_state, logical_target))
    session_profiles = _load_session_profiles(agent_state)
    proxy_manager = _get_focus_proxy_manager()

    for candidate in candidate_focuses:
        focus = str(candidate.get("focus") or "").strip()
        if not focus:
            continue
        primary_url = str(candidate.get("primary_url") or "").strip() or None
        target_inputs = (
            [_base_url(primary_url)] if primary_url and _base_url(primary_url) else None
        )

        runtime_result = None
        workflow_result = None
        differential_result = None
        focus_result = None
        skipped_reason = None

        if focus == "authz":
            if not runtime_inventory_available and proxy_manager is not None:
                runtime_result = map_runtime_surface(
                    agent_state=agent_state,
                    target=logical_target,
                    max_seed_items=max(max_hypotheses * 2, 20),
                )
                _append_pipeline_step(
                    steps,
                    step_name="map_runtime_surface",
                    result=runtime_result,
                    metadata={"trigger_focus": focus, "source_tools": list(candidate["tools"])},
                )
                runtime_inventory_available = bool(runtime_result.get("success"))
            if runtime_inventory_available and len(session_profiles) >= 2:
                differential_result = run_inventory_differential_hunt(
                    agent_state=agent_state,
                    target=logical_target,
                    max_endpoints=max(1, min(max_hypotheses, 6)),
                    min_priority="high",
                )
                _append_pipeline_step(
                    steps,
                    step_name="run_inventory_differential_hunt",
                    result=differential_result,
                    metadata={"trigger_focus": focus, "source_tools": list(candidate["tools"])},
                )
            else:
                skipped_reason = (
                    "authz follow-up needs runtime inventory and at least two session profiles"
                )
        elif focus == "workflow_race":
            if not workflow_inventory_available and proxy_manager is not None:
                workflow_result = discover_workflows_from_requests(
                    agent_state=agent_state,
                    target=logical_target,
                    max_workflows=max(4, max_hypotheses),
                )
                _append_pipeline_step(
                    steps,
                    step_name="discover_workflows_from_requests",
                    result=workflow_result,
                    metadata={"trigger_focus": focus, "source_tools": list(candidate["tools"])},
                )
                workflow_inventory_available = bool(workflow_result.get("success"))
            if not workflow_inventory_available:
                skipped_reason = "workflow race follow-up needs proxy traffic or stored workflows"
        elif primary_url is None:
            skipped_reason = "focus follow-up needs a concrete URL candidate"

        if skipped_reason is None:
            focus_result = run_security_focus_pipeline(
                agent_state=agent_state,
                target=logical_target,
                focus=focus,
                targets=target_inputs,
                url=primary_url,
                max_active_targets=max(1, min(max_active_targets, 2)),
                max_hypotheses=max_hypotheses,
                reuse_previous_runs=reuse_previous_runs,
                auto_synthesize_hypotheses=False,
            )
            _append_pipeline_step(
                steps,
                step_name=f"focus:{focus}",
                result=focus_result,
                metadata={
                    "source_tools": list(candidate["tools"]),
                    "confidence": candidate.get("confidence"),
                    "verification_state": candidate.get("verification_state"),
                },
            )

        followup_results.append(
            {
                "focus": focus,
                "confidence": candidate.get("confidence"),
                "verification_state": candidate.get("verification_state"),
                "score": candidate.get("score"),
                "source_tools": list(candidate.get("tools") or []),
                "reasons": list(candidate.get("reasons") or []),
                "primary_url": primary_url,
                "runtime_result": runtime_result,
                "workflow_result": workflow_result,
                "differential_result": differential_result,
                "focus_result": focus_result,
                "skipped": skipped_reason is not None,
                "skipped_reason": skipped_reason,
            }
        )

    return followup_results


def _runtime_suggests_xxe(runtime_entries: list[dict[str, Any]]) -> bool:
    xml_markers = ("xml", "soap", "svg", "rss", "atom")
    for entry in runtime_entries:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("normalized_path") or "").strip().lower()
        if path.endswith(".xml") or any(marker in path for marker in ("/xml", "/soap", "/wsdl")):
            return True
        for content_type in list(entry.get("content_types") or []):
            lowered = str(content_type).strip().lower()
            if any(marker in lowered for marker in xml_markers):
                return True
    return False


def _runtime_entry_parameter_names(entry: dict[str, Any]) -> list[str]:
    parameters: list[str] = []
    for field in ("query_params", "body_params", "path_params", "header_params"):
        for item in list(entry.get(field) or []):
            normalized = str(item).strip().lower()
            if normalized and normalized not in parameters:
                parameters.append(normalized)
    return parameters


def _runtime_suggests_workflow_race(runtime_entries: list[dict[str, Any]]) -> bool:
    keywords = tuple(AUTO_FOCUS_SIGNAL_KEYWORDS.get("workflow_race") or [])
    for entry in runtime_entries:
        if not isinstance(entry, dict):
            continue
        methods = {
            str(method).strip().upper()
            for method in list(entry.get("methods") or [])
            if str(method).strip()
        }
        if not methods.intersection(STATE_CHANGING_METHODS):
            continue
        searchable = " ".join(
            [
                str(entry.get("normalized_path") or ""),
                *[str(item) for item in list(entry.get("query_params") or [])],
                *[str(item) for item in list(entry.get("body_params") or [])],
            ]
        ).lower()
        if any(keyword in searchable for keyword in keywords):
            return True
    return False


def _post_auth_runtime_focuses(
    runtime_entries: list[dict[str, Any]],
    surface_artifacts: list[dict[str, Any]],
) -> list[str]:
    hinted_focuses: list[str] = []
    runtime_baseline_focuses: list[str] = []
    for entry in runtime_entries:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("normalized_path") or "").strip().lower()
        parameters = _runtime_entry_parameter_names(entry)
        content_types = [
            str(item).strip().lower()
            for item in list(entry.get("content_types") or [])
            if str(item).strip()
        ]
        sample_urls = [
            str(item).strip().lower()
            for item in list(entry.get("sample_urls") or [])
            if str(item).strip()
        ]
        searchable = " ".join([path, *parameters, *content_types, *sample_urls]).lower()

        if parameters:
            runtime_baseline_focuses.extend(["sqli", "xss", "ssrf_oob", "path_traversal"])
        elif path:
            runtime_baseline_focuses.extend(["xss", "path_traversal"])

        if any(keyword in parameter for keyword in FOCUS_PARAMETER_HINTS["ssrf_oob"] for parameter in parameters):
            hinted_focuses.append("ssrf_oob")
        if any(keyword in searchable for keyword in ("callback", "webhook", "proxy", "fetch", "relay")):
            hinted_focuses.append("ssrf_oob")

        if any(keyword in parameter for keyword in FOCUS_PARAMETER_HINTS["sqli"] for parameter in parameters):
            hinted_focuses.append("sqli")
        if any(keyword in searchable for keyword in ("query", "search", "report", "filter", "sort", "analytics")):
            hinted_focuses.append("sqli")

        if any(keyword in parameter for keyword in FOCUS_PARAMETER_HINTS["xss"] for parameter in parameters):
            hinted_focuses.append("xss")
        if any(
            keyword in searchable
            for keyword in ("search", "comment", "feedback", "message", "preview", "bio", "description")
        ):
            hinted_focuses.append("xss")

        if any(keyword in parameter for keyword in FOCUS_PARAMETER_HINTS["open_redirect"] for parameter in parameters):
            hinted_focuses.append("open_redirect")
        if any(keyword in searchable for keyword in ("redirect", "bounce", "continue", "return", "relay")):
            hinted_focuses.append("open_redirect")

        if any(keyword in parameter for keyword in FOCUS_PARAMETER_HINTS["ssti"] for parameter in parameters):
            hinted_focuses.append("ssti")
        if any(keyword in searchable for keyword in ("template", "render")):
            hinted_focuses.append("ssti")

        if any(
            keyword in parameter
            for keyword in FOCUS_PARAMETER_HINTS["path_traversal"]
            for parameter in parameters
        ):
            hinted_focuses.append("path_traversal")
        if any(
            keyword in searchable
            for keyword in ("download", "export", "attachment", "document", "avatar", "image", "file")
        ):
            hinted_focuses.append("path_traversal")

        if any(marker in content_type for marker in XML_CONTENT_TYPE_MARKERS for content_type in content_types):
            hinted_focuses.append("xxe")
        if any(keyword in searchable for keyword in XML_PATH_KEYWORDS):
            hinted_focuses.append("xxe")

        if any("multipart/form-data" in content_type for content_type in content_types):
            hinted_focuses.append("file_upload")
        if any(
            keyword in searchable
            for keyword in ("upload", "avatar", "attachment", "document", "image", "import")
        ):
            hinted_focuses.append("file_upload")

    for artifact in surface_artifacts:
        if not isinstance(artifact, dict):
            continue
        searchable = " ".join(
            [
                str(artifact.get("kind") or ""),
                str(artifact.get("path") or ""),
                str(artifact.get("url") or ""),
                str(artifact.get("title") or ""),
            ]
        ).strip().lower()
        if not searchable:
            continue
        if any(keyword in searchable for keyword in ("redirect", "bounce", "continue")):
            hinted_focuses.append("open_redirect")
        if any(keyword in searchable for keyword in ("template", "render")):
            hinted_focuses.append("ssti")
        if any(keyword in searchable for keyword in ("upload", "avatar", "attachment", "image")):
            hinted_focuses.append("file_upload")
        if any(keyword in searchable for keyword in XML_PATH_KEYWORDS):
            hinted_focuses.append("xxe")

    deduped: list[str] = []
    for focus in [*runtime_baseline_focuses, *hinted_focuses]:
        if focus not in deduped:
            deduped.append(focus)
    return deduped


def _post_auth_focus_order(
    *,
    session_profiles: list[dict[str, Any]],
    runtime_entries: list[dict[str, Any]],
    surface_artifacts: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
) -> list[str]:
    focuses: list[str] = []
    if len(session_profiles) >= 2:
        focuses.append("authz")
    if workflows or _runtime_suggests_workflow_race(runtime_entries):
        focuses.append("workflow_race")
    focuses.extend(
        _post_auth_runtime_focuses(
            runtime_entries,
            surface_artifacts,
        )
    )
    if runtime_entries and _runtime_suggests_xxe(runtime_entries):
        focuses.append("xxe")
    deduped: list[str] = []
    for focus in focuses:
        if focus not in deduped:
            deduped.append(focus)
    return deduped


def _run_post_auth_deepening(
    agent_state: Any,
    *,
    logical_target: str,
    steps: list[dict[str, Any]],
    runtime_entries: list[dict[str, Any]],
    surface_artifacts: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    max_active_targets: int,
    max_hypotheses: int,
    reuse_previous_runs: bool,
) -> dict[str, Any] | None:
    from .assessment_hunt_actions import run_inventory_differential_hunt
    from .assessment_session_actions import extract_session_profiles_from_requests

    session_profiles = _load_session_profiles(agent_state)
    proxy_manager = _get_focus_proxy_manager()
    if not session_profiles and not runtime_entries and not workflows and not surface_artifacts:
        return None

    extract_profiles_result = None
    if len(session_profiles) < 2 and proxy_manager is not None and (
        runtime_entries or workflows or surface_artifacts
    ):
        extract_profiles_result = extract_session_profiles_from_requests(
            agent_state=agent_state,
            start_page=1,
            end_page=2,
            page_size=30,
            name_prefix="postauth",
            include_unauthenticated=True,
            max_profiles=6,
        )
        _append_pipeline_step(
            steps,
            step_name="extract_session_profiles_from_requests",
            result=extract_profiles_result,
            metadata={"source": "post_auth_deepening"},
        )
        if extract_profiles_result.get("success"):
            session_profiles = _load_session_profiles(agent_state)

    differential_result = None
    if runtime_entries and len(session_profiles) >= 2:
        differential_result = run_inventory_differential_hunt(
            agent_state=agent_state,
            target=logical_target,
            max_endpoints=max(6, min(max_hypotheses, 12)),
            min_priority="normal",
            include_state_changing=True,
        )
        _append_pipeline_step(
            steps,
            step_name="run_inventory_differential_hunt",
            result=differential_result,
            metadata={"source": "post_auth_deepening"},
        )

    candidate_urls = _unique_strings(
        [
            *_candidate_urls_from_runtime_entries(runtime_entries),
            *_candidate_urls_from_surface_artifacts(surface_artifacts),
        ]
    )
    primary_url = candidate_urls[0] if candidate_urls else None
    target_inputs = (
        [_base_url(primary_url)] if primary_url and _base_url(primary_url) else None
    )

    focus_results: list[dict[str, Any]] = []
    for focus in _post_auth_focus_order(
        session_profiles=session_profiles,
        runtime_entries=runtime_entries,
        surface_artifacts=surface_artifacts,
        workflows=workflows,
    ):
        focus_result = run_security_focus_pipeline(
            agent_state=agent_state,
            target=logical_target,
            focus=focus,
            targets=target_inputs,
            url=primary_url,
            max_active_targets=max(2, min(max_active_targets + 1, 4)),
            max_hypotheses=max(max_hypotheses, 8),
            reuse_previous_runs=reuse_previous_runs,
            auto_build_review=False,
            auto_spawn_review_agents=False,
            auto_spawn_signal_agents=False,
            auto_spawn_impact_agents=False,
            auto_synthesize_hypotheses=False,
        )
        _append_pipeline_step(
            steps,
            step_name=f"post_auth_focus:{focus}",
            result=focus_result,
            metadata={
                "source": "post_auth_deepening",
                "primary_url": primary_url,
                "candidate_url_count": len(candidate_urls),
            },
        )
        focus_results.append(
            {
                "focus": focus,
                "success": bool(focus_result.get("success")),
                "step_count": int(focus_result.get("step_count") or 0)
                if isinstance(focus_result, dict)
                else 0,
                "active_probe_count": len(list(focus_result.get("active_probe_results") or []))
                if isinstance(focus_result, dict)
                else 0,
            }
        )

    return {
        "session_profile_count": len(session_profiles),
        "candidate_url_count": len(candidate_urls),
        "extract_profiles_result": extract_profiles_result,
        "differential_result": differential_result,
        "focus_results": focus_results,
    }


@register_tool(sandbox_execution=False)
def run_security_tool_pipeline(
    agent_state: Any,
    target: str,
    mode: str = "blackbox",
    targets: list[str] | None = None,
    url: str | None = None,
    target_path: str | None = None,
    deep: bool = False,
    max_host_targets: int = 20,
    max_live_targets: int = 8,
    max_active_targets: int = 3,
    max_seed_items: int = 25,
    max_hypotheses: int = 12,
    reuse_previous_runs: bool = True,
    auto_build_review: bool = True,
    auto_spawn_review_agents: bool = True,
    auto_spawn_signal_agents: bool = True,
    auto_spawn_impact_agents: bool = True,
    auto_synthesize_hypotheses: bool = True,
) -> dict[str, Any]:
    try:
        from .assessment_creative_actions import synthesize_attack_hypotheses

        normalized_target = _normalize_non_empty(target, "target")
        normalized_mode = _normalize_pipeline_mode(mode)
        if max_host_targets < 1:
            raise ValueError("max_host_targets must be >= 1")
        if max_live_targets < 1:
            raise ValueError("max_live_targets must be >= 1")
        if max_active_targets < 1:
            raise ValueError("max_active_targets must be >= 1")

        provided_targets = _normalize_targets(targets)
        if url:
            provided_targets = _unique_strings([*provided_targets, str(url).strip()])

        root_agent_id, store = _get_tool_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        desired_tools: list[str] = []
        if normalized_mode in {"blackbox", "hybrid"}:
            desired_tools.extend(
                [
                    "subfinder",
                    "httpx",
                    "naabu",
                    "katana",
                    "nuclei",
                    "ffuf",
                    "arjun",
                    "dirsearch",
                    "wafw00f",
                ]
            )
            if deep:
                desired_tools.extend(["nmap", "sqlmap", "wapiti", "zaproxy"])
        if normalized_mode in {"repo", "hybrid"} and target_path:
            desired_tools.extend(["semgrep", "bandit", "trivy", "trufflehog"])
        available_result = security_tool_doctor(
            agent_state=agent_state,
            tool_names=_unique_strings(desired_tools),
        )
        available_tools = {
            str(item.get("tool_name"))
            for item in available_result.get("tools", [])
            if item.get("available")
        }
        skipped_tools = [
            str(item.get("tool_name"))
            for item in available_result.get("tools", [])
            if not item.get("available")
        ]

        steps: list[dict[str, Any]] = []
        discovered_hosts: list[str] = []
        live_urls: list[str] = []
        sqlmap_candidates: list[dict[str, str]] = []
        default_fuzz_wordlist = _resolve_effective_wordlist_path("ffuf", None)
        attack_surface_review_result = None
        attack_surface_agent_result = None
        strong_signal_agent_result = None
        impact_chain_agent_result = None
        enrichment_result = None
        post_auth_deepening_result = None

        def run_step(
            step_name: str,
            *,
            metadata: dict[str, Any] | None = None,
            include_findings: bool = True,
            **scan_kwargs: Any,
        ) -> dict[str, Any]:
            result = _execute_or_reuse_tool_scan(
                agent_state=agent_state,
                store=store,
                reuse_previous_runs=reuse_previous_runs,
                tool_name=step_name,
                target=normalized_target,
                include_findings=include_findings,
                **scan_kwargs,
            )
            step_metadata = dict(metadata or {})
            if result.get("reused_existing_run"):
                step_metadata["reused_existing_run"] = True
            _append_pipeline_step(
                steps,
                step_name=step_name,
                result=result,
                metadata=step_metadata,
            )
            return result

        if normalized_mode in {"blackbox", "hybrid"}:
            domain_targets = [item for item in provided_targets if item and not _is_http_url(item)]
            direct_url_targets = [item for item in provided_targets if _is_http_url(item)]

            if domain_targets and "subfinder" in available_tools:
                subfinder_result = run_step(
                    "subfinder",
                    targets=domain_targets,
                    recursion=True,
                    collect_sources=True,
                    max_seed_items=max_seed_items,
                )
                discovered_hosts.extend(_extract_host_targets(subfinder_result.get("findings", [])))

            host_candidates = _unique_strings([*domain_targets, *discovered_hosts])
            httpx_targets = _unique_strings([*direct_url_targets, *host_candidates])[:max_host_targets]
            if httpx_targets and "httpx" in available_tools:
                httpx_result = run_step(
                    "httpx",
                    targets=httpx_targets,
                    paths=(DEFAULT_HTTPX_PATHS if deep else ["/"]),
                    max_seed_items=max_seed_items,
                )
                discovered_hosts.extend(_extract_host_targets(httpx_result.get("findings", [])))
                live_urls.extend(_extract_live_urls(httpx_result.get("findings", [])))

            host_targets = _unique_strings(discovered_hosts)[:max_host_targets]
            naabu_ports_by_host: dict[str, list[int]] = {}
            if host_targets and "naabu" in available_tools:
                naabu_result = run_step(
                    "naabu",
                    targets=host_targets,
                    top_ports=(1000 if deep else 200),
                    max_seed_items=max_seed_items,
                )
                naabu_ports_by_host = _extract_open_ports_by_host(
                    list(naabu_result.get("findings") or [])
                )

            if host_targets and deep and "nmap" in available_tools:
                selected_nmap_targets = host_targets[: max(1, min(max_active_targets, len(host_targets)))]
                selected_ports: list[int] = []
                for host in selected_nmap_targets:
                    selected_ports.extend(naabu_ports_by_host.get(host, []))
                deduped_ports = sorted({port for port in selected_ports if port > 0})
                run_step(
                    "nmap",
                    targets=selected_nmap_targets,
                    ports=",".join(str(port) for port in deduped_ports) if deduped_ports else None,
                    top_ports=None if deduped_ports else 200,
                    service_detection=True,
                    default_scripts=True,
                    max_seed_items=max_seed_items,
                    max_hypotheses=max_hypotheses,
                )

            crawl_targets = _unique_strings(live_urls)[:max_live_targets]
            waf_targets = _unique_strings(
                [candidate for candidate in (_base_url(item) for item in crawl_targets) if candidate]
            )[:max_active_targets]
            for waf_target in waf_targets:
                if "wafw00f" not in available_tools:
                    break
                run_step(
                    "wafw00f",
                    url=waf_target,
                    max_seed_items=max_seed_items,
                    metadata={"url": waf_target},
                )

            if crawl_targets and "katana" in available_tools:
                katana_result = run_step(
                    "katana",
                    targets=crawl_targets,
                    use_js_crawl=True,
                    headless=deep,
                    max_seed_items=max_seed_items,
                )
                live_urls.extend(_extract_live_urls(katana_result.get("findings", [])))

            if crawl_targets and "nuclei" in available_tools:
                run_step(
                    "nuclei",
                    targets=crawl_targets,
                    automatic_scan=True,
                    max_hypotheses=max_hypotheses,
                )

            active_urls = _unique_strings([*crawl_targets, *live_urls])[:max_active_targets]
            for active_url in active_urls:
                if "arjun" in available_tools:
                    arjun_result = run_step(
                        "arjun",
                        url=active_url,
                        max_seed_items=max_seed_items,
                        max_hypotheses=max_hypotheses,
                        metadata={"url": active_url},
                    )
                    for finding in arjun_result.get("findings", []):
                        parameter_name = str(finding.get("parameter") or "").strip().lower()
                        if parameter_name in {"id", "query", "search", "filter", "sort"}:
                            candidate_url = _sqlmap_candidate_url(
                                str(finding.get("url") or active_url),
                                str(finding.get("parameter") or ""),
                            )
                            sqlmap_candidates.append(
                                {
                                    "url": candidate_url,
                                    "parameter": str(finding.get("parameter") or ""),
                                }
                            )
                if "dirsearch" in available_tools:
                    run_step(
                        "dirsearch",
                        url=active_url,
                        recursion=deep,
                        max_seed_items=max_seed_items,
                        metadata={"url": active_url},
                    )
                if "ffuf" in available_tools and default_fuzz_wordlist:
                    for fuzz_url in _ffuf_seed_urls([active_url], limit=2):
                        run_step(
                            "ffuf",
                            url=fuzz_url,
                            wordlist_path=default_fuzz_wordlist,
                            recursion=deep,
                            max_seed_items=max_seed_items,
                            metadata={"url": fuzz_url, "wordlist_path": default_fuzz_wordlist},
                        )
                if deep and "wapiti" in available_tools:
                    wapiti_result = run_step(
                        "wapiti",
                        url=active_url,
                        max_hypotheses=max_hypotheses,
                        metadata={"url": active_url},
                    )
                    for finding in wapiti_result.get("findings", []):
                        if str(finding.get("name") or "").strip().lower() not in {"sql", "blindsql"}:
                            continue
                        parameter_name = str(finding.get("parameter") or "").strip() or "id"
                        sqlmap_candidates.append(
                            {
                                "url": _sqlmap_candidate_url(
                                    str(finding.get("url") or active_url),
                                    parameter_name,
                                ),
                                "parameter": parameter_name,
                            }
                        )
                if deep and "zaproxy" in available_tools:
                    run_step(
                        "zaproxy",
                        url=active_url,
                        zapit=True,
                        max_hypotheses=max_hypotheses,
                        metadata={"url": active_url},
                    )
            if deep and "sqlmap" in available_tools:
                deduped_candidates: list[dict[str, str]] = []
                seen_candidates: set[tuple[str, str]] = set()
                for item in sqlmap_candidates:
                    key = (item["url"], item["parameter"])
                    if key in seen_candidates:
                        continue
                    seen_candidates.add(key)
                    deduped_candidates.append(item)
                for item in deduped_candidates[:max_active_targets]:
                    run_step(
                        "sqlmap",
                        url=item["url"],
                        parameter=item["parameter"],
                        max_hypotheses=max_hypotheses,
                        metadata={"url": item["url"], "parameter": item["parameter"]},
                    )

        if normalized_mode in {"repo", "hybrid"} and target_path:
            for repo_tool_name in ["semgrep", "bandit", "trivy", "trufflehog"]:
                if repo_tool_name not in available_tools:
                    continue
                run_step(
                    repo_tool_name,
                    target_path=target_path,
                    max_hypotheses=max_hypotheses,
                )

        if normalized_mode in {"blackbox", "hybrid"}:
            enrichment_result = _run_inventory_enrichment(
                agent_state=agent_state,
                target=normalized_target,
                steps=steps,
                max_seed_items=max_seed_items,
                max_hypotheses=max_hypotheses,
                include_workflows=deep,
            )
            if deep and isinstance(enrichment_result, dict):
                post_auth_deepening_result = _run_post_auth_deepening(
                    agent_state=agent_state,
                    logical_target=normalized_target,
                    steps=steps,
                    runtime_entries=[
                        item
                        for item in list(enrichment_result.get("runtime_entries") or [])
                        if isinstance(item, dict)
                    ],
                    surface_artifacts=[
                        item
                        for item in list(enrichment_result.get("surface_artifacts") or [])
                        if isinstance(item, dict)
                    ],
                    workflows=[
                        item
                        for item in list(enrichment_result.get("workflows") or [])
                        if isinstance(item, dict)
                    ],
                    max_active_targets=max_active_targets,
                    max_hypotheses=max_hypotheses,
                    reuse_previous_runs=reuse_previous_runs,
                )

        successful_steps = [step for step in steps if step.get("success")]
        run_ids = [str(step.get("run_id")) for step in successful_steps if step.get("run_id")]
        reused_step_count = sum(
            1 for step in successful_steps if bool(step.get("metadata", {}).get("reused_existing_run"))
        )
        correlated_hypotheses = _correlate_tool_run_signals(
            agent_state=agent_state,
            logical_target=normalized_target,
            store=store,
            run_ids=run_ids,
            max_hypotheses=max_hypotheses,
        )
        auto_followup_results = _run_pipeline_auto_followups(
            agent_state=agent_state,
            logical_target=normalized_target,
            steps=steps,
            store=store,
            run_ids=run_ids,
            correlated_hypotheses=correlated_hypotheses,
            deep=deep,
            max_active_targets=max_active_targets,
            max_hypotheses=max_hypotheses,
            reuse_previous_runs=reuse_previous_runs,
        )
        successful_steps = [step for step in steps if step.get("success")]
        run_ids = [str(step.get("run_id")) for step in successful_steps if step.get("run_id")]
        reused_step_count = sum(
            1 for step in successful_steps if bool(step.get("metadata", {}).get("reused_existing_run"))
        )
        synthesized_result = None
        if auto_synthesize_hypotheses:
            synthesized_result = synthesize_attack_hypotheses(
                agent_state=agent_state,
                target=normalized_target,
                max_hypotheses=max_hypotheses,
                persist=True,
                include_existing_open=False,
            )
        if auto_build_review:
            review_scope_targets = _attack_surface_review_scope_targets(
                provided_targets,
                discovered_hosts,
                live_urls,
                [str(url).strip()] if url else [],
            )
            attack_surface_review_result = _build_pipeline_attack_surface_review(
                agent_state=agent_state,
                target=normalized_target,
                scope_targets=review_scope_targets,
                max_priorities=max_hypotheses,
            )
            _persist_pipeline_attack_surface_review(agent_state, attack_surface_review_result)
            review_snapshot = _attack_surface_review_snapshot(attack_surface_review_result) or {}
            _append_pipeline_step(
                steps,
                step_name="build_attack_surface_review",
                result=attack_surface_review_result,
                metadata={
                    "scope_target_count": len(review_scope_targets),
                    "needs_more_data": (
                        review_snapshot.get("summary", {}).get("needs_more_data")
                        if isinstance(review_snapshot.get("summary"), dict)
                        else None
                    ),
                },
            )
            if auto_spawn_review_agents and attack_surface_review_result.get("success"):
                attack_surface_agent_result = _spawn_pipeline_attack_surface_agents(
                    agent_state=agent_state,
                    target=normalized_target,
                    max_active_targets=max_active_targets,
                    strategy="coverage_first",
                )
                _append_pipeline_step(
                    steps,
                    step_name="spawn_attack_surface_agents",
                    result=attack_surface_agent_result,
                    metadata={
                        "strategy": "coverage_first",
                        "max_agents": _pipeline_review_agent_limit(max_active_targets),
                        "created_count": (
                            attack_surface_agent_result.get("created_count")
                            if isinstance(attack_surface_agent_result, dict)
                            else None
                        ),
                        "recommended_count": (
                            attack_surface_agent_result.get("recommended_count")
                            if isinstance(attack_surface_agent_result, dict)
                            else None
                        ),
                    },
                )
        if auto_spawn_signal_agents:
            candidate_signal_result = _spawn_pipeline_strong_signal_agents(
                agent_state=agent_state,
                target=normalized_target,
                max_active_targets=max_active_targets,
            )
            if (
                isinstance(candidate_signal_result, dict)
                and candidate_signal_result.get("success")
                and (
                    int(candidate_signal_result.get("recommended_count") or 0) > 0
                    or int(candidate_signal_result.get("skipped_count") or 0) > 0
                )
            ):
                strong_signal_agent_result = candidate_signal_result
                _append_pipeline_step(
                    steps,
                    step_name="spawn_strong_signal_agents",
                    result=strong_signal_agent_result,
                    metadata={
                        "max_agents": _pipeline_signal_agent_limit(max_active_targets),
                        "created_count": (
                            strong_signal_agent_result.get("created_count")
                            if isinstance(strong_signal_agent_result, dict)
                            else None
                        ),
                        "recommended_count": (
                            strong_signal_agent_result.get("recommended_count")
                            if isinstance(strong_signal_agent_result, dict)
                            else None
                        ),
                    },
                )
        if auto_spawn_impact_agents:
            candidate_impact_result = _spawn_pipeline_impact_chain_agents(
                agent_state=agent_state,
                target=normalized_target,
                max_active_targets=max_active_targets,
            )
            if (
                isinstance(candidate_impact_result, dict)
                and candidate_impact_result.get("success")
                and (
                    int(candidate_impact_result.get("recommended_count") or 0) > 0
                    or int(candidate_impact_result.get("skipped_count") or 0) > 0
                )
            ):
                impact_chain_agent_result = candidate_impact_result
                _append_pipeline_step(
                    steps,
                    step_name="spawn_impact_chain_agents",
                    result=impact_chain_agent_result,
                    metadata={
                        "max_agents": _pipeline_impact_agent_limit(max_active_targets),
                        "created_count": (
                            impact_chain_agent_result.get("created_count")
                            if isinstance(impact_chain_agent_result, dict)
                            else None
                        ),
                        "recommended_count": (
                            impact_chain_agent_result.get("recommended_count")
                            if isinstance(impact_chain_agent_result, dict)
                            else None
                        ),
                    },
                )
        successful_steps = [step for step in steps if step.get("success")]
        run_ids = [str(step.get("run_id")) for step in successful_steps if step.get("run_id")]
        summary_payload = {
            "mode": normalized_mode,
            "deep": deep,
            "step_count": len(steps),
            "successful_step_count": len(successful_steps),
            "reused_step_count": reused_step_count,
            "available_tools": sorted(available_tools),
            "skipped_tools": skipped_tools,
            "discovered_hosts": _unique_strings(discovered_hosts),
            "live_urls": _unique_strings(live_urls),
            "run_ids": run_ids,
            "inventory_enrichment": {
                "runtime_mapped": bool(
                    isinstance(enrichment_result, dict)
                    and enrichment_result.get("runtime_entries")
                ),
                "surface_mined": bool(
                    isinstance(enrichment_result, dict)
                    and enrichment_result.get("surface_artifacts")
                ),
                "workflows_mapped": bool(
                    isinstance(enrichment_result, dict)
                    and enrichment_result.get("workflows")
                ),
            },
            "post_auth_deepening_result": post_auth_deepening_result,
            "correlated_hypothesis_count": len(correlated_hypotheses),
            "auto_followup_count": len(auto_followup_results),
            "auto_followup_results": auto_followup_results,
            "attack_surface_review": _attack_surface_review_snapshot(
                attack_surface_review_result
            ),
            "attack_surface_agent_result": attack_surface_agent_result,
            "strong_signal_agent_result": strong_signal_agent_result,
            "impact_chain_agent_result": impact_chain_agent_result,
            "synthesized_hypothesis_count": (
                int(synthesized_result.get("hypothesis_count") or 0)
                if isinstance(synthesized_result, dict) and synthesized_result.get("success")
                else 0
            ),
            "steps": steps,
        }
        summary_evidence = record_evidence(
            agent_state=agent_state,
            title=f"Security tool pipeline summary for {normalized_target}",
            details=json.dumps(summary_payload, ensure_ascii=False),
            source="tool",
            target=normalized_target,
            component=f"toolchain:pipeline:{normalized_mode}",
        )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to run security tool pipeline: {e}"}
    else:
        return {
            "success": True,
            "root_agent_id": root_agent_id,
            "mode": normalized_mode,
            "deep": deep,
            "available_tools": sorted(available_tools),
            "skipped_tools": skipped_tools,
            "step_count": len(steps),
            "successful_step_count": len(successful_steps),
            "reused_step_count": reused_step_count,
            "run_ids": run_ids,
            "discovered_hosts": _unique_strings(discovered_hosts),
            "live_urls": _unique_strings(live_urls),
            "steps": steps,
            "inventory_enrichment_result": enrichment_result,
            "post_auth_deepening_result": post_auth_deepening_result,
            "correlated_hypotheses": correlated_hypotheses,
            "auto_followup_results": auto_followup_results,
            "attack_surface_review_result": attack_surface_review_result,
            "attack_surface_agent_result": attack_surface_agent_result,
            "strong_signal_agent_result": strong_signal_agent_result,
            "impact_chain_agent_result": impact_chain_agent_result,
            "synthesized_hypotheses_result": synthesized_result,
            "evidence_result": summary_evidence,
        }


@register_tool(sandbox_execution=False)
def run_security_tool_scan(
    agent_state: Any,
    tool_name: str,
    target: str,
    component: str | None = None,
    targets: list[str] | None = None,
    target_path: str | None = None,
    url: str | None = None,
    wordlist_path: str | None = None,
    raw_request_path: str | None = None,
    paths: list[str] | None = None,
    headers: dict[str, str] | None = None,
    data: str | None = None,
    request_method: str = "GET",
    ports: str | None = None,
    top_ports: int | None = None,
    parameter: str | None = None,
    configs: list[str] | None = None,
    tags: list[str] | None = None,
    severities: list[str] | None = None,
    proxy_url: str | None = None,
    automatic_scan: bool = False,
    active_only: bool = False,
    collect_sources: bool = False,
    no_interactsh: bool = False,
    use_js_crawl: bool = True,
    headless: bool = False,
    known_files: str = "robotstxt",
    recursion: bool = False,
    recursion_depth: int = 2,
    scan_type: str | None = None,
    host_discovery_disabled: bool = True,
    service_detection: bool = False,
    default_scripts: bool = False,
    store_response: bool = False,
    flush_session: bool = False,
    threads: int = 20,
    rate_limit: int = 50,
    concurrency: int = 20,
    bulk_size: int = 20,
    depth: int = 3,
    timeout: int = 10,
    retries: int = 1,
    max_time_minutes: int | None = None,
    host_timeout: str | None = None,
    script_timeout: str | None = None,
    level: int = 2,
    risk: int = 1,
    zapit: bool = False,
    jwt_token: str | None = None,
    canary_value: str | None = None,
    public_key_path: str | None = None,
    dictionary_path: str | None = None,
    output_path: str | None = None,
    include_findings: bool = False,
    max_seed_items: int = 25,
    max_hypotheses: int = 12,
) -> dict[str, Any]:
    try:
        normalized_tool_name = _normalize_tool_name(tool_name)
        logical_target = _normalize_non_empty(target, "target")
        logical_component = (
            _normalize_non_empty(component, "component")
            if component is not None
            else f"toolchain:{normalized_tool_name}"
        )
        normalized_targets = _normalize_targets(targets)
        normalized_paths = _normalize_paths(paths)
        normalized_headers = _normalize_headers(headers)
        normalized_request_method = str(request_method).strip().upper() or "GET"
        normalized_configs = [str(item).strip() for item in (configs or []) if str(item).strip()]
        normalized_tags = [str(item).strip() for item in (tags or []) if str(item).strip()]
        normalized_severities = [
            str(item).strip() for item in (severities or []) if str(item).strip()
        ]
        normalized_jwt_token = str(jwt_token).strip() if jwt_token is not None else None
        normalized_canary_value = (
            str(canary_value).strip() if canary_value is not None else None
        )
        normalized_public_key_path = (
            str(public_key_path).strip() if public_key_path is not None else None
        )
        normalized_dictionary_path = (
            str(dictionary_path).strip() if dictionary_path is not None else None
        )
        normalized_wordlist_path = _resolve_effective_wordlist_path(
            normalized_tool_name,
            wordlist_path,
        )

        if max_seed_items < 1:
            raise ValueError("max_seed_items must be >= 1")
        if max_hypotheses < 1:
            raise ValueError("max_hypotheses must be >= 1")

        root_agent_id, store = _get_tool_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        scope_payload = _build_scope_payload(
            tool_name=normalized_tool_name,
            target=logical_target,
            component=logical_component,
            targets=normalized_targets,
            target_path=target_path,
            url=url,
            raw_request_path=raw_request_path,
            paths=normalized_paths,
            headers=normalized_headers,
            data=data,
            request_method=normalized_request_method,
            ports=ports,
            top_ports=top_ports,
            parameter=parameter,
            configs=normalized_configs,
            tags=normalized_tags,
            severities=normalized_severities,
            automatic_scan=automatic_scan,
            active_only=active_only,
            collect_sources=collect_sources,
            no_interactsh=no_interactsh,
            use_js_crawl=use_js_crawl,
            headless=headless,
            known_files=known_files,
            recursion=recursion,
            recursion_depth=recursion_depth,
            scan_type=scan_type,
            service_detection=service_detection,
            default_scripts=default_scripts,
            flush_session=flush_session,
            level=level,
            risk=risk,
            zapit=zapit,
            jwt_token=normalized_jwt_token,
            canary_value=normalized_canary_value,
            public_key_path=normalized_public_key_path,
            dictionary_path=normalized_dictionary_path,
        )
        scope_key = _scope_key(scope_payload)
        resolved_output_path = _ensure_output_path(normalized_tool_name, output_path)
        started_at = _utc_now()
        try:
            command = _build_command(
                normalized_tool_name,
                targets=normalized_targets,
                target_path=target_path,
                url=url,
                wordlist_path=normalized_wordlist_path,
                raw_request_path=raw_request_path,
                paths=normalized_paths,
                headers=normalized_headers,
                data=data,
                request_method=normalized_request_method,
                ports=ports,
                top_ports=top_ports,
                parameter=parameter,
                configs=normalized_configs,
                tags=normalized_tags,
                severities=normalized_severities,
                proxy_url=proxy_url,
                automatic_scan=automatic_scan,
                active_only=active_only,
                collect_sources=collect_sources,
                no_interactsh=no_interactsh,
                use_js_crawl=use_js_crawl,
                headless=headless,
                known_files=known_files,
                recursion=recursion,
                recursion_depth=recursion_depth,
                scan_type=scan_type,
                host_discovery_disabled=host_discovery_disabled,
                service_detection=service_detection,
                default_scripts=default_scripts,
                store_response=store_response,
                flush_session=flush_session,
                threads=threads,
                rate_limit=rate_limit,
                concurrency=concurrency,
                bulk_size=bulk_size,
                depth=depth,
                timeout=timeout,
                retries=retries,
                max_time_minutes=max_time_minutes,
                host_timeout=host_timeout,
                script_timeout=script_timeout,
                level=level,
                risk=risk,
                zapit=zapit,
                jwt_token=normalized_jwt_token,
                canary_value=normalized_canary_value,
                public_key_path=normalized_public_key_path,
                dictionary_path=normalized_dictionary_path,
                output_path=resolved_output_path,
            )
            execution = _execute_tool_command(command, timeout=timeout)
        except (OSError, ValueError, subprocess.TimeoutExpired) as scan_error:
            missing_tool_reason = _missing_tool_skip_reason(normalized_tool_name, scan_error)
            if missing_tool_reason is not None:
                return _record_skipped_tool_run(
                    agent_state,
                    store=store,
                    root_agent_id=root_agent_id,
                    tool_name=normalized_tool_name,
                    logical_target=logical_target,
                    logical_component=logical_component,
                    scope_key=scope_key,
                    scope_payload=scope_payload,
                    resolved_output_path=resolved_output_path,
                    include_findings=include_findings,
                    reason=(
                        f"{missing_tool_reason}; skipping wrapped scan and marking "
                        "needs_more_data so other recon pivots can continue."
                    ),
                )
            raise
        output_content = _read_output_file(resolved_output_path)
        incompatibility_reason = _tool_incompatibility_reason(
            normalized_tool_name,
            "\n".join([str(execution.get("stdout") or ""), str(execution.get("stderr") or "")]),
            exit_code=int(execution.get("exit_code") or 0),
        )
        if incompatibility_reason is not None:
            return _record_skipped_tool_run(
                agent_state,
                store=store,
                root_agent_id=root_agent_id,
                tool_name=normalized_tool_name,
                logical_target=logical_target,
                logical_component=logical_component,
                scope_key=scope_key,
                scope_payload=scope_payload,
                resolved_output_path=resolved_output_path,
                include_findings=include_findings,
                reason=(
                    f"{incompatibility_reason}; skipping wrapped scan because this binary does not "
                    "match the expected security tool interface."
                ),
                availability="incompatible_tool",
                command=command,
            )
        if normalized_tool_name == "httpx" and _should_retry_httpx_with_basic_flags(
            execution, output_content
        ):
            command = _build_command(
                normalized_tool_name,
                targets=normalized_targets,
                target_path=target_path,
                url=url,
                wordlist_path=normalized_wordlist_path,
                raw_request_path=raw_request_path,
                paths=normalized_paths,
                headers=normalized_headers,
                data=data,
                request_method=normalized_request_method,
                ports=ports,
                top_ports=top_ports,
                parameter=parameter,
                configs=normalized_configs,
                tags=normalized_tags,
                severities=normalized_severities,
                proxy_url=proxy_url,
                automatic_scan=automatic_scan,
                active_only=active_only,
                collect_sources=collect_sources,
                no_interactsh=no_interactsh,
                use_js_crawl=use_js_crawl,
                headless=headless,
                known_files=known_files,
                recursion=recursion,
                recursion_depth=recursion_depth,
                scan_type=scan_type,
                host_discovery_disabled=host_discovery_disabled,
                service_detection=service_detection,
                default_scripts=default_scripts,
                store_response=store_response,
                flush_session=flush_session,
                threads=threads,
                rate_limit=rate_limit,
                concurrency=concurrency,
                bulk_size=bulk_size,
                depth=depth,
                timeout=timeout,
                retries=retries,
                max_time_minutes=max_time_minutes,
                host_timeout=host_timeout,
                script_timeout=script_timeout,
                level=level,
                risk=risk,
                zapit=zapit,
                jwt_token=normalized_jwt_token,
                canary_value=normalized_canary_value,
                public_key_path=normalized_public_key_path,
                dictionary_path=normalized_dictionary_path,
                output_path=resolved_output_path,
                httpx_rich_metadata=False,
            )
            execution = _execute_tool_command(command, timeout=timeout)
            output_content = _read_output_file(resolved_output_path)
        if not output_content and str(execution.get("stdout") or "").strip():
            output_content = str(execution.get("stdout") or "")
            try:
                Path(resolved_output_path).write_text(output_content, encoding="utf-8")
            except OSError:
                pass
        findings = _parse_findings(
            normalized_tool_name,
            stdout=str(execution.get("stdout") or ""),
            output_content=output_content,
        )
        if normalized_tool_name == "jwt_tool":
            jwt_finding_url = str(url or "").strip() or None
            if jwt_finding_url:
                findings = [
                    {
                        **finding,
                        "url": jwt_finding_url,
                        "path": urlparse(jwt_finding_url).path or "/",
                    }
                    for finding in findings
                ]
        if normalized_tool_name in {
            "bandit",
            "jwt_tool",
            "nmap",
            "nuclei",
            "semgrep",
            "sqlmap",
            "trivy",
            "trufflehog",
            "wapiti",
            "zaproxy",
        }:
            findings = _annotate_scanner_findings(normalized_tool_name, findings)

        discovery_result = None
        finding_updates: list[dict[str, Any]] = []
        parameter_hypothesis_updates: list[dict[str, Any]] = []
        if normalized_tool_name in {"httpx", "katana", "ffuf", "dirsearch"} and findings:
            discovery_result = _seed_discovery_coverage(
                agent_state,
                logical_target=logical_target,
                tool_name=normalized_tool_name,
                findings=findings,
                max_seed_items=max_seed_items,
            )
        if normalized_tool_name == "subfinder" and findings:
            discovery_result = _seed_host_discovery_coverage(
                agent_state,
                logical_target=logical_target,
                tool_name=normalized_tool_name,
                findings=findings,
                max_seed_items=max_seed_items,
            )
        if normalized_tool_name in {"naabu", "nmap"} and findings:
            discovery_result = _seed_service_discovery_coverage(
                agent_state,
                logical_target=logical_target,
                tool_name=normalized_tool_name,
                findings=findings,
                max_seed_items=max_seed_items,
            )
        if normalized_tool_name == "wafw00f" and findings:
            discovery_result = _seed_waf_observations(
                agent_state,
                logical_target=logical_target,
                findings=findings,
                max_seed_items=max_seed_items,
            )
        if normalized_tool_name == "arjun" and findings:
            discovery_result, parameter_hypothesis_updates = _seed_parameter_discovery(
                agent_state,
                logical_target=logical_target,
                findings=findings,
                max_seed_items=max_seed_items,
                max_hypotheses=max_hypotheses,
            )
        scanner_findings = findings
        if normalized_tool_name == "nmap":
            scanner_findings = [
                item for item in findings if str(item.get("kind") or "port") == "script"
            ]
        if normalized_tool_name in {
            "nmap",
            "nuclei",
            "semgrep",
            "sqlmap",
            "bandit",
            "jwt_tool",
            "trivy",
            "trufflehog",
            "wapiti",
            "zaproxy",
        } and scanner_findings:
            finding_updates = _record_scanner_findings(
                agent_state,
                logical_target=logical_target,
                tool_name=normalized_tool_name,
                findings=scanner_findings,
                max_findings=max_hypotheses,
            )
        recorded_hypothesis_count = sum(
            1 for item in finding_updates if isinstance(item.get("hypothesis_result"), dict)
        )

        run_id = _stable_id(
            "scan",
            logical_target,
            logical_component,
            normalized_tool_name,
            started_at,
        )
        evidence_result = _record_run_evidence(
            agent_state,
            tool_name=normalized_tool_name,
            logical_target=logical_target,
            component=logical_component,
            run_id=run_id,
            command=command,
            execution=execution,
            findings=findings,
        )
        run_record: TOOL_RUN = {
            "root_agent_id": root_agent_id,
            "run_id": run_id,
            "tool_name": normalized_tool_name,
            "target": logical_target,
            "component": logical_component,
            "command": command,
            "exit_code": execution.get("exit_code"),
            "stdout_preview": _truncate(str(execution.get("stdout") or ""), 400),
            "stderr_preview": _truncate(str(execution.get("stderr") or ""), 400),
            "finding_count": len(findings),
            "findings": findings,
            "output_path": resolved_output_path,
            "created_at": started_at,
            "updated_at": _utc_now(),
            "scope_key": scope_key,
            "scope": scope_payload,
            "discovery_seed_count": (
                int(discovery_result.get("updated_count") or 0)
                if isinstance(discovery_result, dict)
                else 0
            ),
            "hypothesis_seed_count": recorded_hypothesis_count + len(parameter_hypothesis_updates),
            "evidence_id": evidence_result.get("evidence_id"),
        }
        store[run_id] = run_record

    except (OSError, TypeError, ValueError, subprocess.TimeoutExpired) as e:
        return {"success": False, "error": f"Failed to run security tool scan: {e}"}
    else:
        response: dict[str, Any] = {
            "success": True,
            "root_agent_id": root_agent_id,
            "run_id": run_id,
            "tool_name": normalized_tool_name,
            "target": logical_target,
            "component": logical_component,
            "command": command,
            "tool_exit_code": execution.get("exit_code"),
            "finding_count": len(findings),
            "discovery_seed_count": run_record["discovery_seed_count"],
            "hypothesis_seed_count": run_record["hypothesis_seed_count"],
            "stdout_preview": run_record["stdout_preview"],
            "stderr_preview": run_record["stderr_preview"],
            "scope_key": scope_key,
            "scope": scope_payload,
            "evidence_result": evidence_result,
        }
        if discovery_result is not None:
            response["discovery_result"] = discovery_result
        if finding_updates:
            response["finding_updates"] = finding_updates
        if parameter_hypothesis_updates:
            response["parameter_hypothesis_updates"] = parameter_hypothesis_updates
        if include_findings:
            response["findings"] = findings
        return response


@register_tool(sandbox_execution=False)
def run_security_focus_pipeline(
    agent_state: Any,
    target: str,
    focus: str,
    targets: list[str] | None = None,
    url: str | None = None,
    target_path: str | None = None,
    headers: dict[str, str] | None = None,
    jwt_token: str | None = None,
    callback_base_url: str | None = None,
    canary_value: str | None = None,
    public_key_path: str | None = None,
    dictionary_path: str | None = None,
    max_active_targets: int = 3,
    max_hypotheses: int = 12,
    reuse_previous_runs: bool = True,
    auto_build_review: bool = True,
    auto_spawn_review_agents: bool = True,
    auto_spawn_signal_agents: bool = True,
    auto_spawn_impact_agents: bool = True,
    auto_synthesize_hypotheses: bool = True,
) -> dict[str, Any]:
    try:
        from .assessment_creative_actions import (
            generate_contextual_payloads,
            synthesize_attack_hypotheses,
        )
        from .assessment_oob_actions import oob_interaction_harness
        from .assessment_validation_actions import (
            jwt_variant_harness,
            payload_probe_harness,
            race_condition_harness,
            role_matrix_test,
        )

        normalized_target = _normalize_non_empty(target, "target")
        normalized_focus = _normalize_focus_pipeline_name(focus)
        normalized_headers = _normalize_headers(headers)
        normalized_targets = _normalize_targets(targets)
        if max_active_targets < 1:
            raise ValueError("max_active_targets must be >= 1")
        if max_hypotheses < 1:
            raise ValueError("max_hypotheses must be >= 1")

        root_agent_id, store = _get_tool_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        desired_tools = {
            "auth_jwt": ["jwt_tool", "wafw00f"],
            "ssrf_oob": ["arjun", "wafw00f"],
            "sqli": ["arjun", "sqlmap", "wapiti", "wafw00f"],
            "xss": ["arjun", "wapiti", "zaproxy", "wafw00f"],
            "open_redirect": ["arjun", "wafw00f"],
            "ssti": ["arjun"],
            "xxe": [],
            "file_upload": [],
            "path_traversal": ["arjun"],
            "authz": [],
            "workflow_race": [],
        }[normalized_focus]
        available_result = security_tool_doctor(
            agent_state=agent_state,
            tool_names=desired_tools,
        )
        available_tools = {
            str(item.get("tool_name"))
            for item in available_result.get("tools", [])
            if item.get("available")
        }
        skipped_tools = [
            str(item.get("tool_name"))
            for item in available_result.get("tools", [])
            if not item.get("available")
        ]

        steps: list[dict[str, Any]] = []
        bootstrap_result = None
        synthesized_result = None
        payload_result = None
        harness_result = None
        code_sink_result = None
        attack_surface_review_result = None
        attack_surface_agent_result = None
        strong_signal_agent_result = None
        impact_chain_agent_result = None
        enrichment_result = None
        active_probe_results: list[dict[str, Any]] = []
        artifact_retrieval_results: list[dict[str, Any]] = []
        selected_request_contexts: list[dict[str, Any]] = []
        public_path_hints: list[str] = []

        def run_step(
            step_name: str,
            *,
            metadata: dict[str, Any] | None = None,
            include_findings: bool = True,
            **scan_kwargs: Any,
        ) -> dict[str, Any]:
            result = _execute_or_reuse_tool_scan(
                agent_state=agent_state,
                store=store,
                reuse_previous_runs=reuse_previous_runs,
                tool_name=step_name,
                target=normalized_target,
                include_findings=include_findings,
                **scan_kwargs,
            )
            step_metadata = dict(metadata or {})
            if result.get("reused_existing_run"):
                step_metadata["reused_existing_run"] = True
            _append_pipeline_step(
                steps,
                step_name=step_name,
                result=result,
                metadata=step_metadata,
            )
            return result

        if target_path:
            code_sink_result = _discover_focus_code_sinks(
                agent_state=agent_state,
                target=normalized_target,
                focus=normalized_focus,
                target_path=target_path,
                max_items=max_hypotheses,
            )
            public_path_hints = [
                str(item).strip()
                for item in list(code_sink_result.get("public_path_hints") or [])
                if str(item).strip()
            ]
            _append_pipeline_step(
                steps,
                step_name="whitebox_sink_discovery",
                result=code_sink_result,
                metadata={
                    "focus": normalized_focus,
                    "target_path": target_path,
                },
            )

        enrichment_result = _run_inventory_enrichment(
            agent_state=agent_state,
            target=normalized_target,
            steps=steps,
            max_seed_items=max(max_active_targets * 2, 20),
            max_hypotheses=max_hypotheses,
            include_workflows=True,
        )
        runtime_entries = [
            item
            for item in list(enrichment_result.get("runtime_entries") or [])
            if isinstance(item, dict)
        ]
        surface_artifacts = [
            item
            for item in list(enrichment_result.get("surface_artifacts") or [])
            if isinstance(item, dict)
        ]
        discovered_workflows = [
            item
            for item in list(enrichment_result.get("workflows") or [])
            if isinstance(item, dict)
        ]

        candidate_urls = _unique_strings(
            [
                *[item for item in normalized_targets if _is_http_url(item)],
                *([str(url).strip()] if url else []),
                *[
                    str(item.get("url") or item.get("matched_at") or "").strip()
                    for item in _stored_findings(store, target=normalized_target)
                    if str(item.get("url") or item.get("matched_at") or "").strip()
                ],
                *_candidate_urls_from_runtime_entries(runtime_entries),
                *_candidate_urls_from_surface_artifacts(surface_artifacts),
            ]
        )

        if normalized_focus in {"ssrf_oob", "sqli", "xss", "open_redirect"} and not candidate_urls and (normalized_targets or url):
            bootstrap_result = run_security_tool_pipeline(
                agent_state=agent_state,
                target=normalized_target,
                mode="blackbox",
                targets=normalized_targets or None,
                url=url,
                deep=False,
                max_active_targets=max_active_targets,
                max_hypotheses=max_hypotheses,
                reuse_previous_runs=reuse_previous_runs,
                auto_synthesize_hypotheses=False,
            )
            candidate_urls = _unique_strings(
                [
                    *candidate_urls,
                    *[
                        str(item.get("url") or item.get("matched_at") or "").strip()
                        for item in _stored_findings(store, target=normalized_target)
                        if str(item.get("url") or item.get("matched_at") or "").strip()
                    ],
                    *_candidate_urls_from_runtime_entries(
                        _load_runtime_inventory_entries(agent_state, normalized_target)
                    ),
                    *_candidate_urls_from_surface_artifacts(
                        _load_mined_surface_artifacts(agent_state, normalized_target)
                    ),
                ]
            )

        if not runtime_entries:
            runtime_entries = _load_runtime_inventory_entries(agent_state, normalized_target)
        if not surface_artifacts:
            surface_artifacts = _load_mined_surface_artifacts(agent_state, normalized_target)
        if not discovered_workflows:
            discovered_workflows = _load_discovered_workflows(agent_state, normalized_target)
        session_profiles = _load_session_profiles(agent_state)

        if normalized_focus == "auth_jwt":
            auth_request_contexts = _focus_request_contexts(
                agent_state=agent_state,
                target=normalized_target,
                candidate_url=str(url or (candidate_urls[0] if candidate_urls else "")).strip() or None,
                focus="auth_jwt",
                max_items=max(1, min(max_active_targets, 3)),
                runtime_entries=runtime_entries,
                workflows=discovered_workflows,
                session_profiles=session_profiles,
            )
            selected_request_contexts.extend(auth_request_contexts)
            primary_auth_context = auth_request_contexts[0] if auth_request_contexts else None
            request_url = (
                str(url).strip()
                if url
                else (
                    str(primary_auth_context.get("url") or "").strip()
                    if primary_auth_context
                    else (candidate_urls[0] if candidate_urls else "")
                )
            ) or None
            focus_url = _base_url(request_url or "") or request_url
            if focus_url and "wafw00f" in available_tools:
                run_step("wafw00f", url=focus_url, metadata={"url": focus_url})

            effective_headers = (
                dict(primary_auth_context.get("base_request", {}).get("headers") or {})
                if primary_auth_context
                else {}
            )
            context_cookies = (
                {
                    str(key): str(value)
                    for key, value in dict(
                        primary_auth_context.get("base_request", {}).get("cookies") or {}
                    ).items()
                }
                if primary_auth_context
                else {}
            )
            if context_cookies and "Cookie" not in effective_headers and "cookie" not in effective_headers:
                effective_headers["Cookie"] = "; ".join(
                    f"{key}={value}" for key, value in context_cookies.items()
                )
            effective_headers.update(normalized_headers)
            request_jwt_context = (
                _jwt_from_request_context(primary_auth_context)
                if primary_auth_context is not None
                else None
            )
            normalized_jwt_token = (
                str(jwt_token).strip()
                if jwt_token is not None
                else (
                    str(request_jwt_context.get("token")).strip()
                    if request_jwt_context and request_jwt_context.get("token")
                    else _jwt_from_authorization_header(effective_headers.get("Authorization"))
                )
            )
            if normalized_jwt_token and not any(
                key.lower() == "authorization" for key in effective_headers
            ) and (
                request_jwt_context is None
                or str(request_jwt_context.get("token_location") or "header") == "header"
            ):
                effective_headers["Authorization"] = f"Bearer {normalized_jwt_token}"

            if "jwt_tool" in available_tools and (request_url or normalized_jwt_token or effective_headers):
                jwt_tool_result = run_step(
                    "jwt_tool",
                    url=request_url,
                    headers=effective_headers,
                    jwt_token=normalized_jwt_token,
                    scan_type="playbook" if request_url or effective_headers else "decode",
                    canary_value=canary_value,
                    public_key_path=public_key_path,
                    dictionary_path=dictionary_path,
                    max_hypotheses=max_hypotheses,
                    metadata={"url": request_url},
                )
                if normalized_jwt_token and request_url:
                    base_request = (
                        dict(primary_auth_context.get("base_request") or {})
                        if primary_auth_context
                        else {
                            "method": "GET",
                            "url": request_url,
                            "headers": {
                                key: value
                                for key, value in effective_headers.items()
                                if key.lower() != "authorization"
                            },
                        }
                    )
                    base_request["headers"] = {
                        key: value
                        for key, value in dict(base_request.get("headers") or {}).items()
                        if key.lower() != "authorization"
                    }
                    auth_probe_result = jwt_variant_harness(
                        agent_state=agent_state,
                        target=normalized_target,
                        component=f"focus:jwt:{urlparse(request_url).netloc}{urlparse(request_url).path or '/'}",
                        surface=(
                            f"JWT validation on {urlparse(request_url).path or '/'}"
                        ),
                        base_request=base_request,
                        jwt_token=normalized_jwt_token,
                        token_location=(
                            str(request_jwt_context.get("token_location") or "auto")
                            if request_jwt_context
                            else "auto"
                        ),
                        cookie_name=(
                            str(request_jwt_context.get("cookie_name"))
                            if request_jwt_context and request_jwt_context.get("cookie_name")
                            else None
                        ),
                        query_parameter_name=(
                            str(request_jwt_context.get("query_parameter_name"))
                            if request_jwt_context and request_jwt_context.get("query_parameter_name")
                            else None
                        ),
                        header_name=(
                            str(request_jwt_context.get("header_name") or "Authorization")
                            if request_jwt_context
                            else "Authorization"
                        ),
                        header_prefix=(
                            str(request_jwt_context.get("header_prefix") or "Bearer")
                            if request_jwt_context
                            else "Bearer"
                        ),
                        claim_overrides=(
                            {"role": "admin", "scope": "admin"}
                            if any(
                                item.get("name") == "JWT alg:none acceptance"
                                for item in list(jwt_tool_result.get("findings") or [])
                            )
                            else None
                        ),
                    )
                    active_probe_results.append(auth_probe_result)
                    _append_pipeline_step(
                        steps,
                        step_name="jwt_variant_harness",
                        result=auth_probe_result,
                        metadata={"focus": "auth_jwt", "url": request_url},
                    )

        elif normalized_focus == "ssrf_oob":
            suspicious_parameter_findings: list[dict[str, Any]] = []
            seen_ssrf_candidates: set[tuple[str, str, str]] = set()

            def add_ssrf_candidate(item: dict[str, Any]) -> None:
                parameter_name = str(item.get("parameter") or "").strip()
                candidate_url = str(item.get("url") or "").strip()
                candidate_path = str(item.get("path") or "").strip()
                if not parameter_name:
                    return
                key = (candidate_url, candidate_path, parameter_name)
                if key in seen_ssrf_candidates:
                    return
                seen_ssrf_candidates.add(key)
                suspicious_parameter_findings.append(dict(item))

            for finding in _stored_findings(store, target=normalized_target, tool_name="arjun"):
                if any(
                    keyword in str(finding.get("parameter") or "").strip().lower()
                    for keyword in FOCUS_PARAMETER_HINTS["ssrf_oob"]
                ):
                    add_ssrf_candidate(finding)
            for candidate in _request_context_parameter_candidates(
                runtime_entries,
                focus="ssrf_oob",
            ):
                add_ssrf_candidate(candidate)
            if not suspicious_parameter_findings and "arjun" in available_tools:
                for active_url in candidate_urls[:max_active_targets]:
                    arjun_result = run_step(
                        "arjun",
                        url=active_url,
                        max_seed_items=max_hypotheses,
                        max_hypotheses=max_hypotheses,
                        metadata={"url": active_url},
                    )
                    for finding in arjun_result.get("findings", []):
                        if any(
                            keyword in str(finding.get("parameter") or "").strip().lower()
                            for keyword in FOCUS_PARAMETER_HINTS["ssrf_oob"]
                        ):
                            add_ssrf_candidate(finding)

            primary_finding = suspicious_parameter_findings[0] if suspicious_parameter_findings else {}
            primary_url = (
                str(primary_finding.get("url") or "").strip()
                or (candidate_urls[0] if candidate_urls else None)
            )
            primary_parameter = str(primary_finding.get("parameter") or "url").strip() or "url"
            primary_surface = (
                f"Potential SSRF parameter {primary_parameter} on {_path_for_finding(primary_finding)}"
                if primary_finding
                else f"Potential SSRF sink on {primary_url or normalized_target}"
            )
            primary_component = (
                f"focus:ssrf:{_host_for_finding('arjun', primary_finding)}{_path_for_finding(primary_finding)}"
                if primary_finding
                else f"focus:ssrf:{normalized_target}"
            )

            doctor_result = oob_interaction_harness(
                agent_state=agent_state,
                action="doctor",
            )
            if callback_base_url or doctor_result.get("cli_available"):
                harness_result = oob_interaction_harness(
                    agent_state=agent_state,
                    action="start",
                    target=normalized_target,
                    component=primary_component,
                    surface=primary_surface,
                    vulnerability_type="ssrf",
                    labels=[normalized_focus, primary_parameter],
                    callback_base_url=callback_base_url,
                )
            callback_urls = []
            if isinstance(harness_result, dict):
                callback_urls = [
                    str(item.get("url") or "").strip()
                    for item in (harness_result.get("payloads") or [])
                    if str(item.get("url") or "").strip()
                ]
            payload_result = generate_contextual_payloads(
                vulnerability_type="ssrf",
                surface=primary_surface,
                parameter_names=[primary_parameter],
                callback_urls=callback_urls,
                max_variants=max_hypotheses * 2,
            )
            if primary_url and isinstance(payload_result, dict) and payload_result.get("success"):
                probe_contexts = _focus_request_contexts(
                    agent_state=agent_state,
                    target=normalized_target,
                    candidate_url=primary_url,
                    parameter_name=primary_parameter,
                    focus="ssrf_oob",
                    max_items=max(1, min(max_active_targets, 4)),
                    runtime_entries=runtime_entries,
                    workflows=discovered_workflows,
                    session_profiles=session_profiles,
                )
                if not probe_contexts:
                    probe_contexts = [_fallback_request_context(primary_url, normalized_headers)]
                selected_request_contexts.extend(probe_contexts)

                for request_context in probe_contexts[:max_active_targets]:
                    request_url = str(request_context.get("url") or primary_url).strip()
                    request_path = urlparse(request_url).path or _path_for_finding(primary_finding)
                    request_component = (
                        f"focus:ssrf:{urlparse(request_url).netloc}{request_path}"
                        if request_url
                        else primary_component
                    )
                    request_surface = (
                        f"Potential SSRF parameter {primary_parameter} on {request_path}"
                        if request_url
                        else primary_surface
                    )
                    injection_mode = _request_context_injection_mode(
                        request_context,
                        primary_parameter,
                    )
                    baseline_value = (
                        _request_context_baseline_value(
                            request_context,
                            primary_parameter,
                            injection_mode,
                        )
                        or "https://example.com/"
                    )
                    request_base = dict(request_context.get("base_request") or {})
                    request_base["headers"] = {
                        **dict(request_base.get("headers") or {}),
                        **normalized_headers,
                    }
                    active_probe_result = payload_probe_harness(
                        agent_state=agent_state,
                        target=normalized_target,
                        component=request_component,
                        surface=request_surface,
                        vulnerability_type="ssrf",
                        parameter_name=primary_parameter,
                        base_request=request_base,
                        payloads=payload_result.get("variants"),
                        callback_urls=callback_urls,
                        baseline_value=baseline_value,
                        injection_mode=injection_mode,
                        max_payloads=max(1, min(max_active_targets, 4)),
                        oob_harness_id=(
                            str(harness_result.get("harness_id"))
                            if isinstance(harness_result, dict) and harness_result.get("harness_id")
                            else None
                        ),
                        poll_oob=bool(
                            isinstance(harness_result, dict)
                            and str(harness_result.get("provider") or "").strip().lower()
                            == "interactsh"
                        ),
                        min_anomaly_score=4,
                    )
                    active_probe_results.append(active_probe_result)
                    _append_pipeline_step(
                        steps,
                        step_name="payload_probe_harness",
                        result=active_probe_result,
                        metadata={
                            "focus": "ssrf_oob",
                            "url": request_url,
                            "parameter": primary_parameter,
                            "request_id": request_context.get("request_id"),
                            "request_source": request_context.get("source"),
                            "request_method": request_context.get("method"),
                            "injection_mode": injection_mode,
                        },
                    )

        elif normalized_focus == "sqli":
            suspicious_parameter_findings: list[dict[str, Any]] = []
            seen_sqli_candidates: set[tuple[str, str, str]] = set()

            def add_sqli_candidate(item: dict[str, Any]) -> None:
                parameter_name = str(item.get("parameter") or "").strip()
                candidate_url = str(item.get("url") or "").strip()
                candidate_path = str(item.get("path") or "").strip()
                if not parameter_name:
                    return
                key = (candidate_url, candidate_path, parameter_name)
                if key in seen_sqli_candidates:
                    return
                seen_sqli_candidates.add(key)
                suspicious_parameter_findings.append(dict(item))

            for finding in _stored_findings(store, target=normalized_target, tool_name="arjun"):
                if str(finding.get("parameter") or "").strip().lower() in FOCUS_PARAMETER_HINTS["sqli"]:
                    add_sqli_candidate(finding)
            for candidate in _request_context_parameter_candidates(runtime_entries, focus="sqli"):
                add_sqli_candidate(candidate)
            if not suspicious_parameter_findings and "arjun" in available_tools:
                for active_url in candidate_urls[:max_active_targets]:
                    arjun_result = run_step(
                        "arjun",
                        url=active_url,
                        max_seed_items=max_hypotheses,
                        max_hypotheses=max_hypotheses,
                        metadata={"url": active_url},
                    )
                    for finding in arjun_result.get("findings", []):
                        if (
                            str(finding.get("parameter") or "").strip().lower()
                            in FOCUS_PARAMETER_HINTS["sqli"]
                        ):
                            add_sqli_candidate(finding)

            probe_plans: list[dict[str, Any]] = []
            seen_probe_plans: set[tuple[str, str, str]] = set()
            for finding in suspicious_parameter_findings:
                parameter_name = str(finding.get("parameter") or "").strip() or "id"
                candidate_url = str(
                    finding.get("url") or (candidate_urls[0] if candidate_urls else "")
                ).strip()
                request_contexts = _focus_request_contexts(
                    agent_state=agent_state,
                    target=normalized_target,
                    candidate_url=candidate_url or None,
                    parameter_name=parameter_name,
                    focus="sqli",
                    max_items=1,
                    runtime_entries=runtime_entries,
                    workflows=discovered_workflows,
                    session_profiles=session_profiles,
                )
                request_context = (
                    request_contexts[0]
                    if request_contexts
                    else (
                        _fallback_request_context(
                            _sqlmap_candidate_url(candidate_url, parameter_name),
                            normalized_headers,
                        )
                        if candidate_url
                        else None
                    )
                )
                if request_context is None:
                    continue
                injection_mode = _request_context_injection_mode(request_context, parameter_name)
                base_request = dict(request_context.get("base_request") or {})
                if injection_mode == "query":
                    query_url = _sqlmap_candidate_url(
                        str(base_request.get("url") or request_context.get("url") or candidate_url),
                        parameter_name,
                    )
                    base_request["url"] = query_url
                    request_context = {
                        **request_context,
                        "url": query_url,
                        "base_request": base_request,
                        "query_params": {
                            str(key): str(value)
                            for key, value in parse_qsl(
                                urlparse(query_url).query,
                                keep_blank_values=True,
                            )
                        },
                    }
                plan_key = (
                    str(request_context.get("url") or ""),
                    parameter_name,
                    injection_mode,
                )
                if plan_key in seen_probe_plans:
                    continue
                seen_probe_plans.add(plan_key)
                probe_plans.append(
                    {
                        "parameter": parameter_name,
                        "request_context": request_context,
                        "injection_mode": injection_mode,
                    }
                )

            for candidate_url in candidate_urls:
                parsed = urlparse(candidate_url)
                for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                    if name.lower() not in FOCUS_PARAMETER_HINTS["sqli"]:
                        continue
                    plan_key = (_sqlmap_candidate_url(candidate_url, name), name, "query")
                    if plan_key in seen_probe_plans:
                        continue
                    seen_probe_plans.add(plan_key)
                    probe_plans.append(
                        {
                            "parameter": name,
                            "request_context": _fallback_request_context(
                                _sqlmap_candidate_url(candidate_url, name),
                                normalized_headers,
                            ),
                            "injection_mode": "query",
                        }
                    )

            if candidate_urls and "wafw00f" in available_tools:
                focus_url = _base_url(candidate_urls[0]) or candidate_urls[0]
                run_step("wafw00f", url=focus_url, metadata={"url": focus_url})

            for item in probe_plans[:max_active_targets]:
                parameter_name = str(item["parameter"])
                request_context = dict(item["request_context"])
                selected_request_contexts.append(request_context)
                request_url = str(request_context.get("url") or "").strip()
                request_path = urlparse(request_url).path or "/"
                if "sqlmap" in available_tools:
                    sqlmap_scan_kwargs = _sqlmap_scan_kwargs_from_context(
                        request_context,
                        parameter_name=parameter_name,
                    )
                    run_step(
                        "sqlmap",
                        **sqlmap_scan_kwargs,
                        max_hypotheses=max_hypotheses,
                        metadata={
                            "url": request_url,
                            "parameter": parameter_name,
                            "request_method": request_context.get("method"),
                            "injection_mode": item["injection_mode"],
                        },
                    )
                candidate_surface = (
                    f"Potential SQL injection in parameter {parameter_name} on {request_path}"
                )
                payload_result = generate_contextual_payloads(
                    vulnerability_type="sqli",
                    surface=candidate_surface,
                    parameter_names=[parameter_name],
                    max_variants=max_hypotheses * 2,
                )
                request_base = dict(request_context.get("base_request") or {})
                request_base["headers"] = {
                    **dict(request_base.get("headers") or {}),
                    **normalized_headers,
                }
                active_probe_result = payload_probe_harness(
                    agent_state=agent_state,
                    target=normalized_target,
                    component=f"focus:sqli:{urlparse(request_url).netloc}{request_path}",
                    surface=candidate_surface,
                    vulnerability_type="sqli",
                    parameter_name=parameter_name,
                    base_request=request_base,
                    payloads=(
                        payload_result.get("variants")
                        if isinstance(payload_result, dict) and payload_result.get("success")
                        else None
                    ),
                    baseline_value=(
                        _request_context_baseline_value(
                            request_context,
                            parameter_name,
                            str(item["injection_mode"]),
                        )
                        or _query_parameter_value(request_url, parameter_name)
                        or "1"
                    ),
                    injection_mode=str(item["injection_mode"]),
                    max_payloads=max(1, min(max_active_targets, 4)),
                    min_anomaly_score=4,
                )
                active_probe_results.append(active_probe_result)
                _append_pipeline_step(
                    steps,
                    step_name="payload_probe_harness",
                    result=active_probe_result,
                    metadata={
                        "focus": "sqli",
                        "url": request_url,
                        "parameter": parameter_name,
                        "request_id": request_context.get("request_id"),
                        "request_source": request_context.get("source"),
                        "request_method": request_context.get("method"),
                        "injection_mode": item["injection_mode"],
                    },
                )

        elif normalized_focus == "xss":
            suspicious_parameter_findings: list[dict[str, Any]] = []
            seen_xss_candidates: set[tuple[str, str, str]] = set()

            def add_xss_candidate(item: dict[str, Any]) -> None:
                parameter_name = str(item.get("parameter") or "").strip()
                candidate_url = str(item.get("url") or "").strip()
                candidate_path = str(item.get("path") or "").strip()
                if not parameter_name:
                    return
                key = (candidate_url, candidate_path, parameter_name)
                if key in seen_xss_candidates:
                    return
                seen_xss_candidates.add(key)
                suspicious_parameter_findings.append(dict(item))

            for finding in _stored_findings(store, target=normalized_target):
                parameter_name = str(finding.get("parameter") or "").strip().lower()
                vulnerability_type = str(finding.get("vulnerability_type") or "").strip().lower()
                if parameter_name and any(
                    keyword in parameter_name for keyword in FOCUS_PARAMETER_HINTS["xss"]
                ):
                    add_xss_candidate(finding)
                    continue
                if vulnerability_type == "xss" and parameter_name:
                    add_xss_candidate(finding)
            for candidate in _request_context_parameter_candidates(runtime_entries, focus="xss"):
                add_xss_candidate(candidate)
            if not suspicious_parameter_findings and "arjun" in available_tools:
                for active_url in candidate_urls[:max_active_targets]:
                    arjun_result = run_step(
                        "arjun",
                        url=active_url,
                        max_seed_items=max_hypotheses,
                        max_hypotheses=max_hypotheses,
                        metadata={"url": active_url},
                    )
                    for finding in arjun_result.get("findings", []):
                        if any(
                            keyword in str(finding.get("parameter") or "").strip().lower()
                            for keyword in FOCUS_PARAMETER_HINTS["xss"]
                        ):
                            add_xss_candidate(finding)

            probe_plans: list[dict[str, Any]] = []
            seen_probe_plans: set[tuple[str, str, str]] = set()
            for finding in suspicious_parameter_findings:
                parameter_name = str(finding.get("parameter") or "").strip() or "q"
                candidate_url = str(
                    finding.get("url") or (candidate_urls[0] if candidate_urls else "")
                ).strip()
                request_contexts = _focus_request_contexts(
                    agent_state=agent_state,
                    target=normalized_target,
                    candidate_url=candidate_url or None,
                    parameter_name=parameter_name,
                    focus="xss",
                    max_items=1,
                    runtime_entries=runtime_entries,
                    workflows=discovered_workflows,
                    session_profiles=session_profiles,
                )
                request_context = (
                    request_contexts[0]
                    if request_contexts
                    else (
                        _fallback_request_context(candidate_url, normalized_headers)
                        if candidate_url
                        else None
                    )
                )
                if request_context is None:
                    continue
                injection_mode = _request_context_injection_mode(request_context, parameter_name)
                plan_key = (
                    str(request_context.get("url") or ""),
                    parameter_name,
                    injection_mode,
                )
                if plan_key in seen_probe_plans:
                    continue
                seen_probe_plans.add(plan_key)
                probe_plans.append(
                    {
                        "parameter": parameter_name,
                        "request_context": request_context,
                        "injection_mode": injection_mode,
                    }
                )

            for candidate_url in candidate_urls:
                parsed = urlparse(candidate_url)
                for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                    if not any(keyword in name.lower() for keyword in FOCUS_PARAMETER_HINTS["xss"]):
                        continue
                    plan_key = (candidate_url, name, "query")
                    if plan_key in seen_probe_plans:
                        continue
                    seen_probe_plans.add(plan_key)
                    probe_plans.append(
                        {
                            "parameter": name,
                            "request_context": _fallback_request_context(candidate_url, normalized_headers),
                            "injection_mode": "query",
                        }
                    )

            if candidate_urls and "wafw00f" in available_tools:
                focus_url = _base_url(candidate_urls[0]) or candidate_urls[0]
                run_step("wafw00f", url=focus_url, metadata={"url": focus_url})

            for item in probe_plans[:max_active_targets]:
                parameter_name = str(item["parameter"])
                request_context = dict(item["request_context"])
                selected_request_contexts.append(request_context)
                request_url = str(request_context.get("url") or "").strip()
                request_path = urlparse(request_url).path or "/"
                candidate_surface = (
                    f"Potential XSS in parameter {parameter_name} on {request_path}"
                )
                payload_result = generate_contextual_payloads(
                    vulnerability_type="xss",
                    surface=candidate_surface,
                    parameter_names=[parameter_name],
                    max_variants=max_hypotheses * 2,
                )
                request_base = dict(request_context.get("base_request") or {})
                request_base["headers"] = {
                    **dict(request_base.get("headers") or {}),
                    **normalized_headers,
                }
                active_probe_result = payload_probe_harness(
                    agent_state=agent_state,
                    target=normalized_target,
                    component=f"focus:xss:{urlparse(request_url).netloc}{request_path}",
                    surface=candidate_surface,
                    vulnerability_type="xss",
                    parameter_name=parameter_name,
                    base_request=request_base,
                    payloads=(
                        payload_result.get("variants")
                        if isinstance(payload_result, dict) and payload_result.get("success")
                        else None
                    ),
                    semantic_matchers=["<svg", "onload=alert", "<img src=x onerror", "alert(1)"],
                    baseline_value=(
                        _request_context_baseline_value(
                            request_context,
                            parameter_name,
                            str(item["injection_mode"]),
                        )
                        or _query_parameter_value(request_url, parameter_name)
                        or "hello"
                    ),
                    injection_mode=str(item["injection_mode"]),
                    max_payloads=max(1, min(max_active_targets, 4)),
                    min_anomaly_score=3,
                )
                active_probe_results.append(active_probe_result)
                _append_pipeline_step(
                    steps,
                    step_name="payload_probe_harness",
                    result=active_probe_result,
                    metadata={
                        "focus": "xss",
                        "url": request_url,
                        "parameter": parameter_name,
                        "request_id": request_context.get("request_id"),
                        "request_source": request_context.get("source"),
                        "request_method": request_context.get("method"),
                        "injection_mode": item["injection_mode"],
                    },
                )

        elif normalized_focus == "open_redirect":
            suspicious_parameter_findings: list[dict[str, Any]] = []
            seen_redirect_candidates: set[tuple[str, str, str]] = set()

            def add_redirect_candidate(item: dict[str, Any]) -> None:
                parameter_name = str(item.get("parameter") or "").strip()
                candidate_url = str(item.get("url") or "").strip()
                candidate_path = str(item.get("path") or "").strip()
                if not parameter_name:
                    return
                key = (candidate_url, candidate_path, parameter_name)
                if key in seen_redirect_candidates:
                    return
                seen_redirect_candidates.add(key)
                suspicious_parameter_findings.append(dict(item))

            for finding in _stored_findings(store, target=normalized_target):
                parameter_name = str(finding.get("parameter") or "").strip().lower()
                vulnerability_type = str(finding.get("vulnerability_type") or "").strip().lower()
                if parameter_name and any(
                    keyword in parameter_name for keyword in FOCUS_PARAMETER_HINTS["open_redirect"]
                ):
                    add_redirect_candidate(finding)
                    continue
                if vulnerability_type == "open_redirect" and parameter_name:
                    add_redirect_candidate(finding)
            for candidate in _request_context_parameter_candidates(runtime_entries, focus="open_redirect"):
                add_redirect_candidate(candidate)
            if not suspicious_parameter_findings and "arjun" in available_tools:
                for active_url in candidate_urls[:max_active_targets]:
                    arjun_result = run_step(
                        "arjun",
                        url=active_url,
                        max_seed_items=max_hypotheses,
                        max_hypotheses=max_hypotheses,
                        metadata={"url": active_url},
                    )
                    for finding in arjun_result.get("findings", []):
                        if any(
                            keyword in str(finding.get("parameter") or "").strip().lower()
                            for keyword in FOCUS_PARAMETER_HINTS["open_redirect"]
                        ):
                            add_redirect_candidate(finding)

            probe_plans: list[dict[str, Any]] = []
            seen_probe_plans: set[tuple[str, str, str]] = set()
            for finding in suspicious_parameter_findings:
                parameter_name = str(finding.get("parameter") or "").strip() or "next"
                candidate_url = str(
                    finding.get("url") or (candidate_urls[0] if candidate_urls else "")
                ).strip()
                request_contexts = _focus_request_contexts(
                    agent_state=agent_state,
                    target=normalized_target,
                    candidate_url=candidate_url or None,
                    parameter_name=parameter_name,
                    focus="open_redirect",
                    max_items=1,
                    runtime_entries=runtime_entries,
                    workflows=discovered_workflows,
                    session_profiles=session_profiles,
                )
                request_context = (
                    request_contexts[0]
                    if request_contexts
                    else (
                        _fallback_request_context(candidate_url, normalized_headers)
                        if candidate_url
                        else None
                    )
                )
                if request_context is None:
                    continue
                injection_mode = _request_context_injection_mode(request_context, parameter_name)
                plan_key = (
                    str(request_context.get("url") or ""),
                    parameter_name,
                    injection_mode,
                )
                if plan_key in seen_probe_plans:
                    continue
                seen_probe_plans.add(plan_key)
                probe_plans.append(
                    {
                        "parameter": parameter_name,
                        "request_context": request_context,
                        "injection_mode": injection_mode,
                    }
                )

            for candidate_url in candidate_urls:
                parsed = urlparse(candidate_url)
                for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                    if not any(
                        keyword in name.lower() for keyword in FOCUS_PARAMETER_HINTS["open_redirect"]
                    ):
                        continue
                    plan_key = (candidate_url, name, "query")
                    if plan_key in seen_probe_plans:
                        continue
                    seen_probe_plans.add(plan_key)
                    probe_plans.append(
                        {
                            "parameter": name,
                            "request_context": _fallback_request_context(candidate_url, normalized_headers),
                            "injection_mode": "query",
                        }
                    )

            if candidate_urls and "wafw00f" in available_tools:
                focus_url = _base_url(candidate_urls[0]) or candidate_urls[0]
                run_step("wafw00f", url=focus_url, metadata={"url": focus_url})

            for item in probe_plans[:max_active_targets]:
                parameter_name = str(item["parameter"])
                request_context = dict(item["request_context"])
                selected_request_contexts.append(request_context)
                request_url = str(request_context.get("url") or "").strip()
                request_path = urlparse(request_url).path or "/"
                candidate_surface = (
                    f"Potential open redirect in parameter {parameter_name} on {request_path}"
                )
                payload_result = generate_contextual_payloads(
                    vulnerability_type="open_redirect",
                    surface=candidate_surface,
                    parameter_names=[parameter_name],
                    max_variants=max_hypotheses * 2,
                )
                request_base = dict(request_context.get("base_request") or {})
                request_base["headers"] = {
                    **dict(request_base.get("headers") or {}),
                    **normalized_headers,
                }
                active_probe_result = payload_probe_harness(
                    agent_state=agent_state,
                    target=normalized_target,
                    component=f"focus:open_redirect:{urlparse(request_url).netloc}{request_path}",
                    surface=candidate_surface,
                    vulnerability_type="open_redirect",
                    parameter_name=parameter_name,
                    base_request=request_base,
                    payloads=(
                        payload_result.get("variants")
                        if isinstance(payload_result, dict) and payload_result.get("success")
                        else None
                    ),
                    semantic_matchers=["https://evil.example/landing", "//evil.example/landing", "/admin", "/internal/debug"],
                    baseline_value=(
                        _request_context_baseline_value(
                            request_context,
                            parameter_name,
                            str(item["injection_mode"]),
                        )
                        or _query_parameter_value(request_url, parameter_name)
                        or "/dashboard"
                    ),
                    injection_mode=str(item["injection_mode"]),
                    max_payloads=max(1, min(max_active_targets, 4)),
                    follow_redirects=False,
                    min_anomaly_score=3,
                )
                active_probe_results.append(active_probe_result)
                _append_pipeline_step(
                    steps,
                    step_name="payload_probe_harness",
                    result=active_probe_result,
                    metadata={
                        "focus": "open_redirect",
                        "url": request_url,
                        "parameter": parameter_name,
                        "request_id": request_context.get("request_id"),
                        "request_source": request_context.get("source"),
                        "request_method": request_context.get("method"),
                        "injection_mode": item["injection_mode"],
                    },
                )

        elif normalized_focus == "ssti":
            suspicious_parameter_findings: list[dict[str, Any]] = []
            seen_ssti_candidates: set[tuple[str, str, str]] = set()

            def add_ssti_candidate(item: dict[str, Any]) -> None:
                parameter_name = str(item.get("parameter") or "").strip()
                candidate_url = str(item.get("url") or "").strip()
                candidate_path = str(item.get("path") or "").strip()
                if not parameter_name:
                    return
                key = (candidate_url, candidate_path, parameter_name)
                if key in seen_ssti_candidates:
                    return
                seen_ssti_candidates.add(key)
                suspicious_parameter_findings.append(dict(item))

            for finding in _stored_findings(store, target=normalized_target, tool_name="arjun"):
                if any(
                    keyword in str(finding.get("parameter") or "").strip().lower()
                    for keyword in FOCUS_PARAMETER_HINTS["ssti"]
                ):
                    add_ssti_candidate(finding)
            for candidate in _request_context_parameter_candidates(runtime_entries, focus="ssti"):
                add_ssti_candidate(candidate)
            if not suspicious_parameter_findings and "arjun" in available_tools:
                for active_url in candidate_urls[:max_active_targets]:
                    arjun_result = run_step(
                        "arjun",
                        url=active_url,
                        max_seed_items=max_hypotheses,
                        max_hypotheses=max_hypotheses,
                        metadata={"url": active_url},
                    )
                    for finding in arjun_result.get("findings", []):
                        if any(
                            keyword in str(finding.get("parameter") or "").strip().lower()
                            for keyword in FOCUS_PARAMETER_HINTS["ssti"]
                        ):
                            add_ssti_candidate(finding)

            probe_plans: list[dict[str, Any]] = []
            seen_probe_plans: set[tuple[str, str, str]] = set()
            for finding in suspicious_parameter_findings:
                parameter_name = str(finding.get("parameter") or "").strip() or "template"
                candidate_url = str(
                    finding.get("url") or (candidate_urls[0] if candidate_urls else "")
                ).strip()
                request_contexts = _focus_request_contexts(
                    agent_state=agent_state,
                    target=normalized_target,
                    candidate_url=candidate_url or None,
                    parameter_name=parameter_name,
                    focus="ssti",
                    max_items=1,
                    runtime_entries=runtime_entries,
                    workflows=discovered_workflows,
                    session_profiles=session_profiles,
                )
                request_context = (
                    request_contexts[0]
                    if request_contexts
                    else (
                        _fallback_request_context(candidate_url, normalized_headers)
                        if candidate_url
                        else None
                    )
                )
                if request_context is None:
                    continue
                injection_mode = _request_context_injection_mode(request_context, parameter_name)
                plan_key = (
                    str(request_context.get("url") or ""),
                    parameter_name,
                    injection_mode,
                )
                if plan_key in seen_probe_plans:
                    continue
                seen_probe_plans.add(plan_key)
                probe_plans.append(
                    {
                        "parameter": parameter_name,
                        "request_context": request_context,
                        "injection_mode": injection_mode,
                    }
                )

            for candidate_url in candidate_urls:
                parsed = urlparse(candidate_url)
                for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                    if not any(keyword in name.lower() for keyword in FOCUS_PARAMETER_HINTS["ssti"]):
                        continue
                    plan_key = (candidate_url, name, "query")
                    if plan_key in seen_probe_plans:
                        continue
                    seen_probe_plans.add(plan_key)
                    probe_plans.append(
                        {
                            "parameter": name,
                            "request_context": _fallback_request_context(candidate_url, normalized_headers),
                            "injection_mode": "query",
                        }
                    )

            for item in probe_plans[:max_active_targets]:
                parameter_name = str(item["parameter"])
                request_context = dict(item["request_context"])
                selected_request_contexts.append(request_context)
                request_url = str(request_context.get("url") or "").strip()
                request_path = urlparse(request_url).path or "/"
                candidate_surface = (
                    f"Potential server-side template injection in parameter {parameter_name} on {request_path}"
                )
                payload_result = generate_contextual_payloads(
                    vulnerability_type="ssti",
                    surface=candidate_surface,
                    parameter_names=[parameter_name],
                    max_variants=max_hypotheses * 2,
                )
                request_base = dict(request_context.get("base_request") or {})
                request_base["headers"] = {
                    **dict(request_base.get("headers") or {}),
                    **normalized_headers,
                }
                active_probe_result = payload_probe_harness(
                    agent_state=agent_state,
                    target=normalized_target,
                    component=f"focus:ssti:{urlparse(request_url).netloc}{request_path}",
                    surface=candidate_surface,
                    vulnerability_type="ssti",
                    parameter_name=parameter_name,
                    base_request=request_base,
                    payloads=(
                        payload_result.get("variants")
                        if isinstance(payload_result, dict) and payload_result.get("success")
                        else None
                    ),
                    baseline_value=(
                        _request_context_baseline_value(
                            request_context,
                            parameter_name,
                            str(item["injection_mode"]),
                        )
                        or "hello"
                    ),
                    injection_mode=str(item["injection_mode"]),
                    max_payloads=max(1, min(max_active_targets, 4)),
                    min_anomaly_score=3,
                )
                active_probe_results.append(active_probe_result)
                _append_pipeline_step(
                    steps,
                    step_name="payload_probe_harness",
                    result=active_probe_result,
                    metadata={
                        "focus": "ssti",
                        "url": request_url,
                        "parameter": parameter_name,
                        "request_id": request_context.get("request_id"),
                        "request_source": request_context.get("source"),
                        "request_method": request_context.get("method"),
                        "injection_mode": item["injection_mode"],
                    },
                )

        elif normalized_focus == "xxe":
            xml_contexts = _xml_focus_contexts(
                runtime_entries,
                discovered_workflows,
                session_profiles=session_profiles,
                max_items=max(1, min(max_active_targets, 4)),
            )
            if not xml_contexts and candidate_urls:
                xml_contexts = [
                    _fallback_body_request_context(
                        candidate_urls[0],
                        normalized_headers,
                        method="POST",
                        body="<?xml version=\"1.0\"?><root>safe</root>",
                        content_type="application/xml",
                    )
                ]
            selected_request_contexts.extend(xml_contexts)

            doctor_result = oob_interaction_harness(
                agent_state=agent_state,
                action="doctor",
            )
            if callback_base_url or doctor_result.get("cli_available"):
                harness_result = oob_interaction_harness(
                    agent_state=agent_state,
                    action="start",
                    target=normalized_target,
                    component="focus:xxe",
                    surface="Potential XXE raw XML parsing",
                    vulnerability_type="xxe",
                    labels=[normalized_focus],
                    callback_base_url=callback_base_url,
                )
            callback_urls = []
            if isinstance(harness_result, dict):
                callback_urls = [
                    str(item.get("url") or "").strip()
                    for item in (harness_result.get("payloads") or [])
                    if str(item.get("url") or "").strip()
                ]
            payload_result = generate_contextual_payloads(
                vulnerability_type="xxe",
                surface="Potential XXE raw XML parsing",
                callback_urls=callback_urls,
                max_variants=max_hypotheses * 2,
            )

            for request_context in xml_contexts[:max_active_targets]:
                request_url = str(request_context.get("url") or "").strip()
                request_path = urlparse(request_url).path or "/"
                request_base = dict(request_context.get("base_request") or {})
                request_base["headers"] = {
                    **dict(request_base.get("headers") or {}),
                    **normalized_headers,
                }
                active_probe_result = payload_probe_harness(
                    agent_state=agent_state,
                    target=normalized_target,
                    component=f"focus:xxe:{urlparse(request_url).netloc}{request_path}",
                    surface=f"Potential XXE on {request_path}",
                    vulnerability_type="xxe",
                    parameter_name="xml_body",
                    base_request=request_base,
                    payloads=(
                        payload_result.get("variants")
                        if isinstance(payload_result, dict) and payload_result.get("success")
                        else None
                    ),
                    callback_urls=callback_urls,
                    baseline_value=(
                        _request_context_baseline_value(
                            request_context,
                            "xml_body",
                            "raw_body",
                        )
                        or "<?xml version=\"1.0\"?><root>safe</root>"
                    ),
                    injection_mode="raw_body",
                    max_payloads=max(1, min(max_active_targets, 4)),
                    oob_harness_id=(
                        str(harness_result.get("harness_id"))
                        if isinstance(harness_result, dict) and harness_result.get("harness_id")
                        else None
                    ),
                    poll_oob=bool(
                        isinstance(harness_result, dict)
                        and str(harness_result.get("provider") or "").strip().lower() == "interactsh"
                    ),
                    min_anomaly_score=4,
                )
                active_probe_results.append(active_probe_result)
                _append_pipeline_step(
                    steps,
                    step_name="payload_probe_harness",
                    result=active_probe_result,
                    metadata={
                        "focus": "xxe",
                        "url": request_url,
                        "request_id": request_context.get("request_id"),
                        "request_source": request_context.get("source"),
                        "request_method": request_context.get("method"),
                        "injection_mode": "raw_body",
                    },
                )

        elif normalized_focus == "file_upload":
            upload_contexts = _upload_focus_contexts(
                runtime_entries,
                discovered_workflows,
                session_profiles=session_profiles,
                max_items=max(1, min(max_active_targets, 4)),
            )
            selected_request_contexts.extend(upload_contexts)

            doctor_result = oob_interaction_harness(
                agent_state=agent_state,
                action="doctor",
            )
            if callback_base_url or doctor_result.get("cli_available"):
                harness_result = oob_interaction_harness(
                    agent_state=agent_state,
                    action="start",
                    target=normalized_target,
                    component="focus:file_upload",
                    surface="Potential upload parser and post-storage validation bypass",
                    vulnerability_type="xxe",
                    labels=[normalized_focus],
                    callback_base_url=callback_base_url,
                )
            callback_urls = []
            if isinstance(harness_result, dict):
                callback_urls = [
                    str(item.get("url") or "").strip()
                    for item in (harness_result.get("payloads") or [])
                    if str(item.get("url") or "").strip()
                ]

            for request_context in upload_contexts[:max_active_targets]:
                request_url = str(request_context.get("url") or "").strip()
                request_path = urlparse(request_url).path or "/"
                upload_payloads = _multipart_upload_payloads_from_context(
                    request_context,
                    callback_urls=callback_urls,
                )
                if not upload_payloads:
                    continue
                request_base = dict(request_context.get("base_request") or {})
                request_base["headers"] = {
                    **dict(request_base.get("headers") or {}),
                    **normalized_headers,
                }
                active_probe_result = payload_probe_harness(
                    agent_state=agent_state,
                    target=normalized_target,
                    component=f"focus:file_upload:{urlparse(request_url).netloc}{request_path}",
                    surface=f"Potential file upload validation bypass on {request_path}",
                    vulnerability_type="file_upload",
                    parameter_name="multipart_body",
                    base_request=request_base,
                    payloads=upload_payloads,
                    baseline_value=(
                        _request_context_baseline_value(
                            request_context,
                            "multipart_body",
                            "raw_body",
                        )
                        or str(request_base.get("body") or "")
                    ),
                    injection_mode="raw_body",
                    max_payloads=max(1, min(max_active_targets, 4)),
                    oob_harness_id=(
                        str(harness_result.get("harness_id"))
                        if isinstance(harness_result, dict) and harness_result.get("harness_id")
                        else None
                    ),
                    poll_oob=bool(
                        isinstance(harness_result, dict)
                        and str(harness_result.get("provider") or "").strip().lower() == "interactsh"
                    ),
                    min_anomaly_score=3,
                )
                active_probe_results.append(active_probe_result)
                _append_pipeline_step(
                    steps,
                    step_name="payload_probe_harness",
                    result=active_probe_result,
                    metadata={
                        "focus": "file_upload",
                        "url": request_url,
                        "request_id": request_context.get("request_id"),
                        "request_source": request_context.get("source"),
                        "request_method": request_context.get("method"),
                        "injection_mode": "raw_body",
                    },
                )
                artifact_followup = _upload_followup_findings(
                    agent_state=agent_state,
                    target=normalized_target,
                    request_context=request_context,
                    active_probe_result=active_probe_result,
                    workflows=discovered_workflows,
                    runtime_entries=runtime_entries,
                    public_path_hints=public_path_hints,
                )
                artifact_retrieval_results.append(artifact_followup)
                _append_pipeline_step(
                    steps,
                    step_name="upload_artifact_followup",
                    result=artifact_followup,
                    metadata={
                        "focus": "file_upload",
                        "url": request_url,
                        "request_id": request_context.get("request_id"),
                        "request_source": request_context.get("source"),
                        "request_method": request_context.get("method"),
                    },
                )

        elif normalized_focus == "path_traversal":
            suspicious_parameter_findings: list[dict[str, Any]] = []
            seen_traversal_candidates: set[tuple[str, str, str]] = set()

            def add_traversal_candidate(item: dict[str, Any]) -> None:
                parameter_name = str(item.get("parameter") or "").strip()
                candidate_url = str(item.get("url") or "").strip()
                candidate_path = str(item.get("path") or "").strip()
                if not parameter_name:
                    return
                key = (candidate_url, candidate_path, parameter_name)
                if key in seen_traversal_candidates:
                    return
                seen_traversal_candidates.add(key)
                suspicious_parameter_findings.append(dict(item))

            for finding in _stored_findings(store, target=normalized_target, tool_name="arjun"):
                if any(
                    keyword in str(finding.get("parameter") or "").strip().lower()
                    for keyword in FOCUS_PARAMETER_HINTS["path_traversal"]
                ):
                    add_traversal_candidate(finding)
            for candidate in _request_context_parameter_candidates(runtime_entries, focus="path_traversal"):
                add_traversal_candidate(candidate)
            if not suspicious_parameter_findings and "arjun" in available_tools:
                for active_url in candidate_urls[:max_active_targets]:
                    arjun_result = run_step(
                        "arjun",
                        url=active_url,
                        max_seed_items=max_hypotheses,
                        max_hypotheses=max_hypotheses,
                        metadata={"url": active_url},
                    )
                    for finding in arjun_result.get("findings", []):
                        if any(
                            keyword in str(finding.get("parameter") or "").strip().lower()
                            for keyword in FOCUS_PARAMETER_HINTS["path_traversal"]
                        ):
                            add_traversal_candidate(finding)

            probe_plans: list[dict[str, Any]] = []
            seen_probe_plans: set[tuple[str, str, str]] = set()
            for finding in suspicious_parameter_findings:
                parameter_name = str(finding.get("parameter") or "").strip() or "file"
                candidate_url = str(
                    finding.get("url") or (candidate_urls[0] if candidate_urls else "")
                ).strip()
                request_contexts = _focus_request_contexts(
                    agent_state=agent_state,
                    target=normalized_target,
                    candidate_url=candidate_url or None,
                    parameter_name=parameter_name,
                    focus="path_traversal",
                    max_items=1,
                    runtime_entries=runtime_entries,
                    workflows=discovered_workflows,
                    session_profiles=session_profiles,
                )
                request_context = (
                    request_contexts[0]
                    if request_contexts
                    else (
                        _fallback_request_context(candidate_url, normalized_headers)
                        if candidate_url
                        else None
                    )
                )
                if request_context is None:
                    continue
                injection_mode = _request_context_injection_mode(request_context, parameter_name)
                plan_key = (
                    str(request_context.get("url") or ""),
                    parameter_name,
                    injection_mode,
                )
                if plan_key in seen_probe_plans:
                    continue
                seen_probe_plans.add(plan_key)
                probe_plans.append(
                    {
                        "parameter": parameter_name,
                        "request_context": request_context,
                        "injection_mode": injection_mode,
                    }
                )

            for candidate_url in candidate_urls:
                parsed = urlparse(candidate_url)
                for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                    if not any(keyword in name.lower() for keyword in FOCUS_PARAMETER_HINTS["path_traversal"]):
                        continue
                    plan_key = (candidate_url, name, "query")
                    if plan_key in seen_probe_plans:
                        continue
                    seen_probe_plans.add(plan_key)
                    probe_plans.append(
                        {
                            "parameter": name,
                            "request_context": _fallback_request_context(candidate_url, normalized_headers),
                            "injection_mode": "query",
                        }
                    )

            for item in probe_plans[:max_active_targets]:
                parameter_name = str(item["parameter"])
                request_context = dict(item["request_context"])
                selected_request_contexts.append(request_context)
                request_url = str(request_context.get("url") or "").strip()
                request_path = urlparse(request_url).path or "/"
                candidate_surface = (
                    f"Potential path traversal in parameter {parameter_name} on {request_path}"
                )
                payload_result = generate_contextual_payloads(
                    vulnerability_type="path_traversal",
                    surface=candidate_surface,
                    parameter_names=[parameter_name],
                    max_variants=max_hypotheses * 2,
                )
                request_base = dict(request_context.get("base_request") or {})
                request_base["headers"] = {
                    **dict(request_base.get("headers") or {}),
                    **normalized_headers,
                }
                active_probe_result = payload_probe_harness(
                    agent_state=agent_state,
                    target=normalized_target,
                    component=f"focus:path_traversal:{urlparse(request_url).netloc}{request_path}",
                    surface=candidate_surface,
                    vulnerability_type="path_traversal",
                    parameter_name=parameter_name,
                    base_request=request_base,
                    payloads=(
                        payload_result.get("variants")
                        if isinstance(payload_result, dict) and payload_result.get("success")
                        else None
                    ),
                    baseline_value=(
                        _request_context_baseline_value(
                            request_context,
                            parameter_name,
                            str(item["injection_mode"]),
                        )
                        or "report.pdf"
                    ),
                    injection_mode=str(item["injection_mode"]),
                    max_payloads=max(1, min(max_active_targets, 4)),
                    min_anomaly_score=3,
                )
                active_probe_results.append(active_probe_result)
                _append_pipeline_step(
                    steps,
                    step_name="payload_probe_harness",
                    result=active_probe_result,
                    metadata={
                        "focus": "path_traversal",
                        "url": request_url,
                        "parameter": parameter_name,
                        "request_id": request_context.get("request_id"),
                        "request_source": request_context.get("source"),
                        "request_method": request_context.get("method"),
                        "injection_mode": item["injection_mode"],
                    },
                )

        elif normalized_focus == "authz":
            authz_contexts = _authz_focus_contexts(
                runtime_entries,
                discovered_workflows,
                session_profiles=session_profiles,
                max_items=max(1, min(max_active_targets, 4)),
            )
            selected_request_contexts.extend(authz_contexts)

            for request_context in authz_contexts[:max_active_targets]:
                cases, baseline_case = _authz_cases_for_context(
                    request_context,
                    session_profiles,
                    max_profiles=3,
                )
                if len(cases) < 2:
                    continue
                request_url = str(request_context.get("url") or "").strip()
                request_method = str(request_context.get("method") or "GET").strip().upper()
                request_path = urlparse(request_url).path or "/"
                authz_result = role_matrix_test(
                    agent_state=agent_state,
                    target=normalized_target,
                    component=f"focus:authz:{urlparse(request_url).netloc}{request_path}",
                    surface=f"Authorization matrix on {request_method} {request_path}",
                    method=request_method,
                    url=request_url,
                    cases=cases,
                    baseline_case=baseline_case,
                )
                active_probe_results.append(authz_result)
                _append_pipeline_step(
                    steps,
                    step_name="role_matrix_test",
                    result=authz_result,
                    metadata={
                        "focus": "authz",
                        "url": request_url,
                        "request_id": request_context.get("request_id"),
                        "request_source": request_context.get("source"),
                        "request_method": request_method,
                        "case_count": len(cases),
                        "baseline_case": baseline_case,
                    },
                )

        else:
            race_plans = _workflow_race_plans(
                discovered_workflows,
                runtime_entries,
                session_profiles=session_profiles,
                max_items=max(1, min(max_active_targets, 4)),
            )
            selected_request_contexts.extend(
                [dict(item.get("request_context") or {}) for item in race_plans]
            )

            for plan in race_plans[:max_active_targets]:
                request_context = dict(plan.get("request_context") or {})
                request_url = str(request_context.get("url") or "").strip()
                request_method = str(request_context.get("method") or "POST").strip().upper()
                request_path = urlparse(request_url).path or "/"
                workflow = plan.get("workflow") or {}
                surface = (
                    f"Workflow race on {request_method} {request_path}"
                    if not workflow
                    else str(workflow.get("surface") or f"Workflow race on {request_method} {request_path}")
                )
                base_request = dict(request_context.get("base_request") or {})
                concurrent_requests = []
                for index in range(2):
                    concurrent_spec = {
                        "name": f"race_{index + 1}",
                        "method": str(base_request.get("method") or request_method),
                        "url": str(base_request.get("url") or request_url),
                    }
                    if base_request.get("headers") is not None:
                        concurrent_spec["headers"] = dict(base_request.get("headers") or {})
                    if base_request.get("cookies") is not None:
                        concurrent_spec["cookies"] = dict(base_request.get("cookies") or {})
                    if base_request.get("params") is not None:
                        concurrent_spec["params"] = dict(base_request.get("params") or {})
                    if base_request.get("json_body") is not None:
                        concurrent_spec["json_body"] = json.loads(
                            json.dumps(base_request.get("json_body"), ensure_ascii=False)
                        )
                    elif base_request.get("body") is not None:
                        concurrent_spec["body"] = str(base_request.get("body"))
                    concurrent_requests.append(concurrent_spec)

                race_result = race_condition_harness(
                    agent_state=agent_state,
                    target=normalized_target,
                    component=f"focus:race:{urlparse(request_url).netloc}{request_path}",
                    surface=surface,
                    requests=concurrent_requests,
                    iterations=5,
                    expect_single_success=_workflow_race_expect_single_success(
                        workflow if isinstance(workflow, dict) else {},
                        request_context,
                    ),
                )
                active_probe_results.append(race_result)
                _append_pipeline_step(
                    steps,
                    step_name="race_condition_harness",
                    result=race_result,
                    metadata={
                        "focus": "workflow_race",
                        "url": request_url,
                        "request_id": request_context.get("request_id"),
                        "request_source": request_context.get("source"),
                        "request_method": request_method,
                        "workflow_type": workflow.get("type") if isinstance(workflow, dict) else None,
                    },
                )

        successful_steps = [step for step in steps if step.get("success")]
        run_ids = [str(step.get("run_id")) for step in successful_steps if step.get("run_id")]
        correlated_hypotheses = _correlate_tool_run_signals(
            agent_state=agent_state,
            logical_target=normalized_target,
            store=store,
            run_ids=run_ids,
            max_hypotheses=max_hypotheses,
        )
        if auto_synthesize_hypotheses:
            synthesized_result = synthesize_attack_hypotheses(
                agent_state=agent_state,
                target=normalized_target,
                max_hypotheses=max_hypotheses,
                persist=True,
                include_existing_open=False,
            )
        if auto_build_review:
            review_scope_targets = _attack_surface_review_scope_targets(
                normalized_targets,
                candidate_urls,
                [str(url).strip()] if url else [],
            )
            attack_surface_review_result = _build_pipeline_attack_surface_review(
                agent_state=agent_state,
                target=normalized_target,
                scope_targets=review_scope_targets,
                max_priorities=max_hypotheses,
            )
            _persist_pipeline_attack_surface_review(agent_state, attack_surface_review_result)
            review_snapshot = _attack_surface_review_snapshot(attack_surface_review_result) or {}
            _append_pipeline_step(
                steps,
                step_name="build_attack_surface_review",
                result=attack_surface_review_result,
                metadata={
                    "scope_target_count": len(review_scope_targets),
                    "needs_more_data": (
                        review_snapshot.get("summary", {}).get("needs_more_data")
                        if isinstance(review_snapshot.get("summary"), dict)
                        else None
                    ),
                },
            )
            if auto_spawn_review_agents and attack_surface_review_result.get("success"):
                attack_surface_agent_result = _spawn_pipeline_attack_surface_agents(
                    agent_state=agent_state,
                    target=normalized_target,
                    max_active_targets=max_active_targets,
                    strategy="depth_first",
                )
                _append_pipeline_step(
                    steps,
                    step_name="spawn_attack_surface_agents",
                    result=attack_surface_agent_result,
                    metadata={
                        "strategy": "depth_first",
                        "max_agents": _pipeline_review_agent_limit(max_active_targets),
                        "created_count": (
                            attack_surface_agent_result.get("created_count")
                            if isinstance(attack_surface_agent_result, dict)
                            else None
                        ),
                        "recommended_count": (
                            attack_surface_agent_result.get("recommended_count")
                            if isinstance(attack_surface_agent_result, dict)
                            else None
                        ),
                    },
                )
        if auto_spawn_signal_agents:
            candidate_signal_result = _spawn_pipeline_strong_signal_agents(
                agent_state=agent_state,
                target=normalized_target,
                max_active_targets=max_active_targets,
            )
            if (
                isinstance(candidate_signal_result, dict)
                and candidate_signal_result.get("success")
                and (
                    int(candidate_signal_result.get("recommended_count") or 0) > 0
                    or int(candidate_signal_result.get("skipped_count") or 0) > 0
                )
            ):
                strong_signal_agent_result = candidate_signal_result
                _append_pipeline_step(
                    steps,
                    step_name="spawn_strong_signal_agents",
                    result=strong_signal_agent_result,
                    metadata={
                        "max_agents": _pipeline_signal_agent_limit(max_active_targets),
                        "created_count": (
                            strong_signal_agent_result.get("created_count")
                            if isinstance(strong_signal_agent_result, dict)
                            else None
                        ),
                        "recommended_count": (
                            strong_signal_agent_result.get("recommended_count")
                            if isinstance(strong_signal_agent_result, dict)
                            else None
                        ),
                    },
                )
        if auto_spawn_impact_agents:
            candidate_impact_result = _spawn_pipeline_impact_chain_agents(
                agent_state=agent_state,
                target=normalized_target,
                max_active_targets=max_active_targets,
            )
            if (
                isinstance(candidate_impact_result, dict)
                and candidate_impact_result.get("success")
                and (
                    int(candidate_impact_result.get("recommended_count") or 0) > 0
                    or int(candidate_impact_result.get("skipped_count") or 0) > 0
                )
            ):
                impact_chain_agent_result = candidate_impact_result
                _append_pipeline_step(
                    steps,
                    step_name="spawn_impact_chain_agents",
                    result=impact_chain_agent_result,
                    metadata={
                        "max_agents": _pipeline_impact_agent_limit(max_active_targets),
                        "created_count": (
                            impact_chain_agent_result.get("created_count")
                            if isinstance(impact_chain_agent_result, dict)
                            else None
                        ),
                        "recommended_count": (
                            impact_chain_agent_result.get("recommended_count")
                            if isinstance(impact_chain_agent_result, dict)
                            else None
                        ),
                    },
                )
        successful_steps = [step for step in steps if step.get("success")]
        run_ids = [str(step.get("run_id")) for step in successful_steps if step.get("run_id")]

        summary_payload = {
            "focus": normalized_focus,
            "available_tools": sorted(available_tools),
            "skipped_tools": skipped_tools,
            "run_ids": run_ids,
            "candidate_urls": candidate_urls[:max_active_targets],
            "inventory_enrichment": {
                "runtime_mapped": bool(runtime_entries),
                "surface_mined": bool(surface_artifacts),
                "workflows_mapped": bool(discovered_workflows),
            },
            "bootstrap_result": bootstrap_result,
            "code_sink_result": code_sink_result,
            "active_probe_count": len(active_probe_results),
            "artifact_retrieval_count": len(artifact_retrieval_results),
            "request_context_count": len(selected_request_contexts),
            "request_contexts": [
                {
                    "url": item.get("url"),
                    "method": item.get("method"),
                    "request_id": item.get("request_id"),
                    "source": item.get("source"),
                    "session_profile_id": item.get("session_profile_id"),
                }
                for item in selected_request_contexts[: max_active_targets * 2]
            ],
            "correlated_hypothesis_count": len(correlated_hypotheses),
            "attack_surface_review": _attack_surface_review_snapshot(
                attack_surface_review_result
            ),
            "attack_surface_agent_result": attack_surface_agent_result,
            "strong_signal_agent_result": strong_signal_agent_result,
            "impact_chain_agent_result": impact_chain_agent_result,
            "steps": steps,
        }
        summary_evidence = record_evidence(
            agent_state=agent_state,
            title=f"Security focus pipeline summary for {normalized_target} ({normalized_focus})",
            details=json.dumps(summary_payload, ensure_ascii=False),
            source="tool",
            target=normalized_target,
            component=f"toolchain:focus:{normalized_focus}",
        )

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to run security focus pipeline: {e}"}
    else:
        return {
            "success": True,
            "root_agent_id": root_agent_id,
            "focus": normalized_focus,
            "available_tools": sorted(available_tools),
            "skipped_tools": skipped_tools,
            "step_count": len(steps),
            "successful_step_count": len(successful_steps),
            "run_ids": run_ids,
            "candidate_urls": candidate_urls[:max_active_targets],
            "bootstrap_result": bootstrap_result,
            "payload_result": payload_result,
            "harness_result": harness_result,
            "code_sink_result": code_sink_result,
            "inventory_enrichment_result": enrichment_result,
            "request_contexts": selected_request_contexts,
            "active_probe_results": active_probe_results,
            "artifact_retrieval_results": artifact_retrieval_results,
            "correlated_hypotheses": correlated_hypotheses,
            "attack_surface_review_result": attack_surface_review_result,
            "attack_surface_agent_result": attack_surface_agent_result,
            "strong_signal_agent_result": strong_signal_agent_result,
            "impact_chain_agent_result": impact_chain_agent_result,
            "synthesized_hypotheses_result": synthesized_result,
            "steps": steps,
            "evidence_result": summary_evidence,
        }


@register_tool(sandbox_execution=False)
def list_security_tool_runs(
    agent_state: Any,
    target: str | None = None,
    tool_name: str | None = None,
    include_findings: bool = False,
    max_items: int = 25,
) -> dict[str, Any]:
    try:
        if max_items < 1:
            raise ValueError("max_items must be >= 1")

        root_agent_id, store = _get_tool_store(agent_state)
        _update_agent_context(agent_state, root_agent_id)

        normalized_target = (
            _normalize_non_empty(target, "target") if target is not None else None
        )
        normalized_tool_name = _normalize_tool_name(tool_name) if tool_name is not None else None

        records = list(store.values())
        if normalized_target is not None:
            records = [record for record in records if record.get("target") == normalized_target]
        if normalized_tool_name is not None:
            records = [record for record in records if record.get("tool_name") == normalized_tool_name]

        records.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)

    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to list security tool runs: {e}"}
    else:
        return {
            "success": True,
            "root_agent_id": root_agent_id,
            "run_count": len(records),
            "runs": [
                _record_for_response(record, include_findings=include_findings)
                for record in records[:max_items]
            ],
        }
