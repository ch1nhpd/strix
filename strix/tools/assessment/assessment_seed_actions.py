import ast
import json
import re
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool

from .assessment_actions import bulk_record_coverage


IGNORED_CODE_DIRS = {
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
NEXTJS_PAGE_FILES = {
    "page.js",
    "page.jsx",
    "page.ts",
    "page.tsx",
    "page.mdx",
}
NEXTJS_ROUTE_FILES = {
    "route.js",
    "route.jsx",
    "route.ts",
    "route.tsx",
}
NEXTJS_PAGE_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mdx"}
NEXTJS_SPECIAL_PAGES = {"_app", "_document", "_error", "404", "500"}
HTTP_METHOD_PRIORITIES = {
    "DELETE": 5,
    "PATCH": 5,
    "POST": 4,
    "PUT": 4,
    "GET": 3,
    "HEAD": 2,
    "OPTIONS": 2,
    "ANY": 2,
}
HIGH_VALUE_KEYWORDS = {
    "admin": 6,
    "auth": 6,
    "login": 6,
    "token": 6,
    "password": 6,
    "oauth": 6,
    "session": 6,
    "billing": 5,
    "payment": 5,
    "invoice": 5,
    "wallet": 5,
    "order": 5,
    "checkout": 5,
    "tenant": 5,
    "user": 4,
    "profile": 4,
    "account": 4,
    "export": 4,
    "import": 4,
    "upload": 4,
    "download": 4,
    "webhook": 4,
    "callback": 4,
    "internal": 4,
    "debug": 3,
    "api": 2,
}
FRAMEWORK_SKILLS = {"fastapi": "fastapi", "nextjs": "nextjs", "nestjs": "nestjs"}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _relative_component(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return path.name


def _join_url_parts(*parts: str) -> str:
    normalized: list[str] = []
    for part in parts:
        if not part:
            continue
        cleaned = str(part).strip().strip("/")
        if cleaned:
            normalized.append(cleaned)
    return "/" + "/".join(normalized) if normalized else "/"


def _dedupe_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        key = (
            str(item.get("target", "")),
            str(item.get("component", "")),
            str(item.get("surface", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _route_priority(path: str, method: str = "ANY") -> str:
    score = HTTP_METHOD_PRIORITIES.get(method.upper(), 2)
    lowered = path.lower()
    for keyword, weight in HIGH_VALUE_KEYWORDS.items():
        if keyword in lowered:
            score += weight
    if path == "/":
        score -= 1

    if score >= 10:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 3:
        return "normal"
    return "low"


def _surface_sort_key(item: dict[str, Any]) -> tuple[int, str, str]:
    priority_order = {"critical": 0, "high": 1, "normal": 2, "low": 3}
    surface = str(item.get("surface", ""))
    component = str(item.get("component", ""))
    return (priority_order.get(str(item.get("priority", "normal")), 2), component, surface)


def _highest_priority(priorities: list[str]) -> str:
    priority_order = {"critical": 0, "high": 1, "normal": 2, "low": 3}
    if not priorities:
        return "normal"
    return min(priorities, key=lambda priority: priority_order.get(priority, 2))


def _limit_route_items(items: list[dict[str, Any]], max_route_items: int) -> list[dict[str, Any]]:
    route_items = [item for item in items if str(item.get("component", "")).startswith("route:")]
    non_route_items = [item for item in items if item not in route_items]
    route_items.sort(key=_surface_sort_key)
    return _dedupe_items(non_route_items + route_items[:max_route_items])


def _find_python_files(root: Path) -> list[Path]:
    return [
        path
        for path in root.rglob("*.py")
        if not any(part in IGNORED_CODE_DIRS for part in path.parts)
    ]


def _find_typescript_files(root: Path) -> list[Path]:
    return [
        path
        for path in root.rglob("*")
        if path.suffix in {".ts", ".tsx", ".js", ".jsx"}
        and not any(part in IGNORED_CODE_DIRS for part in path.parts)
    ]


def _extract_json_dependencies(path: Path) -> tuple[set[str], set[str]]:
    if not path.exists():
        return set(), set()

    try:
        payload = json.loads(_read_text(path))
    except json.JSONDecodeError:
        return set(), set()

    dependencies = payload.get("dependencies", {})
    dev_dependencies = payload.get("devDependencies", {})
    dep_names = {
        name
        for name in [*dependencies.keys(), *dev_dependencies.keys()]
        if isinstance(name, str)
    }
    scripts = {
        name
        for name in payload.get("scripts", {}).keys()
        if isinstance(name, str)
    }
    return dep_names, scripts


def _detect_frameworks(root: Path) -> list[str]:
    detected: list[str] = []
    package_json = root / "package.json"
    dependencies, _ = _extract_json_dependencies(package_json)

    if "next" in dependencies or (root / "app").exists() or (root / "pages").exists():
        detected.append("nextjs")
    if "@nestjs/core" in dependencies:
        detected.append("nestjs")

    pyproject = _read_text(root / "pyproject.toml")
    requirements = _read_text(root / "requirements.txt")
    python_files = _find_python_files(root)
    if "fastapi" in pyproject.lower() or "fastapi" in requirements.lower():
        detected.append("fastapi")
    elif any(
        "from fastapi" in _read_text(path) or "import fastapi" in _read_text(path)
        for path in python_files[:50]
    ):
        detected.append("fastapi")

    deduped: list[str] = []
    for framework in detected:
        if framework not in deduped:
            deduped.append(framework)
    return deduped


def _normalize_next_segment(segment: str) -> str:
    if not segment or segment == "index":
        return ""
    if segment.startswith("(") and segment.endswith(")"):
        return ""
    if segment.startswith("[[...") and segment.endswith("]]"):
        return f"*{segment[5:-2]}?"
    if segment.startswith("[...") and segment.endswith("]"):
        return f"*{segment[4:-1]}"
    if segment.startswith("[") and segment.endswith("]"):
        return f":{segment[1:-1]}"
    return segment


def _next_app_route_from_dir(app_dir: Path, route_dir: Path) -> str:
    relative = route_dir.relative_to(app_dir)
    segments = [_normalize_next_segment(part) for part in relative.parts]
    return _join_url_parts(*segments)


def _next_pages_route_from_file(pages_dir: Path, file_path: Path) -> str | None:
    relative = file_path.relative_to(pages_dir)
    parts = list(relative.parts)
    stem = file_path.stem

    if parts[0] == "api":
        route_parts = ["api", *parts[1:-1]]
        if stem != "index":
            route_parts.append(stem)
        normalized = [_normalize_next_segment(part) for part in route_parts]
        return _join_url_parts(*normalized)

    if stem in NEXTJS_SPECIAL_PAGES:
        return None

    route_parts = list(parts[:-1])
    if stem != "index":
        route_parts.append(stem)
    normalized = [_normalize_next_segment(part) for part in route_parts]
    return _join_url_parts(*normalized)


def _extract_next_route_methods(file_path: Path) -> list[str]:
    content = _read_text(file_path)
    methods = {
        method
        for method in re.findall(
            r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b",
            content,
        )
    }
    methods.update(
        re.findall(
            r"export\s+const\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b",
            content,
        )
    )
    return sorted(methods) or ["ANY"]


def _seed_item(
    *,
    target: str,
    component: str,
    surface: str,
    priority: str,
    rationale: str,
    next_step: str,
) -> dict[str, Any]:
    return {
        "target": target,
        "component": component,
        "surface": surface,
        "status": "uncovered",
        "priority": priority,
        "rationale": rationale,
        "next_step": next_step,
    }


def _extract_nextjs_inventory(root: Path, target: str) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    route_count = 0
    features: list[str] = []

    app_dir = root / "app"
    pages_dir = root / "pages"

    if app_dir.exists():
        for file_path in app_dir.rglob("*"):
            if file_path.is_dir() or any(part in IGNORED_CODE_DIRS for part in file_path.parts):
                continue
            if file_path.name in NEXTJS_PAGE_FILES:
                route = _next_app_route_from_dir(app_dir, file_path.parent)
                items.append(
                    _seed_item(
                        target=target,
                        component=f"route:{_relative_component(root, file_path)}",
                        surface=f"Next.js page route {route}",
                        priority=_route_priority(route, "GET"),
                        rationale=(
                            "Auto-seeded from Next.js App Router page discovery for coverage of "
                            "SSR/client-rendered entry points."
                        ),
                        next_step=(
                            "Validate authorization, data exposure, and client-side trust "
                            f"boundaries on {route}"
                        ),
                    )
                )
                route_count += 1
            elif file_path.name in NEXTJS_ROUTE_FILES:
                route = _next_app_route_from_dir(app_dir, file_path.parent)
                methods = _extract_next_route_methods(file_path)
                method_label = "/".join(methods)
                items.append(
                    _seed_item(
                        target=target,
                        component=f"route:{_relative_component(root, file_path)}",
                        surface=f"Next.js route handler {method_label} {route}",
                        priority=_highest_priority(
                            [_route_priority(route, method) for method in methods]
                        ),
                        rationale=(
                            "Auto-seeded from Next.js route-handler extraction to force direct "
                            "API authorization and input testing."
                        ),
                        next_step=(
                            "Run role-matrix and state-change testing on this route handler, "
                            "including middleware and cache boundary checks"
                        ),
                    )
                )
                route_count += 1

        server_actions = [
            file_path
            for file_path in app_dir.rglob("*")
            if file_path.is_file()
            and file_path.suffix in NEXTJS_PAGE_EXTENSIONS
            and "\"use server\"" in _read_text(file_path)
        ]
        if server_actions:
            features.append("server_actions")
            items.append(
                _seed_item(
                    target=target,
                    component="framework:nextjs",
                    surface="Next.js server actions authorization and input boundary",
                    priority="high",
                    rationale=(
                        "Auto-seeded because Server Actions frequently hide privileged writes "
                        "behind client flows."
                    ),
                    next_step=(
                        "Replay server actions outside the intended UI flow and compare "
                        "unauthenticated, user, and privileged sessions"
                    ),
                )
            )

    if pages_dir.exists():
        for file_path in pages_dir.rglob("*"):
            if file_path.is_dir() or file_path.suffix not in NEXTJS_PAGE_EXTENSIONS:
                continue
            if any(part in IGNORED_CODE_DIRS for part in file_path.parts):
                continue

            route = _next_pages_route_from_file(pages_dir, file_path)
            if route is None:
                continue

            component = f"route:{_relative_component(root, file_path)}"
            if route.startswith("/api/") or route == "/api":
                items.append(
                    _seed_item(
                        target=target,
                        component=component,
                        surface=f"Next.js pages API route {route}",
                        priority=_route_priority(route, "ANY"),
                        rationale=(
                            "Auto-seeded from Next.js Pages Router API discovery to force "
                            "handler-level auth and validation review."
                        ),
                        next_step=(
                            "Probe alternate methods, middleware bypasses, and role parity on "
                            f"{route}"
                        ),
                    )
                )
            else:
                items.append(
                    _seed_item(
                        target=target,
                        component=component,
                        surface=f"Next.js pages route {route}",
                        priority=_route_priority(route, "GET"),
                        rationale=(
                            "Auto-seeded from Next.js Pages Router discovery to cover SSR, props, "
                            "and client trust boundaries."
                        ),
                        next_step=(
                            "Check access control, data leakage, and SSR/client inconsistencies on "
                            f"{route}"
                        ),
                    )
                )
            route_count += 1

    middleware_files = [
        root / "middleware.ts",
        root / "middleware.js",
        root / "middleware.mjs",
    ]
    if any(path.exists() for path in middleware_files):
        features.append("middleware")
        items.append(
            _seed_item(
                target=target,
                component="framework:nextjs",
                surface="Next.js middleware authorization and path normalization boundary",
                priority="high",
                rationale=(
                    "Auto-seeded because middleware bypasses often expose high-impact auth drift "
                    "between route layers."
                ),
                next_step=(
                    "Test header/path normalization variants and compare middleware outcomes "
                    "against route-handler enforcement"
                ),
            )
        )

    next_config_candidates = [
        root / "next.config.js",
        root / "next.config.mjs",
        root / "next.config.ts",
        root / "next.config.cjs",
    ]
    next_config_text = "\n".join(
        _read_text(path) for path in next_config_candidates if path.exists()
    )
    if next_config_text:
        if "remotePatterns" in next_config_text or "images:" in next_config_text:
            features.append("image_optimizer")
            items.append(
                _seed_item(
                    target=target,
                    component="framework:nextjs",
                    surface="Next.js image optimizer and remote loader boundary",
                    priority="high",
                    rationale=(
                        "Auto-seeded because remote image configuration can expose SSRF or "
                        "cache-poisoning paths."
                    ),
                    next_step=(
                        "Validate remotePatterns/domains and attempt internal-host and redirect "
                        "probing through image fetch flows"
                    ),
                )
            )
        if "revalidate" in next_config_text or "experimental" in next_config_text:
            features.append("cache_boundary")

    if "cache_boundary" in features:
        items.append(
            _seed_item(
                target=target,
                component="framework:nextjs",
                surface="Next.js cache, ISR, and RSC personalization boundary",
                priority="high",
                rationale=(
                    "Auto-seeded because Next.js cache boundaries frequently leak personalized "
                    "content across users or tenants."
                ),
                next_step=(
                    "Diff cached responses across users, cookies, and role contexts; verify Vary "
                    "and revalidation behavior"
                ),
            )
        )

    return {
        "framework": "nextjs",
        "skill": FRAMEWORK_SKILLS["nextjs"],
        "items": items,
        "route_count": route_count,
        "features": sorted(set(features)),
    }


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _string_from_node(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = [
            part.value
            for part in node.values
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
        ]
        return "".join(parts) if parts else None
    return None


def _keyword_string(call: ast.Call, name: str) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return _string_from_node(keyword.value)
    return None


def _first_arg_string(call: ast.Call) -> str | None:
    if not call.args:
        return None
    return _string_from_node(call.args[0])


class _FastAPIModuleCollector(ast.NodeVisitor):
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.router_prefixes: dict[str, str] = {}
        self.include_edges: list[tuple[str, str, str]] = []
        self.routes: list[dict[str, str]] = []
        self.features: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
        if not targets or not isinstance(node.value, ast.Call):
            return

        call_name = _call_name(node.value.func)
        if call_name == "APIRouter":
            prefix = _keyword_string(node.value, "prefix") or ""
            for target in targets:
                self.router_prefixes[target] = prefix
        elif call_name == "FastAPI":
            for target in targets:
                self.router_prefixes.setdefault(target, "")
            self.features.add("fastapi_app")
            if _keyword_string(node.value, "openapi_url") is not None or _keyword_string(
                node.value, "docs_url"
            ) is not None:
                self.features.add("api_docs")

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            owner = node.func.value.id
            action = node.func.attr

            if action == "include_router":
                router_name = None
                if node.args and isinstance(node.args[0], ast.Name):
                    router_name = node.args[0].id
                elif node.args and isinstance(node.args[0], ast.Attribute):
                    router_name = node.args[0].attr
                prefix = _keyword_string(node, "prefix") or ""
                if router_name:
                    self.include_edges.append((owner, router_name, prefix))
            elif action == "mount":
                self.features.add("mounted_apps")

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._collect_routes(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._collect_routes(node)

    def _collect_routes(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            if not isinstance(decorator.func, ast.Attribute):
                continue
            if not isinstance(decorator.func.value, ast.Name):
                continue

            method = decorator.func.attr.lower()
            if method not in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "options",
                "head",
                "websocket",
            }:
                continue

            route_path = _first_arg_string(decorator) or _keyword_string(decorator, "path") or ""
            router_name = decorator.func.value.id
            self.routes.append(
                {
                    "router": router_name,
                    "method": "WEBSOCKET" if method == "websocket" else method.upper(),
                    "path": route_path,
                    "function": node.name,
                }
            )
            if method == "websocket":
                self.features.add("websocket")


def _expand_fastapi_prefixes(collector: _FastAPIModuleCollector) -> dict[str, list[str]]:
    incoming: dict[str, list[tuple[str, str]]] = {}
    for parent, child, prefix in collector.include_edges:
        incoming.setdefault(child, []).append((parent, prefix))

    memo: dict[str, list[str]] = {}

    def resolve(router_name: str, stack: set[str]) -> list[str]:
        if router_name in memo:
            return memo[router_name]
        if router_name in stack:
            return [collector.router_prefixes.get(router_name, "")]

        local_prefix = collector.router_prefixes.get(router_name, "")
        if router_name not in incoming:
            memo[router_name] = [local_prefix]
            return memo[router_name]

        stack.add(router_name)
        expanded: list[str] = []
        for parent, edge_prefix in incoming.get(router_name, []):
            for parent_prefix in resolve(parent, stack):
                expanded.append(_join_url_parts(parent_prefix, edge_prefix, local_prefix))
        stack.remove(router_name)
        memo[router_name] = expanded or [local_prefix]
        return memo[router_name]

    for router_name in collector.router_prefixes:
        resolve(router_name, set())

    return memo


def _extract_fastapi_inventory(root: Path, target: str) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    route_count = 0
    features: set[str] = set()

    for file_path in _find_python_files(root):
        content = _read_text(file_path)
        if "fastapi" not in content.lower():
            continue

        if any(marker in content for marker in ["Depends(", "Security("]):
            features.add("dependency_auth")
        if any(marker in content for marker in ["UploadFile", "File(", "FileResponse", "StaticFiles"]):
            features.add("file_boundary")
        if "Jinja2Templates" in content:
            features.add("templating")

        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue

        collector = _FastAPIModuleCollector(file_path)
        collector.visit(tree)
        features.update(collector.features)
        prefix_map = _expand_fastapi_prefixes(collector)

        for route in collector.routes:
            prefixes = prefix_map.get(
                route["router"],
                [collector.router_prefixes.get(route["router"], "")],
            )
            for prefix in prefixes:
                full_path = _join_url_parts(prefix, route["path"])
                method = route["method"]
                items.append(
                    _seed_item(
                        target=target,
                        component=f"route:{_relative_component(root, file_path)}",
                        surface=f"FastAPI route {method} {full_path}",
                        priority=_route_priority(full_path, method),
                        rationale=(
                            "Auto-seeded from FastAPI router extraction to force endpoint-level "
                            "auth, validation, and business-logic coverage."
                        ),
                        next_step=(
                            "Validate dependency-based auth, object ownership, and parser "
                            f"differentials on {method} {full_path}"
                        ),
                    )
                )
                route_count += 1

    if "dependency_auth" in features:
        items.append(
            _seed_item(
                target=target,
                component="framework:fastapi",
                surface="FastAPI dependency-based authentication and authorization boundary",
                priority="critical",
                rationale=(
                    "Auto-seeded because FastAPI auth frequently lives in dependencies and can "
                    "drift across routers or methods."
                ),
                next_step=(
                    "Map Depends/Security usage and compare access results across owner, other "
                    "user, and unauthenticated contexts"
                ),
            )
        )

    if "api_docs" in features:
        items.append(
            _seed_item(
                target=target,
                component="framework:fastapi",
                surface="FastAPI OpenAPI and documentation exposure",
                priority="high",
                rationale=(
                    "Auto-seeded because docs and OpenAPI often leak hidden routes and auth "
                    "metadata in production."
                ),
                next_step="Check docs/openapi exposure and reconcile documented vs hidden routes",
            )
        )

    if "websocket" in features:
        items.append(
            _seed_item(
                target=target,
                component="framework:fastapi",
                surface="FastAPI WebSocket authorization parity",
                priority="high",
                rationale=(
                    "Auto-seeded because WebSocket channels often miss route-level authorization "
                    "present on HTTP endpoints."
                ),
                next_step=(
                    "Compare HTTP and WebSocket authorization behavior for equivalent operations "
                    "and topics"
                ),
            )
        )

    if "mounted_apps" in features:
        items.append(
            _seed_item(
                target=target,
                component="framework:fastapi",
                surface="FastAPI mounted sub-apps and static-serving boundary",
                priority="high",
                rationale=(
                    "Auto-seeded because mounted apps can bypass global middleware and auth "
                    "policies."
                ),
                next_step="Inspect mounted apps, static paths, and middleware parity for auth drift",
            )
        )

    if "file_boundary" in features or "templating" in features:
        items.append(
            _seed_item(
                target=target,
                component="framework:fastapi",
                surface="FastAPI file, template, and outbound URL processing boundary",
                priority="high",
                rationale=(
                    "Auto-seeded because upload/download/template flows often hide SSRF, path "
                    "traversal, or injection surfaces."
                ),
                next_step=(
                    "Review upload/download/template paths and validate file name, path, and "
                    "URL handling with malformed inputs"
                ),
            )
        )

    return {
        "framework": "fastapi",
        "skill": FRAMEWORK_SKILLS["fastapi"],
        "items": items,
        "route_count": route_count,
        "features": sorted(features),
    }


def _extract_string_arg(text: str) -> str:
    path_match = re.search(r"path\s*:\s*['\"]([^'\"]*)['\"]", text)
    if path_match:
        return path_match.group(1)
    generic = re.search(r"['\"]([^'\"]*)['\"]", text)
    return generic.group(1) if generic else ""


def _extract_nestjs_inventory(root: Path, target: str) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    route_count = 0
    features: set[str] = set()

    controller_pattern = re.compile(
        r"@Controller\((?P<args>[^)]*)\)\s*(?:export\s+)?class\s+(?P<class>\w+)",
        re.MULTILINE,
    )
    http_pattern = re.compile(
        r"@(?P<method>Get|Post|Put|Patch|Delete|All|Head|Options)\((?P<args>[^)]*)\)",
        re.MULTILINE,
    )
    message_pattern = re.compile(r"@(?P<kind>MessagePattern|EventPattern)\((?P<args>[^)]*)\)")

    for file_path in _find_typescript_files(root):
        content = _read_text(file_path)
        if "@nestjs/" not in content and "@Controller(" not in content:
            continue

        if "@UseGuards" in content or "@Public(" in content:
            features.add("guards")
        if "@WebSocketGateway" in content:
            features.add("websocket")
        if "SwaggerModule.setup" in content or "@nestjs/swagger" in content:
            features.add("swagger")
        if "@MessagePattern" in content or "@EventPattern" in content:
            features.add("microservice")

        controller_match = controller_pattern.search(content)
        controller_prefix = _extract_string_arg(controller_match.group("args")) if controller_match else ""
        controller_name = controller_match.group("class") if controller_match else file_path.stem

        for match in http_pattern.finditer(content):
            decorator = match.group("method").upper()
            route_path = _extract_string_arg(match.group("args"))
            full_path = _join_url_parts(controller_prefix, route_path)
            items.append(
                _seed_item(
                    target=target,
                    component=f"route:{controller_name}",
                    surface=f"NestJS route {decorator} {full_path}",
                    priority=_route_priority(full_path, decorator),
                    rationale=(
                        "Auto-seeded from NestJS controller extraction to force guard, pipe, "
                        "and transport-level authorization testing."
                    ),
                    next_step=(
                        "Compare guard enforcement, DTO validation, and role behavior on "
                        f"{decorator} {full_path}"
                    ),
                )
            )
            route_count += 1

        for match in message_pattern.finditer(content):
            pattern_name = _extract_string_arg(match.group("args")) or "<dynamic>"
            items.append(
                _seed_item(
                    target=target,
                    component=f"route:{controller_name}",
                    surface=f"NestJS {match.group('kind')} {pattern_name}",
                    priority="high",
                    rationale=(
                        "Auto-seeded because non-HTTP transport handlers often miss the auth and "
                        "validation protections present on controllers."
                    ),
                    next_step=(
                        "Check whether equivalent business logic is reachable through unguarded "
                        "message/event handlers"
                    ),
                )
            )

    if "guards" in features:
        items.append(
            _seed_item(
                target=target,
                component="framework:nestjs",
                surface="NestJS guard, decorator, and public-route metadata boundary",
                priority="critical",
                rationale=(
                    "Auto-seeded because guard mismatches and @Public drift are common sources of "
                    "high-impact authorization bypasses."
                ),
                next_step=(
                    "Map global/controller/method guards and compare low-privilege vs privileged "
                    "access across controllers"
                ),
            )
        )

    if "websocket" in features:
        items.append(
            _seed_item(
                target=target,
                component="framework:nestjs",
                surface="NestJS WebSocket gateway authorization parity",
                priority="high",
                rationale=(
                    "Auto-seeded because WebSocket gateways frequently diverge from HTTP guard "
                    "coverage."
                ),
                next_step=(
                    "Replay equivalent operations across HTTP and WebSocket transports and diff "
                    "authorization outcomes"
                ),
            )
        )

    if "microservice" in features:
        items.append(
            _seed_item(
                target=target,
                component="framework:nestjs",
                surface="NestJS microservice transport exposure",
                priority="high",
                rationale=(
                    "Auto-seeded because message/event handlers are often treated as trusted and "
                    "left unguarded."
                ),
                next_step="Inspect MessagePattern/EventPattern handlers for missing guard coverage",
            )
        )

    if "swagger" in features:
        items.append(
            _seed_item(
                target=target,
                component="framework:nestjs",
                surface="NestJS Swagger and API documentation exposure",
                priority="high",
                rationale=(
                    "Auto-seeded because Swagger often reveals internal or admin routes plus DTO "
                    "schemas."
                ),
                next_step="Check deployed Swagger exposure and reconcile docs with hidden endpoints",
            )
        )

    return {
        "framework": "nestjs",
        "skill": FRAMEWORK_SKILLS["nestjs"],
        "items": items,
        "route_count": route_count,
        "features": sorted(features),
    }


def _generic_codebase_items(target: str, root: Path) -> list[dict[str, Any]]:
    return [
        _seed_item(
            target=target,
            component=f"codebase:{root.name}",
            surface="Authentication, authorization, and tenant-boundary coverage",
            priority="critical",
            rationale=(
                "Auto-seeded baseline for source-code targets to force explicit coverage of the "
                "highest-impact privilege boundaries."
            ),
            next_step=(
                "Map roles, sessions, tokens, guards, and object ownership checks across the "
                "highest-value flows"
            ),
        ),
        _seed_item(
            target=target,
            component=f"codebase:{root.name}",
            surface="State-changing workflows and race-window coverage",
            priority="high",
            rationale=(
                "Auto-seeded baseline for source-code targets to force review of multi-step, "
                "single-use, or concurrent state transitions."
            ),
            next_step=(
                "Identify payments, coupon redemption, invitation, OTP, password reset, and "
                "inventory update flows for race testing"
            ),
        ),
    ]


def _generic_runtime_items(target: str) -> list[dict[str, Any]]:
    return [
        _seed_item(
            target=target,
            component="runtime",
            surface="Public attack-surface discovery and privileged route mapping",
            priority="high",
            rationale=(
                "Auto-seeded baseline for runtime-only targets so black-box assessments start "
                "with structured reconnaissance coverage."
            ),
            next_step="Map routes, parameters, and hidden/admin surfaces before narrow exploitation",
        ),
        _seed_item(
            target=target,
            component="runtime",
            surface="Authentication, authorization, and cross-tenant access control coverage",
            priority="critical",
            rationale=(
                "Auto-seeded because serious application bugs often hide in role, session, and "
                "object-boundary enforcement."
            ),
            next_step=(
                "Build role/session matrices and compare owner, other-user, and unauthenticated "
                "responses on high-value flows"
            ),
        ),
        _seed_item(
            target=target,
            component="runtime",
            surface="State-changing endpoints and race-condition coverage",
            priority="high",
            rationale=(
                "Auto-seeded because coupon, balance, invitation, and token flows frequently hide "
                "TOCTOU issues."
            ),
            next_step="Identify single-use or multi-step operations and exercise them concurrently",
        ),
    ]


def _resolve_code_target_path(target: dict[str, Any]) -> Path | None:
    details = target.get("details", {}) or {}
    if target.get("type") == "repository" and details.get("cloned_repo_path"):
        return Path(str(details["cloned_repo_path"]))
    if target.get("type") == "local_code" and details.get("target_path"):
        return Path(str(details["target_path"]))
    return None


def _collect_seed_items(
    scan_config: dict[str, Any],
    *,
    max_route_items: int,
    include_runtime_targets: bool,
) -> dict[str, Any]:
    targets = scan_config.get("targets", [])
    all_items: list[dict[str, Any]] = []
    framework_skills: list[str] = []
    framework_summaries: list[dict[str, Any]] = []
    skipped_targets: list[str] = []

    for target in targets:
        target_label = str(
            target.get("original")
            or target.get("details", {}).get("target_path")
            or "target"
        )
        target_path = _resolve_code_target_path(target)
        if target_path and target_path.exists():
            items = _generic_codebase_items(target_label, target_path)
            route_items: list[dict[str, Any]] = []
            frameworks = _detect_frameworks(target_path)
            detected_features: list[str] = []
            route_count = 0

            for framework in frameworks:
                extractor = {
                    "fastapi": _extract_fastapi_inventory,
                    "nextjs": _extract_nextjs_inventory,
                    "nestjs": _extract_nestjs_inventory,
                }.get(framework)
                if extractor is None:
                    continue
                extracted = extractor(target_path, target_label)
                items.extend(
                    [
                        item
                        for item in extracted["items"]
                        if not str(item["component"]).startswith("route:")
                    ]
                )
                route_items.extend(
                    [
                        item
                        for item in extracted["items"]
                        if str(item["component"]).startswith("route:")
                    ]
                )
                route_count += int(extracted.get("route_count", 0))
                detected_features.extend(extracted.get("features", []))
                skill = extracted.get("skill")
                if isinstance(skill, str) and skill and skill not in framework_skills:
                    framework_skills.append(skill)

            limited_route_items = _limit_route_items(route_items, max_route_items=max_route_items)
            items.extend(limited_route_items)
            all_items.extend(items)
            framework_summaries.append(
                {
                    "target": target_label,
                    "path": str(target_path),
                    "frameworks": frameworks,
                    "route_count": route_count,
                    "seeded_route_items": len(limited_route_items),
                    "features": sorted(set(detected_features)),
                }
            )
        elif include_runtime_targets and target.get("type") in {"web_application", "ip_address"}:
            all_items.extend(_generic_runtime_items(target_label))
            framework_summaries.append(
                {
                    "target": target_label,
                    "path": None,
                    "frameworks": [],
                    "route_count": 0,
                    "seeded_route_items": 0,
                    "features": ["runtime_only"],
                }
            )
        else:
            skipped_targets.append(target_label)

    deduped_items = _dedupe_items(all_items)
    return {
        "items": deduped_items,
        "framework_skills": framework_skills,
        "framework_summaries": framework_summaries,
        "skipped_targets": skipped_targets,
    }


def _get_scan_config(scan_config: dict[str, Any] | None = None) -> dict[str, Any]:
    if scan_config is not None:
        return scan_config

    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer and tracer.scan_config:
            return tracer.scan_config
    except Exception:
        return {}

    return {}


def summarize_bootstrap_for_prompt(result: dict[str, Any]) -> dict[str, Any]:
    summaries = []
    for summary in result.get("framework_summaries", []):
        frameworks = summary.get("frameworks", [])
        summaries.append(
            {
                "target": summary.get("target"),
                "frameworks": frameworks,
                "route_count": summary.get("route_count", 0),
                "seeded_route_items": summary.get("seeded_route_items", 0),
                "features": list(summary.get("features", []))[:4],
            }
        )

    return {
        "coverage_seeded": result.get("seeded_count", 0),
        "frameworks": summaries,
        "framework_skills": result.get("framework_skills", []),
        "skipped_targets": result.get("skipped_targets", []),
    }


def seed_coverage_from_scan_config(
    agent_state: Any,
    scan_config: dict[str, Any] | None = None,
    *,
    max_route_items: int = 40,
    include_runtime_targets: bool = True,
) -> dict[str, Any]:
    resolved_scan_config = _get_scan_config(scan_config)
    collected = _collect_seed_items(
        resolved_scan_config,
        max_route_items=max_route_items,
        include_runtime_targets=include_runtime_targets,
    )
    items = collected["items"]

    if not items:
        return {
            "success": False,
            "seeded_count": 0,
            "error": "No attack-surface items could be auto-seeded from the current targets",
            "framework_skills": collected["framework_skills"],
            "framework_summaries": collected["framework_summaries"],
            "skipped_targets": collected["skipped_targets"],
        }

    response = bulk_record_coverage(
        agent_state=agent_state,
        items=items,
        preserve_existing_status=True,
    )
    response["seeded_count"] = response.get("updated_count", 0)
    response["framework_skills"] = collected["framework_skills"]
    response["framework_summaries"] = collected["framework_summaries"]
    response["skipped_targets"] = collected["skipped_targets"]
    response["seed_source"] = "auto"
    return response


@register_tool(sandbox_execution=False)
def seed_coverage_from_targets(
    agent_state: Any,
    max_route_items: int = 40,
    include_runtime_targets: bool = True,
) -> dict[str, Any]:
    try:
        if max_route_items < 1:
            raise ValueError("max_route_items must be >= 1")
        response = seed_coverage_from_scan_config(
            agent_state,
            max_route_items=max_route_items,
            include_runtime_targets=include_runtime_targets,
        )
    except (TypeError, ValueError) as e:
        return {"success": False, "error": f"Failed to auto-seed coverage: {e}"}
    else:
        return response
