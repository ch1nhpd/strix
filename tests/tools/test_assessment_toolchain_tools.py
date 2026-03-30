import asyncio
import json
import sys
import types
from pathlib import Path
from typing import Any

fake_posthog = types.ModuleType("strix.telemetry.posthog")
fake_posthog.error = lambda *args, **kwargs: None  # type: ignore[attr-defined]

fake_telemetry = types.ModuleType("strix.telemetry")
fake_telemetry.__path__ = []  # type: ignore[attr-defined]
fake_telemetry.posthog = fake_posthog  # type: ignore[attr-defined]

sys.modules.setdefault("strix.telemetry", fake_telemetry)
sys.modules.setdefault("strix.telemetry.posthog", fake_posthog)

from strix.tools.agents_graph import agents_graph_actions
from strix.tools.assessment import clear_assessment_storage, list_assessment_state
from strix.tools.assessment import assessment_browser_actions as browser_assessment_actions
from strix.tools.assessment import assessment_creative_actions as creative_actions
from strix.tools.assessment import assessment_oob_actions as oob_actions
from strix.tools.assessment import assessment_toolchain_actions as toolchain_actions
from strix.tools.assessment import assessment_validation_actions as validation_actions
from strix.tools.executor import execute_tool_invocation


class DummyState:
    def __init__(self, agent_id: str, parent_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.parent_id = parent_id
        self.context: dict[str, Any] = {}

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value


class StaticProxyManager:
    def __init__(self, requests: dict[str, str]) -> None:
        self.requests = requests

    def view_request(
        self,
        request_id: str,
        part: str = "request",
        search_pattern: str | None = None,
        page: int = 1,
        page_size: int = 120,
    ) -> dict[str, Any]:
        content = self.requests.get(request_id)
        if content is None:
            return {"error": "not_found"}
        return {"content": content}


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()


def _patch_scan(
    monkeypatch: Any,
    *,
    tool_output: str = "",
    stdout: str = "",
    exit_code: int = 0,
) -> None:
    monkeypatch.setattr(toolchain_actions, "_resolve_tool_executable", lambda tool_name: tool_name)
    monkeypatch.setattr(
        toolchain_actions,
        "_execute_tool_command",
        lambda command, timeout: {"exit_code": exit_code, "stdout": stdout, "stderr": ""},
    )
    monkeypatch.setattr(toolchain_actions, "_read_output_file", lambda path: tool_output)


def test_security_tool_doctor_reports_available_wrapped_tools(monkeypatch: Any) -> None:
    def fake_resolve(tool_name: str) -> str | None:
        return f"C:/tools/{tool_name}.exe" if tool_name in {"httpx", "nuclei"} else None

    monkeypatch.setattr(toolchain_actions, "_resolve_tool_executable", fake_resolve)
    monkeypatch.setattr(
        toolchain_actions,
        "_execute_tool_command",
        lambda command, timeout: {"exit_code": 0, "stdout": "v1.0.0", "stderr": ""},
    )

    state = DummyState("agent_root")
    result = toolchain_actions.security_tool_doctor(
        agent_state=state,
        tool_names=["httpx", "nuclei", "sqlmap"],
    )

    assert result["success"] is True
    assert result["available_count"] == 2
    assert result["tool_count"] == 3
    assert state.context["tool_scan_root_agent_id"] == "agent_root"
    assert result["tools"][0]["version_output"] == "v1.0.0"
    assert result["tools"][2]["available"] is False


def test_run_security_tool_pipeline_blackbox_deep_orchestrates_expected_steps(
    monkeypatch: Any,
) -> None:
    available_tools = [
        "subfinder",
        "httpx",
        "naabu",
        "nmap",
        "wafw00f",
        "katana",
        "nuclei",
        "arjun",
        "dirsearch",
        "wapiti",
        "zaproxy",
    ]
    calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )

    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {
            "success": True,
            "tools": [
                {"tool_name": tool_name, "available": True, "executable": tool_name}
                for tool_name in available_tools
            ],
        },
    )

    def fake_run_security_tool_scan(agent_state: Any, tool_name: str, target: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((tool_name, kwargs))
        base = {
            "success": True,
            "tool_name": tool_name,
            "target": target,
            "run_id": f"run_{tool_name}_{len(calls)}",
            "finding_count": 0,
            "discovery_seed_count": 0,
            "hypothesis_seed_count": 0,
            "findings": [],
        }
        if tool_name == "subfinder":
            base["findings"] = [{"host": "api.example.com"}, {"host": "admin.example.com"}]
        elif tool_name == "httpx":
            base["findings"] = [
                {"url": "https://api.example.com", "status_code": 200},
                {"url": "https://admin.example.com/admin", "status_code": 401},
            ]
        elif tool_name == "wafw00f":
            base["findings"] = [{"url": "https://api.example.com", "name": "Cloudflare"}]
        elif tool_name == "naabu":
            base["findings"] = [{"kind": "port", "host": "api.example.com", "port": 443}]
        elif tool_name == "nmap":
            base["findings"] = [
                {"kind": "port", "host": "api.example.com", "port": 443, "protocol": "tcp"},
                {"kind": "script", "host": "api.example.com", "port": 443, "script_id": "http-vuln"},
            ]
            base["hypothesis_seed_count"] = 1
        elif tool_name == "katana":
            base["findings"] = [{"url": "https://api.example.com/graphql"}]
        elif tool_name == "nuclei":
            base["findings"] = [{"template_id": "x", "matched_at": "https://api.example.com"}]
            base["hypothesis_seed_count"] = 1
        elif tool_name in {"arjun", "dirsearch", "wapiti", "zaproxy"}:
            base["findings"] = []
        base["finding_count"] = len(base["findings"])
        return base

    monkeypatch.setattr(toolchain_actions, "run_security_tool_scan", fake_run_security_tool_scan)

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_pipeline(
        agent_state=state,
        target="external",
        mode="blackbox",
        targets=["example.com"],
        deep=True,
        max_active_targets=1,
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert [tool_name for tool_name, _ in calls] == [
        "subfinder",
        "httpx",
        "naabu",
        "nmap",
        "wafw00f",
        "katana",
        "nuclei",
        "arjun",
        "dirsearch",
        "wapiti",
        "zaproxy",
    ]
    assert result["discovered_hosts"] == ["api.example.com", "admin.example.com"]
    assert result["live_urls"] == [
        "https://api.example.com",
        "https://admin.example.com/admin",
        "https://api.example.com/graphql",
    ]
    assert result["step_count"] == 11
    assert ledger["assessment_summary"]["evidence_total"] == 1


def test_run_security_tool_scan_httpx_seeds_discovered_paths(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output="\n".join(
            [
                json.dumps(
                    {
                        "url": "https://app.test/admin",
                        "status_code": 401,
                        "title": "Login",
                        "webserver": "nginx",
                        "tech": ["nextjs"],
                    }
                ),
                json.dumps(
                    {
                        "url": "https://app.test/api/orders/123",
                        "status_code": 200,
                        "title": "Order",
                        "webserver": "nginx",
                        "tech": ["nextjs"],
                    }
                ),
            ]
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="httpx",
        target="web",
        targets=["https://app.test"],
        paths=["/admin", "/api/orders/123"],
        include_findings=True,
    )
    ledger = list_assessment_state(agent_state=state)
    runs = toolchain_actions.list_security_tool_runs(agent_state=state, include_findings=True)

    assert result["success"] is True
    assert result["finding_count"] == 2
    assert result["discovery_seed_count"] == 2
    assert runs["run_count"] == 1
    assert runs["runs"][0]["finding_count"] == 2
    assert ledger["assessment_summary"]["coverage_total"] == 2
    assert ledger["assessment_summary"]["evidence_total"] == 1
    surfaces = {item["surface"] for item in ledger["coverage"]}
    assert "Discovered path /admin" in surfaces
    assert "Discovered path /api/orders/123" in surfaces


def test_execute_tool_invocation_allows_tool_args_named_tool_name(
    monkeypatch: Any,
) -> None:
    _patch_scan(
        monkeypatch,
        tool_output=json.dumps(
            {
                "url": "https://accounts.opera.com/security.txt",
                "status": 200,
                "length": 0,
                "words": 0,
                "lines": 0,
            }
        ),
    )

    state = DummyState("agent_root")
    result = asyncio.run(
        execute_tool_invocation(
            {
                "toolName": "run_security_tool_scan",
                "args": {
                    "tool_name": "ffuf",
                    "target": "https://accounts.opera.com",
                    "component": "runtime:path-discovery",
                    "url": "https://accounts.opera.com/FUZZ",
                    "wordlist_path": "/usr/share/wordlists/dirb/common.txt",
                    "include_findings": True,
                },
            },
            agent_state=state,
        )
    )

    assert isinstance(result, dict)
    assert result["success"] is True
    assert result["tool_name"] == "ffuf"


def test_run_security_tool_scan_katana_seeds_crawled_paths(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output="\n".join(
            [
                json.dumps({"url": "https://app.test/graphql", "source": "body"}),
                json.dumps({"url": "https://app.test/internal/debug", "source": "script"}),
            ]
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="katana",
        target="web",
        targets=["https://app.test"],
        include_findings=True,
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["discovery_seed_count"] == 2
    surfaces = {item["surface"] for item in ledger["coverage"]}
    assert "Discovered path /graphql" in surfaces
    assert "Discovered path /internal/debug" in surfaces


def test_run_security_tool_scan_arjun_seeds_parameters_and_risky_hypotheses(
    monkeypatch: Any,
) -> None:
    _patch_scan(
        monkeypatch,
        tool_output=json.dumps(
            {
                "https://app.test/fetch": ["callback_url", "user_id", "q"],
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="arjun",
        target="web",
        url="https://app.test/fetch",
        include_findings=True,
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["discovery_seed_count"] == 3
    assert result["hypothesis_seed_count"] >= 2
    surfaces = {item["surface"] for item in ledger["coverage"]}
    assert "Discovered parameter callback_url on /fetch" in surfaces
    assert "Discovered parameter user_id on /fetch" in surfaces
    assert any(item["vulnerability_type"] == "ssrf" for item in ledger["hypotheses"])
    assert any(item["vulnerability_type"] == "idor" for item in ledger["hypotheses"])


def test_run_security_tool_scan_subfinder_seeds_discovered_hosts(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output="\n".join(
            [
                json.dumps({"host": "api.example.com", "input": "example.com", "sources": ["crtsh"]}),
                json.dumps({"host": "admin.example.com", "input": "example.com", "sources": ["shodan"]}),
            ]
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="subfinder",
        target="external",
        targets=["example.com"],
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["discovery_seed_count"] == 2
    surfaces = {item["surface"] for item in ledger["coverage"]}
    assert "Discovered host api.example.com" in surfaces
    assert "Discovered host admin.example.com" in surfaces


def test_run_security_tool_scan_naabu_seeds_open_ports(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output="\n".join(
            [
                json.dumps({"host": "api.example.com", "ip": "1.2.3.4", "port": 443}),
                json.dumps({"host": "api.example.com", "ip": "1.2.3.4", "port": 9200}),
            ]
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="naabu",
        target="external",
        targets=["api.example.com"],
        top_ports=100,
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["discovery_seed_count"] == 2
    assert any(item["surface"] == "Open tcp port 443 on api.example.com" for item in ledger["coverage"])
    assert any(item["surface"] == "Open tcp port 9200 on api.example.com" for item in ledger["coverage"])


def test_run_security_tool_scan_nmap_seeds_services_and_script_hypothesis(
    monkeypatch: Any,
) -> None:
    _patch_scan(
        monkeypatch,
        tool_output=(
            "<?xml version='1.0'?>\n"
            "<nmaprun>"
            "<host><status state='up'/>"
            "<address addr='10.0.0.5' addrtype='ipv4'/>"
            "<hostnames><hostname name='legacy.example.com'/></hostnames>"
            "<ports>"
            "<port protocol='tcp' portid='80'>"
            "<state state='open'/>"
            "<service name='http' product='nginx' version='1.20'/>"
            "</port>"
            "<port protocol='tcp' portid='8080'>"
            "<state state='open'/>"
            "<service name='http-proxy'/>"
            "<script id='http-vuln-cve2021-test' output='VULNERABLE: test issue'/>"
            "</port>"
            "</ports>"
            "</host>"
            "</nmaprun>"
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="nmap",
        target="external",
        targets=["legacy.example.com"],
        service_detection=True,
        default_scripts=True,
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["discovery_seed_count"] == 2
    assert result["hypothesis_seed_count"] == 1
    assert any(
        item["surface"] == "Open tcp port 80 (http nginx 1.20) on legacy.example.com"
        for item in ledger["coverage"]
    )
    assert any(
        item["surface"] == "Nmap script finding http-vuln-cve2021-test on port 8080 at legacy.example.com"
        for item in ledger["coverage"]
    )


def test_run_security_tool_scan_nuclei_creates_hypothesis_and_coverage(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output=json.dumps(
            {
                "template-id": "exposed-admin-export",
                "matched-at": "https://app.test/admin/export",
                "host": "app.test",
                "info": {
                    "severity": "high",
                    "name": "Admin export exposure",
                    "tags": ["auth", "exposure"],
                },
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="nuclei",
        target="web",
        targets=["https://app.test"],
        automatic_scan=True,
        include_findings=True,
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["hypothesis_seed_count"] == 1
    assert any(item["surface"] == "Nuclei finding exposed-admin-export on /admin/export" for item in ledger["coverage"])
    assert any(item["vulnerability_type"] == "authentication" for item in ledger["hypotheses"])


def test_run_security_tool_scan_ffuf_seeds_hidden_path_coverage(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output=json.dumps(
            {
                "results": [
                    {
                        "url": "https://app.test/backup",
                        "status": 403,
                        "length": 128,
                        "words": 14,
                    }
                ]
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="ffuf",
        target="web",
        url="https://app.test/FUZZ",
        wordlist_path="wordlist.txt",
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["discovery_seed_count"] == 1
    assert any(item["surface"] == "Discovered path /backup" for item in ledger["coverage"])


def test_run_security_tool_scan_dirsearch_seeds_discovered_paths(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output=json.dumps(
            {
                "results": [
                    {
                        "url": "https://app.test/.git/config",
                        "status": 200,
                        "content-length": 87,
                    }
                ]
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="dirsearch",
        target="web",
        url="https://app.test",
        recursion=True,
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["discovery_seed_count"] == 1
    assert any(item["surface"] == "Discovered path /.git/config" for item in ledger["coverage"])


def test_run_security_tool_scan_semgrep_creates_code_hypothesis(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output=json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.lang.security.audit.sql-injection",
                        "path": "api/orders.py",
                        "start": {"line": 42},
                        "extra": {
                            "message": "Possible SQL injection",
                            "severity": "ERROR",
                        },
                    }
                ]
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="semgrep",
        target="repo",
        target_path="E:/PentestTool/strix/strix",
        configs=["p/default"],
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["hypothesis_seed_count"] == 1
    assert any(
        item["surface"] == "Semgrep finding python.lang.security.audit.sql-injection at api/orders.py:42"
        for item in ledger["coverage"]
    )
    assert any(item["vulnerability_type"] == "sqli" for item in ledger["hypotheses"])


def test_run_security_tool_scan_bandit_creates_code_hypothesis(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output=json.dumps(
            {
                "results": [
                    {
                        "test_id": "B602",
                        "filename": "worker/tasks.py",
                        "line_number": 18,
                        "issue_text": "subprocess call with shell=True identified, security issue.",
                        "issue_severity": "HIGH",
                        "issue_confidence": "HIGH",
                    }
                ]
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="bandit",
        target="repo",
        target_path="E:/PentestTool/strix/strix",
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["hypothesis_seed_count"] == 1
    assert any(
        item["surface"] == "Bandit finding B602 at worker/tasks.py:18"
        for item in ledger["coverage"]
    )
    assert any(item["vulnerability_type"] == "rce" for item in ledger["hypotheses"])


def test_run_security_tool_scan_wapiti_creates_vulnerability_hypothesis(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output=json.dumps(
            {
                "vulnerabilities": {
                    "sql": [
                        {
                            "url": "https://app.test/products?id=1",
                            "parameter": "id",
                            "info": "Blind SQL injection suspected",
                            "level": "high",
                        }
                    ]
                }
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="wapiti",
        target="web",
        url="https://app.test",
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["hypothesis_seed_count"] == 1
    assert any(
        item["surface"] == "Wapiti finding sql via id on /products"
        for item in ledger["coverage"]
    )
    assert any(item["vulnerability_type"] == "sqli" for item in ledger["hypotheses"])


def test_run_security_tool_scan_sqlmap_creates_sqli_hypothesis(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        stdout="Parameter: id (GET) is vulnerable",
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="sqlmap",
        target="web",
        url="https://app.test/item?id=1",
        parameter="id",
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["hypothesis_seed_count"] == 1
    assert any(
        item["surface"].startswith("Potential SQL injection in parameter id")
        for item in ledger["coverage"]
    )
    assert any(item["vulnerability_type"] == "sqli" for item in ledger["hypotheses"])


def test_run_security_tool_scan_jwt_tool_creates_jwt_hypothesis(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        stdout="[+] alg:none acceptance detected for target token",
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="jwt_tool",
        target="web",
        url="https://app.test/api/profile",
        jwt_token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["hypothesis_seed_count"] == 1
    assert any(
        item["surface"] == "JWT finding JWT alg:none acceptance on app.test"
        for item in ledger["coverage"]
    )
    assert any(item["vulnerability_type"] == "jwt" for item in ledger["hypotheses"])


def test_run_security_tool_scan_trivy_creates_code_hypotheses(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output=json.dumps(
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Class": "lang-pkgs",
                        "Type": "pip",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2024-0001",
                                "PkgName": "jinja2",
                                "Title": "Template sandbox breakout",
                                "Description": "Dangerous template sandbox escape path",
                                "Severity": "CRITICAL",
                            }
                        ],
                    },
                    {
                        "Target": "config/.env",
                        "Class": "secret",
                        "Secrets": [
                            {
                                "RuleID": "aws-access-key-id",
                                "Title": "AWS Access Key",
                                "Match": "AKIA****************",
                                "Severity": "HIGH",
                            }
                        ],
                    },
                ]
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="trivy",
        target="repo",
        target_path="E:/PentestTool/strix/strix",
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["hypothesis_seed_count"] == 2
    assert any(
        item["surface"] == "Trivy finding CVE-2024-0001 at requirements.txt"
        for item in ledger["coverage"]
    )
    assert any(item["vulnerability_type"] == "secret_exposure" for item in ledger["hypotheses"])


def test_run_security_tool_scan_wafw00f_records_defense_surface(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output=json.dumps(
            {
                "url": "https://app.test",
                "firewall": "Cloudflare",
                "manufacturer": "Cloudflare",
                "detected": True,
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="wafw00f",
        target="web",
        url="https://app.test",
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["discovery_seed_count"] == 1
    assert result["hypothesis_seed_count"] == 0
    assert any(
        item["surface"] == "WAF detected on app.test: Cloudflare (Cloudflare)"
        for item in ledger["coverage"]
    )


def test_run_security_tool_scan_zaproxy_creates_alert_hypothesis(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        tool_output=json.dumps(
            {
                "site": [
                    {
                        "@name": "https://app.test",
                        "alerts": [
                            {
                                "alert": "Cross Site Scripting (Reflected)",
                                "riskcode": "2",
                                "desc": "Reflected XSS discovered",
                                "instances": [
                                    {
                                        "uri": "https://app.test/search",
                                        "param": "q",
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="zaproxy",
        target="web",
        url="https://app.test",
        zapit=True,
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["hypothesis_seed_count"] == 1
    assert any(
        item["surface"] == "ZAP finding Cross Site Scripting (Reflected) via q on /search"
        for item in ledger["coverage"]
    )
    assert any(item["vulnerability_type"] == "xss" for item in ledger["hypotheses"])


def test_run_security_tool_scan_trufflehog_creates_secret_hypothesis(monkeypatch: Any) -> None:
    _patch_scan(
        monkeypatch,
        stdout=json.dumps(
            {
                "DetectorName": "AWS",
                "Verified": True,
                "Redacted": "AKIA****************",
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {
                            "file": "config/.env",
                        }
                    }
                },
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_scan(
        agent_state=state,
        tool_name="trufflehog",
        target="repo",
        target_path="E:/PentestTool/strix/strix",
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["hypothesis_seed_count"] == 1
    assert any(
        item["surface"] == "Potential secret exposure via AWS in config/.env"
        for item in ledger["coverage"]
    )
    assert any(item["vulnerability_type"] == "secret_exposure" for item in ledger["hypotheses"])


def test_run_security_tool_pipeline_reuses_prior_scope_runs(monkeypatch: Any) -> None:
    call_count = {"scan": 0}
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {
            "success": True,
            "tools": [{"tool_name": "httpx", "available": True, "executable": "httpx"}],
        },
    )
    monkeypatch.setattr(toolchain_actions, "_resolve_tool_executable", lambda tool_name: tool_name)

    def fake_execute(command: list[str], timeout: int) -> dict[str, Any]:
        call_count["scan"] += 1
        return {"exit_code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(toolchain_actions, "_execute_tool_command", fake_execute)
    monkeypatch.setattr(
        toolchain_actions,
        "_read_output_file",
        lambda path: json.dumps({"url": "https://app.test", "status_code": 200}),
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )

    state = DummyState("agent_root")
    first = toolchain_actions.run_security_tool_pipeline(
        agent_state=state,
        target="web",
        mode="blackbox",
        url="https://app.test",
        reuse_previous_runs=True,
        auto_synthesize_hypotheses=False,
    )
    second = toolchain_actions.run_security_tool_pipeline(
        agent_state=state,
        target="web",
        mode="blackbox",
        url="https://app.test",
        reuse_previous_runs=True,
        auto_synthesize_hypotheses=False,
    )

    assert first["success"] is True
    assert second["success"] is True
    assert call_count["scan"] == 1
    assert second["reused_step_count"] == 1


def test_run_security_focus_pipeline_auth_jwt_uses_specialized_steps(monkeypatch: Any) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {
            "success": True,
            "tools": [
                {"tool_name": "jwt_tool", "available": True, "executable": "jwt_tool"},
                {"tool_name": "wafw00f", "available": True, "executable": "wafw00f"},
            ],
        },
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        validation_actions,
        "jwt_variant_harness",
        lambda *args, **kwargs: {
            "success": True,
            "tool_name": "jwt_variant_harness",
            "suspicious_variants": [{"name": "invalid_signature"}],
        },
    )

    def fake_run_security_tool_scan(agent_state: Any, tool_name: str, target: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(tool_name)
        findings = []
        if tool_name == "jwt_tool":
            findings = [{"name": "JWT alg:none acceptance", "url": "https://app.test/api"}]
        return {
            "success": True,
            "tool_name": tool_name,
            "target": target,
            "run_id": f"run_{tool_name}_{len(calls)}",
            "finding_count": len(findings),
            "discovery_seed_count": 0,
            "hypothesis_seed_count": len(findings),
            "findings": findings,
        }

    monkeypatch.setattr(toolchain_actions, "run_security_tool_scan", fake_run_security_tool_scan)

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="auth_jwt",
        url="https://app.test/api",
        jwt_token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert calls == ["wafw00f", "jwt_tool"]
    assert result["focus"] == "auth_jwt"
    assert result["active_probe_results"][0]["success"] is True


def test_run_security_focus_pipeline_auth_jwt_uses_proxy_request_context(monkeypatch: Any) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    harness_calls: list[dict[str, Any]] = []
    token = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ."
        "signature"
    )
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {
            "success": True,
            "tools": [
                {"tool_name": "jwt_tool", "available": True, "executable": "jwt_tool"},
                {"tool_name": "wafw00f", "available": True, "executable": "wafw00f"},
            ],
        },
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        toolchain_actions,
        "_load_runtime_inventory_entries",
        lambda agent_state, target: [
            {
                "host": "app.test",
                "sample_urls": ["https://app.test/api/profile"],
                "sample_request_ids": ["req_jwt"],
                "methods": ["POST"],
                "query_params": [],
                "body_params": [],
                "content_types": ["application/json"],
                "auth_hints": ["bearer"],
            }
        ],
    )
    monkeypatch.setattr(toolchain_actions, "_load_discovered_workflows", lambda *args, **kwargs: [])
    monkeypatch.setattr(toolchain_actions, "_load_session_profiles", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        toolchain_actions,
        "_get_focus_proxy_manager",
        lambda: StaticProxyManager(
            {
                "req_jwt": (
                    "POST /api/profile HTTP/1.1\n"
                    "Host: app.test\n"
                    "Origin: https://app.test\n"
                    f"Authorization: Bearer {token}\n"
                    "Content-Type: application/json\n"
                    "\n"
                    '{"view":"self"}'
                )
            }
        ),
    )

    def fake_jwt_variant_harness(*args: Any, **kwargs: Any) -> dict[str, Any]:
        harness_calls.append(kwargs)
        return {
            "success": True,
            "tool_name": "jwt_variant_harness",
            "suspicious_variants": [],
        }

    monkeypatch.setattr(validation_actions, "jwt_variant_harness", fake_jwt_variant_harness)

    def fake_run_security_tool_scan(agent_state: Any, tool_name: str, target: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((tool_name, kwargs))
        return {
            "success": True,
            "tool_name": tool_name,
            "target": target,
            "run_id": f"run_{tool_name}_{len(calls)}",
            "finding_count": 0,
            "discovery_seed_count": 0,
            "hypothesis_seed_count": 0,
            "findings": [],
        }

    monkeypatch.setattr(toolchain_actions, "run_security_tool_scan", fake_run_security_tool_scan)

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="auth_jwt",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert [tool_name for tool_name, _ in calls] == ["wafw00f", "jwt_tool"]
    assert calls[1][1]["url"] == "https://app.test/api/profile"
    assert calls[1][1]["headers"]["Authorization"] == f"Bearer {token}"
    assert harness_calls[0]["jwt_token"] == token
    assert harness_calls[0]["base_request"]["method"] == "POST"
    assert harness_calls[0]["base_request"]["json_body"] == {"view": "self"}
    assert "Authorization" not in harness_calls[0]["base_request"]["headers"]


def test_run_security_focus_pipeline_auth_jwt_detects_cookie_token_context(monkeypatch: Any) -> None:
    harness_calls: list[dict[str, Any]] = []
    token = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ."
        "signature"
    )
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {
            "success": True,
            "tools": [{"tool_name": "jwt_tool", "available": True, "executable": "jwt_tool"}],
        },
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        toolchain_actions,
        "_load_runtime_inventory_entries",
        lambda agent_state, target: [
            {
                "host": "app.test",
                "sample_urls": ["https://app.test/api/profile"],
                "sample_request_ids": ["req_cookie_jwt"],
                "methods": ["GET"],
                "query_params": [],
                "body_params": [],
                "content_types": ["application/json"],
                "auth_hints": ["cookie"],
            }
        ],
    )
    monkeypatch.setattr(toolchain_actions, "_load_discovered_workflows", lambda *args, **kwargs: [])
    monkeypatch.setattr(toolchain_actions, "_load_session_profiles", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        toolchain_actions,
        "_get_focus_proxy_manager",
        lambda: StaticProxyManager(
            {
                "req_cookie_jwt": (
                    "GET /api/profile HTTP/1.1\n"
                    "Host: app.test\n"
                    f"Cookie: session={token}\n"
                    "\n"
                )
            }
        ),
    )
    monkeypatch.setattr(
        validation_actions,
        "jwt_variant_harness",
        lambda *args, **kwargs: (harness_calls.append(kwargs) or {"success": True, "tool_name": "jwt_variant_harness"}),
    )
    monkeypatch.setattr(
        toolchain_actions,
        "run_security_tool_scan",
        lambda agent_state, tool_name, target, **kwargs: {
            "success": True,
            "tool_name": tool_name,
            "target": target,
            "run_id": "run_jwt",
            "finding_count": 0,
            "discovery_seed_count": 0,
            "hypothesis_seed_count": 0,
            "findings": [],
        },
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="auth_jwt",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert harness_calls[0]["jwt_token"] == token
    assert harness_calls[0]["token_location"] == "cookie"
    assert harness_calls[0]["cookie_name"] == "session"


def test_run_security_focus_pipeline_ssrf_oob_prepares_harness_and_payloads(
    monkeypatch: Any,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {
            "success": True,
            "tools": [
                {"tool_name": "arjun", "available": True, "executable": "arjun"},
            ],
        },
    )
    monkeypatch.setattr(
        creative_actions,
        "generate_contextual_payloads",
        lambda **kwargs: {
            "success": True,
            "surface": kwargs["surface"],
            "variant_count": 1,
            "variants": [{"payload": "http://cb.test/oob", "encoding": "raw"}],
        },
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        validation_actions,
        "payload_probe_harness",
        lambda *args, **kwargs: {
            "success": True,
            "tool_name": "payload_probe_harness",
            "finding_count": 1,
            "triage_result": {"suspicious_observations": [{"name": "variant_1"}]},
        },
    )
    monkeypatch.setattr(
        oob_actions,
        "oob_interaction_harness",
        lambda agent_state, action, **kwargs: (
            {"success": True, "cli_available": True}
            if action == "doctor"
            else {
                "success": True,
                "harness_id": "oob_1",
                "payloads": [{"label": "ssrf_oob", "url": "http://cb.test/oob"}],
            }
        ),
    )

    def fake_run_security_tool_scan(agent_state: Any, tool_name: str, target: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(tool_name)
        findings = [{"url": "https://app.test/fetch", "parameter": "callback_url", "path": "/fetch"}]
        return {
            "success": True,
            "tool_name": tool_name,
            "target": target,
            "run_id": f"run_{tool_name}_{len(calls)}",
            "finding_count": len(findings),
            "discovery_seed_count": len(findings),
            "hypothesis_seed_count": 1,
            "findings": findings,
        }

    monkeypatch.setattr(toolchain_actions, "run_security_tool_scan", fake_run_security_tool_scan)

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="ssrf_oob",
        url="https://app.test/fetch",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert calls == ["arjun"]
    assert result["harness_result"]["success"] is True
    assert result["payload_result"]["success"] is True
    assert result["active_probe_results"][0]["success"] is True


def test_run_security_focus_pipeline_ssrf_oob_uses_proxy_json_request_context(
    monkeypatch: Any,
) -> None:
    probe_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {"success": True, "tools": []},
    )
    monkeypatch.setattr(
        creative_actions,
        "generate_contextual_payloads",
        lambda **kwargs: {
            "success": True,
            "surface": kwargs["surface"],
            "variant_count": 1,
            "variants": [{"payload": "http://cb.test/oob", "encoding": "raw"}],
        },
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        toolchain_actions,
        "_load_runtime_inventory_entries",
        lambda agent_state, target: [
            {
                "host": "app.test",
                "sample_urls": ["https://app.test/api/webhooks"],
                "sample_request_ids": ["req_ssrf"],
                "methods": ["POST"],
                "query_params": [],
                "body_params": ["callback_url"],
                "content_types": ["application/json"],
                "auth_hints": ["bearer"],
            }
        ],
    )
    monkeypatch.setattr(toolchain_actions, "_load_discovered_workflows", lambda *args, **kwargs: [])
    monkeypatch.setattr(toolchain_actions, "_load_session_profiles", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        toolchain_actions,
        "_get_focus_proxy_manager",
        lambda: StaticProxyManager(
            {
                "req_ssrf": (
                    "POST /api/webhooks HTTP/1.1\n"
                    "Host: app.test\n"
                    "Origin: https://app.test\n"
                    "Authorization: Bearer owner-token\n"
                    "Content-Type: application/json\n"
                    "\n"
                    '{"callback_url":"https://example.com/","event":"build"}'
                )
            }
        ),
    )
    monkeypatch.setattr(
        validation_actions,
        "payload_probe_harness",
        lambda *args, **kwargs: (
            probe_calls.append(kwargs)
            or {
                "success": True,
                "tool_name": "payload_probe_harness",
                "finding_count": 1,
                "triage_result": {"suspicious_observations": [{"name": "variant_1"}]},
            }
        ),
    )
    monkeypatch.setattr(
        oob_actions,
        "oob_interaction_harness",
        lambda agent_state, action, **kwargs: (
            {"success": True, "cli_available": True}
            if action == "doctor"
            else {
                "success": True,
                "harness_id": "oob_1",
                "payloads": [{"label": "ssrf_oob", "url": "http://cb.test/oob"}],
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="ssrf_oob",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert probe_calls[0]["base_request"]["method"] == "POST"
    assert probe_calls[0]["base_request"]["json_body"] == {
        "callback_url": "https://example.com/",
        "event": "build",
    }
    assert probe_calls[0]["injection_mode"] == "json"
    assert probe_calls[0]["baseline_value"] == "https://example.com/"
    assert result["request_contexts"][0]["request_id"] == "req_ssrf"


def test_run_security_focus_pipeline_sqli_runs_arjun_then_sqlmap(monkeypatch: Any) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {
            "success": True,
            "tools": [
                {"tool_name": "arjun", "available": True, "executable": "arjun"},
                {"tool_name": "sqlmap", "available": True, "executable": "sqlmap"},
                {"tool_name": "wafw00f", "available": True, "executable": "wafw00f"},
            ],
        },
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        validation_actions,
        "payload_probe_harness",
        lambda *args, **kwargs: {
            "success": True,
            "tool_name": "payload_probe_harness",
            "finding_count": 1,
            "triage_result": {"suspicious_observations": [{"name": "variant_1"}]},
        },
    )

    def fake_run_security_tool_scan(agent_state: Any, tool_name: str, target: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(tool_name)
        findings = []
        if tool_name == "arjun":
            findings = [{"url": "https://app.test/items", "parameter": "id", "path": "/items"}]
        elif tool_name == "sqlmap":
            findings = [{"parameter": "id", "message": "sqlmap reported injectable parameter"}]
        return {
            "success": True,
            "tool_name": tool_name,
            "target": target,
            "run_id": f"run_{tool_name}_{len(calls)}",
            "finding_count": len(findings),
            "discovery_seed_count": 0,
            "hypothesis_seed_count": len(findings),
            "findings": findings,
        }

    monkeypatch.setattr(toolchain_actions, "run_security_tool_scan", fake_run_security_tool_scan)

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="sqli",
        url="https://app.test/items",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert calls == ["arjun", "wafw00f", "sqlmap"]
    assert result["active_probe_results"][0]["success"] is True


def test_run_security_focus_pipeline_sqli_uses_proxy_form_request_context(
    monkeypatch: Any,
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    probe_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {
            "success": True,
            "tools": [
                {"tool_name": "sqlmap", "available": True, "executable": "sqlmap"},
            ],
        },
    )
    monkeypatch.setattr(
        creative_actions,
        "generate_contextual_payloads",
        lambda **kwargs: {
            "success": True,
            "surface": kwargs["surface"],
            "variant_count": 1,
            "variants": [{"payload": "' OR SLEEP(5)--", "encoding": "raw"}],
        },
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        toolchain_actions,
        "_load_runtime_inventory_entries",
        lambda agent_state, target: [
            {
                "host": "app.test",
                "sample_urls": ["https://app.test/report/run"],
                "sample_request_ids": ["req_sqli"],
                "methods": ["POST"],
                "query_params": [],
                "body_params": ["query"],
                "content_types": ["application/x-www-form-urlencoded"],
                "auth_hints": ["cookie"],
            }
        ],
    )
    monkeypatch.setattr(toolchain_actions, "_load_discovered_workflows", lambda *args, **kwargs: [])
    monkeypatch.setattr(toolchain_actions, "_load_session_profiles", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        toolchain_actions,
        "_get_focus_proxy_manager",
        lambda: StaticProxyManager(
            {
                "req_sqli": (
                    "POST /report/run HTTP/1.1\n"
                    "Host: app.test\n"
                    "Origin: https://app.test\n"
                    "Cookie: sid=user\n"
                    "Content-Type: application/x-www-form-urlencoded\n"
                    "\n"
                    "query=monthly&format=json"
                )
            }
        ),
    )
    monkeypatch.setattr(
        validation_actions,
        "payload_probe_harness",
        lambda *args, **kwargs: (
            probe_calls.append(kwargs)
            or {
                "success": True,
                "tool_name": "payload_probe_harness",
                "finding_count": 1,
                "triage_result": {"suspicious_observations": [{"name": "variant_1"}]},
            }
        ),
    )

    def fake_run_security_tool_scan(agent_state: Any, tool_name: str, target: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((tool_name, kwargs))
        return {
            "success": True,
            "tool_name": tool_name,
            "target": target,
            "run_id": f"run_{tool_name}_{len(calls)}",
            "finding_count": 0,
            "discovery_seed_count": 0,
            "hypothesis_seed_count": 0,
            "findings": [],
        }

    monkeypatch.setattr(toolchain_actions, "run_security_tool_scan", fake_run_security_tool_scan)

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="sqli",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert [tool_name for tool_name, _ in calls] == ["sqlmap"]
    assert calls[0][1]["url"] == "https://app.test/report/run"
    assert calls[0][1]["data"] == "query=monthly&format=json"
    assert calls[0][1]["headers"]["Cookie"] == "sid=user"
    assert probe_calls[0]["base_request"]["method"] == "POST"
    assert probe_calls[0]["base_request"]["body"] == "query=monthly&format=json"
    assert probe_calls[0]["injection_mode"] == "body"
    assert probe_calls[0]["baseline_value"] == "monthly"


def test_run_security_focus_pipeline_authz_uses_role_matrix(monkeypatch: Any) -> None:
    matrix_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {"success": True, "tools": []},
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        toolchain_actions,
        "_load_runtime_inventory_entries",
        lambda agent_state, target: [
            {
                "host": "app.test",
                "priority": "critical",
                "sample_urls": ["https://app.test/api/orders/123"],
                "sample_request_ids": ["req_authz"],
                "methods": ["GET"],
                "query_params": ["id"],
                "body_params": [],
                "content_types": ["application/json"],
                "auth_hints": ["bearer"],
            }
        ],
    )
    monkeypatch.setattr(toolchain_actions, "_load_discovered_workflows", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        toolchain_actions,
        "_load_session_profiles",
        lambda *args, **kwargs: [
            {"profile_id": "sess_user", "name": "user", "role": "user", "base_url": "https://app.test"},
            {"profile_id": "sess_admin", "name": "admin", "role": "admin", "base_url": "https://app.test"},
        ],
    )
    monkeypatch.setattr(
        toolchain_actions,
        "_get_focus_proxy_manager",
        lambda: StaticProxyManager(
            {
                "req_authz": (
                    "GET /api/orders/123 HTTP/1.1\n"
                    "Host: app.test\n"
                    "Authorization: Bearer owner-token\n"
                    "Accept: application/json\n"
                    "\n"
                )
            }
        ),
    )
    monkeypatch.setattr(
        validation_actions,
        "role_matrix_test",
        lambda *args, **kwargs: (
            matrix_calls.append(kwargs)
            or {"success": True, "tool_name": "role_matrix_test", "suspicious_matches": []}
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="authz",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert matrix_calls[0]["method"] == "GET"
    assert matrix_calls[0]["baseline_case"] == "admin"
    assert [case["name"] for case in matrix_calls[0]["cases"]] == ["guest", "admin", "user"]
    assert matrix_calls[0]["cases"][0]["url"] == "http://app.test/api/orders/123"


def test_run_security_focus_pipeline_path_traversal_uses_payload_probe(monkeypatch: Any) -> None:
    probe_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {"success": True, "tools": []},
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        toolchain_actions,
        "_load_runtime_inventory_entries",
        lambda agent_state, target: [
            {
                "host": "app.test",
                "priority": "high",
                "sample_urls": ["https://app.test/download?file=report.pdf"],
                "sample_request_ids": ["req_traversal"],
                "methods": ["GET"],
                "query_params": ["file"],
                "body_params": [],
                "content_types": ["text/html"],
                "auth_hints": ["cookie"],
            }
        ],
    )
    monkeypatch.setattr(toolchain_actions, "_load_discovered_workflows", lambda *args, **kwargs: [])
    monkeypatch.setattr(toolchain_actions, "_load_session_profiles", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        toolchain_actions,
        "_get_focus_proxy_manager",
        lambda: StaticProxyManager(
            {
                "req_traversal": (
                    "GET /download?file=report.pdf HTTP/1.1\n"
                    "Host: app.test\n"
                    "Origin: https://app.test\n"
                    "Cookie: sid=user\n"
                    "\n"
                )
            }
        ),
    )
    monkeypatch.setattr(
        validation_actions,
        "payload_probe_harness",
        lambda *args, **kwargs: (
            probe_calls.append(kwargs)
            or {
                "success": True,
                "tool_name": "payload_probe_harness",
                "finding_count": 1,
                "triage_result": {"suspicious_observations": [{"name": "variant_1"}]},
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="path_traversal",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert probe_calls[0]["vulnerability_type"] == "path_traversal"
    assert probe_calls[0]["parameter_name"] == "file"
    assert probe_calls[0]["injection_mode"] == "query"
    assert probe_calls[0]["baseline_value"] == "report.pdf"


def test_run_security_focus_pipeline_ssti_uses_payload_probe(monkeypatch: Any) -> None:
    probe_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {"success": True, "tools": []},
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        toolchain_actions,
        "_load_runtime_inventory_entries",
        lambda agent_state, target: [
            {
                "host": "app.test",
                "priority": "high",
                "sample_urls": ["https://app.test/render?template=invoice"],
                "sample_request_ids": ["req_ssti"],
                "methods": ["GET"],
                "query_params": ["template"],
                "body_params": [],
                "content_types": ["text/html"],
                "auth_hints": ["cookie"],
            }
        ],
    )
    monkeypatch.setattr(toolchain_actions, "_load_discovered_workflows", lambda *args, **kwargs: [])
    monkeypatch.setattr(toolchain_actions, "_load_session_profiles", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        toolchain_actions,
        "_get_focus_proxy_manager",
        lambda: StaticProxyManager(
            {
                "req_ssti": (
                    "GET /render?template=invoice HTTP/1.1\n"
                    "Host: app.test\n"
                    "Origin: https://app.test\n"
                    "Cookie: sid=user\n"
                    "\n"
                )
            }
        ),
    )
    monkeypatch.setattr(
        validation_actions,
        "payload_probe_harness",
        lambda *args, **kwargs: (
            probe_calls.append(kwargs)
            or {
                "success": True,
                "tool_name": "payload_probe_harness",
                "finding_count": 1,
                "triage_result": {"suspicious_observations": [{"name": "variant_1"}]},
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="ssti",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert probe_calls[0]["vulnerability_type"] == "ssti"
    assert probe_calls[0]["parameter_name"] == "template"
    assert probe_calls[0]["injection_mode"] == "query"
    assert probe_calls[0]["baseline_value"] == "invoice"


def test_run_security_focus_pipeline_xxe_uses_raw_body_probe(monkeypatch: Any) -> None:
    probe_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {"success": True, "tools": []},
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        toolchain_actions,
        "_load_runtime_inventory_entries",
        lambda agent_state, target: [
            {
                "host": "app.test",
                "priority": "high",
                "sample_urls": ["https://app.test/import/xml"],
                "sample_request_ids": ["req_xxe"],
                "methods": ["POST"],
                "query_params": [],
                "body_params": [],
                "content_types": ["application/xml"],
                "auth_hints": ["cookie"],
            }
        ],
    )
    monkeypatch.setattr(toolchain_actions, "_load_discovered_workflows", lambda *args, **kwargs: [])
    monkeypatch.setattr(toolchain_actions, "_load_session_profiles", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        toolchain_actions,
        "_get_focus_proxy_manager",
        lambda: StaticProxyManager(
            {
                "req_xxe": (
                    "POST /import/xml HTTP/1.1\n"
                    "Host: app.test\n"
                    "Origin: https://app.test\n"
                    "Cookie: sid=user\n"
                    "Content-Type: application/xml\n"
                    "\n"
                    "<?xml version=\"1.0\"?><root>safe</root>"
                )
            }
        ),
    )
    monkeypatch.setattr(
        validation_actions,
        "payload_probe_harness",
        lambda *args, **kwargs: (
            probe_calls.append(kwargs)
            or {
                "success": True,
                "tool_name": "payload_probe_harness",
                "finding_count": 1,
                "triage_result": {"suspicious_observations": [{"name": "variant_1"}]},
            }
        ),
    )
    monkeypatch.setattr(
        oob_actions,
        "oob_interaction_harness",
        lambda agent_state, action, **kwargs: (
            {"success": True, "cli_available": True}
            if action == "doctor"
            else {
                "success": True,
                "harness_id": "oob_xxe",
                "provider": "interactsh",
                "payloads": [{"label": "xxe_oob", "url": "http://cb.test/xxe"}],
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="xxe",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert probe_calls[0]["vulnerability_type"] == "xxe"
    assert probe_calls[0]["injection_mode"] == "raw_body"
    assert probe_calls[0]["base_request"]["body"] == "<?xml version=\"1.0\"?><root>safe</root>"
    assert probe_calls[0]["oob_harness_id"] == "oob_xxe"


def test_run_security_focus_pipeline_file_upload_uses_multipart_variants(monkeypatch: Any) -> None:
    probe_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {"success": True, "tools": []},
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        toolchain_actions,
        "_load_runtime_inventory_entries",
        lambda agent_state, target: [
            {
                "host": "app.test",
                "priority": "high",
                "sample_urls": ["https://app.test/upload/avatar"],
                "sample_request_ids": ["req_upload"],
                "methods": ["POST"],
                "query_params": [],
                "body_params": [],
                "content_types": ["multipart/form-data"],
                "auth_hints": ["cookie"],
            }
        ],
    )
    monkeypatch.setattr(toolchain_actions, "_load_discovered_workflows", lambda *args, **kwargs: [])
    monkeypatch.setattr(toolchain_actions, "_load_session_profiles", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        toolchain_actions,
        "_get_focus_proxy_manager",
        lambda: StaticProxyManager(
            {
                "req_upload": (
                    "POST /upload/avatar HTTP/1.1\n"
                    "Host: app.test\n"
                    "Origin: https://app.test\n"
                    "Cookie: sid=user\n"
                    "Content-Type: multipart/form-data; boundary=abc123\n"
                    "\n"
                    "--abc123\r\n"
                    "Content-Disposition: form-data; name=\"file\"; filename=\"avatar.jpg\"\r\n"
                    "Content-Type: image/jpeg\r\n"
                    "\r\n"
                    "JPEGDATA\r\n"
                    "--abc123--\r\n"
                )
            }
        ),
    )
    monkeypatch.setattr(
        oob_actions,
        "oob_interaction_harness",
        lambda agent_state, action, **kwargs: (
            {"success": True, "cli_available": True}
            if action == "doctor"
            else {
                "success": True,
                "harness_id": "oob_upload",
                "provider": "interactsh",
                "payloads": [{"label": "upload_oob", "url": "http://cb.test/upload"}],
            }
        ),
    )
    monkeypatch.setattr(
        validation_actions,
        "payload_probe_harness",
        lambda *args, **kwargs: (
            probe_calls.append(kwargs)
            or {
                "success": True,
                "tool_name": "payload_probe_harness",
                "finding_count": 1,
                "triage_result": {"suspicious_observations": [{"name": "variant_1"}]},
            }
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="file_upload",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert probe_calls[0]["vulnerability_type"] == "file_upload"
    assert probe_calls[0]["injection_mode"] == "raw_body"
    assert probe_calls[0]["oob_harness_id"] == "oob_upload"
    assert probe_calls[0]["payloads"]
    assert any(item.get("expected_rejection") for item in probe_calls[0]["payloads"])
    assert any("shell.php" in item["payload"] for item in probe_calls[0]["payloads"])
    assert any("http://cb.test/upload" in item["payload"] for item in probe_calls[0]["payloads"])


def test_run_security_focus_pipeline_file_upload_followup_records_svg_retrieval(monkeypatch: Any) -> None:
    browser_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {"success": True, "tools": []},
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(
        toolchain_actions,
        "_load_runtime_inventory_entries",
        lambda agent_state, target: [
            {
                "host": "app.test",
                "priority": "high",
                "sample_urls": ["https://app.test/upload/avatar"],
                "sample_request_ids": ["req_upload_followup"],
                "methods": ["POST"],
                "query_params": [],
                "body_params": [],
                "content_types": ["multipart/form-data"],
                "auth_hints": ["cookie"],
            }
        ],
    )
    monkeypatch.setattr(
        toolchain_actions,
        "_load_discovered_workflows",
        lambda *args, **kwargs: [
            {
                "workflow_id": "wf_profile",
                "host": "app.test",
                "sequence": [
                    {"request_id": "req_upload_followup", "method": "POST", "path": "/upload/avatar"},
                    {"request_id": "req_profile", "method": "GET", "path": "/profile"},
                ],
            }
        ],
    )
    monkeypatch.setattr(toolchain_actions, "_load_session_profiles", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        toolchain_actions,
        "_get_focus_proxy_manager",
        lambda: StaticProxyManager(
            {
                "req_upload_followup": (
                    "POST /upload/avatar HTTP/1.1\n"
                    "Host: app.test\n"
                    "Origin: https://app.test\n"
                    "Cookie: sid=user\n"
                    "Content-Type: multipart/form-data; boundary=abc123\n"
                    "\n"
                    "--abc123\r\n"
                    "Content-Disposition: form-data; name=\"file\"; filename=\"avatar.jpg\"\r\n"
                    "Content-Type: image/jpeg\r\n"
                    "\r\n"
                    "JPEGDATA\r\n"
                    "--abc123--\r\n"
                )
            }
        ),
    )
    monkeypatch.setattr(
        oob_actions,
        "oob_interaction_harness",
        lambda agent_state, action, **kwargs: {"success": True, "cli_available": False},
    )
    monkeypatch.setattr(
        browser_assessment_actions,
        "confirm_active_artifact_in_browser",
        lambda *args, **kwargs: (
            browser_calls.append(kwargs)
            or {
                "success": True,
                "available": True,
                "confirmed_execution": True,
                "coverage_result": {"coverage_id": "cov_browser"},
                "hypothesis_result": {"hypothesis_id": "hyp_browser"},
                "evidence_result": {"evidence_id": "evi_browser"},
                "signal_logs": ["__strix_browser_signal__:alert:1"],
            }
        ),
    )
    monkeypatch.setattr(
        validation_actions,
        "payload_probe_harness",
        lambda *args, **kwargs: {
            "success": True,
            "tool_name": "payload_probe_harness",
            "finding_count": 1,
            "request_variants": [
                {
                    "name": "variant_1_svg_active_content_raw",
                    "payload": (
                        "--abc123\r\n"
                        "Content-Disposition: form-data; name=\"file\"; filename=\"avatar.svg\"\r\n"
                        "Content-Type: image/svg+xml\r\n"
                        "\r\n"
                        "<?xml version=\"1.0\"?><svg onload=\"alert(1)\"></svg>\r\n"
                        "--abc123--\r\n"
                    ),
                    "strategy": "svg_active_content",
                    "encoding": "raw",
                    "expected_markers": ["avatar.svg", "image/svg+xml", ".svg"],
                    "expected_rejection": True,
                }
            ],
            "triage_result": {
                "suspicious_observations": [
                    {
                        "name": "variant_1_svg_active_content_raw",
                        "top_issue_type": "dangerous_variant_acceptance",
                        "status_code": 200,
                        "location": "/uploads/avatar.svg",
                        "body_preview": '{"url":"/uploads/avatar.svg"}',
                    }
                ]
            },
        },
    )

    def fake_execute_request(spec: dict[str, Any], *, timeout: int, follow_redirects: bool) -> dict[str, Any]:
        if spec["url"] == "https://app.test/uploads/avatar.svg":
            return {
                "name": spec["name"],
                "method": spec["method"],
                "url": spec["url"],
                "status_code": 200,
                "content_type": "image/svg+xml",
                "body_length": 32,
                "body_hash": "svghash",
                "body_preview": "<svg onload=\"alert(1)\"></svg>",
                "elapsed_ms": 22,
            }
        return {
            "name": spec["name"],
            "method": spec["method"],
            "url": spec["url"],
            "status_code": 404,
            "content_type": "text/plain",
            "body_length": 9,
            "body_hash": "missing",
            "body_preview": "not found",
            "elapsed_ms": 18,
        }

    monkeypatch.setattr(toolchain_actions, "_execute_request", fake_execute_request)

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="file_upload",
        auto_synthesize_hypotheses=False,
    )
    ledger = list_assessment_state(agent_state=state)

    assert result["success"] is True
    assert result["artifact_retrieval_results"][0]["finding_count"] == 2
    assert result["artifact_retrieval_results"][0]["browser_confirmation_count"] == 1
    assert result["artifact_retrieval_results"][0]["findings"][0]["issue_type"] == "uploaded_svg_active_content"
    assert result["artifact_retrieval_results"][0]["findings"][1]["issue_type"] == "stored_xss_browser_confirmed"
    assert browser_calls[0]["viewer_urls"] == ["https://app.test/profile"]
    assert any(item["vulnerability_type"] == "xss" for item in ledger["hypotheses"])


def test_run_security_focus_pipeline_includes_whitebox_sink_discovery(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        "\n".join(
            [
                "from fastapi import FastAPI, UploadFile",
                "from fastapi.staticfiles import StaticFiles",
                "from starlette.responses import FileResponse",
                "app = FastAPI()",
                'app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")',
                "async def upload_avatar(file: UploadFile):",
                "    return {'ok': True}",
                "def download_avatar(name: str):",
                "    return FileResponse(f'uploads/{name}')",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {"success": True, "tools": []},
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(toolchain_actions, "_load_runtime_inventory_entries", lambda *args, **kwargs: [])
    monkeypatch.setattr(toolchain_actions, "_load_discovered_workflows", lambda *args, **kwargs: [])
    monkeypatch.setattr(toolchain_actions, "_load_session_profiles", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        oob_actions,
        "oob_interaction_harness",
        lambda agent_state, action, **kwargs: {"success": True, "cli_available": False},
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="repo-web",
        focus="file_upload",
        target_path=str(tmp_path),
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert result["code_sink_result"]["finding_count"] >= 2
    assert "/uploads" in result["code_sink_result"]["public_path_hints"]
    assert any(step["step"] == "whitebox_sink_discovery" for step in result["steps"])


def test_run_security_focus_pipeline_whitebox_sink_discovery_tracks_source_to_sink(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "render.py"
    app_file.write_text(
        "\n".join(
            [
                "from fastapi import FastAPI, Request",
                "from flask import render_template_string",
                "app = FastAPI()",
                '@app.get("/preview")',
                "async def preview(template: str, request: Request):",
                "    rendered = template",
                "    return render_template_string(rendered)",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {"success": True, "tools": []},
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(toolchain_actions, "_load_runtime_inventory_entries", lambda *args, **kwargs: [])
    monkeypatch.setattr(toolchain_actions, "_load_discovered_workflows", lambda *args, **kwargs: [])
    monkeypatch.setattr(toolchain_actions, "_load_session_profiles", lambda *args, **kwargs: [])

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="repo-ssti",
        focus="ssti",
        target_path=str(tmp_path),
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert result["code_sink_result"]["finding_count"] >= 1
    assert result["code_sink_result"]["findings"][0]["source_to_sink"] is True
    assert "template" in result["code_sink_result"]["findings"][0]["source_parameters"]
    assert "/preview" in result["code_sink_result"]["findings"][0]["route_paths"]


def test_run_security_focus_pipeline_workflow_race_uses_race_harness(monkeypatch: Any) -> None:
    race_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {"success": True, "tools": []},
    )
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )
    monkeypatch.setattr(toolchain_actions, "_load_runtime_inventory_entries", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        toolchain_actions,
        "_load_discovered_workflows",
        lambda *args, **kwargs: [
            {
                "workflow_id": "wf_1",
                "host": "app.test",
                "type": "coupon",
                "priority": "critical",
                "repeated_write": True,
                "surface": "Coupon redemption workflow",
                "sequence": [
                    {
                        "request_id": "req_coupon_1",
                        "method": "POST",
                        "path": "/coupon/redeem",
                        "normalized_path": "/coupon/redeem",
                    },
                    {
                        "request_id": "req_coupon_2",
                        "method": "POST",
                        "path": "/coupon/redeem",
                        "normalized_path": "/coupon/redeem",
                    },
                ],
            }
        ],
    )
    monkeypatch.setattr(toolchain_actions, "_load_session_profiles", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        toolchain_actions,
        "_get_focus_proxy_manager",
        lambda: StaticProxyManager(
            {
                "req_coupon_1": (
                    "POST /coupon/redeem HTTP/1.1\n"
                    "Host: app.test\n"
                    "Cookie: sid=user\n"
                    "Content-Type: application/json\n"
                    "\n"
                    '{"coupon":"SAVE50"}'
                ),
                "req_coupon_2": (
                    "POST /coupon/redeem HTTP/1.1\n"
                    "Host: app.test\n"
                    "Cookie: sid=user\n"
                    "Content-Type: application/json\n"
                    "\n"
                    '{"coupon":"SAVE50"}'
                ),
            }
        ),
    )
    monkeypatch.setattr(
        validation_actions,
        "race_condition_harness",
        lambda *args, **kwargs: (
            race_calls.append(kwargs)
            or {"success": True, "tool_name": "race_condition_harness", "anomalies": []}
        ),
    )

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_focus_pipeline(
        agent_state=state,
        target="web",
        focus="workflow_race",
        auto_synthesize_hypotheses=False,
    )

    assert result["success"] is True
    assert race_calls[0]["expect_single_success"] is True
    assert len(race_calls[0]["requests"]) == 2
    assert race_calls[0]["requests"][0]["method"] == "POST"
    assert race_calls[0]["requests"][0]["json_body"] == {"coupon": "SAVE50"}


def test_run_security_tool_pipeline_hybrid_includes_repo_scans(monkeypatch: Any) -> None:
    available_tools = [
        "arjun",
        "dirsearch",
        "httpx",
        "katana",
        "nuclei",
        "semgrep",
        "bandit",
        "trivy",
        "trufflehog",
    ]
    calls: list[str] = []
    monkeypatch.setattr(
        creative_actions,
        "synthesize_attack_hypotheses",
        lambda *args, **kwargs: {"success": False, "error": "no hypotheses"},
    )

    monkeypatch.setattr(
        toolchain_actions,
        "security_tool_doctor",
        lambda agent_state, tool_names=None: {
            "success": True,
            "tools": [
                {"tool_name": tool_name, "available": True, "executable": tool_name}
                for tool_name in available_tools
            ],
        },
    )

    def fake_run_security_tool_scan(agent_state: Any, tool_name: str, target: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(tool_name)
        findings = []
        if tool_name == "httpx":
            findings = [{"url": "https://app.test", "status_code": 200}]
        elif tool_name == "katana":
            findings = [{"url": "https://app.test/api/orders"}]
        return {
            "success": True,
            "tool_name": tool_name,
            "target": target,
            "run_id": f"run_{tool_name}_{len(calls)}",
            "finding_count": len(findings),
            "discovery_seed_count": 0,
            "hypothesis_seed_count": 0,
            "findings": findings,
        }

    monkeypatch.setattr(toolchain_actions, "run_security_tool_scan", fake_run_security_tool_scan)

    state = DummyState("agent_root")
    result = toolchain_actions.run_security_tool_pipeline(
        agent_state=state,
        target="hybrid",
        mode="hybrid",
        url="https://app.test",
        target_path="E:/PentestTool/strix/strix",
        deep=False,
    )

    assert result["success"] is True
    assert calls == [
        "httpx",
        "katana",
        "nuclei",
        "arjun",
        "dirsearch",
        "semgrep",
        "bandit",
        "trivy",
        "trufflehog",
    ]
    assert result["step_count"] == 9
