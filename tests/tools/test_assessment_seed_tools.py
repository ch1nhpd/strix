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
from strix.tools.assessment.assessment_seed_actions import seed_coverage_from_scan_config


class DummyState:
    def __init__(self, agent_id: str, parent_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.parent_id = parent_id
        self.context: dict[str, Any] = {}

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value


def setup_function() -> None:
    clear_assessment_storage()
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_seed_coverage_extracts_nextjs_routes(tmp_path: Path) -> None:
    _write(
        tmp_path / "package.json",
        """
{
  "dependencies": {
    "next": "15.0.0"
  }
}
""".strip(),
    )
    _write(tmp_path / "app" / "admin" / "page.tsx", "export default function Page() { return null }")
    _write(
        tmp_path / "app" / "api" / "orders" / "[id]" / "route.ts",
        """
export async function GET() { return Response.json({ ok: true }) }
export async function POST() { return Response.json({ ok: true }) }
""".strip(),
    )
    _write(tmp_path / "middleware.ts", "export function middleware() { return Response.next() }")

    scan_config = {
        "targets": [
            {
                "type": "local_code",
                "original": "next-app",
                "details": {"target_path": str(tmp_path)},
            }
        ]
    }
    state = DummyState("agent_root")

    result = seed_coverage_from_scan_config(state, scan_config, max_route_items=10)
    ledger = list_assessment_state(agent_state=state, include_evidence=False)

    assert result["success"] is True
    assert "nextjs" in result["framework_skills"]
    assert result["framework_summaries"][0]["route_count"] >= 2
    assert ledger["assessment_summary"]["coverage_total"] >= 4

    surfaces = {item["surface"] for item in ledger["coverage"]}
    assert "Next.js page route /admin" in surfaces
    assert "Next.js route handler GET/POST /api/orders/:id" in surfaces
    assert "Next.js middleware authorization and path normalization boundary" in surfaces


def test_seed_coverage_extracts_fastapi_routes(tmp_path: Path) -> None:
    _write(
        tmp_path / "main.py",
        """
from fastapi import APIRouter, Depends, FastAPI

app = FastAPI(docs_url="/docs")
router = APIRouter(prefix="/api")

def get_current_user():
    return {"id": 1}

@router.get("/users")
def list_users(user = Depends(get_current_user)):
    return []

app.include_router(router)
""".strip(),
    )
    state = DummyState("agent_root")
    scan_config = {
        "targets": [
            {
                "type": "local_code",
                "original": "fastapi-app",
                "details": {"target_path": str(tmp_path)},
            }
        ]
    }

    result = seed_coverage_from_scan_config(state, scan_config, max_route_items=10)
    ledger = list_assessment_state(agent_state=state, include_evidence=False)

    assert result["success"] is True
    assert "fastapi" in result["framework_skills"]

    surfaces = {item["surface"] for item in ledger["coverage"]}
    assert "FastAPI route GET /api/users" in surfaces
    assert "FastAPI dependency-based authentication and authorization boundary" in surfaces
    assert "FastAPI OpenAPI and documentation exposure" in surfaces
