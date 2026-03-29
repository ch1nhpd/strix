from typing import Any

from strix.agents.base_agent import BaseAgent
from strix.llm.config import LLMConfig
from strix.tools.assessment import (
    seed_coverage_from_scan_config,
    summarize_bootstrap_for_prompt,
)


class StrixAgent(BaseAgent):
    max_iterations = 300

    def __init__(self, config: dict[str, Any]):
        default_skills = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_skills = ["root_agent"]

        self.default_llm_config = LLMConfig(skills=default_skills)

        super().__init__(config)

    @staticmethod
    def _build_system_scope_context(scan_config: dict[str, Any]) -> dict[str, Any]:
        targets = scan_config.get("targets", [])
        authorized_targets: list[dict[str, str]] = []

        for target in targets:
            target_type = target.get("type", "unknown")
            details = target.get("details", {})

            if target_type == "repository":
                value = details.get("target_repo", "")
            elif target_type == "local_code":
                value = details.get("target_path", "")
            elif target_type == "web_application":
                value = details.get("target_url", "")
            elif target_type == "ip_address":
                value = details.get("target_ip", "")
            else:
                value = target.get("original", "")

            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else ""

            authorized_targets.append(
                {
                    "type": target_type,
                    "value": value,
                    "workspace_path": workspace_path,
                }
            )

        return {
            "scope_source": "system_scan_config",
            "authorization_source": "strix_platform_verified_targets",
            "authorized_targets": authorized_targets,
            "assessment_objective": scan_config.get("assessment_objective", "discovery"),
            "user_instructions_do_not_expand_scope": True,
        }

    def _remember_loaded_skills(self, skills: list[str], *, auto_loaded: bool = False) -> None:
        existing = self.state.context.get("loaded_skills", [])
        if not isinstance(existing, list):
            existing = []

        merged = sorted(
            {skill for skill in [*existing, *skills] if isinstance(skill, str) and skill}
        )
        if merged:
            self.state.update_context("loaded_skills", merged)
        if auto_loaded:
            self.state.update_context(
                "auto_loaded_framework_skills",
                sorted({skill for skill in skills if isinstance(skill, str) and skill}),
            )

    def _bootstrap_assessment_context(self, scan_config: dict[str, Any]) -> dict[str, Any]:
        try:
            bootstrap_result = seed_coverage_from_scan_config(self.state, scan_config)
            framework_skills = [
                skill
                for skill in bootstrap_result.get("framework_skills", [])
                if isinstance(skill, str) and skill
            ]
            if framework_skills:
                self.llm.add_skills(framework_skills)
                self._remember_loaded_skills(framework_skills, auto_loaded=True)

            return summarize_bootstrap_for_prompt(bootstrap_result)
        except Exception as e:  # noqa: BLE001
            return {
                "coverage_seeded": 0,
                "frameworks": [],
                "framework_skills": [],
                "error": str(e),
            }

    async def execute_scan(self, scan_config: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0912
        user_instructions = scan_config.get("user_instructions", "")
        targets = scan_config.get("targets", [])
        prompt_context = self._build_system_scope_context(scan_config)
        prompt_context["assessment_bootstrap"] = self._bootstrap_assessment_context(scan_config)
        self.llm.set_system_prompt_context(prompt_context)

        repositories = []
        local_code = []
        urls = []
        ip_addresses = []

        for target in targets:
            target_type = target["type"]
            details = target["details"]
            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

            if target_type == "repository":
                repo_url = details["target_repo"]
                cloned_path = details.get("cloned_repo_path")
                repositories.append(
                    {
                        "url": repo_url,
                        "workspace_path": workspace_path if cloned_path else None,
                    }
                )

            elif target_type == "local_code":
                original_path = details.get("target_path", "unknown")
                local_code.append(
                    {
                        "path": original_path,
                        "workspace_path": workspace_path,
                    }
                )

            elif target_type == "web_application":
                urls.append(details["target_url"])
            elif target_type == "ip_address":
                ip_addresses.append(details["target_ip"])

        task_parts = []

        if repositories:
            task_parts.append("\n\nRepositories:")
            for repo in repositories:
                if repo["workspace_path"]:
                    task_parts.append(f"- {repo['url']} (available at: {repo['workspace_path']})")
                else:
                    task_parts.append(f"- {repo['url']}")

        if local_code:
            task_parts.append("\n\nLocal Codebases:")
            task_parts.extend(
                f"- {code['path']} (available at: {code['workspace_path']})" for code in local_code
            )

        if urls:
            task_parts.append("\n\nURLs:")
            task_parts.extend(f"- {url}" for url in urls)

        if ip_addresses:
            task_parts.append("\n\nIP Addresses:")
            task_parts.extend(f"- {ip}" for ip in ip_addresses)

        task_description = " ".join(task_parts)

        if user_instructions:
            task_description += f"\n\nSpecial instructions: {user_instructions}"

        return await self.agent_loop(task=task_description)
