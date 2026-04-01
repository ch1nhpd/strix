import threading
from datetime import UTC, datetime
from typing import Any, Literal

from strix.tools.registry import register_tool


_agent_graph: dict[str, Any] = {
    "nodes": {},
    "edges": [],
}

_root_agent_id: str | None = None

_agent_messages: dict[str, list[dict[str, Any]]] = {}

_running_agents: dict[str, threading.Thread] = {}

_agent_instances: dict[str, Any] = {}

_agent_states: dict[str, Any] = {}


def _auto_trigger_orchestration_followup(state: Any, completion_status: str) -> dict[str, Any] | None:
    if getattr(state, "parent_id", None) is None:
        return None
    try:
        from strix.tools.assessment.assessment_orchestration_actions import (
            trigger_attack_surface_orchestration_on_child_completion,
        )
    except Exception:  # noqa: BLE001
        return None
    try:
        return trigger_attack_surface_orchestration_on_child_completion(
            agent_state=state,
            completion_status=completion_status,
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "success": False,
            "triggered": False,
            "error": f"Failed to auto-trigger orchestration follow-up: {exc}",
        }


def _run_agent_in_thread(
    agent: Any, state: Any, inherited_messages: list[dict[str, Any]]
) -> dict[str, Any]:
    try:
        if inherited_messages:
            state.add_message("user", "<inherited_context_from_parent>")
            for msg in inherited_messages:
                state.add_message(msg["role"], msg["content"])
            state.add_message("user", "</inherited_context_from_parent>")

        parent_info = _agent_graph["nodes"].get(state.parent_id, {})
        parent_name = parent_info.get("name", "Unknown Parent")

        context_status = (
            "inherited conversation context from your parent for background understanding"
            if inherited_messages
            else "started with a fresh context"
        )

        task_xml = f"""<agent_delegation>
    <identity>
        ⚠️ You are NOT your parent agent. You are a NEW, SEPARATE sub-agent (not root).

        Your Info: {state.agent_name} ({state.agent_id})
        Parent Info: {parent_name} ({state.parent_id})
    </identity>

    <your_task>{state.task}</your_task>

    <instructions>
        - You have {context_status}
        - Inherited context is for BACKGROUND ONLY - don't continue parent's work
        - Maintain strict self-identity: never speak as or for your parent
        - Do not merge your conversation with the parent's;
        - Do not claim parent's actions or messages as your own
        - Focus EXCLUSIVELY on your delegated task above
        - Work independently with your own approach
        - Use agent_finish when complete to report back to parent
        - You are a SPECIALIST for this specific task
        - You share the same container as other agents but have your own tool server instance
        - All agents share /workspace directory and proxy history for better collaboration
        - You can see files created by other agents and proxy traffic from previous work
        - Build upon previous work but focus on your specific delegated task
    </instructions>
</agent_delegation>"""

        state.add_message("user", task_xml)

        _agent_states[state.agent_id] = state

        _agent_graph["nodes"][state.agent_id]["state"] = state.model_dump()

        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(agent.agent_loop(state.task))
        finally:
            loop.close()

    except Exception as e:
        node = _agent_graph["nodes"][state.agent_id]
        node["status"] = "error"
        node["finished_at"] = datetime.now(UTC).isoformat()
        node["result"] = {"error": str(e)}
        autorun_result = _auto_trigger_orchestration_followup(state, "error")
        if autorun_result is not None:
            node["orchestration_autorun"] = autorun_result
        _running_agents.pop(state.agent_id, None)
        _agent_instances.pop(state.agent_id, None)
        raise
    else:
        node = _agent_graph["nodes"][state.agent_id]
        existing_status = str(node.get("status") or "").strip().lower()
        if state.stop_requested:
            final_status = "stopped"
        elif existing_status in {"failed", "stopped"}:
            final_status = existing_status
        else:
            final_status = "completed"
        node["status"] = final_status
        if not node.get("finished_at"):
            node["finished_at"] = datetime.now(UTC).isoformat()
        if node.get("result") is None:
            node["result"] = result
        autorun_result = _auto_trigger_orchestration_followup(state, final_status)
        if autorun_result is not None:
            node["orchestration_autorun"] = autorun_result
        _running_agents.pop(state.agent_id, None)
        _agent_instances.pop(state.agent_id, None)

        return {"result": result}


@register_tool(sandbox_execution=False)
def view_agent_graph(agent_state: Any) -> dict[str, Any]:
    try:
        structure_lines = ["=== AGENT GRAPH STRUCTURE ==="]

        def _build_tree(agent_id: str, depth: int = 0) -> None:
            node = _agent_graph["nodes"][agent_id]
            indent = "  " * depth

            you_indicator = " ← This is you" if agent_id == agent_state.agent_id else ""

            structure_lines.append(f"{indent}* {node['name']} ({agent_id}){you_indicator}")
            structure_lines.append(f"{indent}  Task: {node['task']}")
            structure_lines.append(f"{indent}  Status: {node['status']}")

            children = [
                edge["to"]
                for edge in _agent_graph["edges"]
                if edge["from"] == agent_id and edge["type"] == "delegation"
            ]

            if children:
                structure_lines.append(f"{indent}   Children:")
                for child_id in children:
                    _build_tree(child_id, depth + 2)

        root_agent_id = _root_agent_id
        if not root_agent_id and _agent_graph["nodes"]:
            for agent_id, node in _agent_graph["nodes"].items():
                if node.get("parent_id") is None:
                    root_agent_id = agent_id
                    break
            if not root_agent_id:
                root_agent_id = next(iter(_agent_graph["nodes"].keys()))

        if root_agent_id and root_agent_id in _agent_graph["nodes"]:
            _build_tree(root_agent_id)
        else:
            structure_lines.append("No agents in the graph yet")

        graph_structure = "\n".join(structure_lines)

        total_nodes = len(_agent_graph["nodes"])
        running_count = sum(
            1 for node in _agent_graph["nodes"].values() if node["status"] == "running"
        )
        waiting_count = sum(
            1 for node in _agent_graph["nodes"].values() if node["status"] == "waiting"
        )
        stopping_count = sum(
            1 for node in _agent_graph["nodes"].values() if node["status"] == "stopping"
        )
        completed_count = sum(
            1 for node in _agent_graph["nodes"].values() if node["status"] == "completed"
        )
        stopped_count = sum(
            1 for node in _agent_graph["nodes"].values() if node["status"] == "stopped"
        )
        failed_count = sum(
            1 for node in _agent_graph["nodes"].values() if node["status"] in ["failed", "error"]
        )

    except Exception as e:  # noqa: BLE001
        return {
            "error": f"Failed to view agent graph: {e}",
            "graph_structure": "Error retrieving graph structure",
        }
    else:
        return {
            "graph_structure": graph_structure,
            "summary": {
                "total_agents": total_nodes,
                "running": running_count,
                "waiting": waiting_count,
                "stopping": stopping_count,
                "completed": completed_count,
                "stopped": stopped_count,
                "failed": failed_count,
            },
        }


def _agent_state_context(agent_state: Any) -> dict[str, Any]:
    context = getattr(agent_state, "context", None)
    return dict(context) if isinstance(context, dict) else {}


def _agent_state_runtime_snapshot(agent_state: Any) -> dict[str, Any]:
    direct_snapshot = getattr(agent_state, "runtime_snapshot", None)
    if isinstance(direct_snapshot, dict):
        return dict(direct_snapshot)

    context = _agent_state_context(agent_state)
    for key in (
        "_recovered_root_runtime_snapshot",
        "runtime_snapshot",
        "recovered_runtime_snapshot",
    ):
        candidate = context.get(key)
        if isinstance(candidate, dict):
            return dict(candidate)
    return {}


def _parent_runtime_defaults(agent_state: Any, parent_agent: Any) -> dict[str, Any]:
    timeout = None
    scan_mode = "deep"
    assessment_objective = "discovery"
    interactive = False
    system_prompt_context: dict[str, Any] = {}

    if parent_agent and hasattr(parent_agent, "llm_config"):
        if hasattr(parent_agent.llm_config, "timeout"):
            timeout = parent_agent.llm_config.timeout
        if hasattr(parent_agent.llm_config, "scan_mode"):
            scan_mode = parent_agent.llm_config.scan_mode
        if hasattr(parent_agent.llm_config, "assessment_objective"):
            assessment_objective = parent_agent.llm_config.assessment_objective
        interactive = getattr(parent_agent.llm_config, "interactive", False)
        if hasattr(parent_agent, "llm") and hasattr(parent_agent.llm, "_system_prompt_context"):
            system_prompt_context = dict(
                getattr(parent_agent.llm, "_system_prompt_context", {})
            )
        return {
            "timeout": timeout,
            "scan_mode": scan_mode,
            "assessment_objective": assessment_objective,
            "interactive": interactive,
            "system_prompt_context": system_prompt_context,
        }

    runtime_snapshot = _agent_state_runtime_snapshot(agent_state)
    runtime = (
        dict(runtime_snapshot.get("runtime"))
        if isinstance(runtime_snapshot.get("runtime"), dict)
        else {}
    )
    timeout = runtime.get("timeout")
    scan_mode = str(runtime.get("scan_mode") or scan_mode)
    assessment_objective = str(
        runtime.get("assessment_objective") or assessment_objective
    )
    interactive = bool(runtime.get("interactive", interactive))
    if isinstance(runtime.get("system_prompt_context"), dict):
        system_prompt_context = dict(runtime.get("system_prompt_context") or {})
    return {
        "timeout": timeout,
        "scan_mode": scan_mode,
        "assessment_objective": assessment_objective,
        "interactive": interactive,
        "system_prompt_context": system_prompt_context,
    }


def _inherited_framework_skills(agent_state: Any) -> list[str]:
    context = _agent_state_context(agent_state)
    skill_values = context.get("auto_loaded_framework_skills", [])
    if not isinstance(skill_values, list):
        skill_values = []

    if not skill_values:
        runtime_snapshot = _agent_state_runtime_snapshot(agent_state)
        runtime_context = runtime_snapshot.get("context")
        if isinstance(runtime_context, dict):
            candidate_values = runtime_context.get("auto_loaded_framework_skills", [])
            if isinstance(candidate_values, list):
                skill_values = candidate_values

    inherited_skills: list[str] = []
    for skill in skill_values:
        if isinstance(skill, str) and skill and skill not in inherited_skills:
            inherited_skills.append(skill)
    return inherited_skills


@register_tool(sandbox_execution=False)
def create_agent(
    agent_state: Any,
    task: str,
    name: str,
    inherit_context: bool = True,
    skills: str | None = None,
) -> dict[str, Any]:
    try:
        parent_id = agent_state.agent_id

        from strix.skills import parse_skill_list, validate_requested_skills

        skill_list = parse_skill_list(skills)
        validation_error = validate_requested_skills(skill_list)
        if validation_error:
            return {
                "success": False,
                "error": validation_error,
                "agent_id": None,
            }

        from strix.agents import StrixAgent
        from strix.agents.state import AgentState
        from strix.llm.config import LLMConfig

        parent_agent = _agent_instances.get(parent_id)

        runtime_defaults = _parent_runtime_defaults(agent_state, parent_agent)
        timeout = runtime_defaults["timeout"]
        scan_mode = str(runtime_defaults["scan_mode"] or "deep")
        assessment_objective = str(
            runtime_defaults["assessment_objective"] or "discovery"
        )
        interactive = bool(runtime_defaults["interactive"])
        system_prompt_context = (
            dict(runtime_defaults["system_prompt_context"])
            if isinstance(runtime_defaults["system_prompt_context"], dict)
            else {}
        )

        inherited_framework_skills = _inherited_framework_skills(agent_state)

        merged_skill_list: list[str] = []
        for skill in [*inherited_framework_skills, *skill_list]:
            if skill not in merged_skill_list:
                merged_skill_list.append(skill)

        state = AgentState(
            task=task,
            agent_name=name,
            parent_id=parent_id,
            max_iterations=300,
            waiting_timeout=300 if interactive else 600,
        )

        llm_config = LLMConfig(
            skills=merged_skill_list,
            timeout=timeout,
            scan_mode=scan_mode,
            assessment_objective=assessment_objective,
            interactive=interactive,
            system_prompt_context=system_prompt_context,
        )

        agent_config = {
            "llm_config": llm_config,
            "state": state,
        }

        agent = StrixAgent(agent_config)

        inherited_messages = []
        if inherit_context:
            inherited_messages = agent_state.get_conversation_history()

        _agent_instances[state.agent_id] = agent

        thread = threading.Thread(
            target=_run_agent_in_thread,
            args=(agent, state, inherited_messages),
            daemon=True,
            name=f"Agent-{name}-{state.agent_id}",
        )
        thread.start()
        _running_agents[state.agent_id] = thread

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to create agent: {e}", "agent_id": None}
    else:
        return {
            "success": True,
            "agent_id": state.agent_id,
            "message": f"Agent '{name}' created and started asynchronously",
            "agent_info": {
                "id": state.agent_id,
                "name": name,
                "status": "running",
                "parent_id": parent_id,
            },
            "inherited_skills": inherited_framework_skills,
            "requested_skills": skill_list,
            "active_skills": merged_skill_list,
        }


@register_tool(sandbox_execution=False)
def send_message_to_agent(
    agent_state: Any,
    target_agent_id: str,
    message: str,
    message_type: Literal["query", "instruction", "information"] = "information",
    priority: Literal["low", "normal", "high", "urgent"] = "normal",
) -> dict[str, Any]:
    try:
        if target_agent_id not in _agent_graph["nodes"]:
            return {
                "success": False,
                "error": f"Target agent '{target_agent_id}' not found in graph",
                "message_id": None,
            }

        sender_id = agent_state.agent_id

        from uuid import uuid4

        message_id = f"msg_{uuid4().hex[:8]}"
        message_data = {
            "id": message_id,
            "from": sender_id,
            "to": target_agent_id,
            "content": message,
            "message_type": message_type,
            "priority": priority,
            "timestamp": datetime.now(UTC).isoformat(),
            "delivered": False,
            "read": False,
        }

        if target_agent_id not in _agent_messages:
            _agent_messages[target_agent_id] = []

        _agent_messages[target_agent_id].append(message_data)

        _agent_graph["edges"].append(
            {
                "from": sender_id,
                "to": target_agent_id,
                "type": "message",
                "message_id": message_id,
                "message_type": message_type,
                "priority": priority,
                "created_at": datetime.now(UTC).isoformat(),
            }
        )

        message_data["delivered"] = True

        target_name = _agent_graph["nodes"][target_agent_id]["name"]
        sender_name = _agent_graph["nodes"][sender_id]["name"]

        return {
            "success": True,
            "message_id": message_id,
            "message": f"Message sent from '{sender_name}' to '{target_name}'",
            "delivery_status": "delivered",
            "target_agent": {
                "id": target_agent_id,
                "name": target_name,
                "status": _agent_graph["nodes"][target_agent_id]["status"],
            },
        }

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to send message: {e}", "message_id": None}


@register_tool(sandbox_execution=False)
def agent_finish(
    agent_state: Any,
    result_summary: str,
    findings: list[str] | None = None,
    success: bool = True,
    report_to_parent: bool = True,
    final_recommendations: list[str] | None = None,
) -> dict[str, Any]:
    try:
        if not hasattr(agent_state, "parent_id") or agent_state.parent_id is None:
            return {
                "agent_completed": False,
                "error": (
                    "This tool can only be used by subagents. "
                    "Root/main agents must use finish_scan instead."
                ),
                "parent_notified": False,
            }

        agent_id = agent_state.agent_id

        if agent_id not in _agent_graph["nodes"]:
            return {"agent_completed": False, "error": "Current agent not found in graph"}

        agent_node = _agent_graph["nodes"][agent_id]

        agent_node["status"] = "finished" if success else "failed"
        agent_node["finished_at"] = datetime.now(UTC).isoformat()
        agent_node["result"] = {
            "summary": result_summary,
            "findings": findings or [],
            "success": success,
            "recommendations": final_recommendations or [],
        }

        parent_notified = False

        if report_to_parent and agent_node["parent_id"]:
            parent_id = agent_node["parent_id"]

            if parent_id in _agent_graph["nodes"]:
                findings_xml = "\n".join(
                    f"        <finding>{finding}</finding>" for finding in (findings or [])
                )
                recommendations_xml = "\n".join(
                    f"        <recommendation>{rec}</recommendation>"
                    for rec in (final_recommendations or [])
                )

                report_message = f"""<agent_completion_report>
    <agent_info>
        <agent_name>{agent_node["name"]}</agent_name>
        <agent_id>{agent_id}</agent_id>
        <task>{agent_node["task"]}</task>
        <status>{"SUCCESS" if success else "FAILED"}</status>
        <completion_time>{agent_node["finished_at"]}</completion_time>
    </agent_info>
    <results>
        <summary>{result_summary}</summary>
        <findings>
{findings_xml}
        </findings>
        <recommendations>
{recommendations_xml}
        </recommendations>
    </results>
</agent_completion_report>"""

                if parent_id not in _agent_messages:
                    _agent_messages[parent_id] = []

                from uuid import uuid4

                _agent_messages[parent_id].append(
                    {
                        "id": f"report_{uuid4().hex[:8]}",
                        "from": agent_id,
                        "to": parent_id,
                        "content": report_message,
                        "message_type": "information",
                        "priority": "high",
                        "timestamp": datetime.now(UTC).isoformat(),
                        "delivered": True,
                        "read": False,
                    }
                )

                parent_notified = True

        _running_agents.pop(agent_id, None)

        return {
            "agent_completed": True,
            "parent_notified": parent_notified,
            "completion_summary": {
                "agent_id": agent_id,
                "agent_name": agent_node["name"],
                "task": agent_node["task"],
                "success": success,
                "findings_count": len(findings or []),
                "has_recommendations": bool(final_recommendations),
                "finished_at": agent_node["finished_at"],
            },
        }

    except Exception as e:  # noqa: BLE001
        return {
            "agent_completed": False,
            "error": f"Failed to complete agent: {e}",
            "parent_notified": False,
        }


def stop_agent(agent_id: str) -> dict[str, Any]:
    try:
        if agent_id not in _agent_graph["nodes"]:
            return {
                "success": False,
                "error": f"Agent '{agent_id}' not found in graph",
                "agent_id": agent_id,
            }

        agent_node = _agent_graph["nodes"][agent_id]

        if agent_node["status"] in ["completed", "error", "failed", "stopped"]:
            return {
                "success": True,
                "message": f"Agent '{agent_node['name']}' was already stopped",
                "agent_id": agent_id,
                "previous_status": agent_node["status"],
            }

        if agent_id in _agent_states:
            agent_state = _agent_states[agent_id]
            agent_state.request_stop()

        if agent_id in _agent_instances:
            agent_instance = _agent_instances[agent_id]
            if hasattr(agent_instance, "state"):
                agent_instance.state.request_stop()
            if hasattr(agent_instance, "cancel_current_execution"):
                agent_instance.cancel_current_execution()

        agent_node["status"] = "stopping"

        try:
            from strix.telemetry.tracer import get_global_tracer

            tracer = get_global_tracer()
            if tracer:
                tracer.update_agent_status(agent_id, "stopping")
        except (ImportError, AttributeError):
            pass

        agent_node["result"] = {
            "summary": "Agent stop requested by user",
            "success": False,
            "stopped_by_user": True,
        }

        return {
            "success": True,
            "message": f"Stop request sent to agent '{agent_node['name']}'",
            "agent_id": agent_id,
            "agent_name": agent_node["name"],
            "note": "Agent will stop gracefully after current iteration",
        }

    except Exception as e:  # noqa: BLE001
        return {
            "success": False,
            "error": f"Failed to stop agent: {e}",
            "agent_id": agent_id,
        }


def send_user_message_to_agent(agent_id: str, message: str) -> dict[str, Any]:
    try:
        if agent_id not in _agent_graph["nodes"]:
            return {
                "success": False,
                "error": f"Agent '{agent_id}' not found in graph",
                "agent_id": agent_id,
            }

        agent_node = _agent_graph["nodes"][agent_id]

        if agent_id not in _agent_messages:
            _agent_messages[agent_id] = []

        from uuid import uuid4

        message_data = {
            "id": f"user_msg_{uuid4().hex[:8]}",
            "from": "user",
            "to": agent_id,
            "content": message,
            "message_type": "instruction",
            "priority": "high",
            "timestamp": datetime.now(UTC).isoformat(),
            "delivered": True,
            "read": False,
        }

        _agent_messages[agent_id].append(message_data)

        return {
            "success": True,
            "message": f"Message sent to agent '{agent_node['name']}'",
            "agent_id": agent_id,
            "agent_name": agent_node["name"],
        }

    except Exception as e:  # noqa: BLE001
        return {
            "success": False,
            "error": f"Failed to send message to agent: {e}",
            "agent_id": agent_id,
        }


@register_tool(sandbox_execution=False)
def wait_for_message(
    agent_state: Any,
    reason: str = "Waiting for messages from other agents",
) -> dict[str, Any]:
    try:
        agent_id = agent_state.agent_id
        agent_name = agent_state.agent_name

        agent_state.enter_waiting_state()

        if agent_id in _agent_graph["nodes"]:
            _agent_graph["nodes"][agent_id]["status"] = "waiting"
            _agent_graph["nodes"][agent_id]["waiting_reason"] = reason

        try:
            from strix.telemetry.tracer import get_global_tracer

            tracer = get_global_tracer()
            if tracer:
                tracer.update_agent_status(agent_id, "waiting")
        except (ImportError, AttributeError):
            pass

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to enter waiting state: {e}", "status": "error"}
    else:
        return {
            "success": True,
            "status": "waiting",
            "message": f"Agent '{agent_name}' is now waiting for messages",
            "reason": reason,
            "agent_info": {
                "id": agent_id,
                "name": agent_name,
                "status": "waiting",
            },
            "resume_conditions": [
                "Message from another agent",
                "Message from user",
                "Direct communication",
                "Waiting timeout reached",
            ],
        }
