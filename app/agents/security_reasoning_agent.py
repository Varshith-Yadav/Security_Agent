from __future__ import annotations

from typing import Dict, Iterable, List

from agents.ollama_client import OllamaClient, OllamaClientError
from graph.builder import GraphBuilder
from graph.execution_engine import ExecutionEngine
from graph.models import AttackPath, BlockedTraversal
from prompts.templates import (
    PLANNER_SYSTEM_PROMPT,
    REPORTER_SYSTEM_PROMPT,
    build_planner_prompt,
    build_reporter_prompt,
)
from state.agent_state import AgentState

try:
    from langgraph.graph import END, START, StateGraph
except ImportError:
    END = "__end__"
    START = "__start__"
    StateGraph = None


class SecurityReasoningAgent:
    def __init__(
        self,
        model: str = "llama3.1:8b",
        ollama_base_url: str = "http://localhost:11434",
        use_llm: bool = True,
        max_iterations: int = 2,
    ):
        self.use_llm = use_llm
        self.default_max_iterations = max_iterations
        self.ollama_client = (
            OllamaClient(model=model, base_url=ollama_base_url) if use_llm else None
        )
        self.workflow = self._build_workflow() if StateGraph else None

    def run(
        self,
        infra_spec: Dict,
        max_depth_override: int | None = None,
        stop_at_first_sensitive_override: bool | None = None,
        start_nodes: List[str] | None = None,
        max_iterations: int | None = None,
    ) -> AgentState:
        initial_state: AgentState = {
            "infra_spec": infra_spec,
            "iteration": 0,
            "max_iterations": max_iterations or self.default_max_iterations,
            "warnings": [],
        }

        if max_depth_override is not None:
            initial_state["max_depth"] = max_depth_override
        if stop_at_first_sensitive_override is not None:
            initial_state["stop_at_first_sensitive"] = stop_at_first_sensitive_override
        if start_nodes is not None:
            initial_state["start_nodes"] = start_nodes

        if self.workflow is None:
            state = dict(initial_state)
            return self._run_fallback(state)

        return self.workflow.invoke(initial_state)

    def _build_workflow(self):
        workflow = StateGraph(AgentState)
        workflow.add_node("ingest", self._ingest_node)
        workflow.add_node("planner", self._planner_node)
        workflow.add_node("simulate", self._simulate_node)
        workflow.add_node("assess", self._assess_node)
        workflow.add_node("reporter", self._reporter_node)

        workflow.add_edge(START, "ingest")
        workflow.add_edge("ingest", "planner")
        workflow.add_edge("planner", "simulate")
        workflow.add_edge("simulate", "assess")
        workflow.add_conditional_edges(
            "assess",
            self._route_after_assess,
            {
                "planner": "planner",
                "reporter": "reporter",
            },
        )
        workflow.add_edge("reporter", END)
        return workflow.compile()

    def _ingest_node(self, state: AgentState) -> AgentState:
        infra_spec = state["infra_spec"]
        graph = GraphBuilder.from_infra_spec(infra_spec)

        simulation = infra_spec.get("simulation", {})
        warnings = list(state.get("warnings", []))
        start_nodes = list(state.get("start_nodes") or [])
        if start_nodes:
            valid_nodes = [node for node in start_nodes if node in graph.nodes]
            if valid_nodes:
                start_nodes = valid_nodes
            else:
                warnings.append(
                    "Provided start_nodes are invalid; defaulting to graph entry points."
                )
                start_nodes = graph.get_entry_points()
        else:
            start_nodes = graph.get_entry_points()

        max_depth = int(state.get("max_depth", simulation.get("max_depth", 6)))
        stop_at_first_sensitive = bool(
            state.get(
                "stop_at_first_sensitive",
                simulation.get("stop_at_first_sensitive", True),
            )
        )

        if not start_nodes:
            warnings.append("No entry points found. Simulation may discover no paths.")

        return {
            "graph": graph,
            "start_nodes": start_nodes,
            "max_depth": max_depth,
            "stop_at_first_sensitive": stop_at_first_sensitive,
            "warnings": warnings,
        }

    def _planner_node(self, state: AgentState) -> AgentState:
        graph: GraphBuilder = state["graph"]
        entry_points = graph.get_entry_points()
        sensitive_targets = graph.get_sensitive_targets()
        current_depth = int(state["max_depth"])
        iteration = int(state.get("iteration", 0)) + 1

        chosen_start_nodes = list(state.get("start_nodes", entry_points))
        chosen_depth = current_depth
        planner_notes = (
            "Heuristic plan: simulate from entry points toward sensitive targets."
        )
        warnings = list(state.get("warnings", []))

        if self.use_llm and self.ollama_client:
            prompt = build_planner_prompt(
                entry_points=entry_points,
                sensitive_targets=sensitive_targets,
                current_depth=current_depth,
                iteration=iteration,
                previous_summary=self._summary_text(state.get("summary", {})),
            )
            try:
                decision = self.ollama_client.generate_json(
                    prompt=prompt,
                    system_prompt=PLANNER_SYSTEM_PROMPT,
                )
                chosen_start_nodes = self._sanitize_start_nodes(
                    decision.get("start_nodes"),
                    valid_entry_points=entry_points,
                    fallback=chosen_start_nodes,
                )
                chosen_depth = self._sanitize_depth(
                    decision.get("max_depth"),
                    fallback=current_depth,
                )
                reasoning = str(decision.get("reasoning", "")).strip()
                if reasoning:
                    planner_notes = reasoning
            except OllamaClientError as exc:
                warnings.append(f"Planner fallback used: {exc}")

        return {
            "iteration": iteration,
            "start_nodes": chosen_start_nodes,
            "max_depth": chosen_depth,
            "planner_notes": planner_notes,
            "warnings": warnings,
        }

    def _simulate_node(self, state: AgentState) -> AgentState:
        graph: GraphBuilder = state["graph"]
        engine = ExecutionEngine(graph)
        attack_paths, blocked = engine.simulate_attack_paths(
            start_nodes=state["start_nodes"],
            max_depth=int(state["max_depth"]),
            stop_at_first_sensitive=bool(state["stop_at_first_sensitive"]),
        )
        summary = engine.summary(attack_paths)

        return {
            "attack_paths": attack_paths,
            "blocked": blocked,
            "summary": summary,
        }

    def _assess_node(self, state: AgentState) -> AgentState:
        summary = state.get("summary", {})
        discovered_paths = int(summary.get("discovered_paths", 0))
        iteration = int(state.get("iteration", 0))
        max_iterations = int(state.get("max_iterations", self.default_max_iterations))
        current_depth = int(state["max_depth"])
        warnings = list(state.get("warnings", []))

        continue_loop = False
        next_depth = current_depth
        if discovered_paths == 0 and iteration < max_iterations:
            continue_loop = True
            next_depth = min(current_depth + 2, 12)
            warnings.append(
                f"No sensitive paths found at depth {current_depth}. "
                f"Retrying with depth {next_depth}."
            )
        elif discovered_paths == 0 and iteration >= max_iterations:
            warnings.append("No sensitive paths found after max iterations.")

        return {
            "continue_loop": continue_loop,
            "max_depth": next_depth,
            "warnings": warnings,
        }

    def _reporter_node(self, state: AgentState) -> AgentState:
        attack_paths: List[AttackPath] = list(state.get("attack_paths", []))
        blocked_paths: List[BlockedTraversal] = list(state.get("blocked", []))
        warnings = list(state.get("warnings", []))

        discovered_lines = [
            f"- {' -> '.join(path.nodes)} | risk={path.risk_score}"
            for path in attack_paths
        ]
        blocked_lines = [
            f"- {' -> '.join(item.nodes)} -X-> {item.attempted_target} | {item.reason}"
            for item in blocked_paths
        ]
        summary_text = self._summary_text(state.get("summary", {}))

        report = self._fallback_report(
            summary_text=summary_text,
            discovered_lines=discovered_lines,
            blocked_lines=blocked_lines,
            planner_notes=state.get("planner_notes", ""),
        )

        if self.use_llm and self.ollama_client:
            prompt = build_reporter_prompt(
                summary=summary_text,
                discovered_paths=discovered_lines,
                blocked_paths=blocked_lines,
            )
            try:
                report = self.ollama_client.generate(
                    prompt=prompt,
                    system_prompt=REPORTER_SYSTEM_PROMPT,
                    expect_json=False,
                )
            except OllamaClientError as exc:
                warnings.append(f"Reporter fallback used: {exc}")

        return {
            "report": report,
            "warnings": warnings,
            "continue_loop": False,
        }

    def _route_after_assess(self, state: AgentState) -> str:
        return "planner" if state.get("continue_loop", False) else "reporter"

    def _run_fallback(self, state: Dict) -> AgentState:
        state.update(self._ingest_node(state))
        while True:
            state.update(self._planner_node(state))
            state.update(self._simulate_node(state))
            state.update(self._assess_node(state))
            if not state.get("continue_loop", False):
                break
        state.update(self._reporter_node(state))
        return state

    @staticmethod
    def _sanitize_start_nodes(
        proposed_nodes,
        valid_entry_points: Iterable[str],
        fallback: List[str],
    ) -> List[str]:
        valid = set(valid_entry_points)
        if isinstance(proposed_nodes, str):
            proposed_nodes = [proposed_nodes]

        if not isinstance(proposed_nodes, list):
            return list(fallback)

        sanitized = [str(node) for node in proposed_nodes if str(node) in valid]
        return sanitized or list(fallback)

    @staticmethod
    def _sanitize_depth(value, fallback: int) -> int:
        try:
            depth = int(value)
        except (TypeError, ValueError):
            return fallback
        return min(max(depth, 2), 12)

    @staticmethod
    def _summary_text(summary: Dict) -> str:
        if not summary:
            return "No simulation summary available."
        return (
            f"Entry points={summary.get('entry_points', 0)}, "
            f"Sensitive targets={summary.get('sensitive_targets', 0)}, "
            f"Discovered paths={summary.get('discovered_paths', 0)}, "
            f"Blocked traversals={summary.get('blocked_paths', 0)}"
        )

    @staticmethod
    def _fallback_report(
        summary_text: str,
        discovered_lines: List[str],
        blocked_lines: List[str],
        planner_notes: str,
    ) -> str:
        discovered = "\n".join(discovered_lines) if discovered_lines else "- none"
        blocked = "\n".join(blocked_lines) if blocked_lines else "- none"
        planner = planner_notes or "No planner notes."

        return (
            "Executive Summary\n"
            f"{summary_text}\n\n"
            "Planner Notes\n"
            f"{planner}\n\n"
            "Confirmed Attack Paths\n"
            f"{discovered}\n\n"
            "Blocked or Limited Paths\n"
            f"{blocked}\n\n"
            "Defensive Priorities\n"
            "- Harden entry points and enforce least privilege.\n"
            "- Remove high-risk role permissions along discovered attack paths.\n"
            "- Add explicit deny policies to critical assets where possible."
        )
