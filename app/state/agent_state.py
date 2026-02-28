from typing import Any, Dict, List, TypedDict

from graph.models import AttackPath, BlockedTraversal


class AgentState(TypedDict, total=False):
    infra_spec: Dict[str, Any]
    graph: Any

    iteration: int
    max_iterations: int

    planner_notes: str
    start_nodes: List[str]
    max_depth: int
    stop_at_first_sensitive: bool

    attack_paths: List[AttackPath]
    blocked: List[BlockedTraversal]
    summary: Dict[str, int]

    continue_loop: bool
    warnings: List[str]
    report: str
