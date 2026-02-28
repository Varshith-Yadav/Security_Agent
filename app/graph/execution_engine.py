from typing import Dict, List, Optional, Set, Tuple

from .builder import GraphBuilder
from .capability import Capability
from .models import AttackPath, BlockedTraversal
from .state import NodeState


class ExecutionEngine:
    def __init__(self, graph: GraphBuilder):
        self.graph = graph
        self.blocked: List[BlockedTraversal] = []

    def simulate_attack_paths(
        self,
        start_nodes: Optional[List[str]] = None,
        max_depth: int = 6,
        stop_at_first_sensitive: bool = True,
    ) -> Tuple[List[AttackPath], List[BlockedTraversal]]:
        if start_nodes is None:
            start_nodes = self.graph.get_entry_points()

        attack_paths: List[AttackPath] = []
        self.blocked = []

        for node in self.graph.nodes.values():
            node.set_state(NodeState.CREATED)

        for start_node_id in start_nodes:
            if start_node_id not in self.graph.nodes:
                continue

            start_node = self.graph.nodes[start_node_id]
            self._dfs(
                current_id=start_node_id,
                visited={start_node_id},
                path_nodes=[start_node_id],
                edge_types=[],
                acquired_capabilities=set(start_node.capabilities),
                max_depth=max_depth,
                stop_at_first_sensitive=stop_at_first_sensitive,
                attack_paths=attack_paths,
            )

        return attack_paths, self.blocked

    def _dfs(
        self,
        current_id: str,
        visited: Set[str],
        path_nodes: List[str],
        edge_types: List[str],
        acquired_capabilities: Set[Capability],
        max_depth: int,
        stop_at_first_sensitive: bool,
        attack_paths: List[AttackPath],
    ):
        current_node = self.graph.nodes[current_id]
        current_node.set_state(NodeState.RUNNING)

        if current_node.sensitive and len(path_nodes) > 1:
            current_node.set_state(NodeState.COMPLETED)
            attack_paths.append(
                AttackPath(
                    nodes=list(path_nodes),
                    edge_types=list(edge_types),
                    acquired_capabilities={cap.name for cap in acquired_capabilities},
                    risk_score=self._score_path(path_nodes),
                )
            )
            if stop_at_first_sensitive:
                return

        if len(path_nodes) - 1 >= max_depth:
            current_node.set_state(NodeState.COMPLETED)
            return

        for edge in self.graph.edges.get(current_id, []):
            if edge.target in visited:
                continue

            target_node = self.graph.nodes[edge.target]
            is_allowed, reason = self.graph.permission_manager.explain_connection(
                source=current_node,
                target=target_node,
                required_capability=edge.required_capability,
                effective_capabilities=acquired_capabilities,
            )
            if not is_allowed:
                default_required = self.graph.permission_manager.required_for_target(
                    target_node
                )
                required = (
                    edge.required_capability.name
                    if edge.required_capability is not None
                    else (default_required.name if default_required else None)
                )
                self.blocked.append(
                    BlockedTraversal(
                        nodes=list(path_nodes),
                        attempted_target=edge.target,
                        reason=reason,
                        edge_type=edge.edge_type,
                        required_capability=required,
                    )
                )
                continue

            visited.add(edge.target)
            path_nodes.append(edge.target)
            edge_types.append(edge.edge_type)

            target_node.set_state(NodeState.READY)
            next_capabilities = set(acquired_capabilities).union(target_node.capabilities)

            self._dfs(
                current_id=edge.target,
                visited=visited,
                path_nodes=path_nodes,
                edge_types=edge_types,
                acquired_capabilities=next_capabilities,
                max_depth=max_depth,
                stop_at_first_sensitive=stop_at_first_sensitive,
                attack_paths=attack_paths,
            )

            edge_types.pop()
            path_nodes.pop()
            visited.remove(edge.target)

        current_node.set_state(NodeState.COMPLETED)

    def _score_path(self, path_nodes: List[str]) -> float:
        total = 0.0
        for node_id in path_nodes:
            node = self.graph.nodes[node_id]
            total += node.exploitability
            if node.sensitive:
                total += 4.0
        return round(total, 2)

    def summary(self, attack_paths: List[AttackPath]) -> Dict[str, int]:
        return {
            "entry_points": len(self.graph.get_entry_points()),
            "sensitive_targets": len(self.graph.get_sensitive_targets()),
            "discovered_paths": len(attack_paths),
            "blocked_paths": len(self.blocked),
        }
