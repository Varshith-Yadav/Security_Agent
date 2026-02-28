from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

from .capability import Capability
from .node import Node
from .permission import PermissionManager
from .policy import PolicyEngine

CapabilityLike = Union[Capability, str]


@dataclass
class Edge:
    source: str
    target: str
    edge_type: str = "network"
    required_capability: Optional[Capability] = None
    metadata: Optional[Dict[str, Any]] = None


class GraphBuilder:
    def __init__(
        self,
        permission_manager: Optional[PermissionManager] = None,
        policy_engine: Optional[PolicyEngine] = None,
    ):
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[str, List[Edge]] = {}
        self.policy_engine = policy_engine or PolicyEngine()
        self.permission_manager = permission_manager or PermissionManager(self.policy_engine)

    def add_node(self, node: Node):
        self.nodes[node.node_id] = node
        self.edges.setdefault(node.node_id, [])

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str = "network",
        required_capability: Optional[CapabilityLike] = None,
        metadata: Optional[Dict[str, Any]] = None,
        strict: bool = False,
    ):
        source = self.nodes.get(source_id)
        target = self.nodes.get(target_id)
        if not source or not target:
            raise ValueError(f"Invalid edge ({source_id} -> {target_id})")

        parsed_required_capability = (
            Capability.parse(required_capability)
            if required_capability is not None
            else None
        )

        if strict:
            is_allowed, reason = self.permission_manager.explain_connection(
                source=source,
                target=target,
                required_capability=parsed_required_capability,
            )
            if not is_allowed:
                raise PermissionError(
                    f"{source.node_id} cannot connect to {target.node_id}: {reason}"
                )

        self.edges[source_id].append(
            Edge(
                source=source_id,
                target=target_id,
                edge_type=edge_type,
                required_capability=parsed_required_capability,
                metadata=metadata or {},
            )
        )

    def get_entry_points(self) -> List[str]:
        return [node_id for node_id, node in self.nodes.items() if node.entry_point]

    def get_sensitive_targets(self) -> List[str]:
        return [node_id for node_id, node in self.nodes.items() if node.sensitive]

    def display_graph(self):
        for source_id, edge_list in self.edges.items():
            if not edge_list:
                print(f"{source_id} -> []")
                continue

            labels = []
            for edge in edge_list:
                required = (
                    edge.required_capability.name
                    if edge.required_capability is not None
                    else "TARGET_POLICY"
                )
                labels.append(
                    f"{edge.target}(type={edge.edge_type}, requires={required})"
                )
            print(f"{source_id} -> [{', '.join(labels)}]")

    @classmethod
    def from_infra_spec(cls, spec: Dict[str, Any]) -> "GraphBuilder":
        graph = cls()
        graph.policy_engine.load_from_dict(spec.get("policies", {}))

        for node_data in spec.get("nodes", []):
            required_capability = node_data.get("required_capability")
            node = Node(
                node_id=node_data["id"],
                role=node_data["role"],
                entry_point=bool(node_data.get("entry_point", False)),
                sensitive=bool(node_data.get("sensitive", False)),
                exploitability=float(node_data.get("exploitability", 1.0)),
                required_capability=(
                    Capability.parse(required_capability)
                    if required_capability
                    else None
                ),
                attached_role=node_data.get("attached_role"),
                metadata=dict(node_data.get("metadata", {})),
            )
            node.add_capabilities(node_data.get("capabilities", []))
            graph.add_node(node)

        for edge_data in spec.get("edges", []):
            graph.add_edge(
                source_id=edge_data["source"],
                target_id=edge_data["target"],
                edge_type=edge_data.get("type", "network"),
                required_capability=edge_data.get("required_capability"),
                metadata=dict(edge_data.get("metadata", {})),
            )

        return graph
