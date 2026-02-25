# graph_builder.py

from typing import Dict, List, Callable, Tuple
from node import Node
from permission import PermissionManager


class GraphBuilder:
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[str, List[Tuple[str, Callable]]] = {}
        self.permission_manager = PermissionManager()

    def add_node(self, node: Node):
        self.nodes[node.node_id] = node
        self.edges[node.node_id] = []

    def add_edge(self, source_id: str, target_id: str, condition: Callable = None):
        source = self.nodes.get(source_id)
        target = self.nodes.get(target_id)

        if not source or not target:
            raise ValueError("Invalid node IDs")

        if not self.permission_manager.validate_connection(source, target):
            raise PermissionError("Permission denied")

        # If no condition → always true
        condition = condition if condition else lambda context: True

        self.edges[source_id].append((target_id, condition))