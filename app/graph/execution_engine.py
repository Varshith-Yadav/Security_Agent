# execution_engine.py

from typing import Dict
from graph.builder import GraphBuilder
from state import NodeState


class ExecutionEngine:
    def __init__(self, graph: GraphBuilder):
        self.graph = graph
        self.context: Dict = {}

    def run(self, start_node_id: str):

        if start_node_id not in self.graph.nodes:
            raise ValueError("Invalid start node")

        self._execute_node(start_node_id)

    def _execute_node(self, node_id: str):

        node = self.graph.nodes[node_id]

        if node.state == NodeState.COMPLETED:
            return  # Avoid re-execution

        print(f"\nExecuting {node.node_id} ({node.role})")

        output = node.execute(self.context)
        self.context[node.node_id] = output

        # Conditional routing
        for neighbor_id, condition in self.graph.edges[node_id]:
            if condition(self.context):
                self._execute_node(neighbor_id)