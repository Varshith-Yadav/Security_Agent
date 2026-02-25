# node.py

from typing import Set, Callable, Any, Dict
from capability import Capability
from state import NodeState


class Node:
    def __init__(self, node_id: str, role: str, execute_fn: Callable[[Dict], Any] = None):
        self.node_id = node_id
        self.role = role
        self.capabilities: Set[Capability] = set()
        self.execute_fn = execute_fn
        self.state = NodeState.CREATED

    def add_capability(self, capability: Capability):
        self.capabilities.add(capability)

    def has_capability(self, capability: Capability) -> bool:
        return capability in self.capabilities

    def set_state(self, new_state: NodeState):
        self.state = new_state

    def execute(self, context: Dict):
        if not self.execute_fn:
            raise NotImplementedError(f"No execution logic for {self.node_id}")

        self.set_state(NodeState.RUNNING)

        try:
            output = self.execute_fn(context)
            self.set_state(NodeState.COMPLETED)
            return output
        except Exception as e:
            self.set_state(NodeState.FAILED)
            raise e

    def __repr__(self):
        return f"Node(id={self.node_id}, role={self.role}, state={self.state.name})"