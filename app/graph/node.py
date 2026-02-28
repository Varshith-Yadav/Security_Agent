from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional, Set, Union

from .capability import Capability
from .state import NodeState

CapabilityLike = Union[Capability, str]


@dataclass
class Node:
    node_id: str
    role: str
    entry_point: bool = False
    sensitive: bool = False
    exploitability: float = 1.0
    required_capability: Optional[Capability] = None
    attached_role: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    capabilities: Set[Capability] = field(default_factory=set)
    state: NodeState = NodeState.CREATED

    @property
    def id(self) -> str:
        return self.node_id

    @property
    def type(self) -> str:
        return self.role

    def add_capability(self, capability: CapabilityLike):
        self.capabilities.add(Capability.parse(capability))

    def add_capabilities(self, capabilities: Iterable[CapabilityLike]):
        for capability in capabilities:
            self.add_capability(capability)

    def has_capability(self, capability: Optional[CapabilityLike]) -> bool:
        if capability is None:
            return True
        return Capability.parse(capability) in self.capabilities

    def set_state(self, new_state: NodeState):
        self.state = new_state

    def capability_names(self) -> Set[str]:
        return {capability.name for capability in self.capabilities}

    def __repr__(self):
        capabilities = sorted(self.capability_names())
        return (
            "Node("
            f"id={self.node_id}, role={self.role}, entry_point={self.entry_point}, "
            f"sensitive={self.sensitive}, state={self.state.name}, capabilities={capabilities}"
            ")"
        )
