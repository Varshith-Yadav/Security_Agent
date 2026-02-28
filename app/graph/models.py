from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class AttackPath:
    nodes: List[str]
    edge_types: List[str]
    acquired_capabilities: Set[str] = field(default_factory=set)
    risk_score: float = 0.0


@dataclass
class BlockedTraversal:
    nodes: List[str]
    attempted_target: str
    reason: str
    edge_type: str
    required_capability: Optional[str] = None
