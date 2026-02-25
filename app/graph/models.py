from dataclasses import dataclass, field
from typing import Set, Optional


@dataclass
class Node:
    id: str
    type: str  # EC2, IAM_ROLE, S3
    entry_point: bool = False
    sensitive: bool = False
    capabilities: Set[str] = field(default_factory=set)
    required_capability: Optional[str] = None
    attached_role: Optional[str] = None


@dataclass
class Edge:
    source: str
    target: str
    type: str  # network, assume_role, permission