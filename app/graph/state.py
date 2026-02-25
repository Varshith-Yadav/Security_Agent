# state.py

from enum import Enum, auto


class NodeState(Enum):
    CREATED = auto()
    READY = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()