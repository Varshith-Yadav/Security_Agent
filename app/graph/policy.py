from typing import Dict, Set, Tuple


class PolicyEngine:
    def __init__(self):
        # Explicit allow: (source_id, target_id)
        self.explicit_allow: Set[Tuple[str, str]] = set()

        # Explicit deny: (source_id, target_id)
        self.explicit_deny: Set[Tuple[str, str]] = set()

        # Role-to-role rules
        # Example: ("Analyzer", "Memory")
        self.role_permissions: Set[Tuple[str, str]] = set()

    def allow(self, source_id: str, target_id: str):
        self.explicit_allow.add((source_id, target_id))

    def deny(self, source_id: str, target_id: str):
        self.explicit_deny.add((source_id, target_id))

    def allow_role(self, source_role: str, target_role: str):
        self.role_permissions.add((source_role, target_role))

    def is_explicitly_denied(self, source_id: str, target_id: str) -> bool:
        return (source_id, target_id) in self.explicit_deny

    def is_explicitly_allowed(self, source_id: str, target_id: str) -> bool:
        return (source_id, target_id) in self.explicit_allow

    def is_role_allowed(self, source_role: str, target_role: str) -> bool:
        return (source_role, target_role) in self.role_permissions