from typing import Any, Dict, Iterable, Set, Tuple


class PolicyEngine:
    def __init__(self):
        self.explicit_allow: Set[Tuple[str, str]] = set()
        self.explicit_deny: Set[Tuple[str, str]] = set()
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

    def load_from_dict(self, policy_data: Dict[str, Any]):
        if not policy_data:
            return

        for source_id, target_id in self._pairs(policy_data.get("explicit_allow")):
            self.allow(source_id, target_id)

        for source_id, target_id in self._pairs(policy_data.get("explicit_deny")):
            self.deny(source_id, target_id)

        for source_role, target_role in self._pairs(policy_data.get("role_permissions")):
            self.allow_role(source_role, target_role)

    @staticmethod
    def _pairs(value: Any) -> Iterable[Tuple[str, str]]:
        if not value:
            return []

        if isinstance(value, dict):
            value = value.items()

        pairs = []
        for item in value:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise ValueError(f"Invalid policy pair: {item}")
            source, target = str(item[0]), str(item[1])
            pairs.append((source, target))
        return pairs
