from typing import Optional

from .capability import Capability
from .node import Node


class PermissionManager:
    def __init__(self):
        self.required_capabilities = {
            "Analyzer": Capability.ANALYZE,
            "Memory": Capability.STORE_MEMORY,
            "API": Capability.CALL_API,
            "EC2": Capability.SSH,
            "IAM_ROLE": Capability.ASSUME_ROLE,
            "SecretsManager": Capability.DUMP_SECRETS,
            "RDS": Capability.READ,
            "S3": Capability.READ,
        }

    def required_for_target(self, target: Node) -> Optional[Capability]:
        if target.required_capability is not None:
            return target.required_capability
        return self.required_capabilities.get(target.role)

    def validate_connection(
        self,
        source: Node,
        target: Node,
        required_capability: Optional[Capability] = None,
    ) -> bool:
        required_cap = required_capability or self.required_for_target(target)
        return source.has_capability(required_cap)

    def missing_capability_for_connection(
        self,
        source: Node,
        target: Node,
        required_capability: Optional[Capability] = None,
    ) -> Optional[Capability]:
        required_cap = required_capability or self.required_for_target(target)
        if source.has_capability(required_cap):
            return None
        return required_cap
    

    def validate_connection(self, source: Node, target: Node) -> bool:

        # 1️⃣ Explicit deny overrides everything
        if self.policy_engine.is_explicitly_denied(source.node_id, target.node_id):
            return False

        # 2️⃣ Explicit allow
        if self.policy_engine.is_explicitly_allowed(source.node_id, target.node_id):
            return True

        # 3️⃣ Role-level permission
        if self.policy_engine.is_role_allowed(source.role, target.role):
            return True

        # 4️⃣ Capability-based fallback
        required_cap = self.required_capabilities.get(target.role)

        if required_cap:
            return source.has_capability(required_cap)

        return True
