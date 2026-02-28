from typing import Optional, Set, Tuple, Union

from .capability import Capability
from .node import Node
from .policy import PolicyEngine

CapabilityLike = Union[Capability, str]


class PermissionManager:
    def __init__(self, policy_engine: Optional[PolicyEngine] = None):
        self.policy_engine = policy_engine or PolicyEngine()
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
        required_capability: Optional[CapabilityLike] = None,
        effective_capabilities: Optional[Set[Capability]] = None,
    ) -> bool:
        allowed, _ = self.explain_connection(
            source=source,
            target=target,
            required_capability=required_capability,
            effective_capabilities=effective_capabilities,
        )
        return allowed

    def explain_connection(
        self,
        source: Node,
        target: Node,
        required_capability: Optional[CapabilityLike] = None,
        effective_capabilities: Optional[Set[Capability]] = None,
    ) -> Tuple[bool, str]:
        if self.policy_engine.is_explicitly_denied(source.node_id, target.node_id):
            return False, "blocked by explicit deny policy"

        if self.policy_engine.is_explicitly_allowed(source.node_id, target.node_id):
            return True, "allowed by explicit allow policy"

        if self.policy_engine.is_role_allowed(source.role, target.role):
            return True, "allowed by role policy"

        required = (
            Capability.parse(required_capability)
            if required_capability is not None
            else self.required_for_target(target)
        )
        if required is None:
            return True, "allowed (no required capability)"

        available_capabilities = effective_capabilities or source.capabilities
        if required in available_capabilities:
            return True, f"allowed by capability {required.name}"

        return False, f"missing capability {required.name}"
