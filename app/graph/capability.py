from enum import Enum
from typing import Union


class Capability(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    STORE_MEMORY = "store_memory"
    CALL_API = "call_api"
    ANALYZE = "analyze"
    SSH = "ssh"
    ASSUME_ROLE = "assume_role"
    DUMP_SECRETS = "dump_secrets"
    EXFILTRATE = "exfiltrate"

    @classmethod
    def parse(cls, value: Union["Capability", str]) -> "Capability":
        if isinstance(value, cls):
            return value

        normalized = str(value).strip()
        by_name = normalized.upper()
        if by_name in cls.__members__:
            return cls[by_name]

        by_value = normalized.lower().replace(" ", "_").replace("-", "_")
        for capability in cls:
            if capability.value == by_value:
                return capability

        raise ValueError(f"Unknown capability: {value}")
