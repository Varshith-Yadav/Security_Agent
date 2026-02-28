from typing import Any, Dict, List, Optional

import yaml


def load_yaml(file_path: str) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        raise ValueError("YAML root must be a map/object")
    return data


def load_yaml_from_text(yaml_text: str) -> Dict[str, Any]:
    data = yaml.safe_load(yaml_text) or {}
    if not isinstance(data, dict):
        raise ValueError("YAML root must be a map/object")
    return data


def normalize_infra_spec(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    nodes = _normalize_nodes(raw_data.get("nodes", []))
    edges = _normalize_edges(raw_data.get("edges", []))
    policies = raw_data.get("policies", {}) or {}
    simulation = raw_data.get("simulation", {}) or {}

    if not isinstance(policies, dict):
        raise ValueError("'policies' must be a map/object")
    if not isinstance(simulation, dict):
        raise ValueError("'simulation' must be a map/object")

    return {
        "nodes": nodes,
        "edges": edges,
        "policies": policies,
        "simulation": {
            "max_depth": int(simulation.get("max_depth", 6)),
            "stop_at_first_sensitive": bool(
                simulation.get("stop_at_first_sensitive", True)
            ),
        },
    }


def _normalize_nodes(raw_nodes: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw_nodes, list):
        raise ValueError("'nodes' must be a list")

    normalized = []
    for node in raw_nodes:
        if not isinstance(node, dict):
            raise ValueError(f"Invalid node entry: {node}")
        if "id" not in node or "role" not in node:
            raise ValueError(f"Each node requires 'id' and 'role': {node}")

        capabilities = node.get("capabilities", [])
        if capabilities is None:
            capabilities = []
        if not isinstance(capabilities, list):
            raise ValueError(f"Node capabilities must be a list: {node}")

        metadata = node.get("metadata", {})
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise ValueError(f"Node metadata must be a map/object: {node}")

        normalized.append(
            {
                "id": str(node["id"]),
                "role": str(node["role"]),
                "entry_point": bool(node.get("entry_point", False)),
                "sensitive": bool(node.get("sensitive", False)),
                "exploitability": float(node.get("exploitability", 1.0)),
                "required_capability": node.get("required_capability"),
                "attached_role": node.get("attached_role"),
                "capabilities": capabilities,
                "metadata": metadata,
            }
        )
    return normalized


def _normalize_edges(raw_edges: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw_edges, list):
        raise ValueError("'edges' must be a list")

    normalized = []
    for edge in raw_edges:
        if not isinstance(edge, dict):
            raise ValueError(f"Invalid edge entry: {edge}")
        if "source" not in edge or "target" not in edge:
            raise ValueError(f"Each edge requires 'source' and 'target': {edge}")

        metadata = edge.get("metadata", {})
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise ValueError(f"Edge metadata must be a map/object: {edge}")

        normalized.append(
            {
                "source": str(edge["source"]),
                "target": str(edge["target"]),
                "type": str(edge.get("type", "network")),
                "required_capability": edge.get("required_capability"),
                "metadata": metadata,
            }
        )
    return normalized


def load_and_normalize(file_path: Optional[str] = None, yaml_text: Optional[str] = None):
    if file_path:
        raw = load_yaml(file_path)
    elif yaml_text:
        raw = load_yaml_from_text(yaml_text)
    else:
        raise ValueError("Provide either file_path or yaml_text")

    return normalize_infra_spec(raw)
