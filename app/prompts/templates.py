from typing import Iterable, List


PLANNER_SYSTEM_PROMPT = (
    "You are a red-team security planner. "
    "You choose attack simulation parameters from the infrastructure graph context. "
    "Return strict JSON only."
)

REPORTER_SYSTEM_PROMPT = (
    "You are a security analyst. "
    "Create concise, accurate, technical risk reports for attack-path simulation output."
)


def build_planner_prompt(
    entry_points: Iterable[str],
    sensitive_targets: Iterable[str],
    current_depth: int,
    iteration: int,
    previous_summary: str,
) -> str:
    entries = ", ".join(entry_points) or "none"
    sensitive = ", ".join(sensitive_targets) or "none"

    return f"""
Choose next simulation parameters.

Context:
- Entry points: {entries}
- Sensitive targets: {sensitive}
- Current max depth: {current_depth}
- Iteration: {iteration}
- Previous summary: {previous_summary or "none"}

Output JSON schema:
{{
  "start_nodes": ["entry-node-id"],
  "max_depth": 6,
  "reasoning": "short rationale"
}}

Rules:
- Keep start_nodes to known entry points only.
- max_depth must be an integer from 2 to 12.
- Prefer realistic attacker behavior and shortest feasible paths first.
""".strip()


def build_reporter_prompt(
    summary: str,
    discovered_paths: List[str],
    blocked_paths: List[str],
) -> str:
    discovered = "\n".join(discovered_paths) if discovered_paths else "- none"
    blocked = "\n".join(blocked_paths) if blocked_paths else "- none"

    return f"""
Generate a technical report with these sections:
1) Executive Summary
2) Confirmed Attack Paths
3) Blocked/Limited Paths
4) Defensive Priorities

Simulation summary:
{summary}

Discovered paths:
{discovered}

Blocked traversals:
{blocked}
""".strip()
