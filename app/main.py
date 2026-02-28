import argparse
from pathlib import Path
from typing import List

from agents.security_reasoning_agent import SecurityReasoningAgent
from utils.ymal_parser import load_and_normalize

DEFAULT_SAMPLE_PATH = (
    Path(__file__).resolve().parents[1] / "infra_samples" / "agentic_demo.yaml"
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Agentic Security Reasoning Agent (LangGraph + Ollama)"
    )
    parser.add_argument(
        "--infra-file",
        help=(
            "Path to infrastructure YAML. "
            "Defaults to infra_samples/agentic_demo.yaml."
        ),
    )
    parser.add_argument(
        "--model",
        default="llama3.1:8b",
        help="Ollama model name (default: llama3.1:8b).",
    )
    parser.add_argument(
        "--ollama-url",
        default="http://localhost:11434",
        help="Ollama base URL (default: http://localhost:11434).",
    )
    parser.add_argument(
        "--disable-llm",
        action="store_true",
        help="Disable Ollama calls and use deterministic fallback planning/reporting.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        help="Override simulation max depth.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=2,
        help="Maximum planner/simulator cycles (default: 2).",
    )
    parser.add_argument(
        "--start-nodes",
        help="Comma-separated entry nodes to start from.",
    )
    parser.add_argument(
        "--continue-after-sensitive",
        action="store_true",
        help="Continue traversing after reaching sensitive targets.",
    )
    return parser.parse_args()


def parse_start_nodes(raw: str | None) -> List[str] | None:
    if not raw:
        return None
    nodes = [item.strip() for item in raw.split(",")]
    nodes = [node for node in nodes if node]
    return nodes or None


def print_report(result: dict):
    summary = result.get("summary", {})
    attack_paths = result.get("attack_paths", [])
    blocked = result.get("blocked", [])
    warnings = result.get("warnings", [])

    print("=== Simulation Summary ===")
    print(
        f"Entry points: {summary.get('entry_points', 0)} | "
        f"Sensitive targets: {summary.get('sensitive_targets', 0)} | "
        f"Discovered paths: {summary.get('discovered_paths', 0)} | "
        f"Blocked traversals: {summary.get('blocked_paths', 0)}"
    )
    print()

    print("=== Discovered Attack Paths ===")
    if not attack_paths:
        print("No sensitive attack paths discovered.")
    else:
        for index, path in enumerate(attack_paths, start=1):
            print(f"{index}. {' -> '.join(path.nodes)} | risk={path.risk_score}")
            print(f"   Techniques: {' -> '.join(path.edge_types)}")
            print(
                f"   Capabilities: {', '.join(sorted(path.acquired_capabilities))}"
            )
    print()

    print("=== Blocked Traversals ===")
    if not blocked:
        print("No blocked traversals.")
    else:
        for index, item in enumerate(blocked, start=1):
            print(
                f"{index}. {' -> '.join(item.nodes)} -X-> {item.attempted_target} "
                f"[{item.edge_type}] | reason: {item.reason}"
            )
    print()

    print("=== Analyst Report ===")
    print(result.get("report", "No report generated."))
    print()

    if warnings:
        print("=== Warnings ===")
        for warning in warnings:
            print(f"- {warning}")
        print()


def main():
    args = parse_args()
    infra_path = Path(args.infra_file) if args.infra_file else DEFAULT_SAMPLE_PATH

    spec = load_and_normalize(file_path=str(infra_path))
    agent = SecurityReasoningAgent(
        model=args.model,
        ollama_base_url=args.ollama_url,
        use_llm=not args.disable_llm,
        max_iterations=args.max_iterations,
    )

    result = agent.run(
        infra_spec=spec,
        max_depth_override=args.max_depth,
        stop_at_first_sensitive_override=(
            False if args.continue_after_sensitive else None
        ),
        start_nodes=parse_start_nodes(args.start_nodes),
        max_iterations=args.max_iterations,
    )

    graph = result.get("graph")
    print("=== Infrastructure Graph ===")
    if graph is None:
        print("Graph unavailable.")
    else:
        graph.display_graph()
    print()

    print_report(result)


if __name__ == "__main__":
    main()
