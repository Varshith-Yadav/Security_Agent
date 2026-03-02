# Security Reasoning Agent

Agentic AI project for attack-path simulation using:

- LangGraph workflow orchestration
- Ollama local LLM (planner + reporter)
- Infrastructure graph traversal with policy-aware permission checks

The simulator models how an attacker can move from entry points to sensitive assets, then reports:

- confirmed attack paths
- blocked traversals with reasons
- risk score per discovered path
- defensive priorities

## Features

- YAML-driven infrastructure modeling (nodes, edges, policies, simulation config)
- Capability-based and policy-based access reasoning
- DFS attack-path simulation with stateful node execution
- LangGraph loop:
  - ingest
  - planner
  - simulate
  - assess
  - reporter
- Ollama optional:
  - if Ollama is unavailable, deterministic fallback planning/reporting is used

## Project Structure

```text
security_agent/
  app/
    main.py
    agents/
      ollama_client.py
      security_reasoning_agent.py
    graph/
      builder.py
      capability.py
      execution_engine.py
      models.py
      node.py
      permission.py
      policy.py
      state.py
    prompts/
      templates.py
    state/
      agent_state.py
    utils/
      ymal_parser.py
  infra_samples/
    agentic_demo.yaml
  requirements.txt
```

## How It Works

1. `app/main.py` parses CLI args and loads infra YAML.
2. YAML is normalized by `app/utils/ymal_parser.py`.
3. `GraphBuilder.from_infra_spec(...)` creates nodes/edges and loads policy rules.
4. `SecurityReasoningAgent` runs LangGraph nodes:
   - `ingest`: graph + simulation context
   - `planner`: choose start nodes/depth (LLM or fallback)
   - `simulate`: execute attack-path traversal
   - `assess`: optionally iterate with deeper search if needed
   - `reporter`: generate analyst report (LLM or fallback)
5. `ExecutionEngine` outputs:
   - `attack_paths` (to sensitive nodes)
   - `blocked` traversals (with denial reason)
   - `summary` metrics

## Prerequisites

- Python 3.10+
- Optional for LLM mode:
  - Ollama installed and running locally
  - A pulled model (default: `llama3.1:8b`)

## Setup

From repository root (`security_agent`):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run

### 1) Deterministic mode (no Ollama)

```powershell
python app\main.py --disable-llm
```

### 2) Ollama LLM mode

Start Ollama and pull model first:

```powershell
ollama serve
ollama pull llama3.1:8b
```

Then run:

```powershell
python app\main.py --model llama3.1:8b --ollama-url http://localhost:11434
```

## CLI Options

```text
--infra-file <path>            Path to infra YAML (default: infra_samples/agentic_demo.yaml)
--model <name>                 Ollama model (default: llama3.1:8b)
--ollama-url <url>             Ollama base URL (default: http://localhost:11434)
--disable-llm                  Disable Ollama and use fallback logic
--max-depth <int>              Override simulation depth
--max-iterations <int>         Planner/simulator loop count (default: 2)
--start-nodes <a,b,c>          Comma-separated start nodes
--continue-after-sensitive     Continue traversal after sensitive node is reached
```

## Infrastructure YAML Format

Top-level keys:

- `nodes`: list of assets/identities
- `edges`: directed possible movement paths
- `policies`: explicit allow/deny and role-based policy
- `simulation`: traversal configuration

Minimal example:

```yaml
nodes:
  - id: internet
    role: External
    entry_point: true
    capabilities: [ssh]
  - id: app-role
    role: IAM_ROLE
    capabilities: [dump_secrets]
  - id: secrets-prod
    role: SecretsManager
    sensitive: true

edges:
  - source: internet
    target: app-role
    type: assume_role
  - source: app-role
    target: secrets-prod
    type: permission

policies:
  role_permissions:
    - [External, IAM_ROLE]
    - [IAM_ROLE, SecretsManager]

simulation:
  max_depth: 6
  stop_at_first_sensitive: true
```

## Output Sections

The program prints:

- infrastructure graph
- simulation summary
- discovered attack paths
- blocked traversals
- analyst report
- warnings (for fallback and validation situations)

## Notes

- `app/utils/ymal_parser.py` name intentionally uses `ymal` in the current codebase.
- If Ollama is down, the run still succeeds using deterministic fallback logic.

