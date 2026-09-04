# Cortex

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Commercial License Available](https://img.shields.io/badge/Commercial_License-Available-green.svg)](LICENSE-COMMERCIAL.md)

Local AI agent with tool calling, powered by Ollama.

Like Claude Code or Cursor — but running entirely on your machine, with your own models, **fully open source forever**.

> **Why Cortex?** Unlike permissively-licensed alternatives, Cortex uses AGPLv3 — meaning every fork, every SaaS deployment, every modification stays open. Your investment in the project is protected: no corporation can absorb Cortex into a closed product. Improvements always flow back to the community.

## Features

- **10 tools**: bash, read/write/edit files, grep, glob, list_dir, and optional Consciousness Server integration
- **Policy Engine**: regex-based deny/ask/allow rules per tool (blocks `rm -rf`, asks before `sudo`)
- **Recovery Engine**: auto-retry on failures, optional fallback to Anthropic API
- **Context Compression**: auto-summarizes old messages when context gets too large
- **Worker mode**: autonomous task execution loop (poll server, execute, report results)
- **Web UI**: browser-based chat with WebSocket streaming
- **Model switching**: change models mid-conversation with `/model`
- **Plugin system**: extend Cortex with custom tools and modes

## Quick Start

**Prerequisites:** Python 3.12+, `curl`, and Ollama (installed in step 1).
`run.sh` creates a venv on first run, so no system-wide pip install is needed.
Debian and Ubuntu ship `venv` separately: `sudo apt install python3-venv`.

```bash
# 1. Install Ollama (https://ollama.com)
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull a model with tool calling support
ollama pull gemma4:e4b    # 9.6 GB download, runs on CPU
# or
ollama pull gemma4:26b    # 18 GB, needs GPU

# 3. Run Cortex
git clone https://github.com/build-on-ai/cortex.git
cd cortex
./run.sh agent            # Interactive CLI
./run.sh web              # Web UI at http://localhost:8080
./run.sh worker           # Autonomous task worker
```

`run.sh` auto-creates a Python venv and installs pinned dependencies
from `requirements.txt` on first run.

## Connecting to Consciousness Server

Cortex talks to [consciousness-server](https://github.com/build-on-ai/consciousness-server) (CS) for memory, briefings, multi-agent task queues, and chat between agents. Connecting is **optional** — Cortex works standalone — but it unlocks the multi-agent features.

**Easiest path (CS on the same machine):**

Clone both repositories next to each other, then prepare CS before starting
either process. The CS checkout owns its ports and the signing keys.

```bash
git clone --recurse-submodules https://github.com/build-on-ai/consciousness-server.git
git clone https://github.com/build-on-ai/cortex.git

cd consciousness-server
bin/sync-ports
bin/bootstrap-keys --client cortex-local
(cd key-server && npm install)
(cd deploy && docker compose up -d --build)

# Start Cortex with the identity minted above.
cd ../cortex
CS_HOME=../consciousness-server \
AGENT_NAME=cortex-local \
CS_SIGNING_KEY=../consciousness-server/deploy/keys/cortex-local \
./run.sh agent
```

`CS_HOME` points Cortex at CS's own port registry, so it follows whichever
port palette that deployment uses. When `CS_HOME` is unset, Cortex also looks
at `$CS_PORTS_FILE` and a CS checkout sitting next to this one.

No registry in reach means Cortex does not know where CS is — it says so at
startup instead of probing ports at random. Point it at the checkout, or name
the server directly:

```bash
CS_HOME=/path/to/consciousness-server ./run.sh agent   # read the registry
CS_URL=http://192.0.2.5:13032 AGENT_NAME=cortex-remote \
  CS_SIGNING_KEY=/path/to/cortex-remote ./run.sh agent
```

When `CS_URL` is set, `CS_SIGNING_KEY` is required. Its public half must be
registered in the CS key-server as `keys/agents/<AGENT_NAME>.pub`.

Disable discovery entirely with `CORTEX_AUTO_DISCOVER_CS=0`.

**Different host or port:**

```bash
CS_URL=http://192.0.2.5:13032 AGENT_NAME=cortex-laptop \
  CS_SIGNING_KEY=/path/to/cortex-laptop ./run.sh agent
```

`AGENT_NAME` is the identifier other agents see — give each Cortex instance a unique one if you run several.

**Multi-agent demo (3 Cortex instances coordinating via CS):**

Give each instance its own registered identity before starting it:

```bash
CS_HOME=/path/to/consciousness-server
CORTEX_HOME=/path/to/cortex
for name in worker-A worker-B operator; do
  "$CS_HOME/bin/bootstrap-keys" --client "$name"
done

tmux new-session -d -s cortex-demo
tmux send-keys -t cortex-demo \
  "CS_HOME=$CS_HOME AGENT_NAME=worker-A CS_SIGNING_KEY=$CS_HOME/deploy/keys/worker-A $CORTEX_HOME/run.sh worker" Enter
tmux split-window -t cortex-demo -h
tmux send-keys -t cortex-demo \
  "CS_HOME=$CS_HOME AGENT_NAME=worker-B CS_SIGNING_KEY=$CS_HOME/deploy/keys/worker-B $CORTEX_HOME/run.sh worker" Enter
tmux split-window -t cortex-demo -v
tmux send-keys -t cortex-demo \
  "CS_HOME=$CS_HOME AGENT_NAME=operator CS_SIGNING_KEY=$CS_HOME/deploy/keys/operator $CORTEX_HOME/run.sh agent" Enter
tmux attach -t cortex-demo
```

Workers register with CS, poll for tasks, execute, and report. The
operator (interactive CLI) drops tasks into the queue and watches
results land as CS notes.

The protocol Cortex relies on is the set of HTTP routes asserted by
[`tests/test_cs_contract.py`](tests/test_cs_contract.py) — agent
registration, heartbeat/status, briefing fetch, task create /
pending / get / status update, note create, and conversation
persistence. The nightly `cs-contract` CI job re-runs that test
against the published CS image so a route refactor on either side
gets caught immediately. For the longer-form CS-side narrative
(operator workflows, queueing semantics, leader-election notes),
see [`docs/MULTI-AGENT.md` in consciousness-server](https://github.com/build-on-ai/consciousness-server/blob/main/docs/MULTI-AGENT.md);
if that link drifts, the contract test in this repo remains the
source of truth for what Cortex actually calls.

## Modes

| Mode | Command | Description |
|------|---------|-------------|
| **CLI** | `./run.sh agent` | Interactive terminal chat with tool calling |
| **Web** | `./run.sh web` | Browser UI with streaming at `http://localhost:8080` |
| **Worker** | `./run.sh worker` | Polls task server, executes tasks, reports results |
| **One-shot** | `./run.sh worker --once` | Execute one pending task and exit |
| **Plugin** | `./run.sh agent --mode NAME` | Activate a plugin by name |

## Commands

| Command | Description |
|---------|-------------|
| `/model` | Show current model and list available |
| `/model <name>` | Switch to a different Ollama model |
| `/policy` | Show active policy rules |
| `/tokens` | Show estimated token count |
| `/think` | Toggle thinking mode |
| `/clear` | Clear conversation history |
| `/status` | Show agent status (model, CS, tools, plugins) |
| `/plugins` | List available plugins |
| `/rewind` | Rewind conversation |
| `/exit` | Save session and exit |

## Policy Engine

Cortex includes a rule-based policy engine that checks every tool call before execution:

- **DENY** (blocked silently): `rm -rf /`, `mkfs`, `dd`, fork bombs, `curl | bash`, `shutdown`
- **ASK** (requires user confirmation): `sudo`, `apt install`, `pip install`, `git push --force`, `kill`
- **ALLOW** (runs immediately): `ls`, `cat`, `grep`, `git status`, `ps`, `python3`

Custom rules layer on top of the defaults via a JSON file pointed at
by the `POLICY_FILE` env var (no auto-discovery — set the variable
explicitly):

```bash
POLICY_FILE=/path/to/my-policy.json ./run.sh agent
```

A worked example with the supported shape lives in
[`policy.example.json`](policy.example.json). The format is one
object per tool, each with `deny` / `ask` / `allow` lists of Python
regular expressions; DENY wins over ASK wins over ALLOW. Shared
keys (`_CREDENTIAL_DENY`, `_PERSISTENCE_DENY`, `_HISTORY_DENY`,
`_SYSTEM_DIRS_DENY`) re-expand across every tool that consumes
them, so an entry written once applies everywhere the default did.

## Security

Cortex is a **local, single-user AI agent**. It trusts the operator of the
machine, the local Ollama instance, and any plugin you load. Filesystem
and shell access are intentionally unsandboxed so the agent can do real
work on your behalf — think `bash`, not browser.

Before deploying outside a single-user workstation (shared host, exposed
network, untrusted plugins), read [SECURITY.md](SECURITY.md). It documents
the threat model, the design decisions that look like vulnerabilities but
aren't, and how to report real security issues.

### Security invariants (REQUIRED for commercial deployments)

The `security/` package and `tests/test_invariants.py` define mandatory
structural security invariants. They are enforced at CI time via an
AST walker plus a runtime sentinel check in `RecoveryEngine`.

For **commercial licensees** ([LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md)):

- Disabling the invariant tests or removing `security/*` helpers
  **voids the security guarantees** the threat model is written
  against.
- Supported deployments MUST run `python3 tests/test_invariants.py`
  as part of CI. A failing run is a release blocker.
- Relaxing an invariant or adding a new untrusted KIND requires an update to
  the invariant tests.

Escape-hatch exemptions carry `# invariant: allow-<rule> until=YYYY-MM-DD
because <reason>` comments and are auto-collected into
[UNSAFE.md](UNSAFE.md) so the whole exemption surface is visible at a
glance.

## Plugins

Cortex supports plugins that add custom tools and modes. Plugins are Python files placed in the `plugins/` directory.

### Creating a Plugin

Create a file in `plugins/` (e.g. `plugins/my_plugin.py`):

```python
PLUGIN_NAME = "my-plugin"
PLUGIN_DESCRIPTION = "What my plugin does"

PLUGIN_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "my_tool",
            "description": "Description of what my tool does",
            "parameters": {
                "type": "object",
                "properties": {
                    "input": {"type": "string", "description": "Input text"}
                },
                "required": ["input"]
            }
        }
    }
]


def execute_tool(name: str, args: dict) -> str:
    """Handle tool calls for this plugin."""
    if name == "my_tool":
        return f"Result: {args['input']}"
    return f"Unknown tool: {name}"


def build_prompt(briefing: str) -> str:
    """Optional: custom system prompt for this plugin mode."""
    return "You are Cortex with my-plugin capabilities..."


def on_activate(config: dict):
    """Optional: called when plugin mode starts."""
    print("My plugin activated!")


def on_deactivate():
    """Optional: called when plugin mode stops."""
    pass
```

### Using a Plugin

```bash
# Run Cortex with a plugin active
./run.sh agent --mode my-plugin

# List available plugins inside Cortex
/plugins
```

### Plugin API

Each plugin file can expose:

| Attribute | Required | Description |
|-----------|----------|-------------|
| `PLUGIN_NAME` | Yes | Unique plugin name |
| `PLUGIN_DESCRIPTION` | No | Short description |
| `PLUGIN_TOOLS` | Yes | List of tool definitions (Ollama format) |
| `execute_tool(name, args)` | Yes | Handle tool calls, return string result |
| `build_prompt(briefing)` | No | Custom system prompt for this mode |
| `on_activate(config)` | No | Initialization hook |
| `on_deactivate()` | No | Cleanup hook |

## Configuration

All settings via environment variables (see `.env.example`):

```bash
OLLAMA_URL=http://localhost:11434   # Ollama API endpoint
OLLAMA_MODEL=gemma4:e4b             # Default model
CS_URL=                             # Task server URL (optional)
CS_SIGNING_KEY=                     # OpenSSH ed25519 private key path — signs CS requests (required when CS_URL is set; public key must be registered on the key-server as keys/agents/<AGENT_NAME>.pub)
ANTHROPIC_API_KEY=                  # Fallback API key (optional; fallback also requires CORTEX_FALLBACK_ANTHROPIC=1)
WEB_PORT=8080                       # Web UI port
AGENT_NAME=cortex                   # Agent identifier
```

## Architecture

```
cortex/
  agent.py       — CLI agent, 10 tools, model switching, plugin loader
  web.py         — Web UI (FastAPI + WebSocket)
  worker.py      — Autonomous worker daemon
  policy.py      — Policy Engine (deny/ask/allow)
  compactor.py   — Context compression
  recovery.py    — Retry + fallback logic
  run.sh         — Launcher (auto venv, GPU detection)
  plugins/       — Plugin directory (optional)
```

## Models

Any Ollama model with tool calling support works. Tested:

Sizes are the download reported by the Ollama registry, so they match
what `ollama pull` actually fetches. First call after a pull also pays
a one-off model load (~10s on CPU for `gemma4:e4b`) before the answer
starts.

| Model | Size | Speed (CPU) | Speed (GPU) |
|-------|------|-------------|-------------|
| `gemma4:e4b` | 9.6 GB | ~16s | ~3s |
| `gemma4:26b` | 18 GB | slow | ~20s |
| `gemma4:31b` | 20 GB | very slow | ~25s |

## License

Cortex is **dual-licensed**:

- **[GNU Affero General Public License v3.0 (AGPLv3)](LICENSE)** — free for open source projects, personal use, and any deployment that complies with AGPLv3 terms (including making modifications and SaaS deployments source-available).

- **[Commercial License](LICENSE-COMMERCIAL.md)** — for organizations that need to use Cortex in proprietary products, closed-source SaaS, or where AGPLv3 is incompatible with their policies.

See [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) for when you need a commercial license and how to obtain one.

## Documentation

Full documentation set lives in [`docs/`](docs/):

- [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) — installation,
  running modes, environment variables, troubleshooting.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module layout,
  dependency graph, security invariants, runtime data flow, CS
  integration, v1.1/v1.2 roadmap.
- [`docs/PLUGIN_GUIDE.md`](docs/PLUGIN_GUIDE.md) — plugin
  authoring reference with worked examples.

Threat model: [`SECURITY.md`](SECURITY.md). Active invariant
exemptions: [`UNSAFE.md`](UNSAFE.md) (auto-generated).
