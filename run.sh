#!/bin/bash
# Cortex — launcher
# Usage:
#   ./run.sh agent    — interactive CLI
#   ./run.sh web      — Web UI (http://localhost:8080)
#   ./run.sh worker   — daemon (poll CS → execute → report)
#   ./run.sh worker --once  — one task and exit

set -euo pipefail

# Portable script path resolution (readlink -f isn't available on macOS by default).
_resolve_path() {
    local src="$1"
    while [ -L "$src" ]; do
        local dir
        dir="$(cd -P "$(dirname "$src")" >/dev/null 2>&1 && pwd)"
        src="$(readlink "$src")"
        [[ "$src" != /* ]] && src="$dir/$src"
    done
    echo "$(cd -P "$(dirname "$src")" >/dev/null 2>&1 && pwd)"
}
DIR="$(_resolve_path "${BASH_SOURCE[0]}")"
cd "$DIR"

# Load .env if present. Pattern is the same as docker-compose: KEY=VALUE per
# line, comments with '#', no shell expansion of unquoted strings. set -a /
# set +a means every variable defined in .env becomes exported without
# spelling 'export' on each line. .env is gitignored and holds
# deployment-specific settings.
if [ -f "$DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$DIR/.env"
    set +a
fi

# Venv — install from requirements.txt (pinned versions, hash-friendly)
# Test the activate script, not the directory: a venv that failed to build
# leaves the directory behind, and every later run then sources a file that
# does not exist.
if [ ! -f "$DIR/venv/bin/activate" ]; then
    echo "Creating venv..."
    if ! python3 -m venv "$DIR/venv"; then
        echo "python3 -m venv failed. On Debian/Ubuntu install the venv module:" >&2
        echo "  sudo apt install python3-venv" >&2
        exit 1
    fi
    # shellcheck disable=SC1091
    source "$DIR/venv/bin/activate"
    pip install -q --upgrade pip
    pip install -q -r "$DIR/requirements.txt"
else
    # shellcheck disable=SC1091
    source "$DIR/venv/bin/activate"
fi

# Auto-detect GPU. Only set OLLAMA_MODEL if the user hasn't set one —
# respect env and never overwrite an explicit choice.
if [ -z "${OLLAMA_MODEL:-}" ]; then
    if nvidia-smi &>/dev/null; then
        export OLLAMA_MODEL="gemma4:26b"
        echo "[GPU] Model: $OLLAMA_MODEL (auto)"
    else
        export OLLAMA_MODEL="gemma4:e4b"
        echo "[CPU] Model: $OLLAMA_MODEL (auto)"
    fi
else
    echo "[env] Model: $OLLAMA_MODEL"
fi

# CS URL — Consciousness Server (optional)
export CS_URL="${CS_URL:-}"

export AGENT_NAME="${AGENT_NAME:-cortex}"

# Check Ollama
if ! curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "Ollama not running — start it: systemctl start ollama"
    exit 1
fi

MODE="${1:-agent}"
shift 2>/dev/null || true

case "$MODE" in
    agent|cli|chat)
        python3 "$DIR/agent.py" "$@"
        ;;
    web|ui)
        echo "Web UI: http://localhost:${WEB_PORT:-8080}"
        python3 "$DIR/web.py" "$@"
        ;;
    worker|daemon)
        python3 "$DIR/worker.py" "$@"
        ;;
    *)
        echo "Usage: $0 {agent|web|worker} [options]"
        echo ""
        echo "  agent         Interactive CLI (like Claude Code)"
        echo "  web           Web UI in browser"
        echo "  worker        Daemon — polls CS for tasks automatically"
        echo "  worker --once One task and exit"
        echo ""
        echo "Plugins:"
        echo "  agent --mode NAME   Activate a plugin (e.g. --mode sec)"
        echo "  Plugins are loaded from ./plugins/ directory"
        ;;
esac
