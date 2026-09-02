# Cortex — Plugin Guide

A Cortex plugin is one Python file in `plugins/`. Cortex discovers
and loads it at startup; wiring is automatic.

## Minimal plugin

```python
# plugins/echo.py

PLUGIN_NAME = "echo"

PLUGIN_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "shout",
            "description": "Return the input in upper case.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                },
                "required": ["text"],
            },
        },
    },
]

def execute_tool(name: str, args: dict) -> str:
    if name == "shout":
        return str(args.get("text", "")).upper()
    return f"Unknown tool: {name}"
```

That's a working plugin. Drop it into `plugins/`, restart Cortex,
and the model can now call `shout`.

## Required symbols

| Symbol | Type | Purpose |
|:--|:--|:--|
| `PLUGIN_NAME` | `str` | Human-readable name, shown in logs / UI. Must match `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`, no `..`. If malformed, Cortex falls back to the filename stem and warns. |
| `PLUGIN_TOOLS` | `list[dict]` | Ollama tool schemas. Same shape as the built-in `TOOLS` list in `agent.py`. |
| `execute_tool(name, args) -> str` | callable | Dispatched on tool invocation. Return value is ingested by Cortex and wrapped into `<tool_output_<nonce> untrusted="true">` automatically — you return raw text. |

## Optional hooks

| Hook | When called | Notes |
|:--|:--|:--|
| `build_prompt(briefing: str) -> str` | Plugin mode activation (`--mode <name>`) | Wrapped automatically in `<plugin_guidance_<nonce> untrusted="true">`. Rule #13 tells the model to treat its contents as data, not as overrides of the base system prompt. |
| `on_activate(config: dict)` | Plugin mode activation | `config` keys: `ollama_url`, `ollama_model`, `cs_url`, `agent_name`. |
| `on_deactivate()` | Normal exit / SIGINT / SIGTERM | Registered via `atexit` + signal handler. SIGKILL and OOM-kill do not fire it. |

## Using the plugin

### Plain mode

Plugin tools are available in the default agent loop:

```bash
./run.sh agent
# Chat with the model; tool calls route to echo.shout transparently.
```

The built-in tools (`bash`, `read_file`, etc.) are still active; the
plugin's tools are added on top.

### Plugin mode

```bash
./run.sh agent --mode echo
```

Cortex now runs with the plugin's `build_prompt` output appended
to the system prompt, and the banner shows `Plugin: echo`. You can
drop the built-in tools from the prompt by having `build_prompt`
say so — the model still sees them, but the narrative is plugin-
specific.

## What you get for free

You don't have to write any of this — Cortex does it for you:

- **Path confinement.** `plugin_dir.resolve()` must land under
  `PROJECT_ROOT`, and each plugin file's resolved path must stay
  inside `plugin_dir`. Symlink escapes refused at load.
- **Namespace isolation.** Loaded under `cortex_plugins.<stem>`;
  you can't accidentally shadow `os` by naming your file `os.py`.
- **Rollback.** If your top-level code raises, every entry in
  `sys.modules` registered since load start (including submodules
  your code imported) is popped. The import failure is logged and
  the rest of the agent starts normally.
- **Policy gating.** Your `execute_tool` gets called only after
  the Policy Engine clears the call. Write your logic assuming
  args are policy-vetted; you don't need to re-check paths for
  `../../etc/shadow`.
- **Untrusted wrapping.** `execute_tool`'s return value is fenced
  in a nonce-tagged untrusted container before the model sees it.
  You don't call `wrap_untrusted` yourself.
- **Plugin prompt untrusted wrap.** If you write a `build_prompt`,
  its output is wrapped the same way — a user who installs a
  plugin that turns out to have a prompt-injection payload in its
  guidance text still can't override rule #13.

## What you should think about

- **Your code runs with the agent's privileges.** If you open a
  socket, spawn a subprocess, or write to disk in `execute_tool`,
  that happens as whatever user Cortex runs as. The Policy Engine
  gates *agent-initiated* tool calls; your plugin's own side
  effects are not policy-checked.
- **Return strings, not structured data.** `execute_tool` must
  return `str`. Serialise JSON yourself if you want structured
  output.
- **Long-running work.** A single `execute_tool` call blocks the
  agent loop. For anything over a few seconds, either (a) return
  quickly with a task id and have a separate tool poll it, or
  (b) spawn a thread in `on_activate` and have `execute_tool`
  read from a queue.
- **State lives across calls.** Module-level globals in your
  plugin persist between `execute_tool` calls within one session.
  Use `on_activate` for one-time setup, `on_deactivate` for
  cleanup.
- **Plugins are trusted code.** A plugin can read files, open
  network sockets, import `ctypes`, do whatever Python allows.
  Cortex does NOT sandbox plugins today (see SECURITY.md →
  "What the security invariants DO and DO NOT protect against").
  If you distribute plugins to third parties, tell them to read
  the Python before enabling them.

## Worked example: weather lookup

```python
# plugins/weather.py
import requests

PLUGIN_NAME = "weather"

PLUGIN_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Fetch current weather for a city (wttr.in).",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {
                        "type": "string",
                        "description": "City name, e.g. 'Kraków'",
                    },
                },
                "required": ["city"],
            },
        },
    },
]

def execute_tool(name: str, args: dict) -> str:
    if name != "get_weather":
        return f"Unknown tool: {name}"
    city = str(args.get("city", "")).strip()
    if not city:
        return "Error: city is required"
    try:
        r = requests.get(
            f"https://wttr.in/{city}?format=3",
            timeout=5,
        )
        r.raise_for_status()
        return r.text.strip()
    except requests.RequestException as e:
        return f"Weather fetch failed: {e}"
```

The model can now ask for the weather. When you type "what's the
weather in Kraków?", the model emits a `get_weather` tool call,
your plugin runs, and the return value lands in the conversation
as `<tool_output_<nonce> untrusted="true" tool="get_weather">Kraków:
⛅ +12°C</tool_output_<nonce>>`.

## Worked example: CS task dispatcher

```python
# plugins/dispatcher.py
import os
import requests

PLUGIN_NAME = "dispatcher"

PLUGIN_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "enqueue_task",
            "description": "Queue a task in CS for another agent.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_agent": {"type": "string"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                },
                "required": ["target_agent", "title", "description"],
            },
        },
    },
]

_CS_URL = None
_AGENT_NAME = None

def on_activate(config: dict) -> None:
    global _CS_URL, _AGENT_NAME
    _CS_URL = config.get("cs_url")
    _AGENT_NAME = config.get("agent_name")

def execute_tool(name: str, args: dict) -> str:
    if name != "enqueue_task":
        return f"Unknown tool: {name}"
    if not _CS_URL:
        return "CS not configured (set CS_URL)."
    try:
        r = requests.post(
            f"{_CS_URL}/api/tasks",
            json={
                "target": args["target_agent"],
                "title": args["title"],
                "description": args["description"],
                "source": _AGENT_NAME,
            },
            timeout=5,
        )
        r.raise_for_status()
        return f"Queued: task {r.json().get('id')}"
    except Exception as e:
        return f"Queue failed: {e}"
```

Use: `./run.sh agent --mode dispatcher`, then ask the model to
queue work for another agent. The CS polls it; the other agent
picks it up in its next loop.

## Troubleshooting

**Plugin doesn't appear at startup.**
Filename must match `^[A-Za-z][A-Za-z0-9_]*\.py$`. Starting with
underscore (`_private.py`) is intentionally skipped.

**`Plugin 'X' failed to load: ModuleNotFoundError: No module named 'requests'`.**
Your plugin uses a dependency not in `requirements.txt`. Install
it in the Cortex venv: `./run.sh` has created it under
`./venv/`; use `./venv/bin/pip install <pkg>`.

**Tool call returns "Unknown tool" even though my tool exists.**
Check `PLUGIN_TOOLS` schema — the tool name in
`function.name` must match the string you compare against in
`execute_tool`.

**Plugin imports fine but tool calls hang.**
A tool call blocks until `execute_tool` returns. If your
implementation does network I/O without a timeout, the whole
agent hangs. Always pass `timeout=` to `requests`, `urllib`,
subprocess, etc.

**Want to share state between plugins.**
Keep it in your plugin's module globals and expose an API via
`execute_tool` that queries it. Don't reach into Cortex's
internals — the import graph is one-way from `security/`
outward.
