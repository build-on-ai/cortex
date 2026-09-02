# Cortex — Documentation Index

| File | Audience |
|:--|:--|
| [USER_GUIDE.md](USER_GUIDE.md) | Operators running Cortex. Installation, modes, env vars, troubleshooting. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Developers / auditors. Module layout, dependency graph, invariants, runtime flow, CS integration, v1.1 roadmap. |
| [PLUGIN_GUIDE.md](PLUGIN_GUIDE.md) | Plugin authors. Required symbols, optional hooks, what's automatic, worked examples. |

Threat model, design decisions and known limitations live in
[`../SECURITY.md`](../SECURITY.md). Active invariant exemptions are
auto-tracked in [`../UNSAFE.md`](../UNSAFE.md).

## Fast answers

- **"How do I run it?"** → `USER_GUIDE.md` → "Running modes".
- **"Can a plugin break security?"** → `ARCHITECTURE.md` →
  "Security invariants" + `PLUGIN_GUIDE.md` → "What you should
  think about".
- **"Is CS talk encrypted?"** → Short answer: no, plaintext HTTP;
  wrap in VPN if crossing networks. Native TLS lands in v1.1.
- **"Does the worker broadcast / open WebSocket?"** → No, it's
  HTTP polling. `ARCHITECTURE.md` → "Worker: polling, not WS /
  broadcast".
- **"Can CS be the hub for multi-agent infrastructure?"** → Yes
  today with caveats (plaintext HTTP, no per-caller auth on CS
  side in v1.0); better in v1.1.
