"""Message constructors: every message in the conversation history goes through
one of these, so untrusted data always gets a nonce-tagged container.

Bare dict literals are banned outside this module by tests/test_invariants.py.
To construct one by hand, mark the line with
`# invariant: allow-raw-message because <reason>`.
"""
from __future__ import annotations

import html as _html
import secrets as _secrets
from typing import Any, Literal, TypedDict

# Typed message shapes let static checking catch invalid message values.
Role = Literal["system", "user", "assistant", "tool"]


class Message(TypedDict, total=False):
    role: Role
    content: str


class ToolMessage(TypedDict):
    role: Literal["tool"]
    content: str
    name: str

# A tag with one of these prefixes is data, whatever its nonce, role or nesting.
# Rule #13 in the system prompt lists the same set and must stay in sync.
UNTRUSTED_KINDS = (
    "tool_output",
    "compacted_history",
    "external_briefing",
    "worker_task",
    "plugin_guidance",
    "recovery_note",
)


def wrap_untrusted(kind: str, content: Any, **attrs: Any) -> str:
    """Wraps content in an untrusted container tagged with a fresh per-call nonce.

    The payload cannot predict the nonce, so it can neither forge a matching
    closer nor override the untrusted attribute. The nonce is regenerated if the
    payload already contains it.
    """
    if kind not in UNTRUSTED_KINDS:
        # Not an error, but a soft signal — new KINDs must be added
        # to UNTRUSTED_KINDS so rule #13 can enumerate them.
        raise ValueError(
            f"wrap_untrusted: kind={kind!r} not in UNTRUSTED_KINDS. "
            f"Add it to security/messages.py and to rule #13 first."
        )
    if not isinstance(content, str):
        content = str(content)
    for _ in range(8):
        nonce = _secrets.token_urlsafe(6)  # ~48 bits
        tag = f"{kind}_{nonce}"
        if f"<{tag}" not in content and f"</{tag}>" not in content:
            break
    safe = content.replace(f"</{tag}>", f"<_/{tag}>")
    attr_s = ""
    for k, v in attrs.items():
        attr_s += f' {k}="{_html.escape(str(v), quote=True)}"'
    return f'<{tag} untrusted="true"{attr_s}>\n{safe}\n</{tag}>'


# Bound as default args, so replacing the module attribute does not reach helpers
# already defined. Guards against a careless plugin, not a hostile one.

def wrap_tool_output(name: str, result: str,
                     _wrap=wrap_untrusted) -> str:
    """Tool-output ingress — thin alias so existing imports keep
    working. Prefer ``make_tool_result`` for new code."""
    return _wrap("tool_output", result, tool=name)


def make_message(role: str, content: str, *,
                 authoritative: bool = False,
                 source: str | None = None,
                 _wrap=wrap_untrusted,
                 **attrs: Any) -> dict:
    """Canonical conversation-message constructor.

    `authoritative` is a required keyword: content is emitted verbatim only when
    the caller states it came from the operator or the model directly. Otherwise
    it is wrapped in an untrusted container keyed by `source`.
    """
    if role not in ("system", "user", "assistant", "tool"):
        raise ValueError(f"make_message: unknown role {role!r}")
    if authoritative:
        return {"role": role, "content": content}
    if not source:
        raise ValueError(
            "make_message: source='<kind>' is required when "
            "authoritative=False — pick one of UNTRUSTED_KINDS or add a "
            "new KIND to security/messages.py + rule #13 first."
        )
    return {"role": role, "content": _wrap(source, content, **attrs)}


def make_tool_result(name: str, content: str, *,
                     source: str = "tool_output",
                     _wrap=wrap_untrusted) -> dict:
    """Canonical ``role="tool"`` message. See .

    ``source`` kept for back-compat with worker.py / web.py call sites
    that distinguish real tool output from policy DENY / ASK /
    invalid-name responses. The wire format is identical — a
    ``<tool_output_<nonce> untrusted="true">`` container — so the
    model applies rule #13 the same way regardless of ``source``.
    """
    return {
        "role": "tool",
        "content": _wrap("tool_output", content, tool=name, source=source),
        "name": name,
    }


def make_system_note(content: str, *, source: str = "recovery_note") -> dict:
    """Mechanically-injected system-role note (e.g. recovery hint).

    Wrapped, not authoritative — agent rule #13 extended to cover
    ``recovery_note_<nonce>``. Prevents class where a future
    interpolated exception message turned into a system-role prompt
    injection.
    """
    return make_message("system", content, source=source)


def make_user_note(content: str, *, source: str = "compacted_history") -> dict:
    """Mechanically-injected user-role note (compacted history,
    context-overflow placeholder). Always wrapped — authoritative
    user turns come directly from the human, not from this helper."""
    return make_message("user", content, source=source)
