"""Anthropic fallback policy.

Uploading conversation history when Ollama is unreachable is not the default:
it needs an explicit opt-in, logs every upload with its size, and can strip
untrusted containers before the upload leaves the host.
"""
from __future__ import annotations

import logging as _logging
import os as _os
import re as _re
from typing import Callable

_log = _logging.getLogger("security.fallback")

# Matches the containers wrap_untrusted emits, so redaction keeps file contents
# and tool output on the host.
_UNTRUSTED_TAG_RE = _re.compile(
    r"<(tool_output|compacted_history|external_briefing|worker_task|plugin_guidance|recovery_note)_[A-Za-z0-9_-]+"
    r"[^>]*>.*?</\1_[A-Za-z0-9_-]+>",
    _re.DOTALL,
)


import weakref as _weakref


# Fallback callables are capabilities, not type checks. The witness and
# registry are closure cells, so only this module can issue a valid token.

def _make_sentinel_machinery():
    """Build the sentinel class, its witness token, and its registry
    inside a closure. Returns the class + an identity predicate.

    The witness and the registry are closure cells — no module-level
    name, no ``sys.modules`` attribute, no ``from … import`` path
    reaches them. The only way to satisfy the predicate is to obtain
    an instance produced by the single registering call site.
    """
    witness = object()
    registry: "_weakref.WeakSet[object]" = _weakref.WeakSet()

    class _FallbackSentinel:
        """Capability token proving a callable came from as_recovery_callable().

        Not constructible from outside: the witness its __init__ needs lives in a
        closure. Membership is checked by identity, so subclasses and copies are refused.
        """

        __slots__ = ("_fn", "__weakref__")

        def __init_subclass__(cls, **kwargs):
            raise TypeError(
                "_FallbackSentinel is sealed; only FallbackPolicy may produce it"
            )

        def __init__(self, fn, _witness=None):
            if _witness is not witness:
                raise TypeError(
                    "_FallbackSentinel is not publicly constructible; "
                    "go through FallbackPolicy.from_env(...).as_recovery_callable()"
                )
            object.__setattr__(self, "_fn", fn)
            registry.add(self)

        def __setattr__(self, name, value):
            raise AttributeError(
                f"_FallbackSentinel is immutable; cannot set {name!r}"
            )

        def __call__(self, messages, *args, **kwargs):
            if self not in registry:
                raise RuntimeError("_FallbackSentinel tampered — refusing to call")
            return self._fn(messages, *args, **kwargs)

        # The witness lives in a closure, and the module-private _make is the only
        # construction entry point.
        @classmethod
        def _make(cls, fn):
            return cls(fn, _witness=witness)

    def _is_registered(obj):
        return obj in registry

    return _FallbackSentinel, _is_registered


_FallbackSentinel, _is_registered_sentinel = _make_sentinel_machinery()
# `_WITNESS` and `_REGISTRY` must not exist at module level.


class FallbackPolicy:
    """Policy decision object for whether an Anthropic upload should
    happen and how it should be shaped.

    Instantiate once at startup (``FallbackPolicy.from_env()``), pass
    to ``RecoveryEngine`` and any other consumer. All the decisions
    sit on the instance so nothing is re-checked inline.
    """

    def __init__(self, *, enabled: bool, redact_tool_outputs: bool,
                 call_fn: Callable | None):
        self.enabled = enabled
        self.redact_tool_outputs = redact_tool_outputs
        self._call_fn = call_fn

    @classmethod
    def from_env(cls, *, anthropic_key: str, call_fn: Callable | None) -> "FallbackPolicy":
        """Wire the policy from environment variables.

        Rules:
          * no key → disabled, no matter what.
          * key + CORTEX_FALLBACK_ANTHROPIC=1 → enabled.
          * anything else → disabled, even with key.
        """
        if not anthropic_key or not call_fn:
            return cls(enabled=False, redact_tool_outputs=False, call_fn=None)
        enabled = _os.getenv("CORTEX_FALLBACK_ANTHROPIC") == "1"
        redact = _os.getenv("CORTEX_FALLBACK_REDACT_TOOL_OUTPUTS") == "1"
        return cls(enabled=enabled, redact_tool_outputs=redact, call_fn=call_fn)

    def as_recovery_callable(self) -> _FallbackSentinel | None:
        """The sentinel-wrapped callable for RecoveryEngine, or None when fallback is off.

        Only a return value from this method survives RecoveryEngine's check, so no
        call-site construction can synthesise one without going through the policy.
        """
        if not self.enabled:
            return None
        call_fn = self._call_fn
        redact = self.redact_tool_outputs

        def _logged_fallback(messages: list, *a, **kw):
            payload = messages
            if redact:
                payload = [
                    {**m, "content": _UNTRUSTED_TAG_RE.sub(
                        "[REDACTED untrusted container]",
                        m.get("content", "") or "",
                    )}
                    for m in messages
                ]
            total_chars = sum(len(m.get("content", "") or "") for m in payload)
            _log.warning(
                "fallback: uploading %d messages / %d chars to api.anthropic.com "
                "(CORTEX_FALLBACK_ANTHROPIC=1; redact=%s)",
                len(payload), total_chars, "on" if redact else "off",
            )
            return call_fn(payload, *a, **kw)

        # The witness lives in a closure and only _make supplies it, so there is no
        # module-level constant to import.
        return _FallbackSentinel._make(_logged_fallback)
