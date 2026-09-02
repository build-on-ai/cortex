"""Cortex security helpers: the single source of truth for the invariants.

Every import of a security primitive comes from this package, and
tests/test_invariants.py fails CI when one is bypassed. Nothing here may
import from the application modules, and helpers take their dependencies
as explicit arguments.
"""

from security.messages import (
    wrap_untrusted,
    wrap_tool_output,
    make_message,
    make_tool_result,
    make_system_note,
    make_user_note,
    UNTRUSTED_KINDS,
    Role,
    Message,
    ToolMessage,
)
from security.auth import (
    ClientIdentity,
    require_auth,
    build_require_auth,
    public_endpoint,
    SessionManager,
    get_session_manager,
    rate_limit_key,
    note_auth_fail,
    AuthError,
)
from security.paths import normalize_path, path_under
# _FallbackSentinel is deliberately not re-exported: an importable sentinel
# makes forging one a one-liner. RecoveryEngine uses the private predicate in
# security.fallback instead.
from security.fallback import FallbackPolicy
# `cryptography` is imported lazily inside load_signing_key, so this package
# stays dependency-free when signing is off.
from security.signing import (
    SigningError,
    canonical_message,
    configure_signing,
    signing_configured,
    sign_headers,
)

__all__ = [
    # messages
    "wrap_untrusted", "wrap_tool_output",
    "make_message", "make_tool_result", "make_system_note", "make_user_note",
    "UNTRUSTED_KINDS", "Role", "Message", "ToolMessage",
    # auth
    "ClientIdentity", "require_auth", "build_require_auth", "public_endpoint",
    "SessionManager", "get_session_manager", "rate_limit_key", "note_auth_fail", "AuthError",
    # paths
    "normalize_path", "path_under",
    # fallback — _FallbackSentinel deliberately NOT exported
    "FallbackPolicy",
    # signing (CS request signing)
    "SigningError", "canonical_message", "configure_signing",
    "signing_configured", "sign_headers",
]
