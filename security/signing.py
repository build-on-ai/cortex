"""ed25519 request signing for Consciousness Server requests.

The canonical message mirrors key-server's buildCanonicalMessage byte for byte:
five fields joined by a single LF, carried in X-Agent-Id, X-Timestamp, X-Nonce
and X-Signature. Protocol:
https://github.com/build-on-ai/consciousness-server/blob/main/docs/SIGNING-PROTOCOL.md

Off unless CS_SIGNING_KEY is configured; the cryptography import is lazy, so an
unconfigured Cortex never needs the package.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
from datetime import datetime, timezone

__all__ = [
    "SigningError",
    "EMPTY_BODY_SHA256",
    "canonical_message",
    "load_signing_key",
    "configure_signing",
    "signing_configured",
    "sign_headers",
]

# sha256 of zero bytes — the body hash for GET / bodyless requests.
EMPTY_BODY_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

# Verifier-side check (key-server looksIso8601) — kept here so tests
# can assert our timestamps would pass it.
ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


class SigningError(Exception):
    """CS request signing is misconfigured (bad key path / type /
    missing dependency). Raised at configure time — callers treat it
    as fatal rather than silently sending unsigned requests
    (fail-closed, not fail-open)."""


def load_signing_key(key_path: str):
    """Load an unencrypted OpenSSH ed25519 private key from *key_path*.

    Returns an ``Ed25519PrivateKey``. Raises :class:`SigningError`
    with an actionable message on every failure mode: missing
    ``cryptography`` package, unreadable file, wrong format,
    passphrase-protected key, or a non-ed25519 key type.
    """
    try:
        # Lazy import — only a signing-enabled Cortex needs cryptography.
        from cryptography.hazmat.primitives.serialization import (
            load_ssh_private_key,
        )
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as e:
        raise SigningError(
            "CS_SIGNING_KEY is set but the 'cryptography' package is not "
            "installed. Install dependencies (pip install -r "
            "requirements.txt) or unset CS_SIGNING_KEY."
        ) from e

    key_path = os.path.expanduser(key_path)
    try:
        with open(key_path, "rb") as f:
            key_bytes = f.read()
    except OSError as e:
        raise SigningError(
            f"CS_SIGNING_KEY: cannot read private key file {key_path!r}: {e}"
        ) from e

    try:
        key = load_ssh_private_key(key_bytes, password=None)
    except Exception as e:  # cryptography raises ValueError/TypeError/UnsupportedAlgorithm
        raise SigningError(
            f"CS_SIGNING_KEY: {key_path!r} is not an unencrypted OpenSSH "
            f"private key ({e}). Generate one with: "
            f"ssh-keygen -t ed25519 -N '' -f <path>"
        ) from e

    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError(
            f"CS_SIGNING_KEY: {key_path!r} is a "
            f"{type(key).__name__.replace('PrivateKey', '').lower() or 'non-ed25519'} "
            f"key; the CS signing protocol accepts ed25519 only. "
            f"Generate one with: ssh-keygen -t ed25519 -N '' -f <path>"
        )
    return key


def canonical_message(method: str, path: str, timestamp: str,
                      nonce: str, body_sha256: str) -> bytes:
    """The exact bytes that get signed / verified.

    Mirrors key-server ``buildCanonicalMessage()``: five fields joined
    by a single LF. The query string is stripped from *path* the same
    way the reference signer does (``path.split('?')[0]``) — the query
    is not part of the signature in this protocol version.
    """
    clean_path = path.split("?")[0]
    return "\n".join([
        str(method).upper(),
        clean_path,
        str(timestamp),
        str(nonce),
        str(body_sha256),
    ]).encode("utf-8")



_PRIVATE_KEY = None
_KEY_PATH = ""


def configure_signing(key_path: str) -> None:
    """Load and pin the signing key. Raises SigningError on any
    problem — the caller (agent.py startup) turns that into a hard
    exit instead of falling back to unsigned requests."""
    global _PRIVATE_KEY, _KEY_PATH
    _PRIVATE_KEY = load_signing_key(key_path)
    _KEY_PATH = key_path


def signing_configured() -> bool:
    return _PRIVATE_KEY is not None


def sign_headers(agent_id: str, method: str, path: str,
                 body: bytes = b"") -> dict:
    """Build the four signed headers for one CS request.

    ``body`` must be the exact raw bytes that will go on the wire
    (empty for bodyless requests). Requires ``configure_signing()``
    to have been called first.
    """
    if _PRIVATE_KEY is None:
        raise SigningError(
            "sign_headers() called but no signing key is configured — "
            "call configure_signing(key_path) first."
        )
    if not isinstance(body, bytes):
        raise SigningError(
            f"sign_headers() body must be bytes (the exact wire bytes), "
            f"got {type(body).__name__}"
        )
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = secrets.token_hex(16)
    body_sha256 = hashlib.sha256(body).hexdigest()
    message = canonical_message(method, path, timestamp, nonce, body_sha256)
    signature = base64.b64encode(_PRIVATE_KEY.sign(message)).decode("ascii")
    return {
        "X-Agent-Id": agent_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }
