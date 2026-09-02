"""Tests for security/signing.py and cs_client.py — ed25519 CS request signing.

Covers the known-answer roundtrip, the canonical-message rules, a
cross-implementation check against Node's crypto.verify, fail-closed
configuration, and that the bytes signed are the bytes sent.

Run: python3 -m pytest tests/test_signing.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

_REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from security import signing  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization  # noqa: E402

ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def _write_openssh_key(tmp_path: pathlib.Path, name: str = "test_ed25519"):
    """Generate an ed25519 keypair, write the private half in OpenSSH
    format (what ssh-keygen -t ed25519 produces). Returns (path, key)."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / name
    key_path.write_bytes(pem)
    key_path.chmod(0o600)
    return key_path, key


@pytest.fixture()
def configured_key(tmp_path):
    """Configure module signing with a throwaway key; reset after."""
    key_path, key = _write_openssh_key(tmp_path)
    signing.configure_signing(str(key_path))
    yield key
    signing._PRIVATE_KEY = None
    signing._KEY_PATH = ""


def _verify(pub, headers: dict, method: str, path: str, body: bytes) -> None:
    """Rebuild the canonical message the way key-server does and verify
    the signature — raises InvalidSignature on mismatch."""
    msg = signing.canonical_message(
        method, path, headers["X-Timestamp"], headers["X-Nonce"],
        hashlib.sha256(body).hexdigest(),
    )
    pub.verify(base64.b64decode(headers["X-Signature"]), msg)


# known-answer / roundtrip

def test_sign_headers_roundtrip(configured_key):
    body = b'{"title":"hello"}'
    headers = signing.sign_headers("agent1", "post", "/api/notes", body)

    assert set(headers) == {"X-Agent-Id", "X-Timestamp",
                            "X-Nonce", "X-Signature"}
    assert headers["X-Agent-Id"] == "agent1"
    # key-server's looksIso8601 must accept the timestamp
    assert ISO_RE.match(headers["X-Timestamp"])
    # 16 random bytes as 32 hex chars
    assert re.fullmatch(r"[0-9a-f]{32}", headers["X-Nonce"])
    # 64-byte ed25519 signature on the wire as base64
    assert len(base64.b64decode(headers["X-Signature"])) == 64

    # Inverse operation: verify with the public key. Method was passed
    # lowercase — canonical message must carry it uppercased.
    _verify(configured_key.public_key(), headers, "POST", "/api/notes", body)


def test_canonical_message_known_answer():
    msg = signing.canonical_message(
        "post", "/api/notes", "2026-04-19T22:00:00Z", "abc123",
        signing.EMPTY_BODY_SHA256)
    assert msg == (
        b"POST\n/api/notes\n2026-04-19T22:00:00Z\nabc123\n"
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_query_string_stripped(configured_key):
    """Protocol: the query string is not signed. Signing a path WITH a
    query must produce a signature over the path WITHOUT it — exactly
    what the verifier reconstructs."""
    headers = signing.sign_headers("agent1", "GET",
                                   "/api/tasks/pending/x?limit=5&x=1", b"")
    pub = configured_key.public_key()
    # verifies against the stripped path...
    _verify(pub, headers, "GET", "/api/tasks/pending/x", b"")
    # ...and canonical_message strips it identically on the verify side
    # (split('?')[0] mirror), so the full-path form verifies too:
    _verify(pub, headers, "GET", "/api/tasks/pending/x?limit=5&x=1", b"")
    # but a message built over the unstripped path bytes must fail
    from cryptography.exceptions import InvalidSignature
    raw = b"GET\n/api/tasks/pending/x?limit=5&x=1\n" + \
        headers["X-Timestamp"].encode() + b"\n" + \
        headers["X-Nonce"].encode() + b"\n" + \
        signing.EMPTY_BODY_SHA256.encode()
    with pytest.raises(InvalidSignature):
        pub.verify(base64.b64decode(headers["X-Signature"]), raw)


def test_empty_body_hash(configured_key):
    """Empty body is signed over sha256 of zero bytes (protocol
    constant), same as the Node reference signer with no body arg."""
    assert hashlib.sha256(b"").hexdigest() == signing.EMPTY_BODY_SHA256
    headers = signing.sign_headers("agent1", "GET", "/health", b"")
    _verify(configured_key.public_key(), headers, "GET", "/health", b"")


def test_tampered_body_fails_verification(configured_key):
    from cryptography.exceptions import InvalidSignature
    body = b'{"status":"DONE"}'
    headers = signing.sign_headers("agent1", "PATCH", "/api/tasks/1/status",
                                   body)
    with pytest.raises(InvalidSignature):
        _verify(configured_key.public_key(), headers, "PATCH",
                "/api/tasks/1/status", b'{"status":"dONE"}')


# cross-implementation: verify a Python signature in Node

# Inputs go through env vars, not argv — a PEM's leading dash would be
# parsed as a node CLI option.
_NODE_VERIFY_JS = r"""
const crypto = require('crypto');
const ok = crypto.verify(
  null,
  Buffer.from(process.env.CANONICAL_B64, 'base64'),
  crypto.createPublicKey(process.env.PUB_PEM),
  Buffer.from(process.env.SIG_B64, 'base64')
);
process.stdout.write(ok ? 'valid' : 'INVALID');
"""


def _node_verify(pub_pem: str, canonical: bytes, sig_b64: str):
    import os as _os
    env = dict(_os.environ,
               PUB_PEM=pub_pem,
               CANONICAL_B64=base64.b64encode(canonical).decode(),
               SIG_B64=sig_b64)
    return subprocess.run(["node", "-e", _NODE_VERIFY_JS], env=env,
                          capture_output=True, text=True, timeout=30)


@pytest.mark.skipif(shutil.which("node") is None,
                    reason="node not installed — cross-impl check skipped")
def test_cross_implementation_node_verifies_python_signature(configured_key):
    """key-server verifies with Node's crypto.verify. Sign here, verify
    there — byte-level agreement on the canonical message included
    (Node rebuilds nothing: it gets the same canonical bytes the
    verifier would reconstruct per SIGNING-PROTOCOL rules)."""
    body = b'{"agent":"cortex","content":"cross-impl"}'
    headers = signing.sign_headers("cortex", "POST", "/api/notes?q=1", body)

    # Reconstruct canonical message the verifier way: uppercased method,
    # path without query, sha256(body) hex.
    canonical = "\n".join([
        "POST", "/api/notes", headers["X-Timestamp"], headers["X-Nonce"],
        hashlib.sha256(body).hexdigest(),
    ]).encode()

    pub_pem = configured_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    out = _node_verify(pub_pem, canonical, headers["X-Signature"])
    assert out.returncode == 0, out.stderr
    assert out.stdout == "valid", (
        f"Node crypto.verify rejected a Python signature: {out.stdout!r} "
        f"{out.stderr!r}")

    # Negative control: flip one body byte → different hash → invalid.
    bad_canonical = "\n".join([
        "POST", "/api/notes", headers["X-Timestamp"], headers["X-Nonce"],
        hashlib.sha256(body[:-1] + b"X").hexdigest(),
    ]).encode()
    out2 = _node_verify(pub_pem, bad_canonical, headers["X-Signature"])
    assert out2.stdout == "INVALID"


# fail-closed configuration

def test_missing_key_file_raises(tmp_path):
    with pytest.raises(signing.SigningError, match="cannot read"):
        signing.load_signing_key(str(tmp_path / "nope"))


def test_garbage_key_raises(tmp_path):
    p = tmp_path / "garbage"
    p.write_text("not a key at all\n")
    with pytest.raises(signing.SigningError, match="OpenSSH"):
        signing.load_signing_key(str(p))


def test_non_ed25519_key_rejected(tmp_path):
    """ECDSA in valid OpenSSH format must be rejected with a clear
    message — protocol is ed25519-only."""
    from cryptography.hazmat.primitives.asymmetric import ec
    ec_key = ec.generate_private_key(ec.SECP256R1())
    p = tmp_path / "ecdsa_key"
    p.write_bytes(ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    with pytest.raises(signing.SigningError, match="ed25519"):
        signing.load_signing_key(str(p))


def test_sign_without_configuration_raises(monkeypatch):
    monkeypatch.setattr(signing, "_PRIVATE_KEY", None)
    with pytest.raises(signing.SigningError, match="no signing key"):
        signing.sign_headers("a", "GET", "/health", b"")


# cs_client egress: headers on/off, signed bytes == sent bytes

class _CapturedRequest:
    def __init__(self):
        self.kwargs = None

    def fake_request(self, method, url, **kwargs):
        self.kwargs = {"method": method, "url": url, **kwargs}

        class _Resp:
            ok = True
            status_code = 200

            def json(self):
                return {}
        return _Resp()


@pytest.fixture()
def cs_client_mod(monkeypatch):
    import os as _os
    import cs_client
    # Never leak a real CS_SIGNING_KEY from the environment into tests.
    monkeypatch.delenv("CS_SIGNING_KEY", raising=False)
    yield cs_client
    # Restores the unconfigured state; fixture teardown runs before monkeypatch undoes
    # its own setenv.
    _os.environ.pop("CS_SIGNING_KEY", None)
    cs_client.configure("", "cortex")
    signing._PRIVATE_KEY = None
    signing._KEY_PATH = ""


def test_cs_request_unsigned_by_default(cs_client_mod, monkeypatch):
    """CS_SIGNING_KEY unset → zero signing headers, exact pre-signing
    behaviour."""
    cap = _CapturedRequest()
    monkeypatch.setattr(cs_client_mod.requests, "request", cap.fake_request)
    cs_client_mod.configure("http://cs.example:3032", "cortex")
    assert not cs_client_mod.signing_enabled()

    r = cs_client_mod.cs_request("POST", "/api/notes",
                                 json={"agent": "cortex"}, timeout=3)
    assert r.ok
    headers = cap.kwargs["headers"] or {}
    assert not any(h.startswith("X-") for h in headers)
    assert headers.get("Content-Type") == "application/json"
    assert cap.kwargs["timeout"] == 3
    assert cap.kwargs["url"] == "http://cs.example:3032/api/notes"


def test_cs_request_signed_when_key_configured(cs_client_mod, tmp_path,
                                               monkeypatch):
    key_path, key = _write_openssh_key(tmp_path)
    monkeypatch.setenv("CS_SIGNING_KEY", str(key_path))
    cap = _CapturedRequest()
    monkeypatch.setattr(cs_client_mod.requests, "request", cap.fake_request)
    cs_client_mod.configure("http://cs.example:3032", "cortex-laptop")
    assert cs_client_mod.signing_enabled()

    payload = {"agent": "cortex-laptop", "content": "zażółć gęślą jaźń"}
    cs_client_mod.cs_request("POST", "/api/notes", json=payload, timeout=5)

    headers = cap.kwargs["headers"]
    for h in ("X-Agent-Id", "X-Timestamp", "X-Nonce", "X-Signature"):
        assert h in headers, f"missing {h}"
    assert headers["X-Agent-Id"] == "cortex-laptop"

    # The invariant that makes signing sound: the bytes that were
    # signed are byte-identical to the bytes handed to requests.
    sent_body = cap.kwargs["data"]
    assert isinstance(sent_body, bytes)
    assert json.loads(sent_body.decode("utf-8")) == payload
    _verify(key.public_key(), headers, "POST", "/api/notes", sent_body)


def test_cs_request_get_with_params_signs_query_free_path(
        cs_client_mod, tmp_path, monkeypatch):
    """params → query string; the signature covers the bare path only
    (query is unsigned per protocol)."""
    key_path, key = _write_openssh_key(tmp_path)
    monkeypatch.setenv("CS_SIGNING_KEY", str(key_path))
    cap = _CapturedRequest()
    monkeypatch.setattr(cs_client_mod.requests, "request", cap.fake_request)
    cs_client_mod.configure("http://cs.example:3032", "cortex")

    cs_client_mod.cs_request("GET", "/api/briefing/cortex",
                             params={"hours": 24}, timeout=3)
    assert cap.kwargs["params"] == {"hours": 24}
    assert cap.kwargs["data"] is None
    _verify(key.public_key(), cap.kwargs["headers"], "GET",
            "/api/briefing/cortex", b"")


def test_cs_request_without_cs_url_raises(cs_client_mod):
    import requests as _requests
    cs_client_mod.configure("", "cortex")
    with pytest.raises(_requests.exceptions.ConnectionError):
        cs_client_mod.cs_request("GET", "/health")


def test_configure_with_bad_key_fails_closed(cs_client_mod, tmp_path,
                                             monkeypatch):
    """A set-but-broken CS_SIGNING_KEY must raise, not degrade to
    unsigned requests."""
    bad = tmp_path / "bad_key"
    bad.write_text("garbage")
    monkeypatch.setenv("CS_SIGNING_KEY", str(bad))
    with pytest.raises(signing.SigningError):
        cs_client_mod.configure("http://cs.example:3032", "cortex")
