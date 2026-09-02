#!/usr/bin/env python3
# Cortex — Local AI Agent
# Copyright (c) 2025-2026 BuildOnAI
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Commercial licensing available — see LICENSE-COMMERCIAL.md
"""The only egress point for Consciousness Server traffic.

Every CS request goes through cs_request, enforced by tests/test_invariants.py,
so no call site can bypass request signing. The body is serialised here and
those exact bytes are both signed and sent.
"""
from __future__ import annotations

import json as _json
import os
import requests
from urllib.parse import urlparse

from security.signing import configure_signing, sign_headers, SigningError

__all__ = ["configure", "cs_request", "signing_enabled", "SigningError"]

_CS_URL = ""          # normalized base URL, "" = CS features off
_BASE_PATH = ""       # path prefix of CS_URL (usually ""), part of the signed path
_AGENT_ID = "cortex"  # X-Agent-Id — must match keys/agents/<id>.pub on the key-server
_SIGNING = False

_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


def configure(cs_url: str, agent_id: str) -> None:
    """Wire the client. Called from agent.py once CS_URL is validated
    and auto-discovery has run. Reads ``CS_SIGNING_KEY`` from the
    environment; raises :class:`SigningError` if the key is set but
    unusable — the caller treats that as fatal (no fail-open)."""
    global _CS_URL, _BASE_PATH, _AGENT_ID, _SIGNING
    _CS_URL = (cs_url or "").rstrip("/")
    # A base path in CS_URL reaches the server in the request path, so it is signed too.
    _BASE_PATH = urlparse(_CS_URL).path if _CS_URL else ""
    _AGENT_ID = agent_id or "cortex"
    key_path = os.getenv("CS_SIGNING_KEY", "").strip()
    if key_path:
        configure_signing(key_path)  # raises SigningError on any problem
        _SIGNING = True
    else:
        _SIGNING = False


def signing_enabled() -> bool:
    return _SIGNING


def cs_request(method: str, path: str, json=None, params=None,
               timeout: float = 5) -> requests.Response:
    """Sends one HTTP request to CS. The only sanctioned way to do so.

    `json` is serialised once, here, and the same bytes are signed and sent.
    `params` become the query string and are not signed. Raises the usual
    requests exceptions.
    """
    if not _CS_URL:
        raise requests.exceptions.ConnectionError(
            "Consciousness Server not configured (CS_URL empty)")
    verb = str(method).upper()
    if verb not in _ALLOWED_METHODS:
        raise ValueError(f"cs_request: unsupported method {method!r}")
    if not path.startswith("/"):
        path = "/" + path

    headers = {}
    body = b""
    if json is not None:
        body = _json.dumps(json, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if _SIGNING:
        headers.update(
            sign_headers(_AGENT_ID, verb, f"{_BASE_PATH}{path}", body))

    return requests.request(
        verb,
        f"{_CS_URL}{path}",
        data=body if json is not None else None,
        params=params,
        headers=headers or None,
        timeout=timeout,
    )
