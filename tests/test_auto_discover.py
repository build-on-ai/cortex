"""Auto-discovery of a local Consciousness Server.

Cortex reads the CS port from that deployment's ports.yaml, so CS_URL need not
be set by hand. These tests pin both halves of the two-stage probe: a slow but
real CS is found, and a missing one still fails fast.

Run: python3 -m pytest tests/test_auto_discover.py
"""
from __future__ import annotations

import http.server
import os
import pathlib
import socket
import sys
import threading
import time

os.environ["CORTEX_AUTO_DISCOVER_CS"] = "0"  # no probe at import time
os.environ.setdefault("CS_URL", "")

_REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

import agent  # noqa: E402


class _SlowHealthHandler(http.server.BaseHTTPRequestHandler):
    """Stands in for a CS whose /health waits on a blocked subsystem."""

    delay = 2.5

    def do_GET(self):  # noqa: N802 — stdlib naming
        if self.path != "/health":
            self.send_error(404)
            return
        time.sleep(self.delay)
        body = b'{"status":"ok","semantic_search":"timeout"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Probe:
    """Point auto-discovery at *url*, restore the environment after."""

    def __init__(self, url: str, **env):
        self.env = {"CORTEX_AUTO_DISCOVER_CS": "1",
                    "CORTEX_AUTO_DISCOVER_URL": url, **env}
        self.saved: dict = {}

    def __enter__(self):
        for k, v in self.env.items():
            self.saved[k] = os.environ.get(k)
            os.environ[k] = v
        return self

    def __exit__(self, *_exc):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return False


def test_discovers_cs_with_a_slow_health_endpoint():
    """A CS that takes 2.5s to answer /health is still a CS.

    Regression guard: with the old flat 1s timeout this returns "".
    """
    port = _free_port()
    server = http.server.HTTPServer(("127.0.0.1", port), _SlowHealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    try:
        with _Probe(url):
            found = agent._auto_discover_cs()
    finally:
        server.shutdown()
        server.server_close()

    assert found == url, (
        f"auto-discovery missed a live CS answering in "
        f"{_SlowHealthHandler.delay}s (got {found!r})"
    )


def test_missing_cs_fails_fast():
    """No listener means no wait — the TCP stage refuses immediately.

    Without stage 1, a generous HTTP timeout would be charged to every
    start on a machine with no CS.
    """
    port = _free_port()  # nothing bound to it now
    started = time.monotonic()
    with _Probe(f"http://127.0.0.1:{port}", CORTEX_AUTO_DISCOVER_TIMEOUT="30"):
        found = agent._auto_discover_cs()
    elapsed = time.monotonic() - started

    assert found == "", f"probe claimed to find a CS at a dead port: {found!r}"
    assert elapsed < 2, f"probe against a dead port took {elapsed:.1f}s"


def test_probe_disabled_by_env():
    """CORTEX_AUTO_DISCOVER_CS=0 stays an off switch."""
    with _Probe("http://127.0.0.1:1", CORTEX_AUTO_DISCOVER_CS="0"):
        assert agent._auto_discover_cs() == ""


# Standalone runner

if __name__ == "__main__":
    import traceback

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  OK   {fn.__name__}")
            passed += 1
        except Exception:
            print(f"  FAIL {fn.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
