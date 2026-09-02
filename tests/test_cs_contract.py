#!/usr/bin/env python3
"""Contract test: every CS endpoint cortex uses still exists in the published
consciousness-server.

Cortex and CS are separate repositories, so a route rename on either side
silently turns into a 404. The CI workflow starts a fresh CS stack, mints
signing keys and points CS_URL at the port from CS's registry; it also runs
nightly, so a CS-side refactor is caught without a cortex change.

Run: CS_URL=http://127.0.0.1:<port> python3 tests/test_cs_contract.py
"""
import os
import sys

import requests

# No default: a literal port would test whatever answers on it. Checked in main(),
# not at import, because pytest imports this file to collect it.
CS_URL = os.environ.get("CS_URL", "")

_NO_CS_URL = (
    "CS_URL is not set. This test talks to a running CS, and the port comes from "
    "that deployment's ports.yaml — guessing one here would test the wrong thing.\n"
    'Example: CS_URL="http://127.0.0.1:$(/path/to/cs/lib/ports.py '
    'consciousness-server)" python3 tests/test_cs_contract.py'
)
AGENT = "CONTRACT_TEST"
TASK_ID_PLACEHOLDER = "00000000-0000-0000-0000-000000000000"

# (method, path, description). The set mirrors every distinct CS URL
# referenced in agent.py and worker.py — keep them in sync.
ENDPOINTS = [
    ("POST",  "/api/agents/register",                         "agent registration"),
    ("POST",  f"/api/agents/{AGENT}/heartbeat",               "heartbeat"),
    ("PATCH", f"/api/agents/{AGENT}/status",                  "status update"),
    ("GET",   f"/api/briefing/{AGENT}",                       "briefing"),
    ("POST",  "/api/memory/conversations",                    "conversation persist"),
    ("POST",  "/api/notes",                                   "note create"),
    ("POST",  "/api/tasks/create",                            "task create"),
    ("GET",   f"/api/tasks/pending/{AGENT}",                  "pending tasks"),
    ("GET",   f"/api/tasks/{TASK_ID_PLACEHOLDER}",            "task get"),
    ("PATCH", f"/api/tasks/{TASK_ID_PLACEHOLDER}/status",     "task status update"),
]


def route_exists(method: str, path: str) -> tuple[bool, str]:
    # JSON means a handler fired, even on a 400 or 404; the framework's own 404 comes
    # back as HTML and means no route.
    try:
        r = requests.request(method, f"{CS_URL}{path}", json={}, timeout=5)
    except requests.RequestException as exc:
        return False, f"network error: {exc}"

    content_type = r.headers.get("Content-Type", "")
    if "application/json" in content_type:
        return True, f"HTTP {r.status_code} JSON"
    body_sample = r.text[:160].replace("\n", " ")
    return False, f"HTTP {r.status_code} non-JSON: {body_sample}"


def main() -> int:
    if not CS_URL:
        print(_NO_CS_URL, file=sys.stderr)
        return 2

    try:
        h = requests.get(f"{CS_URL}/health", timeout=5)
        h.raise_for_status()
    except Exception as exc:
        print(f"[FATAL] {CS_URL}/health unreachable: {exc}", file=sys.stderr)
        return 2

    print(f"CS_URL={CS_URL} — verifying {len(ENDPOINTS)} endpoints")
    failures = []
    for method, path, desc in ENDPOINTS:
        ok, detail = route_exists(method, path)
        mark = " OK " if ok else "FAIL"
        print(f"  [{mark}] {method:5s} {path:50s} {detail}  ({desc})")
        if not ok:
            failures.append((method, path, desc, detail))

    if failures:
        print(f"\n{len(failures)}/{len(ENDPOINTS)} contract mismatch — "
              "cortex will break on these routes")
        return 1
    print(f"\nAll {len(ENDPOINTS)} endpoints present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
