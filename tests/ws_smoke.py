"""
WebSocket smoke harness for the Cortex web UI.

Not part of the invariants/policy CI runs — those exercise the
Policy Engine and AST invariants. This script drives a live
`./run.sh web` instance over WebSockets to confirm a real chat
round-trip works against the auth-on server.

Run:
    ./run.sh web        # in another terminal
    WEB_TOKEN=... python3 tests/ws_smoke.py
"""

import asyncio
import json
import os
import websockets

# pull WEB_TOKEN from env so ws_test works against an auth-on
# server. The prior hardcoded URL silently failed (handshake closed with
# 4401) unless the user also ran the server with WEB_TOKEN="". Appending
# ?token= keeps this path working; the browser flow uses the cookie.
_TOKEN = os.getenv("WEB_TOKEN", "")
_BASE_WS = os.getenv("CORTEX_WS_URL", "ws://localhost:8080/ws")
WS_URL = f"{_BASE_WS}?token={_TOKEN}" if _TOKEN else _BASE_WS
TIMEOUT = 300  # seconds per test

async def collect_until_done(ws, test_name, timeout=TIMEOUT):
    """Collect all messages until type 'done' or 'error'."""
    messages = []
    final_text = ""
    tool_calls = []
    tool_results = []
    error_msg = None
    done_received = False

    try:
        async with asyncio.timeout(timeout):
            while True:
                raw = await ws.recv()
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    msg = {"type": "raw", "data": raw}

                messages.append(msg)
                mtype = msg.get("type", "unknown")

                if mtype == "delta":
                    final_text += msg.get("content", "")
                elif mtype == "tool_call":
                    tool_calls.append(msg)
                elif mtype == "tool_result":
                    tool_results.append(msg)
                elif mtype == "error":
                    error_msg = msg.get("content", msg.get("message", str(msg)))
                    # server sends error then stops — no 'done' after error
                    break
                elif mtype == "done":
                    done_received = True
                    break
    except asyncio.TimeoutError:
        print(f"  [TIMEOUT] {test_name} exceeded {timeout}s")

    return messages, final_text, tool_calls, tool_results, error_msg, done_received


async def run_tests():
    print("=" * 70)
    print("Cortex WebSocket Test Suite")
    print(f"URL: {WS_URL}")
    print("=" * 70)

    results = []

    # Long rather than None: the connection survives a slow model, and a silent
    # server still closes the socket after ping_timeout.
    async with websockets.connect(
        WS_URL,
        ping_interval=60,
        ping_timeout=30,
        open_timeout=15,
    ) as ws:

        # Init: wait for status message
        print("\n[INIT] Waiting for initial status message...")
        try:
            async with asyncio.timeout(15):
                raw = await ws.recv()
                init_msg = json.loads(raw)
                print(f"  type={init_msg.get('type')}  content={init_msg.get('content', '')}")
        except asyncio.TimeoutError:
            print("  [WARN] No initial message within 15s, continuing...")
        except Exception as e:
            print(f"  [WARN] Init error: {e}")

        # TEST 1: Basic chat
        print("\n" + "─" * 70)
        print("TEST 1: Basic chat (no tools)")
        print("  Send: What is 2+2? Answer with a single word.")
        payload = {"type": "message", "content": "What is 2+2? Answer with a single word.", "think": False}
        await ws.send(json.dumps(payload))

        msgs, text, tcs, trs, err, done = await collect_until_done(ws, "Test 1")
        types_received = [m.get("type") for m in msgs]
        print(f"  Types received : {types_received}")
        print(f"  Final text     : {repr(text[:300])}")
        print(f"  Tool calls     : {len(tcs)}")
        print(f"  Error          : {err}")
        print(f"  Done received  : {done}")
        results.append({
            "test": "Test 1 - Basic chat",
            "types": types_received,
            "text": text[:300],
            "tool_count": len(tcs),
            "error": err,
            "done": done,
        })

        # TEST 2: Tool call - safe bash
        print("\n" + "─" * 70)
        print("TEST 2: Tool call - safe command")
        print("  Send: Uruchom bash: echo hello world")
        payload = {"type": "message", "content": "Uruchom bash: echo hello world", "think": False}
        await ws.send(json.dumps(payload))

        msgs, text, tcs, trs, err, done = await collect_until_done(ws, "Test 2")
        types_received = [m.get("type") for m in msgs]
        print(f"  Types received : {types_received}")
        print(f"  Final text     : {repr(text[:300])}")
        print(f"  Tool calls ({len(tcs)}):")
        for tc in tcs:
            print(f"    name={tc.get('name')}  arg={tc.get('arg','')}  id={tc.get('id')}")
        print(f"  Tool results ({len(trs)}):")
        for tr in trs:
            print(f"    id={tr.get('id')}  result={repr(str(tr.get('result',''))[:200])}")
        print(f"  Error          : {err}")
        print(f"  Done received  : {done}")
        results.append({
            "test": "Test 2 - Safe tool call",
            "types": types_received,
            "text": text[:300],
            "tool_count": len(tcs),
            "tool_calls": [{"name": t.get("name"), "arg": t.get("arg"), "result": trs[i].get("result") if i < len(trs) else None}
                           for i, t in enumerate(tcs)],
            "error": err,
            "done": done,
        })

        # TEST 3: Policy DENY
        print("\n" + "─" * 70)
        print("TEST 3: Policy DENY test")
        print("  Send: Uruchom bash: rm -rf /home")
        payload = {"type": "message", "content": "Uruchom bash: rm -rf /home", "think": False}
        await ws.send(json.dumps(payload))

        msgs, text, tcs, trs, err, done = await collect_until_done(ws, "Test 3")
        types_received = [m.get("type") for m in msgs]
        print(f"  Types received : {types_received}")
        print(f"  Final text     : {repr(text[:300])}")
        deny_found = False
        print(f"  Tool calls ({len(tcs)}):")
        for tc in tcs:
            tc_name = tc.get("name", "")
            print(f"    name={tc_name}  arg={tc.get('arg','')}  id={tc.get('id')}")
            if "[DENY]" in tc_name or "DENY" in str(tc).upper():
                deny_found = True
        # Also check raw messages for DENY keyword
        all_raw = json.dumps(msgs)
        if "[DENY]" in all_raw or '"DENY"' in all_raw:
            deny_found = True
        print(f"  [DENY] detected: {deny_found}")
        print(f"  Error          : {err}")
        print(f"  Done received  : {done}")
        results.append({
            "test": "Test 3 - Policy DENY",
            "types": types_received,
            "text": text[:300],
            "tool_count": len(tcs),
            "deny_found": deny_found,
            "error": err,
            "done": done,
        })

        # TEST 4: Policy ASK (sudo)
        print("\n" + "─" * 70)
        print("TEST 4: Policy ASK test")
        print("  Send: Uruchom bash: sudo apt update")
        payload = {"type": "message", "content": "Uruchom bash: sudo apt update", "think": False}
        await ws.send(json.dumps(payload))

        msgs, text, tcs, trs, err, done = await collect_until_done(ws, "Test 4")
        types_received = [m.get("type") for m in msgs]
        print(f"  Types received : {types_received}")
        print(f"  Final text     : {repr(text[:300])}")
        ask_found = False
        deny_found_t4 = False
        print(f"  Tool calls ({len(tcs)}):")
        for tc in tcs:
            tc_name = tc.get("name", "")
            print(f"    name={tc_name}  arg={tc.get('arg','')}  id={tc.get('id')}")
            if "[ASK]" in tc_name or "ASK" in str(tc).upper():
                ask_found = True
            if "[DENY]" in tc_name or "DENY" in str(tc).upper():
                deny_found_t4 = True
        all_raw = json.dumps(msgs)
        if "[ASK]" in all_raw:
            ask_found = True
        if "[DENY]" in all_raw:
            deny_found_t4 = True
        print(f"  [ASK] detected : {ask_found}")
        print(f"  [DENY] detected: {deny_found_t4}")
        print(f"  Error          : {err}")
        print(f"  Done received  : {done}")
        results.append({
            "test": "Test 4 - Policy ASK",
            "types": types_received,
            "text": text[:300],
            "tool_count": len(tcs),
            "ask_found": ask_found,
            "deny_found": deny_found_t4,
            "error": err,
            "done": done,
        })

    # Summary table
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"{'Endpoint':<35} {'Status':<8} {'Response'}")
    print("-" * 70)
    for r in results:
        if r.get("error"):
            status = "ERROR"
        elif r.get("done"):
            status = "OK"
        else:
            status = "TIMEOUT"

        notes = []
        t = r.get("text", "")
        if t:
            notes.append(f"reply={repr(t[:50])}")
        if r.get("tool_count", 0):
            notes.append(f"tools={r['tool_count']}")
        if r.get("deny_found"):
            notes.append("[DENY] confirmed")
        if r.get("ask_found"):
            notes.append("[ASK] confirmed")
        if r.get("error"):
            notes.append(f"err={r['error'][:50]}")
        resp = " | ".join(notes) if notes else "(no output)"
        print(f"{r['test']:<35} {status:<8} {resp}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_tests())
