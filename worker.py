#!/usr/bin/env python3
"""Worker loop — the closed task loop: CS task, agent run, result back to CS.

Modes:
  worker.py            poll CS every 10s, take tasks, run them, report
  worker.py --once     take one task, run it, exit
  worker.py --task ID  run one named task

The agent registers with CS, sends heartbeats and reports its state.
"""

import os
import re
import sys
import json
import time
import signal
import datetime
import logging
import argparse
from pathlib import Path
from urllib.parse import urlparse

# Import agent modules
sys.path.insert(0, str(Path(__file__).parent))
from security import parse_tool_arguments
from agent import (
    execute_tool, call_model, call_anthropic, build_system_prompt,
    wrap_tool_output, make_tool_result, _valid_tool_name,
    FALLBACK_ANTHROPIC_ENABLED, FALLBACK_REDACT_TOOL_OUTPUTS,
    TOOLS, OLLAMA_URL, OLLAMA_MODEL, CS_URL, ANTHROPIC_KEY,
    MAX_TOOL_LOOPS, CONTEXT_MAX_TOKENS, C
)
# Configured by agent.py with the validated CS_URL. Every CS call below goes
# through cs_request, so request signing applies to all of them.
from cs_client import cs_request
from policy import PolicyEngine, PolicyDecision
from compactor import compact_messages, should_compact, estimate_tokens
from recovery import RecoveryEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("worker")

AGENT_NAME    = os.getenv("AGENT_NAME", "cortex")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "10"))  # seconds
HEARTBEAT_INTERVAL = 30  # seconds

# task_id is interpolated into CS URLs, so a crafted response must not reach
# them; UUIDs, slugs and short IDs all fit this shape.
_TASK_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

def _valid_task_id(tid) -> bool:
    return isinstance(tid, str) and bool(_TASK_ID_RE.match(tid))

# agent.validate_cs_url already exits at import time on a malformed CS_URL.

running = True

def signal_handler(sig, frame):
    global running
    log.info("Stop signal received — finishing after the current task...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)



def cs_register():
    """Zarejestruj agenta w CS."""
    try:
        r = cs_request("POST", "/api/agents/register", json={
            "name": AGENT_NAME,
            "location": os.getenv("AGENT_LOCATION", "local"),
            "role": "Cortex Agent",  # invariant: allow-raw-message until=2026-12-01 because CS agent registration payload, not LLM conversation role
            "capabilities": ["chat", "coding", "tasks", "bash", "files"]
        }, timeout=5)
        if r.ok:
            log.info(f"Zarejestrowany w CS jako {AGENT_NAME}")
            return True
        log.warning(f"CS register failed: {r.status_code}")
    except Exception as e:
        log.error(f"CS unreachable: {e}")
    return False


def cs_heartbeat():
    """Send a heartbeat to CS."""
    try:
        cs_request("POST", f"/api/agents/{AGENT_NAME}/heartbeat", timeout=3)
    except Exception as e:
        log.debug("heartbeat failed: %s", e)


def cs_set_status(status: str):
    """Ustaw status agenta (FREE/BUSY/OFFLINE)."""
    try:
        cs_request("PATCH", f"/api/agents/{AGENT_NAME}/status",
                   json={"status": status}, timeout=3)
    except Exception as e:
        log.debug("set_status(%s) failed: %s", status, e)


def cs_get_pending_tasks() -> list:
    """Pobierz pending taski dla tego agenta."""
    try:
        r = cs_request("GET", f"/api/tasks/pending/{AGENT_NAME}", timeout=5)
        if r.ok:
            data = r.json()
            if isinstance(data, list):
                return data
            return data.get("tasks", data.get("data", []))
    except Exception as e:
        log.debug(f"Error fetching tasks: {e}")
    return []


def cs_update_task(task_id: str, status: str, result: str = ""):
    """Zaktualizuj status taska w CS."""
    if not _valid_task_id(task_id):
        log.error("Refusing CS task update — invalid task_id: %r", task_id)
        return False
    try:
        payload = {"status": status}
        if result:
            payload["result"] = result
        r = cs_request("PATCH", f"/api/tasks/{task_id}/status",
                       json=payload, timeout=5)
        if r.ok:
            log.info(f"Task {task_id[:8]}... → {status}")
            return True
        log.warning(f"Task update failed: {r.status_code} {r.text[:100]}")
    except Exception as e:
        log.error(f"Task update error: {e}")
    return False


def cs_note(content: str, note_type: str = "observation"):
    """Save a note to CS."""
    try:
        cs_request("POST", "/api/notes", json={
            "agent": AGENT_NAME,
            "type": note_type,
            "content": content
        }, timeout=3)
    except Exception as e:
        log.debug("cs_note failed: %s", e)



def execute_task(task: dict, policy: PolicyEngine, recovery: RecoveryEngine) -> tuple[bool, str]:
    """
    Wykonaj task przez agent loop.
    Returns: (success, result_summary)
    """
    task_id = task.get("id")
    if not _valid_task_id(task_id):
        log.error("Task without a valid id: %r — skipping", task)
        return False, "Invalid task id"
    title = task.get("title", "?")
    description = task.get("description", "")
    priority = task.get("priority", "MEDIUM")

    log.info(f"Running: [{priority}] {title}")

    # Oznacz jako IN_PROGRESS
    cs_update_task(task_id, "IN_PROGRESS")
    cs_set_status("BUSY")

    # Buduj kontekst dla modelu
    briefing = ""
    try:
        r = cs_request("GET", f"/api/briefing/{AGENT_NAME}",
                       params={"hours": 4}, timeout=3)
        if r.ok:
            briefing = json.dumps(r.json(), ensure_ascii=False)[:500]
    except Exception as e:
        log.debug("briefing fetch failed: %s", e)

    # The system prompt holds trusted content only; untrusted task fields go into a
    # user message through the same wrap_untrusted container as every other ingress.
    system_prompt = build_system_prompt(briefing)

    from security import wrap_untrusted, make_message
    task_body = f"title: {title}\npriority: {priority}\n\n{description}"
    user_task = wrap_untrusted("worker_task", task_body, id=str(task_id))

    messages = [
        make_message("system", system_prompt, authoritative=True),
        # The body is already wrapped, so this turn counts as authoritative.
        make_message("user", user_task, authoritative=True),
    ]

    # Agent loop
    loop_count = 0
    final_content = ""

    try:
        while loop_count < MAX_TOOL_LOOPS:
            loop_count += 1

            # heartbeat per iteration
            cs_heartbeat()

            # kompresja kontekstu
            if should_compact(messages, CONTEXT_MAX_TOKENS):
                log.info("Kompresja kontekstu...")
                messages[:] = compact_messages(
                    messages, OLLAMA_URL, OLLAMA_MODEL,
                    keep_last=6, max_tokens=CONTEXT_MAX_TOKENS
                )

            # call model
            response, messages[:] = recovery.handle_api_call(
                lambda msgs, **kw: call_model(msgs, TOOLS),
                messages,
                error_type="api_error"
            )

            if response is None:
                return False, "Model unreachable after retry"

            msg = response.get("message", {})
            content = msg.get("content", "")
            tc_list = msg.get("tool_calls", [])

            if not tc_list:
                final_content = content or "(no response)"
                # Real model-generated assistant turn — authoritative.
                messages.append(make_message("assistant", final_content, authoritative=True))
                break

            # A real assistant turn; the tool results that follow are the untrusted part
            # and go through make_tool_result.
            assistant_msg = make_message("assistant", content, authoritative=True)
            assistant_msg["tool_calls"] = tc_list  # non-content field; the message role already went through make_message above
            messages.append(assistant_msg)

            tool_results = []
            for tc in tc_list:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                # Validated before the policy check, so the name field in a DENY or ASK response
                # cannot carry model-injected text.
                if not _valid_tool_name(name):
                    log.warning(f"invalid tool name rejected: {str(name)[:80]!r}")
                    tool_results.append(make_tool_result(
                        "invalid", "[BLOCKED] invalid tool name",
                        source="invalid_name",
                    ))
                    continue
                args = parse_tool_arguments(fn.get("arguments", {}))

                # Policy check
                decision, reason = policy.check(name, args)
                if decision == PolicyDecision.DENY:
                    log.warning(f"DENY: {name} — {reason}")
                    tool_results.append(make_tool_result(
                        name, f"[ZABLOKOWANE] {reason}", source="policy_deny",
                    ))
                    continue

                if decision == PolicyDecision.ASK:
                    # w trybie worker — skip ASK (bezpieczniej)
                    log.warning(f"SKIP (wymaga potwierdzenia): {name} — {reason}")
                    tool_results.append(make_tool_result(
                        name, f"[SKIPPED — manual confirmation required] {reason}",
                        source="policy_ask_skip",
                    ))
                    continue

                # Execute
                log.info(f"  > {name}: {json.dumps(args)[:60]}")
                result = execute_tool(name, args)

                # Recovery on error — agent.py returns "Tool error ..." / "Timeout ..."
                if result.startswith(("Tool error", "Timeout", "Tool error")):
                    action, msg_text = recovery.handle_tool_error(name, args, result)
                    if action == "retry":
                        result = execute_tool(name, args)

                # Real output, DENY reasons and ASK skips all go through the same container.
                tool_results.append(make_tool_result(name, result))

            messages.extend(tool_results)

        if not final_content:
            final_content = content or "(przekroczono limit iteracji)"

        # Truncate result to 2000 chars for CS
        result_summary = final_content[:2000]
        return True, result_summary

    except Exception as e:
        log.error(f"Error running task: {e}")
        return False, f"Error: {e}"



def worker_loop(policy: PolicyEngine, recovery: RecoveryEngine):
    """Main worker loop — poll → execute → report → repeat."""
    log.info(f"Worker loop start (poll co {POLL_INTERVAL}s)")

    last_heartbeat = 0

    while running:
        now = time.time()

        # heartbeat
        if now - last_heartbeat > HEARTBEAT_INTERVAL:
            cs_heartbeat()
            last_heartbeat = now

        # poll for tasks
        tasks = cs_get_pending_tasks()

        if tasks:
            # take the first task (highest priority)
            task = tasks[0]
            task_id = task["id"]

            log.info(f"Znaleziono task: {task.get('title', '?')}")

            success, result = execute_task(task, policy, recovery)

            status = "DONE" if success else "FAILED"
            cs_update_task(task_id, status, result)

            # Notka do CS
            cs_note(
                f"Task {status}: {task.get('title', '?')}\n{result[:500]}",
                note_type="observation" if success else "blocker"
            )

            cs_set_status("FREE")
            recovery.reset()
        else:
            # no tasks — wait
            cs_set_status("FREE")

        # sleep z graceful shutdown
        for _ in range(POLL_INTERVAL):
            if not running:
                break
            time.sleep(1)

    # cleanup
    cs_set_status("OFFLINE")
    log.info("Worker finished")


def run_single_task(task_id: str, policy: PolicyEngine, recovery: RecoveryEngine):
    """Wykonaj konkretny task po ID."""
    if not _valid_task_id(task_id):
        log.error("Invalid task id: %r (expected %s)", task_id, _TASK_ID_RE.pattern)
        return
    try:
        r = cs_request("GET", f"/api/tasks/{task_id}", timeout=5)
        if not r.ok:
            log.error(f"Task {task_id} not found")
            return
        task = r.json()
    except Exception as e:
        log.error(f"Error fetching task: {e}")
        return

    success, result = execute_task(task, policy, recovery)
    status = "DONE" if success else "FAILED"
    cs_update_task(task_id, status, result)
    cs_set_status("FREE")

    print(f"\n{'OK' if success else 'FAIL'}: {result[:500]}")



def main():
    parser = argparse.ArgumentParser(description="Cortex Worker Agent")
    parser.add_argument("--once", action="store_true", help="Take one task and exit")
    parser.add_argument("--task", type=str, help="Wykonaj konkretny task po ID")
    args = parser.parse_args()

    print(f"""
{C.BLUE}+======================================================+{C.RESET}
{C.BLUE}|{C.RESET}  {C.BOLD}{C.CYAN}Cortex Worker{C.RESET}  {C.DIM}|{C.RESET}  {C.PURPLE}{AGENT_NAME}{C.RESET}  {C.DIM}|{C.RESET}  {C.GREEN}{OLLAMA_MODEL}{C.RESET}        {C.BLUE}|{C.RESET}
{C.BLUE}|{C.RESET}  {C.DIM}Task → Agent → CS → Repeat{C.RESET}                            {C.BLUE}|{C.RESET}
{C.BLUE}+======================================================+{C.RESET}
""")
    # Where the worker will reach CS, as agent mode also reports.
    print(f"  {C.DIM}CS endpoint:{C.RESET} {CS_URL or C.AMBER + '(CS_URL not set)' + C.RESET}")

    # fallback policy via security.fallback (see agent.py).
    from security import FallbackPolicy as _FallbackPolicy
    policy = PolicyEngine()
    recovery = RecoveryEngine(
        fallback_fn=_FallbackPolicy.from_env(
            anthropic_key=ANTHROPIC_KEY,
            call_fn=call_anthropic,
        ).as_recovery_callable(),
        compact_fn=lambda msgs: compact_messages(
            msgs, OLLAMA_URL, OLLAMA_MODEL, keep_last=6, max_tokens=CONTEXT_MAX_TOKENS
        )
    )

    # The outcome is printed, so it is clear whether the worker is connected or standalone.
    if cs_register():
        import cs_client as _cs_client_mod
        if _cs_client_mod.signing_enabled():
            sig = f"{C.GREEN}signed (ed25519){C.RESET}"
        else:
            sig = f"{C.DIM}unsigned — CS will reject; set CS_SIGNING_KEY{C.RESET}"
        print(f"  {C.GREEN}✓ connected to CS{C.RESET} — registered as {AGENT_NAME}, requests {sig}")
    else:
        print(f"  {C.AMBER}⚠ CS unreachable{C.RESET} — working without registration")
        log.warning("CS unreachable — working without registration")

    if args.task:
        # Run one named task.
        run_single_task(args.task, policy, recovery)
    elif args.once:
        # Mode: take one task
        tasks = cs_get_pending_tasks()
        if tasks:
            task = tasks[0]
            success, result = execute_task(task, policy, recovery)
            cs_update_task(task["id"], "DONE" if success else "FAILED", result)
            print(f"\n{'OK' if success else 'FAIL'}: {result[:500]}")
        else:
            print("No pending tasks")
    else:
        # Worker loop.
        worker_loop(policy, recovery)


if __name__ == "__main__":
    main()
