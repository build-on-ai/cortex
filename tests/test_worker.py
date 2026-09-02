"""Worker-mode regression tests.

Worker mode has no human in front of it, so a broken call path shows up only
as a task flipping to FAILED. Both tests exercise the real execute_task with
the network edges stubbed, and the model stub carries the real signature of
agent.call_model, so a call site that drops an argument fails here.

Run: python3 -m pytest tests/test_worker.py
"""
from __future__ import annotations

import inspect
import os
import pathlib
import sys

# Imported without touching the network, or the auto-probe fires against whatever
# is listening on the CS port.
os.environ["CORTEX_AUTO_DISCOVER_CS"] = "0"
os.environ.setdefault("CS_URL", "")

_REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

import agent  # noqa: E402
import recovery as recovery_mod  # noqa: E402
import worker  # noqa: E402
from policy import PolicyEngine  # noqa: E402
from recovery import RecoveryEngine  # noqa: E402


_TASK = {
    "id": "test-task-1",
    "title": "Say hello",
    "description": "Reply with one sentence. Do not use tools.",
    "priority": "NORMAL",
}


class _Recorder:
    """Model stub that enforces the real ``call_model`` signature.

    ``inspect.Signature.bind`` raises the same ``TypeError`` the real
    function raises on a missing argument, so a call site that drops
    ``tools`` fails here exactly as it does against Ollama — while a
    plain ``*args`` stub would happily swallow it.
    """

    def __init__(self):
        self.signature = inspect.signature(agent.call_model)
        self.calls: list[inspect.BoundArguments] = []

    def __call__(self, *args, **kwargs):
        bound = self.signature.bind(*args, **kwargs)
        self.calls.append(bound)
        return {"message": {"content": "hello", "tool_calls": []}}


def _stub_cs_and_sleep(recorder: _Recorder) -> list:
    """Replace every outbound edge of execute_task. Returns undo list."""
    undo = []

    def patch(module, name, value):
        undo.append((module, name, getattr(module, name)))
        setattr(module, name, value)

    patch(worker, "call_model", recorder)
    patch(worker, "cs_update_task", lambda *a, **kw: True)
    patch(worker, "cs_set_status", lambda *a, **kw: True)
    patch(worker, "cs_heartbeat", lambda *a, **kw: True)
    patch(worker, "cs_note", lambda *a, **kw: True)
    patch(worker, "cs_request", lambda *a, **kw: None)
    # Retry backoff is 1s + 3s; a failing assertion should not also
    # cost four seconds of wall clock.
    patch(recovery_mod.time, "sleep", lambda *_a, **_kw: None)
    return undo


def _restore(undo: list) -> None:
    for module, name, original in reversed(undo):
        setattr(module, name, original)


def _run_task():
    recorder = _Recorder()
    undo = _stub_cs_and_sleep(recorder)
    try:
        success, result = worker.execute_task(
            _TASK, PolicyEngine(), RecoveryEngine()
        )
    finally:
        _restore(undo)
    return recorder, success, result


def test_execute_task_reaches_the_model():
    """A task must not die on the way to the model.

    Regression guard: with ``call_model(msgs)`` this returns
    (False, "Model unreachable after retry") and ``recorder.calls``
    stays empty, because bind() rejects the call before the stub can
    record it.
    """
    recorder, success, result = _run_task()

    assert recorder.calls, (
        "call_model was never invoked with a valid signature — "
        f"execute_task returned {result!r}. Check the call site in "
        "worker.py against the def in agent.py."
    )
    assert success, f"execute_task failed: {result!r}"
    assert "unreachable" not in result.lower(), result


def test_worker_passes_the_tool_catalogue():
    """The worker must hand the model real tools, not an empty list.

    Worker mode exists to *do* things — bash, file edits, grep. An
    empty or None catalogue would still return a text answer, so the
    arity fix alone is not enough: assert the tools actually arrive.
    """
    recorder, _success, result = _run_task()

    assert recorder.calls, (
        f"the model was never reached — execute_task returned {result!r}; "
        "see test_execute_task_reaches_the_model"
    )
    bound = recorder.calls[0]
    bound.apply_defaults()
    tools = bound.arguments["tools"]

    assert tools, "worker called the model with an empty tool catalogue"
    names = {t["function"]["name"] for t in tools}
    assert {"bash", "read_file", "write_file"} <= names, (
        f"core tools missing from the worker's catalogue: {sorted(names)}"
    )


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
