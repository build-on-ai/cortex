"""Compactor summariser prompt-contract tests.

The summariser receives untrusted conversation text inside an English-tagged
container, which biases a small model toward English, so the prompt pins the
reply language to the conversation's. These tests fail if either the pin or
the wrapper is dropped. The HTTP call is stubbed, so no live model is needed.

Run: python3 -m pytest tests/test_compactor.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import compactor


class _FakeResp:
    def __init__(self, content):
        self._content = content

    def raise_for_status(self):
        pass

    def json(self):
        return {"message": {"content": self._content}}


def _capture_summarizer_payload():
    """Run _summarize with requests.post stubbed; return the JSON payload
    that would have been sent to the model."""
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["payload"] = json
        return _FakeResp("(stub summary)")

    orig = compactor.requests.post
    compactor.requests.post = fake_post
    try:
        # Conversation must exceed the 500-char short-circuit in _summarize
        # so the LLM path (and thus the prompt we assert on) actually runs.
        msgs = [
            {"role": "user",
             "content": f"Zdanie testowe {i} o konfiguracji backupu bazy danych na serwerze."}
            for i in range(20)
        ]
        compactor._summarize(msgs, "http://stub", "stub-model")
    finally:
        compactor.requests.post = orig

    assert "payload" in captured, "_summarize did not call the model (short-circuited?)"
    return captured["payload"]


def _system_message(payload):
    return next(m for m in payload["messages"] if m["role"] == "system")["content"]


def _user_message(payload):
    return next(m for m in payload["messages"] if m["role"] == "user")["content"]


def test_summarizer_pins_reply_language():
    """The prompt must instruct the model to reply in the conversation's
    language, countering the English bias of the untrusted wrapper tags."""
    text = _system_message(_capture_summarizer_payload()).lower()
    assert "same language as the conversation" in text, (
        "summarizer system prompt must pin reply language — the "
        "untrusted wrapper tags will silently flip summaries to English"
    )


def test_summarizer_wraps_conversation_as_untrusted():
    """The conversation text is untrusted ingress and must stay wrapped in
    the compacted_history container (the /fix)."""
    user = _user_message(_capture_summarizer_payload())
    assert "compacted_history" in user, (
        "summarizer must route the conversation through the untrusted "
        "compacted_history wrapper — untrusted text lost its boundary"
    )
    assert 'untrusted="true"' in user


if __name__ == "__main__":
    import traceback

    mod = sys.modules[__name__]
    tests = [(n, getattr(mod, n)) for n in dir(mod) if n.startswith("test_")]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  OK   {name}")
            passed += 1
        except Exception:
            print(f"  FAIL {name}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
