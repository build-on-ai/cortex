#!/usr/bin/env python3
"""Tool calls and the auth-failure counter each have one home.

agent.py, worker.py and web.py held three copies of the same argument parsing,
and web.py kept a second copy of the rate-limit machinery with its own dict and
lock. Two dicts meant two budgets: the same address got ten attempts at the
bootstrap path and another ten across the API.

Run: python3 tests/test_toolcalls.py
"""
import ast
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from security import parse_tool_arguments, valid_tool_name, note_auth_fail, rate_limit_key
from security import auth as _auth

REPO = pathlib.Path(__file__).resolve().parent.parent
failures = 0


def check(condition, description):
    global failures
    if not condition:
        failures += 1
        print("FAIL " + description, file=sys.stderr)


# --- argument parsing --------------------------------------------------------

check(parse_tool_arguments({"a": 1}) == {"a": 1}, "a dict passes through unchanged")
check(parse_tool_arguments('{"a": 1}') == {"a": 1}, "a JSON object parses")
check(parse_tool_arguments("not json") == {}, "garbage yields {} rather than raising")
check(parse_tool_arguments(None) == {}, "None yields {}")
check(parse_tool_arguments(b"") == {}, "bytes yield {}")

# Valid JSON that is not an object. The old code handed the string or list on,
# reaching policy.check and then args.get() — an AttributeError in the loop.
check(parse_tool_arguments('"text"') == {}, "a bare JSON string is not an argument list")
check(parse_tool_arguments("[1, 2]") == {}, "a JSON array is not an argument list")
check(parse_tool_arguments("42") == {}, "a JSON number is not an argument list")

# --- tool name ---------------------------------------------------------------

check(valid_tool_name("read_file") is True, "an ordinary name is accepted")
check(valid_tool_name("rm -rf /") is False, "a name with spaces is rejected")
check(valid_tool_name("") is False, "an empty name is rejected")
check(valid_tool_name(None) is False, "a non-string is rejected")
check(valid_tool_name("a" * 65) is False, "a name longer than 64 chars is rejected")

# --- one failure counter, not two --------------------------------------------

_auth._auth_fail_log.clear()
IP = "203.0.113.7"
results = [note_auth_fail(IP) for _ in range(10)]
check(results[:9] == [False] * 9, "the first nine attempts stay under the limit")
check(results[9] is True, "the tenth attempt trips it")
check(len(_auth._auth_fail_log) == 1, "one address occupies one bucket")
_auth._auth_fail_log.clear()

# Addresses of different families must not share a bucket.
check(rate_limit_key("::ffff:203.0.113.7") == rate_limit_key("203.0.113.7"),
      "an IPv4-mapped address buckets with its IPv4 form")
check(rate_limit_key("2001:db8::1") == rate_limit_key("2001:db8::ffff"),
      "addresses in one /64 share a bucket")
check(rate_limit_key("2001:db8::1") != rate_limit_key("2001:db9::1"),
      "addresses in different /64s get separate buckets")
check(rate_limit_key("fe80::1%eth0") == rate_limit_key("fe80::1"),
      "a zone id does not create a fresh bucket")

# --- no module may grow its own copy back ------------------------------------

def defines_locally(filename: str, names: set[str]) -> set[str]:
    """Which of *names* this file defines itself rather than importing."""
    tree = ast.parse((REPO / filename).read_text(encoding="utf-8"))
    own = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
            own.add(node.name)
    return own


for filename in ("web.py", "agent.py", "worker.py"):
    own = defines_locally(filename, {
        "_rate_limit_key", "rate_limit_key",
        "_note_auth_fail", "note_auth_fail",
        "_client_ip", "parse_tool_arguments",
    })
    check(not own, f"{filename} defines its own copy instead of importing: {sorted(own)}")

if failures:
    print("\n" + str(failures) + " checks failed", file=sys.stderr)
    sys.exit(1)
print("ok - tool calls and the auth-failure counter have one source each")
