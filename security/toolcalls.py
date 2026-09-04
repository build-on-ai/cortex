"""Reading a model's tool call: the name and the arguments.

Both come from the model, so both are untrusted input on its way into the
policy engine. They were parsed inline in agent.py, worker.py and web.py, in
three copies of the same block — with the name checked before the arguments in
two of them and after in the third.
"""

from __future__ import annotations

import json
import re

# A model can emit anything into function.name; this is what the executor will
# accept as one.
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")


def valid_tool_name(name) -> bool:
    return isinstance(name, str) and bool(_TOOL_NAME_RE.match(name))


def parse_tool_arguments(raw) -> dict:
    """Return the call's arguments as a dict.

    Providers differ: some send a JSON object, others a JSON string. Anything
    that is neither becomes an empty dict rather than an exception, because a
    malformed call has to reach the policy engine and be refused there — a
    crash in the loop would take the whole turn down instead.
    """
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    # A bare string or number is valid JSON but not an argument list.
    return parsed if isinstance(parsed, dict) else {}
