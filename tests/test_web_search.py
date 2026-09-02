"""Smoke tests for plugins/web_search.py.

requests.get is monkey-patched, so no live SearXNG is needed. Covers the happy
path, empty results, invalid query and category, an unreachable instance, a
non-JSON reply, result clamping and the time-range filter.

Run: python3 -m pytest tests/test_web_search.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

# Make project root importable so we can load plugins/web_search.py the same
# way Cortex does at runtime.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

# Import via the file path so we don't depend on the cortex_plugins.<stem>
# namespace that agent.py builds at load time.
import importlib.util

_SPEC = importlib.util.spec_from_file_location(
    "web_search_plugin_under_test",
    PROJECT_ROOT / "plugins" / "web_search.py",
)
web_search = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(web_search)


def _mock_response(status_code: int = 200, json_body: dict | None = None, text: str = ""):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    if json_body is not None:
        resp.json.return_value = json_body
        resp.text = json.dumps(json_body)
    else:
        resp.json.side_effect = ValueError("not json")
        resp.text = text
    return resp


# Happy path


def test_happy_path_returns_formatted_results():
    payload = {
        "results": [
            {
                "title": "ed25519 — Wikipedia",
                "url": "https://en.wikipedia.org/wiki/EdDSA",
                "content": "EdDSA is a digital signature scheme using a variant of Schnorr signature.",
                "engine": "wikipedia",
            },
            {
                "title": "RFC 8032: Edwards-Curve Digital Signature Algorithm",
                "url": "https://datatracker.ietf.org/doc/html/rfc8032",
                "content": "Defines EdDSA, including Ed25519 and Ed448 variants.",
                "engine": "duckduckgo",
            },
        ],
        "suggestions": ["ed25519 keypair", "ed448"],
    }
    with patch.object(requests, "get", return_value=_mock_response(200, payload)) as m:
        out = web_search.execute_tool("web_search", {"query": "ed25519"})
    assert "ed25519 — Wikipedia" in out
    assert "https://en.wikipedia.org/wiki/EdDSA" in out
    assert "RFC 8032" in out
    assert "Related queries:" in out
    # SearXNG was contacted exactly once, with the expected params shape.
    call_kwargs = m.call_args.kwargs
    assert call_kwargs["params"]["q"] == "ed25519"
    assert call_kwargs["params"]["format"] == "json"
    assert call_kwargs["params"]["categories"] == "general"


def test_results_trimmed_to_max_results():
    results = [
        {"title": f"Result {i}", "url": f"https://example.com/{i}", "content": f"snippet {i}"}
        for i in range(20)
    ]
    payload = {"results": results}
    with patch.object(requests, "get", return_value=_mock_response(200, payload)):
        out = web_search.execute_tool("web_search", {"query": "x", "max_results": 5})
    assert "Result 0" in out
    assert "Result 4" in out
    assert "Result 5" not in out


def test_long_snippet_is_truncated():
    long_content = "x" * 1000
    payload = {"results": [{"title": "T", "url": "https://e", "content": long_content}]}
    with patch.object(requests, "get", return_value=_mock_response(200, payload)):
        out = web_search.execute_tool("web_search", {"query": "x"})
    assert "..." in out
    assert "x" * 1000 not in out


# Empty results


def test_empty_results_returns_clear_message():
    payload = {"results": []}
    with patch.object(requests, "get", return_value=_mock_response(200, payload)):
        out = web_search.execute_tool("web_search", {"query": "asdkjfh"})
    assert "no results" in out.lower()
    assert "asdkjfh" in out


# Input validation


def test_unknown_tool_name_returns_error():
    out = web_search.execute_tool("not_web_search", {"query": "x"})
    assert "Unknown tool" in out


def test_empty_query_returns_error():
    out = web_search.execute_tool("web_search", {"query": ""})
    assert "Error" in out
    assert "query is required" in out


def test_query_too_long_returns_error():
    out = web_search.execute_tool("web_search", {"query": "x" * 501})
    assert "Error" in out
    assert "too long" in out


def test_invalid_category_returns_error():
    out = web_search.execute_tool(
        "web_search", {"query": "x", "category": "totally_made_up"}
    )
    assert "Error" in out
    assert "category" in out


def test_max_results_clamps_to_30_max():
    payload = {
        "results": [
            {"title": f"R{i}", "url": f"https://e/{i}", "content": "s"} for i in range(50)
        ]
    }
    with patch.object(requests, "get", return_value=_mock_response(200, payload)):
        out = web_search.execute_tool("web_search", {"query": "x", "max_results": 999})
    # Clamped to 30; result 29 present, result 30 absent.
    assert "R29" in out
    assert "R30" not in out


def test_max_results_clamps_to_1_min():
    payload = {
        "results": [
            {"title": "R1", "url": "https://e/1", "content": "s"},
            {"title": "R2", "url": "https://e/2", "content": "s"},
        ]
    }
    with patch.object(requests, "get", return_value=_mock_response(200, payload)):
        out = web_search.execute_tool("web_search", {"query": "x", "max_results": 0})
    assert "R1" in out
    assert "R2" not in out


def test_non_integer_max_results_falls_back_to_default():
    payload = {"results": [{"title": "T", "url": "https://e", "content": "s"}]}
    with patch.object(requests, "get", return_value=_mock_response(200, payload)):
        out = web_search.execute_tool(
            "web_search", {"query": "x", "max_results": "not-a-number"}
        )
    assert "T" in out


def test_time_range_filter_accepts_valid_values():
    payload = {"results": []}
    with patch.object(requests, "get", return_value=_mock_response(200, payload)) as m:
        web_search.execute_tool(
            "web_search", {"query": "x", "time_range": "week"}
        )
    assert m.call_args.kwargs["params"].get("time_range") == "week"


def test_time_range_filter_drops_invalid_values():
    payload = {"results": []}
    with patch.object(requests, "get", return_value=_mock_response(200, payload)) as m:
        web_search.execute_tool(
            "web_search", {"query": "x", "time_range": "forever"}
        )
    assert "time_range" not in m.call_args.kwargs["params"]


# Network failure modes


def test_connection_error_returns_helpful_hint():
    with patch.object(
        requests, "get", side_effect=requests.ConnectionError("Connection refused")
    ):
        out = web_search.execute_tool("web_search", {"query": "x"})
    assert "cannot reach SearXNG" in out
    assert "WEB_SEARCH_SEARXNG_URL" in out
    assert "docker run" in out  # operator-friendly hint


def test_timeout_returns_operator_hint():
    with patch.object(requests, "get", side_effect=requests.Timeout("timed out")):
        out = web_search.execute_tool("web_search", {"query": "x"})
    assert "timed out" in out.lower()
    assert "curl" in out


def test_403_returns_json_disabled_hint():
    with patch.object(requests, "get", return_value=_mock_response(403, text="Forbidden")):
        out = web_search.execute_tool("web_search", {"query": "x"})
    assert "403" in out
    assert "json" in out.lower()


def test_non_json_response_returns_diagnostic():
    with patch.object(
        requests, "get", return_value=_mock_response(200, text="<html>not json</html>")
    ):
        out = web_search.execute_tool("web_search", {"query": "x"})
    assert "not JSON" in out


def test_500_error_returns_status_in_message():
    with patch.object(
        requests, "get", return_value=_mock_response(500, text="server error")
    ):
        out = web_search.execute_tool("web_search", {"query": "x"})
    assert "500" in out


# Tool schema sanity


def test_plugin_exports_required_symbols():
    """Cortex plugin loader expects these three module attributes."""
    assert hasattr(web_search, "PLUGIN_NAME")
    assert isinstance(web_search.PLUGIN_NAME, str)
    assert hasattr(web_search, "PLUGIN_TOOLS")
    assert isinstance(web_search.PLUGIN_TOOLS, list)
    assert hasattr(web_search, "execute_tool")
    assert callable(web_search.execute_tool)


def test_plugin_tool_schema_shape():
    """PLUGIN_TOOLS entry must match the Ollama tool schema Cortex expects."""
    assert len(web_search.PLUGIN_TOOLS) == 1
    tool = web_search.PLUGIN_TOOLS[0]
    assert tool["type"] == "function"
    fn = tool["function"]
    assert fn["name"] == "web_search"
    assert "description" in fn
    params = fn["parameters"]
    assert params["type"] == "object"
    assert "query" in params["properties"]
    assert "query" in params["required"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
