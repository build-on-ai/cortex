# Web search through a self-hosted SearXNG, so queries never leave this host
# for a search engine directly. Expects it on localhost:8888; set
# WEB_SEARCH_SEARXNG_URL if it runs elsewhere.

import json
import os

import requests

PLUGIN_NAME = "web_search"

_SEARXNG_URL = os.environ.get("WEB_SEARCH_SEARXNG_URL", "http://localhost:8888").rstrip("/")
_TIMEOUT = float(os.environ.get("WEB_SEARCH_TIMEOUT", "8"))
_USER_AGENT = "Cortex/web_search-plugin"

# Categories SearXNG accepts; "general" covers the largest set of engines.
_VALID_CATEGORIES = {"general", "images", "videos", "news", "map", "music", "it", "science", "files", "social media"}

PLUGIN_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": (
                "Search the web via a local SearXNG instance (privacy-preserving "
                "meta-search). Returns ranked results with title, URL, and snippet. "
                "Queries are sent to your SearXNG host, not directly to Google/Bing. "
                "Useful for: looking up documentation, current events, package versions, "
                "CVE details, recent news. Returns plain-text results, not raw HTML."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (free-text, like you'd type into a search engine).",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default 10, max 30).",
                        "default": 10,
                    },
                    "category": {
                        "type": "string",
                        "description": (
                            "Result category: general | news | science | it | files | "
                            "images | videos | map | music | social media. Default: general."
                        ),
                        "default": "general",
                    },
                    "time_range": {
                        "type": "string",
                        "description": (
                            "Restrict to recent results: day | week | month | year. "
                            "Omit for no time filter."
                        ),
                    },
                },
                "required": ["query"],
            },
        },
    },
]


def _format_results(query: str, payload: dict, max_results: int) -> str:
    """Render SearXNG JSON response as a model-friendly text block."""
    results = payload.get("results") or []
    if not results:
        return (
            f"web_search: no results for query={query!r}.\n"
            f"(SearXNG responded but returned an empty results list — try a different query "
            f"or check that the configured engines in SearXNG are not all disabled.)"
        )

    results = results[:max_results]
    lines = [f"web_search results for query={query!r} (top {len(results)}):", ""]
    for idx, r in enumerate(results, start=1):
        title = (r.get("title") or "(no title)").strip()
        url = (r.get("url") or "").strip()
        content = (r.get("content") or "").strip()
        # Trim very long snippets; the model has limited context budget.
        if len(content) > 400:
            content = content[:397] + "..."
        engine = r.get("engine") or ""
        lines.append(f"[{idx}] {title}")
        if url:
            lines.append(f"    {url}")
        if content:
            lines.append(f"    {content}")
        if engine:
            lines.append(f"    (via {engine})")
        lines.append("")
    # Suggestions / corrections from SearXNG, if present
    suggestions = payload.get("suggestions") or []
    if suggestions:
        lines.append("Related queries: " + ", ".join(suggestions[:5]))
    return "\n".join(lines).rstrip()


def execute_tool(name: str, args: dict) -> str:
    if name != "web_search":
        return f"Unknown tool: {name}"

    query = str(args.get("query", "")).strip()
    if not query:
        return "Error: query is required"
    if len(query) > 500:
        return "Error: query too long (max 500 chars)"

    try:
        max_results = int(args.get("max_results", 10))
    except (TypeError, ValueError):
        max_results = 10
    max_results = max(1, min(30, max_results))

    category = str(args.get("category", "general")).strip().lower()
    if category not in _VALID_CATEGORIES:
        return (
            f"Error: invalid category {category!r}. "
            f"Valid: {', '.join(sorted(_VALID_CATEGORIES))}"
        )

    params = {
        "q": query,
        "format": "json",
        "categories": category,
    }
    time_range = args.get("time_range")
    if time_range:
        time_range = str(time_range).strip().lower()
        if time_range in {"day", "week", "month", "year"}:
            params["time_range"] = time_range

    url = f"{_SEARXNG_URL}/search"
    try:
        resp = requests.get(
            url,
            params=params,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
    except requests.Timeout:
        return (
            f"web_search timed out after {_TIMEOUT}s contacting SearXNG at {_SEARXNG_URL}. "
            f"Is the instance up? Try: curl -sI {_SEARXNG_URL}"
        )
    except requests.ConnectionError as e:
        return (
            f"web_search cannot reach SearXNG at {_SEARXNG_URL}: {e}. "
            f"Set WEB_SEARCH_SEARXNG_URL to point at a running instance, or start one with: "
            f"docker run -d -p 8888:8080 searxng/searxng"
        )
    except requests.RequestException as e:
        return f"web_search request failed: {e}"

    if resp.status_code == 403:
        return (
            "web_search: SearXNG returned 403 Forbidden — the instance likely has "
            "JSON output disabled. Enable it in SearXNG settings.yml: "
            "search.formats must include 'json'."
        )
    if resp.status_code >= 400:
        return (
            f"web_search: SearXNG returned HTTP {resp.status_code}. "
            f"Body (first 200 chars): {resp.text[:200]!r}"
        )

    try:
        payload = resp.json()
    except (ValueError, json.JSONDecodeError):
        return (
            f"web_search: SearXNG response was not JSON. First 200 chars: {resp.text[:200]!r}. "
            f"Check that the instance has search.formats including 'json'."
        )

    return _format_results(query, payload, max_results)
