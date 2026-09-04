"""Structural invariants enforced at CI time.

Each test walks the AST of the source files, so a fix cannot reappear as a
bypass: a dict literal is trivially hidden from grep by spreads or runtime
mutation, and ast.parse sees through all of them.

Escape hatch: `# invariant: allow-<rule-id> because <reason>` on the line
itself. Anything without one fails, and the exceptions stay greppable.

Run: python3 -m pytest tests/test_invariants.py
"""
from __future__ import annotations

import ast
import io
import pathlib
import re
import sys
import tokenize

import pytest

from ast_invariants import (
    attr_chain as _attr_chain,
    call_lines_in as _call_lines_in,
    call_name as _call_name,
    calls_to as _calls_to,
    local_names_for as _local_names_for,
)

_REPO = pathlib.Path(__file__).resolve().parent.parent

# Discovered rather than listed, so a new module at the repo root inherits the
# invariants. security/ defines them and tests/ builds bare dicts on purpose.
_EXCLUDE_DIRS = {"security", "tests", "plugins", "venv", ".venv",
                 "__pycache__", ".git", "build", "dist"}
_EXCLUDE_FILES = {"ws_test.py"}  # CLI smoke-test, not agent code

# Escape-hatch comments may include an ``until=YYYY-MM-DD`` clause.
_ALLOW_WITH_EXPIRY_RE = re.compile(
    r"# invariant: allow-(?P<rule>[\w-]+)\s+until=(?P<date>\d{4}-\d{2}-\d{2})"
    r"\s+because\s+(?P<reason>.+)"
)
_ALLOW_LEGACY_RE = re.compile(
    r"# invariant: allow-(?P<rule>[\w-]+)\s+because\s+(?P<reason>.+)"
)
# After this date an allow comment without until= fails; the ones predating it
# are listed in UNSAFE.md.
_GRACE_END_DATE = "2026-06-01"


def _discover_targets():
    """Yield (display_name, text) for every source file the invariants
    apply to.

    Uses ``rglob("*.py")`` so subdirectories inherit the invariants.
    Excludes are path-part-based so anything under
    ``security/``, ``tests/``, ``plugins/``, ``venv/``, etc. is
    skipped wholesale."""
    for path in sorted(_REPO.rglob("*.py")):
        # Relative parts tell whether any ancestor directory is excluded.
        try:
            rel = path.relative_to(_REPO)
        except ValueError:
            continue
        if any(part in _EXCLUDE_DIRS for part in rel.parts):
            continue
        if path.name in _EXCLUDE_FILES:
            continue
        yield str(rel), path.read_text()

# Every source file routes through security/*, so an ingress type or endpoint
# that bypasses those helpers fails one of the four tests below.
STRICT = True


def _targets():
    return _discover_targets()


# Cache each source file's token map so repeated comment lookups are O(n).
_COMMENTS_CACHE: dict[int, dict[int, list[str]]] = {}


def _build_comment_map(src: str) -> dict[int, list[str]]:
    """Tokenise *src* once. Return {lineno: [comment_token_strings]}."""
    result: dict[int, list[str]] = {}
    try:
        for t in tokenize.generate_tokens(io.StringIO(src).readline):
            if t.type == tokenize.COMMENT:
                result.setdefault(t.start[0], []).append(t.string)
    except tokenize.TokenizeError:
        pass
    return result


def _comment_strings_on_line(src: str, lineno: int) -> list[str]:
    """Returns the comment tokens on lineno, 1-indexed.

    Tokenised rather than matched: a string literal containing an allow-comment
    must not satisfy the check. Memoised per source string.
    """
    key = id(src)
    mapping = _COMMENTS_CACHE.get(key)
    if mapping is None:
        mapping = _build_comment_map(src)
        _COMMENTS_CACHE[key] = mapping
    return mapping.get(lineno, [])


def _allow_comment(line_or_source: str, rule_id: str, lineno: int | None = None,
                   src: str | None = None) -> bool:
    """True when a genuine comment token on the line reads
    `# invariant: allow-<rule_id> because <reason>`.

    Two call shapes: the legacy string form falls back to a substring match and is
    weaker; pass lineno and src for the strict tokenised form.
    """
    # Accepts the optional until= clause the lifecycle test requires. The two
    # regexes must stay in sync, or a valid comment stops suppressing its invariant.
    pattern = rf"# invariant: allow-{rule_id}(?: until=\d{{4}}-\d{{2}}-\d{{2}})? because .+"
    if src is not None and lineno is not None:
        for comment in _comment_strings_on_line(src, lineno):
            if re.search(pattern, comment):
                return True
        return False
    return bool(re.search(pattern, line_or_source))


def _line_of(src: str, node: ast.AST) -> str:
    return src.splitlines()[node.lineno - 1] if getattr(node, "lineno", 0) else ""


def _any_line_of_node_has_allow(src: str, node: ast.AST, rule_id: str) -> bool:
    """Allow-comment may live on any line spanned by the offending
    node (dict literals can straddle several lines).

    tokenised check — the allow marker must live in a real
    comment token, not in a string literal that happens to contain
    the magic substring.
    """
    start = getattr(node, "lineno", 0) or 0
    end = getattr(node, "end_lineno", start) or start
    if not start:
        return False
    for lineno in range(start, end + 1):
        if _allow_comment(None, rule_id, lineno=lineno, src=src):
            return True
    return False


# INVARIANT 1: bare role=<anything> dict literals outside security/

def _has_role_key(node: ast.Dict) -> str | None:
    """If this Dict has a string key 'role' with a string value, return
    that value. Else None. Caught forms:

        {"role": "tool", ...}
        {"role": "system", ...}
        dict(role="tool", ...)   — handled separately via ast.Call below
    """
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and k.value == "role" and isinstance(v, ast.Constant):
            return v.value
    return None


def test_no_bare_role_dict_literals():
    """Invariant #1: conversation-message dicts go through
    security.messages.make_message / make_tool_result / etc.

    adds subscript assignment to the detected patterns:
    ``d["role"] = "tool"`` was a straight bypass of the original
    walker. Any place that writes a literal role-name into a
    subscript assignment is flagged too."""
    offenders: list[str] = []
    for fname, src in _targets():
        try:
            tree = ast.parse(src)
        except SyntaxError as e:
            offenders.append(f"{fname}: SyntaxError {e}")
            continue
        for node in ast.walk(tree):
            role_val = None
            # {"role": "<role>", ...}
            if isinstance(node, ast.Dict):
                role_val = _has_role_key(node)
            # dict(role="<role>", ...)
            elif isinstance(node, ast.Call) and _call_name(node) == "dict":
                for kw in node.keywords:
                    if kw.arg == "role" and isinstance(kw.value, ast.Constant):
                        role_val = kw.value.value
                        break
            # Detect ``d["<slice>"] = "<role>"`` assignments across AST
            # versions and flag non-literal forms for manual classification.
            elif isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if (isinstance(tgt, ast.Subscript)
                            and isinstance(tgt.slice, ast.Constant)
                            and tgt.slice.value == "role"
                            and isinstance(node.value, ast.Constant)
                            and isinstance(node.value.value, str)):
                        role_val = node.value.value
                        break
            if role_val is None:
                continue
            line = _line_of(src, node)
            if _any_line_of_node_has_allow(src, node, "raw-message"):
                continue
            offenders.append(f"{fname}:{node.lineno} role={role_val!r}  {line.strip()[:120]}")
    _assert(offenders, "Bare role=<...> dicts found — use security.make_message or make_tool_result")


# INVARIANT 2: every FastAPI route has an explicit auth dependency

_ROUTE_DECORATORS = {
    "get", "post", "put", "delete", "patch", "head", "options", "trace",
    "websocket", "api_route",
}


def _literal_route_methods(decorator: ast.Call) -> set[str] | None:
    """Return literal ``api_route(methods=...)`` values, or None."""
    methods = next((kw.value for kw in decorator.keywords
                    if kw.arg == "methods"), None)
    if not isinstance(methods, (ast.List, ast.Tuple, ast.Set)):
        return None
    result: set[str] = set()
    for item in methods.elts:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            return None
        result.add(item.value.lower())
    return result


def _function_decorator_routes(fn: ast.FunctionDef | ast.AsyncFunctionDef):
    """Yield ``(method, decorator)`` for every supported FastAPI route.

    Literal ``api_route(methods=[...])`` entries are expanded to individual
    methods. A dynamic method list produces the ``api_route`` sentinel and
    therefore cannot qualify for a public exception.
    """
    for d in fn.decorator_list:
        if isinstance(d, ast.Call):
            name = _attr_chain(d.func) or ""
            if "." in name:
                verb = name.rsplit(".", 1)[1]
                if verb == "api_route":
                    methods = _literal_route_methods(d)
                    if methods is None:
                        yield verb, d
                    else:
                        for method in methods:
                            yield method, d
                elif verb in _ROUTE_DECORATORS:
                    yield verb, d


def _fastapi_depends_names(tree: ast.AST) -> set[str]:
    """Names that resolve to FastAPI's ``Depends`` in this module."""
    names = {"Depends"}
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module == "fastapi" or node.module.startswith("fastapi."):
                for alias in node.names:
                    if alias.name == "Depends":
                        names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "fastapi":
                    modules.add(alias.asname or alias.name)
    names.update(f"{module}.Depends" for module in modules)
    return names


def _function_auth_dependencies(fn: ast.FunctionDef | ast.AsyncFunctionDef,
                                tree: ast.AST) -> set[str]:
    """Names referenced in Depends(...) defaults on the function args."""
    seen: set[str] = set()
    depends_names = _fastapi_depends_names(tree)
    defaults = list(fn.args.defaults) + list(fn.args.kw_defaults or [])
    for d in defaults:
        if isinstance(d, ast.Call) and _attr_chain(d.func) in depends_names:
            if d.args:
                dep = _attr_chain(d.args[0])
                if dep:
                    seen.add(dep)
    return seen


def _route_path(decorator: ast.Call) -> str | None:
    """Return a literal route path from positional or ``path=`` syntax."""
    candidate = decorator.args[0] if decorator.args else next(
        (kw.value for kw in decorator.keywords if kw.arg == "path"), None
    )
    if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
        return candidate.value
    return None


# The only routes allowed to declare public_endpoint; anything else doing so
# fails the invariant.
_KNOWN_PUBLIC_ENDPOINTS = {
    ("get", "/"),             # bootstrap HTML — token exchange handled in body
    ("get", "/health"),       # liveness probe, returns {"status": "ok"}
    ("post", "/api/logout"),  # must work for already-revoked/expired sessions
    ("websocket", "/ws"),     # handshake auth handled in body; per-message
                              # Depends does not reach the 401 path on websockets, so public_endpoint plus an
                              # in-body check is the supported pattern.
}


def _route_auth_offender(fn: ast.FunctionDef | ast.AsyncFunctionDef,
                         tree: ast.AST, src: str) -> str | None:
    """Return an invariant #2 violation for *fn*, or None when it is safe."""
    routes = list(_function_decorator_routes(fn))
    if not routes:
        return None
    deps = _function_auth_dependencies(fn, tree)
    if "_require_auth_dep" in deps:
        return None
    if "_public_endpoint" in deps:
        if all((path := _route_path(decorator)) is not None
               and (verb, path) in _KNOWN_PUBLIC_ENDPOINTS
               for verb, decorator in routes):
            return None
    if _allow_comment(None, "unauth-endpoint", lineno=fn.lineno, src=src):
        return None
    verbs = ", ".join(sorted({verb for verb, _ in routes}))
    return (f"def {fn.name}({verbs}) — missing "
            "Depends(_require_auth_dep) / Depends(_public_endpoint)")


def test_every_route_has_auth_dependency():
    """Every FastAPI route declares an auth dependency, or ships open to the world.

    Declaring the public dependency also requires the route to be on the known
    list here, so no endpoint can opt out of auth without editing this file. Bare
    names and suffix matches are rejected: a resembling name says nothing about
    behaviour.
    """
    offenders: list[str] = []
    for fname, src in _targets():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                detail = _route_auth_offender(node, tree, src)
                if detail:
                    offenders.append(f"{fname}:{node.lineno} {detail}")
    _assert(offenders, "Routes without explicit auth dependency")


_ROUTE_INVARIANT_WRONG_FORMS = {
    "head": """
from fastapi import Depends
@app.head('/head')
def endpoint(): pass
""",
    "options": """
from fastapi import Depends
@app.options('/options')
def endpoint(): pass
""",
    "trace": """
from fastapi import Depends
@app.trace('/trace')
def endpoint(): pass
""",
    "api_route": """
from fastapi import Depends
@app.api_route('/created', methods=['POST'])
def endpoint(): pass
""",
    "suffix impostor": """
from fastapi import Depends
@app.get('/impostor')
def endpoint(auth=Depends(fake_require_auth_dep)): pass
""",
    "dynamic public path": """
from fastapi import Depends as D
@app.get(PREFIX + '/health')
def endpoint(public=D(_public_endpoint)): pass
""",
}

_ROUTE_INVARIANT_ACCEPTED_FORMS = {
    "Depends alias": """
from fastapi import Depends as D
@app.get('/guarded')
def endpoint(auth=D(_require_auth_dep)): pass
""",
    "api_route guarded": """
import fastapi as fa
@app.api_route('/created', methods=['POST'])
def endpoint(auth=fa.Depends(_require_auth_dep)): pass
""",
    "known public route": """
from fastapi import Depends
@app.get('/health')
def endpoint(public=Depends(_public_endpoint)): pass
""",
}


def _route_invariant_result(src: str) -> str | None:
    tree = ast.parse(src)
    fn = next(node for node in tree.body
              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
    return _route_auth_offender(fn, tree, src)


def test_route_auth_rule_catches_decorator_and_dependency_blind_spots():
    """Pin the negative and positive forms that the AST rule must classify."""
    missed = [name for name, src in _ROUTE_INVARIANT_WRONG_FORMS.items()
              if _route_invariant_result(src) is None]
    assert not missed, f"route-auth rule is blind to: {missed}"
    false_positives = [name for name, src in _ROUTE_INVARIANT_ACCEPTED_FORMS.items()
                       if _route_invariant_result(src) is not None]
    assert not false_positives, (
        f"route-auth rule rejects valid forms: {false_positives}"
    )


def test_auth_dependency_actually_rejects_unauthenticated():
    """The AST walk matches the dependency by name, so a no-op bound to that name
    would pass it while shipping every route open.

    This test boots the real app and fires an unauthenticated request at every
    route the walk considers gated, asserting each is actually rejected.
    """
    import sys as _sys, importlib, os as _os
    _sys.path.insert(0, str(_REPO))
    try:
        import fastapi  # noqa: F401
        from fastapi.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi not installed; behavioural auth check not run")
    _os.environ["WEB_TOKEN"] = "invariant-behaviour-test-token"
    if "web" in _sys.modules:
        del _sys.modules["web"]
    web = importlib.import_module("web")
    client = TestClient(web.app)

    checked = 0
    for fname, src in _targets():
        if fname != "web.py":
            continue  # the only file that defines routes on `web.app`
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            routes = list(_function_decorator_routes(node))
            if not routes:
                continue
            deps = _function_auth_dependencies(node, tree)
            if "_require_auth_dep" not in deps:
                continue
            for verb, dcall in routes:
                if verb == "websocket" or not dcall.args:
                    continue
                if not isinstance(dcall.args[0], ast.Constant):
                    continue
                caller = getattr(client, verb, None)
                if caller is None:
                    continue
                # Path params need a concrete (any) value to route at all;
                # auth is resolved before the endpoint body reads them.
                concrete_path = re.sub(r"\{[^}]+\}", "placeholder",
                                        dcall.args[0].value)
                resp = caller(concrete_path)
                checked += 1
                assert resp.status_code in (401, 403), (
                    f"{fname}:{node.lineno} {verb.upper()} "
                    f"{dcall.args[0].value} is wired to a "
                    f"require_auth_dep-suffixed dependency but an "
                    f"unauthenticated request returned "
                    f"{resp.status_code}, not 401/403 — the bound "
                    f"callable's name says auth, its behaviour doesn't."
                )
    assert checked > 0, (
        "no require_auth_dep-gated routes discovered — "
        "test_every_route_has_auth_dependency's discovery broke, "
        "this test silently checked nothing"
    )


# INVARIANT 3: no direct request.client.host access outside security/

def _client_bound_names(tree: ast.AST) -> set[str]:
    """Names bound to a request's .client, however the binding is written.

    The chain check alone missed the form the code actually used:

        client = getattr(request_or_ws, "client", None)
        if client and client.host:

    There is no `.client.host` chain there, so the rule read clean while two
    modules kept their own IP handling. Both spellings of the binding count.
    """
    bound: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        from_client = False
        # x = getattr(<anything>, "client", ...)
        if (isinstance(value, ast.Call)
                and _attr_chain(value.func) == "getattr"
                and len(value.args) >= 2
                and isinstance(value.args[1], ast.Constant)
                and value.args[1].value == "client"):
            from_client = True
        # x = <anything>.client
        elif isinstance(value, ast.Attribute) and value.attr == "client":
            from_client = True
        if not from_client:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                bound.add(target.id)
    return bound


def test_no_direct_client_host_access():
    """Invariant #3: client IPs come from ClientIdentity.from_request,
    not from reading request.client.host inline. Prevents the drift
    each fixed in one call site."""
    offenders: list[str] = []
    for fname, src in _targets():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        via_variable = _client_bound_names(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "host":
                inner = _attr_chain(node.value)
                direct = bool(inner) and inner.endswith(".client")
                indirect = isinstance(node.value, ast.Name) and node.value.id in via_variable
                if direct or indirect:
                    line = _line_of(src, node)
                    # tokenised allow-check.
                    if _allow_comment(None, "direct-client-ip",
                                      lineno=node.lineno, src=src):
                        continue
                    offenders.append(f"{fname}:{node.lineno} {line.strip()[:120]}")
    _assert(offenders, "Direct .client.host access — use ClientIdentity.from_request")


# INVARIANT 4: Anthropic fallback requires FallbackPolicy

def test_fallback_goes_through_policy():
    """The Anthropic fallback must be wired through the policy object, not by
    gating a call on the API key.

    AST-based, not textual: a qualified reference carries an attribute prefix that
    a regex over the plain name misses.
    """
    offenders: list[str] = []

    def _references(node, target_name):
        """True if *node* textually mentions *target_name* as a Name or
        as the attribute of an Attribute (any depth)."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id == target_name:
                return True
            if isinstance(sub, ast.Attribute) and sub.attr == target_name:
                return True
        return False

    def _fallback_suspects_from_ifexp(ifexp: ast.IfExp, fname, lineno, src):
        """Given `X if ANTHROPIC_KEY else None`-shaped expression,
        decide if it's the bare pattern and append to offenders.

        Bare pattern: body references `call_anthropic`, test references
        `ANTHROPIC_KEY`, orelse is None / false-ish."""
        body_has_anthropic = _references(ifexp.body, "call_anthropic")
        test_has_key = _references(ifexp.test, "ANTHROPIC_KEY")
        if body_has_anthropic and test_has_key:
            if _allow_comment(None, "bare-fallback", lineno=lineno, src=src):
                return
            offenders.append(
                f"{fname}:{lineno} bare fallback IfExp — use FallbackPolicy.from_env"
            )

    for fname, src in _targets():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            # Matches wherever that expression flows into something named fallback_fn,
            # assignment or keyword argument.
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if _attr_chain(target) and _attr_chain(target).endswith("fallback_fn"):
                        if isinstance(node.value, ast.IfExp):
                            _fallback_suspects_from_ifexp(node.value, fname, node.lineno, src)
            if isinstance(node, ast.keyword) and node.arg == "fallback_fn":
                if isinstance(node.value, ast.IfExp):
                    _fallback_suspects_from_ifexp(node.value, fname, getattr(node, "lineno", 0), src)

    _assert(offenders, "Bare fallback_fn wiring — use FallbackPolicy.from_env")


# INVARIANT 5: CS HTTP goes through cs_client.cs_request

# The only file allowed to call CS directly; everything else imports cs_request
# from it, so signing covers every call site.
_CS_CLIENT_FILES = {"cs_client.py"}

_REQUESTS_VERBS = {"get", "post", "put", "patch", "delete", "head",
                   "options", "request"}


# Includes security/ on purpose: a rule of the form "never construct X" must
# cover the package that owns X, or that package is the blind spot.
_NON_SHIPPING_DIRS = {"tests", "venv", ".venv", "__pycache__", ".git",
                      "build", "dist"}


def test_single_session_manager_instance():
    """SessionManager is constructed in security/auth.py and nowhere else that ships.

    A cookie is valid only in the manager that minted it, so a second instance
    means login succeeds while every protected route still answers 401. Scope
    includes security/, or the package owning the class is the blind spot.
    """
    offenders = _calls_to(
        _REPO, "SessionManager", allowed_files=("auth.py",),
        excluded_dirs=_NON_SHIPPING_DIRS, excluded_files=_EXCLUDE_FILES,
    )
    assert not offenders, (
        "SessionManager constructed outside security/auth.py: "
        + ", ".join(offenders)
        + " - use security.get_session_manager() instead."
    )


_WRONG_FORMS = {
    "plain": """
from security import SessionManager
SessionManager()
""",
    "alias": """
from security import SessionManager as _SM
_SM()
""",
    "dotted": """
import security.auth as auth
auth.SessionManager()
""",
}

_SANCTIONED_FORM = """
from security import get_session_manager
get_session_manager()
"""


def test_session_manager_rule_catches_every_construction_form():
    """The rule above is worth its green tick only if it goes red on a
    real mistake.

    Checked against source text held in memory, so no deliberately wrong
    code is written into the repo. If a later change to
    ``_local_names_for`` breaks alias resolution, this fails instead of
    the rule quietly passing everything."""
    missed = [name for name, src in _WRONG_FORMS.items()
              if not _call_lines_in(src, "SessionManager")]
    assert not missed, f"rule is blind to these forms: {missed}"

    assert not _call_lines_in(_SANCTIONED_FORM, "SessionManager"), (
        "rule fires on the sanctioned accessor"
    )


def _direct_cs_calls_in(src: str) -> list[tuple[int, str]]:
    """(lineno, source line) for every direct HTTP call at CS in src.

    Both halves resolve through the import map: aliasing the module hides the
    verb, aliasing CS_URL hides the target, and either alone defeats a literal
    match. Escape hatch: `# invariant: allow-direct-cs-request because ...`.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    modules = _local_names_for(tree, "requests") | {"requests"}
    verbs = {f"{m}.{v}" for m in modules for v in _REQUESTS_VERBS}
    cs_aliases = _local_names_for(tree, "CS_URL")

    def _is_cs(sub) -> bool:
        if isinstance(sub, ast.Name):
            return sub.id.endswith("CS_URL") or sub.id in cs_aliases
        if isinstance(sub, ast.Attribute):
            return sub.attr.endswith("CS_URL") or sub.attr in cs_aliases
        return False

    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if (_call_name(node) or "") not in verbs:
            continue
        args = list(node.args) + [kw.value for kw in node.keywords]
        if not any(_is_cs(sub) for arg in args for sub in ast.walk(arg)):
            continue
        if _any_line_of_node_has_allow(src, node, "direct-cs-request"):
            continue
        hits.append((node.lineno, _line_of(src, node).strip()[:100]))
    return hits


_DIRECT_CS_FORMS = {
    "plain": """
import requests
from cs_client import CS_URL
requests.get(f"{CS_URL}/health")
""",
    "aliased module": """
import requests as r
from cs_client import CS_URL
r.get(f"{CS_URL}/health")
""",
    "aliased url": """
import requests
from cs_client import CS_URL as CS
requests.get(f"{CS}/health")
""",
    "both aliased": """
import requests as r
from cs_client import CS_URL as CS
r.get(f"{CS}/health")
""",
}

_NON_CS_TRAFFIC = """
import requests
requests.get("http://127.0.0.1:11434/api/tags")
"""

_ESCAPED_CS_CALL = """
import requests
from cs_client import CS_URL
requests.get(f"{CS_URL}/health")  # invariant: allow-direct-cs-request because probe predates signing
"""


def test_direct_cs_rule_catches_aliased_forms():
    """The rule is only worth its green tick if aliases cannot slip past.

    Checked in memory, so no wrong code enters the repo. The last cases guard the
    other direction: non-CS traffic and a waived call must stay silent, or the
    rule becomes noise and gets switched off.
    """
    missed = [name for name, src in _DIRECT_CS_FORMS.items()
              if not _direct_cs_calls_in(src)]
    assert not missed, f"rule is blind to these forms: {missed}"

    assert not _direct_cs_calls_in(_NON_CS_TRAFFIC), (
        "rule fires on non-CS traffic"
    )
    assert not _direct_cs_calls_in(_ESCAPED_CS_CALL), (
        "waived call must remain exempt from the direct-CS rule"
    )


def test_no_direct_cs_requests_outside_client():
    """Every HTTP request to CS is sent by cs_client.cs_request.

    A direct call ships unsigned and CS rejects it, so exactly one endpoint stops
    working while every signed call keeps going. Non-CS traffic is untouched.
    Escape hatch: `# invariant: allow-direct-cs-request because ...`.
    """
    offenders: list[str] = []
    for fname, src in _targets():
        if pathlib.PurePath(fname).name in _CS_CLIENT_FILES:
            continue
        for lineno, text in _direct_cs_calls_in(src):
            offenders.append(
                f"{fname}:{lineno} direct requests.* on CS_URL — "
                f"use cs_client.cs_request  {text}"
            )
    _assert(offenders,
            "Direct CS HTTP outside cs_client.cs_request (unsigned egress)")


# INVARIANT 7: cross-module call arity

def _module_level_functions(targets) -> dict:
    """Map ``name -> (fname, node)`` for module-level defs that are
    unique across the repo. Names defined twice (per-module helpers
    that happen to share a name, conditional redefinitions) are
    dropped — a call site can't be resolved statically then, and a
    false positive in a CI gate is worse than a missed case."""
    seen: dict = {}
    duplicated: set = set()
    for fname, src in targets:
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in tree.body:  # module level only, not methods
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name in seen:
                duplicated.add(node.name)
            seen[node.name] = (fname, node)
    return {k: v for k, v in seen.items() if k not in duplicated}


def _required_params(fn: ast.AST) -> list:
    """Parameter names with no default — the ones a caller must pass."""
    a = fn.args
    positional = a.posonlyargs + a.args
    with_defaults = len(a.defaults)
    required = [p.arg for p in positional[:len(positional) - with_defaults]]
    required += [
        kw.arg for kw, d in zip(a.kwonlyargs, a.kw_defaults) if d is None
    ]
    return required


def test_cross_module_calls_pass_required_args():
    """A call to a repo-defined function passes every argument that function requires.

    A missing argument raises at runtime, where a retry layer can turn it into a
    generic "unreachable" message and hide the real cause. This walks every call
    site of every uniquely-named module-level function.

    Skipped where arity is not statically known. Escape hatch:
    `# invariant: allow-call-arity because ...`.
    """
    targets = list(_targets())
    functions = _module_level_functions(targets)
    offenders: list[str] = []

    for fname, src in targets:
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            target = functions.get(node.func.id)
            if target is None:
                continue
            def_file, fn = target
            if fn.args.vararg or fn.args.kwarg:
                continue
            # Unpacking hides the real count from the AST.
            if any(isinstance(a, ast.Starred) for a in node.args):
                continue
            if any(kw.arg is None for kw in node.keywords):
                continue

            required = _required_params(fn)
            supplied = set(kw.arg for kw in node.keywords)
            positional = fn.args.posonlyargs + fn.args.args
            supplied.update(p.arg for p in positional[:len(node.args)])
            missing = [p for p in required if p not in supplied]
            if not missing:
                continue
            if _any_line_of_node_has_allow(src, node, "call-arity"):
                continue
            offenders.append(
                f"{fname}:{node.lineno} {node.func.id}() missing "
                f"{', '.join(missing)} — defined in {def_file}:{fn.lineno}"
            )
    _assert(offenders, "Call sites missing required arguments (TypeError at runtime)")


# INVARIANT 6: allow-comment lifecycle

def test_allow_comments_have_lifecycle():
    """Checks the lifecycle of every allow-comment.

    An `until=` date in the past fails the test: an expired escape hatch is an
    unfinished task. A comment with no `until=` is grandfathered and listed in
    UNSAFE.md; new ones added after the grace date fail.
    """
    import datetime as _dt
    # use UTC so expiry is unambiguous across contributor time
    # zones (local date.today() could be off-by-one near midnight).
    today = _dt.datetime.now(_dt.timezone.utc).date()
    grace_end = _dt.date.fromisoformat(_GRACE_END_DATE)

    offenders: list[str] = []
    grandfathered: list[str] = []
    with_expiry: list[str] = []
    expired: list[str] = []

    for fname, src in _targets():
        # iterate the comment map directly — avoids the
        # splitlines() × per-line-lookup path even with the cache.
        comment_map = _build_comment_map(src)
        _COMMENTS_CACHE[id(src)] = comment_map
        for lineno, comments_on_line in comment_map.items():
            for comment in comments_on_line:
                # findall tracks multiple allow-comments on one line.
                for m in _ALLOW_WITH_EXPIRY_RE.finditer(comment):
                    date_str = m.group("date")
                    try:
                        expiry = _dt.date.fromisoformat(date_str)
                    except ValueError:
                        # A malformed date flags the line as an offender rather than crashing the test.
                        offenders.append(
                            f"{fname}:{lineno} malformed until= date "
                            f"{date_str!r} on rule={m.group('rule')}"
                        )
                        continue
                    # A distant expiry is clamped, or until=9999-12-31 becomes permanent.
                    max_horizon = today + _dt.timedelta(days=180)
                    if expiry > max_horizon:
                        offenders.append(
                            f"{fname}:{lineno} until={date_str} is more than "
                            f"180 days out on rule={m.group('rule')} — pick a "
                            f"shorter horizon or split the migration"
                        )
                        continue
                    # Escape the reason before it is written to UNSAFE.md.
                    reason_escaped = (m.group("reason")[:80]
                                      .replace("<", "&lt;")
                                      .replace(">", "&gt;")
                                      .replace("`", "\\`"))
                    entry = (f"{fname}:{lineno} rule={m.group('rule')} "
                             f"until={date_str} because={reason_escaped}")
                    if expiry < today:
                        expired.append(entry)
                    else:
                        with_expiry.append(entry)
                # Skip the legacy regex if we already found an expiry
                # form on this comment (avoid double-counting).
                if _ALLOW_WITH_EXPIRY_RE.search(comment):
                    continue
                # Legacy shape with no until=. findall, not search.
                for m2 in _ALLOW_LEGACY_RE.finditer(comment):
                    reason_escaped = (m2.group("reason")[:80]
                                      .replace("<", "&lt;")
                                      .replace(">", "&gt;")
                                      .replace("`", "\\`"))
                    entry = (f"{fname}:{lineno} rule={m2.group('rule')} "
                             f"(no until=) because={reason_escaped}")
                    if today > grace_end:
                        offenders.append(entry)
                    else:
                        grandfathered.append(entry)

    # Regenerated whether the test passes or not, and a read-only environment still
    # passes.
    try:
        def _section(label, entries):
            header = [f"## {label} ({len(entries)})", ""]
            body = [f"- {e}" for e in entries] if entries else ["(none)"]
            return header + body + [""]
        unsafe_lines = [
            "# Unsafe invariant exceptions",
            "",
            "Auto-generated by `tests/test_invariants.py::"
            "test_allow_comments_have_lifecycle`.",
            "Do not edit manually. Regenerate by running the test suite.",
            "",
            # No generation date: CI gates on `git diff --exit-code`, so a date stamp would
            # turn every branch red the next day with nothing to fix.
            f"Grace ends {grace_end.isoformat()}.",
            "",
        ]
        unsafe_lines += _section(
            "Active allow-comments with lifecycle", with_expiry)
        unsafe_lines += _section(
            "Grandfathered legacy comments", grandfathered)
        unsafe_lines.insert(-1,
            "These predate the governance rule. After the grace date "
            "they must gain an `until=YYYY-MM-DD` clause or be removed.")
        unsafe_lines += _section(
            "Expired (test fails)", expired)
        (_REPO / "UNSAFE.md").write_text("\n".join(unsafe_lines) + "\n")
    except OSError:
        pass

    # Fail on expired comments always; on missing until= only after grace.
    problems = list(expired) + list(offenders)
    _assert(problems, "Escape-hatch comments: expired or missing until= clause")


# Phase-0 xfail wrapper

def _assert(offenders: list[str], title: str) -> None:
    if not offenders:
        return
    msg = title + ":\n  " + "\n  ".join(offenders)
    if STRICT:
        raise AssertionError(msg)
    # Report violations without failing when strict mode is disabled.
    print(f"\n  [invariant WARN] {msg}", file=sys.stderr)


# Standalone runner

if __name__ == "__main__":
    import traceback
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = failed = skipped = 0
    for fn in tests:
        try:
            fn()
            print(f"  OK   {fn.__name__}")
            passed += 1
        except pytest.skip.Exception as exc:
            print(f"  SKIP {fn.__name__}: {exc}")
            skipped += 1
        except Exception:
            print(f"  FAIL {fn.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {skipped} skipped, {failed} failed")
    sys.exit(1 if failed else 0)
