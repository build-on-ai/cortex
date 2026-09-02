"""Shared AST primitives for structural-invariant tests.

This module deliberately knows nothing about a particular invariant. Callers
provide repository scope and exemptions; the helpers only resolve Python names
and calls consistently across rules.
"""
from __future__ import annotations

import ast
import pathlib
from collections.abc import Iterable, Iterator


def attr_chain(node: ast.AST) -> str | None:
    """Return a dotted name for a Name or Attribute expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = attr_chain(node.value)
        return f"{inner}.{node.attr}" if inner else node.attr
    return None


def call_name(node: ast.AST) -> str | None:
    """Return the dotted function name for a Call, or None."""
    return attr_chain(node.func) if isinstance(node, ast.Call) else None


def local_names_for(tree: ast.AST, symbol: str) -> set[str]:
    """Return local names bound to *symbol* by imports in *tree*."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == symbol:
                    names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[-1] == symbol:
                    names.add(alias.asname or alias.name)
    return names


def call_lines_in(src: str, symbol: str) -> list[int]:
    """Return lines that call *symbol*, including import aliases and dots."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    local = local_names_for(tree, symbol) | {symbol}
    lines: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = call_name(node) or ""
        if name in local or name.split(".")[-1] == symbol:
            lines.append(node.lineno)
    return lines


def shipping_sources(repo: pathlib.Path, excluded_dirs: Iterable[str],
                     excluded_files: Iterable[str]) -> Iterator[tuple[str, str]]:
    """Yield shipping Python source as ``(relative_path, text)`` pairs."""
    excluded_dir_set = set(excluded_dirs)
    excluded_file_set = set(excluded_files)
    for path in sorted(repo.rglob("*.py")):
        try:
            rel = path.relative_to(repo)
        except ValueError:
            continue
        if any(part in excluded_dir_set for part in rel.parts):
            continue
        if path.name in excluded_file_set:
            continue
        yield str(rel), path.read_text()


def calls_to(repo: pathlib.Path, symbol: str, *, allowed_files: Iterable[str],
             excluded_dirs: Iterable[str],
             excluded_files: Iterable[str]) -> list[str]:
    """Return ``file:line`` for calls to *symbol* outside allowed files."""
    allowed_file_set = set(allowed_files)
    hits: list[str] = []
    for fname, src in shipping_sources(repo, excluded_dirs, excluded_files):
        if pathlib.PurePath(fname).name in allowed_file_set:
            continue
        hits.extend(f"{fname}:{line}" for line in call_lines_in(src, symbol))
    return hits
