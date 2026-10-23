"""Structural guard: every agent->API request takes its headers from ``agent_credential()``.

#990's class is a ``requests`` call to ``API_BASE_URL`` that forgot (or hand-rolled)
its ``Authorization`` header, so the hop arrives as nobody and the API has to
trust a self-asserted ``caller_id``. Convention did not stop the first
instance and will not stop the next, so this test walks the AST of every
module an AGENT's process runs (the MCP server package, the shared
orchestration seam and the ``cao agent`` CLI) and fails, naming ``file:line``,
for any ``requests.<verb>`` / ``httpx.<verb>`` call whose URL is built on
``API_BASE_URL`` and whose ``headers=`` does not come from
:func:`security.agent_credential.agent_credential` or one of its aliases.

``headers`` may be the call itself (``headers=_auth_headers() or None``), a
dict spread (``{**mcp_utils._auth_headers(), "Accept": ...}``) or a local name
assigned from one of those in the same function; a URL may likewise be a local
name assigned from an ``API_BASE_URL`` f-string. Anything the walker cannot
prove is a violation (fail closed), the same stance as
``test/test_bearer_scope_boundary.py`` which polices the OTHER direction (the
bearer must not reach non-local URLs).
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "cli_agent_orchestrator"

# Agent-side modules: everything that runs inside a terminal's process tree.
#
# ``ops_mcp_server`` was MISSING here until the agent-principal demo caught the
# consequence: its ``_auth_headers`` read ``get_local_bearer()`` directly, so
# when the ops server ran inside a terminal -- the case its own gate exists for
# -- it presented the operator's token instead of the terminal's. A fourth
# agent -> API egress outside the one credential helper, in the one package this
# census did not walk. Enumerating the package is the only thing that stops the
# fifth.
SCANNED = [
    *sorted((SRC / "mcp_server").rglob("*.py")),
    *sorted((SRC / "ops_mcp_server").rglob("*.py")),
    SRC / "utils" / "orchestration.py",
    SRC / "cli" / "commands" / "agent.py",
]

HTTP_MODULES = {"requests", "httpx"}
VERBS = {"get", "post", "put", "patch", "delete", "head", "request", "stream"}

# The helper and the names that are thin aliases over it.
ACCEPTED = {"agent_credential", "_auth_headers", "_auth_headers_for"}

# Floor on the number of sites the walker must find, so a refactor that renames
# ``requests`` (``import requests as r``) or moves the files cannot silence it.
MIN_EXPECTED_SITES = 40


def _is_http_call(node: ast.Call) -> bool:
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr in VERBS
        and isinstance(func.value, ast.Name)
        and func.value.id in HTTP_MODULES
    )


def _is_api_base_name(node: ast.AST) -> bool:
    return (isinstance(node, ast.Name) and node.id == "API_BASE_URL") or (
        isinstance(node, ast.Attribute) and node.attr == "API_BASE_URL"
    )


def _url_starts_with_api_base(url: ast.AST) -> bool:
    if isinstance(url, ast.JoinedStr) and url.values:
        first = url.values[0]
        return isinstance(first, ast.FormattedValue) and _is_api_base_name(first.value)
    if isinstance(url, ast.BinOp) and isinstance(url.op, ast.Add):
        return _url_starts_with_api_base(url.left) or _is_api_base_name(url.left)
    return _is_api_base_name(url)


def _url_argument(node: ast.Call) -> Optional[ast.AST]:
    for kw in node.keywords:
        if kw.arg == "url":
            return kw.value
    index = 1 if isinstance(node.func, ast.Attribute) and node.func.attr == "request" else 0
    return node.args[index] if len(node.args) > index else None


def _called_names(expr: ast.AST) -> Iterator[str]:
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Name):
                yield f.id
            elif isinstance(f, ast.Attribute):
                yield f.attr


def _is_def(node: ast.AST) -> bool:
    return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))


class _Scope:
    """One function body (or the module body) with its local-name assignments."""

    def __init__(self, node: ast.AST):
        self.node = node
        self.own: List[ast.AST] = []  # nodes lexically here, not in a nested def
        self.assignments: Dict[str, List[ast.AST]] = {}
        self._collect(node)

    def _collect(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if _is_def(child):
                continue  # a nested def is its own scope
            self.own.append(child)
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        self.assignments.setdefault(target.id, []).append(child.value)
            elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                if child.value is not None:
                    self.assignments.setdefault(child.target.id, []).append(child.value)
            self._collect(child)

    def http_calls(self) -> Iterator[ast.Call]:
        for node in self.own:
            if isinstance(node, ast.Call) and _is_http_call(node):
                yield node

    def resolve(self, expr: ast.AST, depth: int = 0) -> List[ast.AST]:
        """Every expression ``expr`` may evaluate to, following local names a few hops."""
        if isinstance(expr, ast.Name) and depth < 3:
            out: List[ast.AST] = []
            for value in self.assignments.get(expr.id, []):
                out.extend(self.resolve(value, depth + 1))
            return out
        return [expr]


def _scopes(tree: ast.Module) -> Iterator[_Scope]:
    yield _Scope(tree)
    for node in ast.walk(tree):
        if _is_def(node):
            yield _Scope(node)


def _check_tree(tree: ast.Module, label: str) -> Tuple[List[str], int]:
    """Return (violations, api_sites_seen) for one parsed module."""
    violations: List[str] = []
    seen = 0
    for scope in _scopes(tree):
        for call in scope.http_calls():
            url = _url_argument(call)
            if url is None:
                continue
            if not any(_url_starts_with_api_base(u) for u in scope.resolve(url)):
                continue  # remote-capable site: test_bearer_scope_boundary owns it
            seen += 1
            headers = next((kw.value for kw in call.keywords if kw.arg == "headers"), None)
            if headers is None:
                violations.append(
                    f"{label}:{call.lineno}: request to API_BASE_URL sends no headers= "
                    "(must pass agent_credential() or an alias)"
                )
                continue
            names = set()
            for candidate in scope.resolve(headers):
                names |= set(_called_names(candidate))
            if not names & ACCEPTED:
                violations.append(
                    f"{label}:{call.lineno}: headers= does not come from agent_credential() "
                    f"or an alias ({', '.join(sorted(ACCEPTED))}); saw {sorted(names) or 'a literal'}"
                )
    return violations, seen


def _check_file(path: Path) -> Tuple[List[str], int]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return _check_tree(tree, path.relative_to(SRC.parent.parent).as_posix())


def _scan(paths=SCANNED) -> Tuple[List[str], int]:
    violations: List[str] = []
    total = 0
    for path in paths:
        v, n = _check_file(path)
        violations.extend(v)
        total += n
    return violations, total


def test_every_agent_request_to_the_api_presents_agent_credential():
    violations, _ = _scan()
    assert violations == [], "\n" + "\n".join(violations)


def test_the_walker_sees_the_sites_it_exists_for():
    _, total = _scan()
    assert total >= MIN_EXPECTED_SITES, total


def test_scanned_set_includes_the_three_agent_surfaces():
    names = {p.relative_to(SRC).as_posix() for p in SCANNED}
    assert {"mcp_server/server.py", "mcp_server/utils.py", "mcp_server/app_tools.py"} <= names
    assert {"utils/orchestration.py", "cli/commands/agent.py"} <= names


@pytest.mark.parametrize(
    ("snippet", "fragment"),
    [
        # bare call, no headers at all
        (
            'def f():\n    requests.get(f"{API_BASE_URL}/terminals", timeout=5)\n',
            "x.py:2: request to API_BASE_URL sends no headers=",
        ),
        # hand-rolled bearer
        (
            "def f(tok):\n"
            '    requests.post(f"{API_BASE_URL}/x", headers={"Authorization": f"Bearer {tok}"})\n',
            "x.py:2: headers= does not come from agent_credential()",
        ),
        # URL through a local name, headers from an unrelated helper
        (
            "def f():\n"
            '    url = f"{API_BASE_URL}/x"\n'
            "    h = other_headers()\n"
            "    requests.get(url, headers=h)\n",
            "x.py:4: headers= does not come from agent_credential()",
        ),
        # a module-level call with a literal
        (
            'requests.get(API_BASE_URL + "/x", headers=None)\n',
            "x.py:1: headers= does not come from agent_credential()",
        ),
        # httpx is covered too
        (
            'def f():\n    httpx.get(f"{API_BASE_URL}/x", headers={})\n',
            "x.py:2: headers= does not come from agent_credential()",
        ),
    ],
    ids=["no-headers", "hand-rolled", "via-locals", "module-level", "httpx"],
)
def test_guard_catches_a_bypass_with_file_and_line(snippet, fragment):
    violations, seen = _check_tree(ast.parse(textwrap.dedent(snippet)), "x.py")
    assert seen == 1
    assert len(violations) == 1 and violations[0].startswith(fragment), violations


@pytest.mark.parametrize(
    "snippet",
    [
        'def f():\n    requests.get(f"{API_BASE_URL}/x", headers=_auth_headers() or None)\n',
        'def f():\n    requests.get(f"{API_BASE_URL}/x", headers=mcp_utils._auth_headers() or None)\n',
        "def f():\n"
        '    h = {**_auth_headers(), "Accept": "text/event-stream"}\n'
        '    requests.get(f"{API_BASE_URL}/x", headers=h, stream=True)\n',
        "def f():\n"
        "    auth_headers = agent_credential() or None\n"
        '    url = f"{API_BASE_URL}/x"\n'
        "    requests.post(url, headers=auth_headers)\n",
        "def f():\n"
        "    def inner():\n"
        "        pass\n"
        '    requests.delete(f"{API_BASE_URL}/x", headers=_auth_headers_for(API_BASE_URL) or None)\n',
    ],
    ids=["direct", "qualified", "dict-spread", "via-locals", "nested-def-sibling"],
)
def test_guard_accepts_the_sanctioned_shapes(snippet):
    violations, seen = _check_tree(ast.parse(textwrap.dedent(snippet)), "x.py")
    assert seen == 1
    assert violations == []


def test_guard_ignores_remote_capable_urls():
    """A URL not built on API_BASE_URL is test_bearer_scope_boundary's business."""
    violations, seen = _check_tree(
        ast.parse('def f(base):\n    requests.get(f"{base}/x", headers={})\n'), "x.py"
    )
    assert (violations, seen) == ([], 0)


# --------------------------------------------------------------------------- #
# The aliases themselves.
#
# The census above proves every call site takes its headers from an ACCEPTED
# name. It said nothing about whether those names are actually aliases over
# ``agent_credential`` -- and that is precisely how ``ops_mcp_server`` shipped an
# ``_auth_headers`` that read ``get_local_bearer()`` directly. Every call site
# was "compliant"; the helper they all went through was the hole. A census of
# call sites with an unchecked definition is a census of nothing.
# --------------------------------------------------------------------------- #
_ALIAS_NAMES = {"_auth_headers", "_auth_headers_for"}


def _alias_definitions() -> Dict[str, bool]:
    """``{"<file>:<line> <name>": calls agent_credential (directly or via a sibling)?}``."""
    out: Dict[str, bool] = {}
    for path in SCANNED:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):  # pragma: no cover - defensive
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name not in _ALIAS_NAMES:
                continue
            called = {
                n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
                for n in ast.walk(node)
                if isinstance(n, ast.Call)
            }
            # ``_auth_headers_for`` delegates to the module's own
            # ``_auth_headers``, which this same test checks independently.
            covered = bool(called & ({"agent_credential"} | (_ALIAS_NAMES - {node.name})))
            rel = path.relative_to(SRC.parents[1])
            out[f"{rel}:{node.lineno} {node.name}"] = covered
    return out


def test_every_accepted_alias_is_really_an_alias():
    """``_auth_headers`` must delegate, not re-implement."""
    definitions = _alias_definitions()
    assert definitions, "no alias definitions found — the walk is broken"
    hand_rolled = sorted(name for name, ok in definitions.items() if not ok)
    assert not hand_rolled, (
        "alias(es) that do not go through agent_credential(): "
        + ", ".join(hand_rolled)
        + ". A call-site census cannot help if the helper every site calls "
        "re-implements credential selection; return agent_credential(...) instead."
    )


def test_the_alias_walk_covers_every_scanned_package():
    """At least one alias per agent-side package, so a package cannot drop out silently."""
    packages = {name.split("/")[2] for name in _alias_definitions()}
    assert {"mcp_server", "ops_mcp_server", "utils"} <= packages, packages


def test_the_alias_check_rejects_a_hand_rolled_definition():
    """The guard can go red for the shape it exists to catch."""
    tree = ast.parse(
        "def _auth_headers():\n"
        "    token = get_local_bearer()\n"
        '    return {"Authorization": f"Bearer {token}"} if token else None\n'
    )
    fn = tree.body[0]
    called = {
        n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
        for n in ast.walk(fn)
        if isinstance(n, ast.Call)
    }
    assert not (called & {"agent_credential"})
