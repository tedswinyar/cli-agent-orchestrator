"""Structural guard: every run-scoped mutation goes through ``authorize()`` (#965 WS4).

``workflow_cancel`` accepted any ``run_id`` because authorization was enforced per tool
by hand and nothing asked "does this caller own this run". The fix is a chokepoint, and
this test is what keeps the next ``run_id`` route from bypassing it. It walks the AST of
``api/main.py`` and ``mcp_server/server.py`` (the same way ``test_http_only_boundary.py``
polices imports) and fails, naming the function and line, when:

1. a route whose path or signature carries ``run_id`` and whose method mutates (POST,
   PUT, PATCH, DELETE) does not call ``check(...)`` or ``_authorize_run_action(...)``
   with one of the ``RUN_*`` actions, unless it is listed in :data:`KNOWN_UNGATED`
   with a reason;
2. an entry in :data:`KNOWN_UNGATED` no longer exists (a stale exemption is a hole
   waiting to be reused);
3. the helper ``_authorize_run_action`` itself does not call ``check`` (so removing the
   one real decision while keeping the wrapper fails);
4. an MCP tool taking ``run_id`` issues a mutating HTTP call to a ``{run_id}`` path that
   is NOT one of the routes gated in (1): the MCP tools are thin clients, identity
   travels as the bearer, so the server-side gate is the only one — this asserts the
   tool can only reach gated routes;
5. ``workflow_journal.py`` contains an UPDATE statement touching either ownership column
   (ownership is frozen at creation; a resume is a new caller, never a re-stamp).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "cli_agent_orchestrator"
MAIN = SRC / "api" / "main.py"
MCP = SRC / "mcp_server" / "server.py"
JOURNAL = SRC / "services" / "workflow_journal.py"

RUN_ACTIONS = {"RUN_CANCEL", "RUN_RESUME", "RUN_REPLAY"}
GATE_CALLS = {"check", "_authorize_run_action"}
MUTATING = {"post", "put", "patch", "delete"}

#: Mutating ``run_id`` routes deliberately NOT gated by WS4, each with the reason. Adding
#: a route here is a conscious decision that shows up in review; the test also fails
#: if an entry goes stale.
KNOWN_UNGATED: dict[tuple[str, str], str] = {
    ("DELETE", "/workflows/runs/{run_id}"): (
        "deletes retained diagnostics for a finished run; no RUN_DELETE action exists in the "
        "WS0 contract. Open question for the landing PR: gate with RUN_CANCEL semantics."
    ),
    ("POST", "/workflows/runs/{run_id}/steps/{step_id}/output"): (
        "the step's own agent reporting its output; the caller is the step terminal, not the "
        "run owner. Belongs to the caller-identity workstream (TERMINAL_ACT_AS), not to run "
        "ownership."
    ),
}


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------
def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _params(fn: ast.AST) -> set[str]:
    args = fn.args
    return {a.arg for a in args.args + args.kwonlyargs + args.posonlyargs}


def _route_decorator(fn: ast.AST):
    """``(METHOD, path)`` for an ``@app.<method>("<path>")`` decorator, else ``None``."""
    for dec in fn.decorator_list:
        if (
            isinstance(dec, ast.Call)
            and isinstance(dec.func, ast.Attribute)
            and isinstance(dec.func.value, ast.Name)
            and dec.func.value.id == "app"
            and dec.args
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
        ):
            return dec.func.attr.upper(), dec.args[0].value
    return None


def _is_mcp_tool(fn: ast.AST) -> bool:
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr == "tool":
            return True
    return False


def _name_of(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _run_gate_calls(fn: ast.AST) -> list[ast.Call]:
    """Calls to a gate function whose action argument is one of the RUN_* constants."""
    found = []
    for sub in ast.walk(fn):
        if not isinstance(sub, ast.Call) or _name_of(sub.func) not in GATE_CALLS:
            continue
        action = sub.args[1] if len(sub.args) > 1 else None
        if action is None:
            for kw in sub.keywords:
                if kw.arg == "action":
                    action = kw.value
        if action is not None and _name_of(action) in RUN_ACTIONS:
            found.append(sub)
    return found


def _run_id_routes():
    for node in ast.walk(_tree(MAIN)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route = _route_decorator(node)
        if route is None:
            continue
        method, path = route
        if "run_id" in _params(node) or "{run_id}" in path:
            yield method, path, node


def _gated_route_paths() -> set[str]:
    return {path for method, path, fn in _run_id_routes() if _run_gate_calls(fn)}


def _requests_calls(fn: ast.AST):
    for sub in ast.walk(fn):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and isinstance(sub.func.value, ast.Name)
            and sub.func.value.id == "requests"
            and sub.args
        ):
            yield sub.func.attr.lower(), sub.args[0]


def _path_template(url: ast.AST) -> str | None:
    """``f"{API_BASE_URL}/workflows/runs/{run_id}/cancel"`` -> ``/workflows/runs/{run_id}/cancel``."""
    if not isinstance(url, ast.JoinedStr):
        return None
    parts = []
    for value in url.values:
        if isinstance(value, ast.Constant):
            parts.append(str(value.value))
        elif isinstance(value, ast.FormattedValue):
            name = _name_of(value.value)
            parts.append("" if name == "API_BASE_URL" else "{" + (name or "?") + "}")
    return "".join(parts)


# ---------------------------------------------------------------------------
# the guard
# ---------------------------------------------------------------------------
def test_every_mutating_run_id_route_calls_the_run_gate():
    violations = []
    for method, path, fn in _run_id_routes():
        if method.lower() not in MUTATING:
            continue
        if (method, path) in KNOWN_UNGATED:
            continue
        if not _run_gate_calls(fn):
            violations.append(f"{fn.name} ({method} {path}) at {MAIN.name}:{fn.lineno}")
    assert not violations, (
        "run-scoped mutation without check(principal, RUN_*, RunRef(...)):\n  "
        + "\n  ".join(violations)
        + "\nRoute every run-scoped mutation through _authorize_run_action, or add it to "
        "KNOWN_UNGATED with a reason."
    )


def test_the_three_ws4_routes_are_gated():
    """Pin the routes this workstream exists for, so a refactor that renames a path and
    silently drops it from the enumeration still fails."""
    gated = _gated_route_paths()
    for path in (
        "/workflows/runs/{run_id}/cancel",
        "/workflows/runs/{run_id}/resume",
        "/workflows/runs/{run_id}/steps/{step_id}:replay",
    ):
        assert path in gated, f"{path} is no longer gated"


def test_known_ungated_entries_are_not_stale():
    live = {(method, path) for method, path, _ in _run_id_routes()}
    stale = set(KNOWN_UNGATED) - live
    assert not stale, f"KNOWN_UNGATED names routes that no longer exist: {sorted(stale)}"
    for key, reason in KNOWN_UNGATED.items():
        assert reason.strip(), f"KNOWN_UNGATED entry {key} has no reason"


def test_the_gate_helper_really_calls_check():
    """Deleting the ``check`` call inside ``_authorize_run_action`` while leaving the wrapper
    in place must fail here, not only in the behavioural tests."""
    helper = next(
        (
            node
            for node in ast.walk(_tree(MAIN))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "_authorize_run_action"
        ),
        None,
    )
    assert helper is not None, "_authorize_run_action is missing from api/main.py"
    calls = [
        sub
        for sub in ast.walk(helper)
        if isinstance(sub, ast.Call) and _name_of(sub.func) == "check" and len(sub.args) >= 3
    ]
    assert calls, f"_authorize_run_action at {MAIN.name}:{helper.lineno} does not call check()"


def test_every_mutating_mcp_tool_with_run_id_targets_a_gated_route():
    gated = _gated_route_paths()
    violations = []
    for node in ast.walk(_tree(MCP)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not _is_mcp_tool(node):
            continue
        if "run_id" not in _params(node):
            continue
        for verb, url in _requests_calls(node):
            if verb not in MUTATING:
                continue
            template = _path_template(url)
            if template is None or "{run_id}" not in template:
                continue  # run START (no run_id in the path) stamps; it does not gate
            if template not in gated:
                violations.append(
                    f"{node.name} at {MCP.name}:{node.lineno} {verb.upper()}s {template}"
                )
    assert (
        not violations
    ), "MCP tool reaches a run-scoped mutation that is not gated server-side:\n  " + "\n  ".join(
        violations
    )


def test_mcp_cancel_and_resume_tools_are_enumerated():
    """The enumeration above is only a guard if it actually sees the two tools."""
    seen = {
        node.name
        for node in ast.walk(_tree(MCP))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _is_mcp_tool(node)
        and "run_id" in _params(node)
    }
    assert {"workflow_cancel", "workflow_resume"} <= seen


@pytest.mark.parametrize("column", ["owner_terminal_id", "ancestor_terminal_ids"])
def test_no_update_statement_touches_an_ownership_column(column):
    """Ownership is frozen at creation. A resume is a NEW caller: it must not re-stamp the
    owner or append itself to the ancestry, and the cheapest way to guarantee that is for
    the journal to have no UPDATE path at all."""
    offenders = []
    for node in ast.walk(_tree(JOURNAL)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value.upper()
            # SQL only: a docstring may say "UPDATEs"; a statement says "UPDATE <table> SET".
            if "UPDATE " in text and " SET " in text and column.upper() in text:
                offenders.append(f"{JOURNAL.name}:{node.lineno}")
    assert not offenders, f"UPDATE statement touches {column}: {offenders}"
