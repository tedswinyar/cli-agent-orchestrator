"""Structural guard: every MCP tool on both servers sits behind the host-layer gate (#671).

Two arrangements, one invariant (no tool is reachable without ``check()``):

* ``cao-mcp-server``: the gate is #972's ``_AllowlistGate`` middleware, which
  asks ``_tool_denied_reason`` once per dispatch, installed after every tool and
  plugin surface is registered (``test/mcp_server/test_mcp_tool_surface_gate_coverage.py``
  drives it against the live registry). The six delegation tools ALSO stack
  ``@_gated(refuse=...)`` directly under ``@mcp.tool``: they were refused on main
  before the middleware existed, their callers pin a structured envelope, and a
  direct call (the ``cao`` CLI paths) never passes through the middleware. No
  other registration may carry the decorator, so nothing is decided twice and
  the record fetch happens once.
* ``cao-ops-mcp-server``: no middleware on main (it is the operator control
  plane), so every ``@mcp.tool`` registration in ``server.py`` and
  ``decision_tools.py`` stacks ``@gated`` directly under it. A bare registration
  fails with ``file:line``.

The registration tables are frozen on purpose. Adding a tool is supposed to
fail here once so the author decides which arrangement covers it and adds it to
the table; a missed exception is a loud failure instead of a quiet grant. The
#671 census counted 34 unique tools on ``cao-mcp-server`` on main; this table
has the same 34.

A runtime census complements the source walk: it lists the tools each live
server exposes and checks the gate marker against the arrangement above, which
also covers registrations made through ``add_tool`` or a plugin hook.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Callable, Dict, List, Tuple

import pytest

import cli_agent_orchestrator
from cli_agent_orchestrator.security import tool_gate
from cli_agent_orchestrator.security.authz import CAO_MCP_SERVER, CAO_OPS_MCP_SERVER

_PACKAGE_ROOT = Path(cli_agent_orchestrator.__file__).parent

#: server -> (gate decorator name, modules that register tools on it)
REGISTRATION_MODULES: Dict[str, Tuple[str, Tuple[Path, ...]]] = {
    CAO_MCP_SERVER: ("_gated", (_PACKAGE_ROOT / "mcp_server" / "server.py",)),
    CAO_OPS_MCP_SERVER: (
        "gated",
        (
            _PACKAGE_ROOT / "ops_mcp_server" / "server.py",
            _PACKAGE_ROOT / "ops_mcp_server" / "decision_tools.py",
        ),
    ),
}

#: The 34 tools the #671 census found on main, by name. ``assign`` and
#: ``handoff`` are each registered twice in source (with and without the
#: working-directory parameter) and count once here.
EXPECTED_CAO_TOOLS: frozenset[str] = frozenset(
    {
        "answer_user_prompt",
        "assign",
        "assign_elastic",
        "complete_assignment",
        "delete_terminal",
        "emit_ui",
        "find_profiles",
        "get_handoff_result",
        "handoff",
        "list_outcomes",
        "list_siblings",
        "load_skill",
        "memory_forget",
        "memory_recall",
        "memory_store",
        "report_outcome",
        "send_message",
        "store_lesson",
        "update_metadata",
        "workflow_cancel",
        "workflow_create",
        "workflow_events",
        "workflow_get",
        "workflow_list",
        "workflow_plan_approval",
        "workflow_result",
        "workflow_resume",
        "workflow_return",
        "workflow_run",
        "workflow_start",
        "workflow_status",
        "workflow_update",
        "workflow_validate",
        "workflow_wait",
    }
)

#: The registrations on ``cao-mcp-server`` that stack ``@_gated(refuse=...)``:
#: refused on main since #769 with envelopes their callers pin.
CAO_DECORATED_TOOLS: frozenset[str] = frozenset(
    {
        "assign",
        "handoff",
        "assign_elastic",
        "workflow_run",
        "workflow_resume",
        "workflow_start",
    }
)

#: Not an ``@mcp.tool`` registration: added through ``add_tool`` on operator
#: opt-in with a custom ``Tool`` whose ``run`` calls the binder below. The
#: binder is the one place the gate can sit for it besides the middleware.
EPHEMERAL_TOOL = "create_ephemeral_agent"
EPHEMERAL_BINDER = "_create_ephemeral_from_arguments"

EXPECTED_OPS_TOOLS: frozenset[str] = frozenset(
    {
        "decisions_list",
        "decisions_purge",
        "decisions_set_exclusions",
        "decisions_set_point",
        "decisions_set_tier",
        "decisions_status",
        "get_profile_details",
        "get_session_info",
        "get_terminal_output",
        "get_terminal_status",
        "install_profile",
        "launch_session",
        "list_profiles",
        "list_sessions",
        "read_session_output",
        "send_session_message",
        "shutdown_session",
    }
)


def _decorator_name(node: ast.expr) -> str:
    """``mcp.tool`` / ``mcp.tool(...)`` -> ``mcp.tool``; ``_gated`` / ``_gated(...)`` -> ``_gated``."""

    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    return ast.dump(node)


def _registrations(path: Path) -> List[Tuple[str, int, List[str]]]:
    """Every function decorated with ``@mcp.tool`` in ``path``: (name, line, decorator names)."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: List[Tuple[str, int, List[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        names = [_decorator_name(d) for d in node.decorator_list]
        if "mcp.tool" in names:
            found.append((node.name, node.lineno, names))
    return found


def _arrangement_violations(server: str, must_carry: Callable[[str], bool]) -> List[str]:
    """Violations of the gate arrangement for ``server``.

    ``must_carry(name)`` says whether a registration must stack the gate
    decorator directly under ``@mcp.tool``; a registration that must not is
    checked for the decorator's absence.
    """
    gate, modules = REGISTRATION_MODULES[server]
    violations: List[str] = []
    for path in modules:
        rel = path.relative_to(_PACKAGE_ROOT)
        for name, lineno, names in _registrations(path):
            position = names.index("mcp.tool")
            below = names[position + 1 :]
            carries = bool(below) and below[0] == gate
            if must_carry(name) and not carries:
                violations.append(
                    f"{rel}:{lineno} @mcp.tool {name} is not wrapped by @{gate} "
                    f"(decorators: {names}); stack @{gate} directly under @mcp.tool"
                )
            elif not must_carry(name) and gate in names:
                violations.append(
                    f"{rel}:{lineno} @mcp.tool {name} carries @{gate} but the "
                    f"_AllowlistGate middleware already gates it (#972); deciding twice "
                    f"doubles the terminal-record fetch. Remove the decorator, or add the "
                    f"tool to CAO_DECORATED_TOOLS with the envelope its callers pin."
                )
    return violations


def _names(server: str) -> set[str]:
    _, modules = REGISTRATION_MODULES[server]
    return {name for path in modules for name, _, _ in _registrations(path)}


@pytest.mark.parametrize("server", sorted(REGISTRATION_MODULES))
def test_registration_modules_exist_and_register_tools(server: str) -> None:
    _, modules = REGISTRATION_MODULES[server]
    for path in modules:
        assert path.is_file(), path
    assert _names(server), f"no @mcp.tool registrations found for {server}"


def test_every_ops_registration_is_wrapped_by_the_gate() -> None:
    violations = _arrangement_violations(CAO_OPS_MCP_SERVER, lambda name: True)
    assert not violations, f"ungated tools on {CAO_OPS_MCP_SERVER}:\n" + "\n".join(violations)


def test_cao_delegation_tools_carry_the_decorator_and_nothing_else_does() -> None:
    violations = _arrangement_violations(CAO_MCP_SERVER, lambda name: name in CAO_DECORATED_TOOLS)
    assert not violations, f"gate arrangement broken on {CAO_MCP_SERVER}:\n" + "\n".join(violations)


def test_cao_decorated_set_is_the_legacy_hard_set() -> None:
    """The decorator sits exactly on the tools #769 refused; the table and the mode agree."""
    assert CAO_DECORATED_TOOLS == tool_gate.LEGACY_HARD_GATED - {EPHEMERAL_TOOL}


def test_cao_middleware_is_installed_after_plugin_registration() -> None:
    """#972's gate wraps every registration, including a plugin's, and asks the policy by name."""
    source = (_PACKAGE_ROOT / "mcp_server" / "server.py").read_text(encoding="utf-8")
    register = source.index("\nregister_mcp_server_surfaces(mcp)")
    install = source.index("\n_install_allowlist_middleware(mcp)")
    assert register < install
    tree = ast.parse(source)
    installer = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "_install_allowlist_middleware"
    )
    args = {
        a.id
        for n in ast.walk(installer)
        if isinstance(n, ast.Call)
        for a in n.args
        if isinstance(a, ast.Name)
    }
    assert "_tool_denied_reason" in args, "the middleware must ask _tool_denied_reason"


def test_cao_mcp_server_registration_table_is_frozen() -> None:
    names = _names(CAO_MCP_SERVER)
    assert names == EXPECTED_CAO_TOOLS, (
        "cao-mcp-server tool table changed. added="
        f"{sorted(names - EXPECTED_CAO_TOOLS)} removed={sorted(EXPECTED_CAO_TOOLS - names)}. "
        "A new tool is gated by the _AllowlistGate middleware by default; add it to "
        "EXPECTED_CAO_TOOLS. If it must bypass the allowlist, that is an "
        "authz.CALLBACK_TOOLS ruling, not a bare registration."
    )
    assert len(names) == 34, "the #671 census counted 34 unique tools on main"


def test_ops_server_registration_table_is_frozen() -> None:
    names = _names(CAO_OPS_MCP_SERVER)
    assert names == EXPECTED_OPS_TOOLS, (
        "cao-ops-mcp-server tool table changed. added="
        f"{sorted(names - EXPECTED_OPS_TOOLS)} removed={sorted(EXPECTED_OPS_TOOLS - names)}. "
        "A new ops tool must stack @gated under @mcp.tool and be added to EXPECTED_OPS_TOOLS."
    )


def test_ephemeral_binder_calls_the_gate() -> None:
    """``create_ephemeral_agent`` is registered via ``add_tool``; its binder must call the gate."""

    path = _PACKAGE_ROOT / "mcp_server" / "server.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    binder = next(
        (
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == EPHEMERAL_BINDER
        ),
        None,
    )
    assert binder is not None, f"{EPHEMERAL_BINDER} not found"
    calls = {_decorator_name(n.func) for n in ast.walk(binder) if isinstance(n, ast.Call)}
    # ``asyncio.to_thread(_tool_denied_reason, ...)`` passes the gate as an argument.
    args = {
        a.id
        for n in ast.walk(binder)
        if isinstance(n, ast.Call)
        for a in n.args
        if isinstance(a, ast.Name)
    }
    assert (
        "_tool_denied_reason" in calls | args
    ), f"mcp_server/server.py:{binder.lineno} {EPHEMERAL_BINDER} does not call _tool_denied_reason"
    assert EPHEMERAL_TOOL in tool_gate.LEGACY_HARD_GATED


@pytest.mark.asyncio
async def test_live_servers_expose_only_gated_functions() -> None:
    """Runtime census: every tool FastMCP lists is covered by its server's arrangement."""

    from cli_agent_orchestrator.mcp_server import server as cao_server
    from cli_agent_orchestrator.ops_mcp_server import server as ops_server

    assert any(
        type(m).__name__ == "_AllowlistGate" for m in getattr(cao_server.mcp, "middleware", [])
    ), "cao-mcp-server has no _AllowlistGate middleware installed"

    for server_name, module, expected, decorated in (
        (CAO_MCP_SERVER, cao_server, EXPECTED_CAO_TOOLS, CAO_DECORATED_TOOLS),
        (CAO_OPS_MCP_SERVER, ops_server, EXPECTED_OPS_TOOLS, EXPECTED_OPS_TOOLS),
    ):
        tools = await module.mcp.list_tools()
        listed = {t.name for t in tools}
        # Default-off surfaces (ephemeral opt-in, plugins) may be absent; nothing
        # outside the table may be present without going through the census.
        unexpected = listed - expected - {EPHEMERAL_TOOL}
        assert not unexpected, f"{server_name} exposes tools outside the census: {unexpected}"
        for tool in tools:
            fn = getattr(tool, "fn", None)
            if fn is None:
                assert tool.name == EPHEMERAL_TOOL, f"{server_name}/{tool.name} has no bound fn"
                continue
            assert tool_gate.is_gated(fn, server_name) == (tool.name in decorated), (
                f"{server_name}/{tool.name}: decorator "
                f"{'missing' if tool.name in decorated else 'present'} "
                f"(expected {'present' if tool.name in decorated else 'absent'})"
            )
