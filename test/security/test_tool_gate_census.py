"""Structural guard: every MCP tool on both servers is wrapped by the host-layer gate (#671).

The gate is a decorator stacked directly under ``@mcp.tool``. That makes the
invariant visible in source, so this census reads the source rather than
trusting a runtime registry: for every ``@mcp.tool`` registration in the three
modules that register tools on ``cao-mcp-server`` and ``cao-ops-mcp-server`` it
asserts the gate decorator is present and is the decorator immediately below
``@mcp.tool`` (the object FastMCP registers is the gated wrapper, not the bare
function). A bare registration fails with ``file:line``.

The registration tables are frozen on purpose. Adding a tool is supposed to
fail here once so the author gates it and adds it to the table; a missed
exception is a loud failure instead of a quiet grant. The #671 census counted
34 unique tools on ``cao-mcp-server`` on main; this table has the same 34.

A runtime census complements the source walk: it lists the tools each live
server exposes and asserts each one's bound function carries the gate marker,
which also covers registrations made through ``add_tool`` or a plugin hook.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Tuple

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

#: Not an ``@mcp.tool`` registration: added through ``add_tool`` on operator
#: opt-in with a custom ``Tool`` whose ``run`` calls the binder below. The
#: binder is the one place the gate can sit for it.
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


def _bare_registrations(server: str) -> List[str]:
    gate, modules = REGISTRATION_MODULES[server]
    violations: List[str] = []
    for path in modules:
        rel = path.relative_to(_PACKAGE_ROOT)
        for name, lineno, names in _registrations(path):
            position = names.index("mcp.tool")
            below = names[position + 1 :]
            if not below or below[0] != gate:
                violations.append(
                    f"{rel}:{lineno} @mcp.tool {name} is not wrapped by @{gate} "
                    f"(decorators: {names}); stack @{gate} directly under @mcp.tool"
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


@pytest.mark.parametrize("server", sorted(REGISTRATION_MODULES))
def test_every_registration_is_wrapped_by_the_gate(server: str) -> None:
    violations = _bare_registrations(server)
    assert not violations, f"ungated tools on {server}:\n" + "\n".join(violations)


def test_cao_mcp_server_registration_table_is_frozen() -> None:
    names = _names(CAO_MCP_SERVER)
    assert names == EXPECTED_CAO_TOOLS, (
        "cao-mcp-server tool table changed. added="
        f"{sorted(names - EXPECTED_CAO_TOOLS)} removed={sorted(EXPECTED_CAO_TOOLS - names)}. "
        "A new tool must stack @_gated under @mcp.tool and be added to EXPECTED_CAO_TOOLS; "
        "if it needs to bypass the allowlist, that is an authz.ALWAYS_ALLOWED_TOOLS ruling, "
        "not a bare registration."
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
    """Runtime census: every tool FastMCP lists is bound to a gated wrapper."""

    from cli_agent_orchestrator.mcp_server import server as cao_server
    from cli_agent_orchestrator.ops_mcp_server import server as ops_server

    for server_name, module, expected in (
        (CAO_MCP_SERVER, cao_server, EXPECTED_CAO_TOOLS),
        (CAO_OPS_MCP_SERVER, ops_server, EXPECTED_OPS_TOOLS),
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
            assert tool_gate.is_gated(
                fn, server_name
            ), f"{server_name}/{tool.name} is exposed without the host-layer gate"
