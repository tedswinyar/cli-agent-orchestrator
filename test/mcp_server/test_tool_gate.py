"""The host-layer tool gate on ``cao-mcp-server`` (#671, WS3 of the agent-principal demo).

What these pin down, on the tree where #972's middleware and the demo's
``authorize()`` chokepoint meet:

* The decision is :func:`security.authz.check` on a ``terminal`` principal
  built from the terminal record, with the #671 ruling encoded there: default
  deny without ``@cao-mcp-server``; the callback tools always allowed; the
  discovery pair on the ``discovery`` grant alone (#972's carve-out); the
  per-tool form ``@cao-mcp-server/<tool>`` grants one tool.
* Every denial on this server is HARD whatever ``CAO_PRINCIPAL_ENFORCE`` says,
  because #972 shipped the whole-surface gate on main as behaviour before the
  flag existed. The flag does not relax it; the audit line says so
  (``enforced: true``).
* The gate is #972's ``_AllowlistGate`` middleware, asking
  ``_tool_denied_reason`` once per dispatch. The six delegation tools also
  carry the decorator, so a direct call still gets their pinned envelopes;
  nothing else is decided twice.

The seam is the same as ``test_tool_allowlist_enforcement.py``: the identity is
stubbed at ``_caller_principal`` through the shared
``test/mcp_server/conftest.py::patch_identity`` builder, and the body it returns
carries the EFFECTIVE allowlist, which is what ``GET /me/principal`` serves.
"""

from __future__ import annotations

import asyncio
import os
from test.mcp_server.conftest import identity_body, patch_identity
from test.security.test_tool_gate_census import EXPECTED_CAO_TOOLS
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastmcp.exceptions import ToolError

from cli_agent_orchestrator.mcp_server import server
from cli_agent_orchestrator.mcp_server.models import HandoffResult
from cli_agent_orchestrator.security import audit, tool_gate
from cli_agent_orchestrator.security.agent_credential import terminal_token
from cli_agent_orchestrator.security.authz import (
    CALLBACK_TOOLS,
    CAO_MCP_SERVER,
    DISCOVERY_TOOLS,
    TOOL_CALL,
    authorize,
)

TERMINAL_ID = "a1b2c3d4"

#: The tools that carry ``@_gated(refuse=...)`` under ``@mcp.tool``: refused on
#: main since #769 with envelopes their callers pin, and reachable by a direct
#: call that never passes through FastMCP dispatch.
DELEGATION_TOOLS = frozenset(tool_gate.LEGACY_HARD_GATED - {"create_ephemeral_agent"})


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Per-test CAO home so the audit log is observable and isolated."""
    monkeypatch.setenv("CAO_HOME_DIR", str(tmp_path / "cao-home"))
    monkeypatch.delenv("CAO_AUTHZ_AUDIT_ALLOWS", raising=False)
    return tmp_path


@pytest.fixture
def warn(home, monkeypatch):
    monkeypatch.delenv("CAO_PRINCIPAL_ENFORCE", raising=False)


@pytest.fixture(params=["warn", "enforce"])
def either_mode(request, home, monkeypatch):
    """Both flag states: on this server they must behave identically."""
    if request.param == "enforce":
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
    else:
        monkeypatch.delenv("CAO_PRINCIPAL_ENFORCE", raising=False)
    return request.param


@pytest.fixture
def bound(monkeypatch):
    monkeypatch.setenv("CAO_TERMINAL_ID", TERMINAL_ID)


def _with_allowlist(allowed):
    return patch_identity(allowed, terminal_id=TERMINAL_ID)


def _unresolvable():
    """The identity fetch failing: the server is down, or the bearer proves nothing."""
    import requests

    return patch_identity(side_effect=requests.RequestException("cao-server unreachable"))


def _gate():
    """#972's installed middleware on the real server object."""
    for middleware in getattr(server.mcp, "middleware", []):
        if type(middleware).__name__ == "_AllowlistGate":
            return middleware
    raise AssertionError("no _AllowlistGate installed on server.mcp")


async def _adispatch(tool_name):
    """Drive the installed gate for ``tool_name``; the body never runs.

    Returns normally when the gate passed the call through; raises ``ToolError``
    when it refused.
    """
    sentinel = object()
    context = SimpleNamespace(message=SimpleNamespace(name=tool_name, arguments={}))

    async def call_next(_context):
        return sentinel

    assert await _gate().on_call_tool(context, call_next) is sentinel


def _dispatch(tool_name):
    """Synchronous form of :func:`_adispatch` for tests that are not themselves async."""
    asyncio.run(_adispatch(tool_name))


# --- the ruling, through the shim --------------------------------------------------


class TestRestrictedTerminal:
    """``tools: [fs_read]``: everything on the server is denied except the ruled exceptions."""

    def test_memory_forget_denied_by_default_deny_rule(self, either_mode, bound):
        with _with_allowlist(["fs_read"]):
            reason = server._tool_denied_reason("memory_forget")
        assert reason is not None
        assert "tool:default-deny" in reason
        assert "memory_forget" in reason
        assert "@cao-mcp-server" in reason

    @pytest.mark.parametrize("tool", sorted(CALLBACK_TOOLS))
    def test_callbacks_always_allowed(self, either_mode, bound, tool):
        with _with_allowlist(["fs_read"]):
            assert server._tool_denied_reason(tool) is None

    @pytest.mark.parametrize("tool", sorted(DISCOVERY_TOOLS))
    def test_discovery_pair_passes_on_the_discovery_grant_alone(self, either_mode, bound, tool):
        with _with_allowlist(["fs_read", "discovery"]):
            assert server._tool_denied_reason(tool) is None

    @pytest.mark.parametrize("tool", sorted(DISCOVERY_TOOLS))
    def test_discovery_pair_denied_without_the_grant(self, either_mode, bound, tool):
        with _with_allowlist(["fs_read"]):
            reason = server._tool_denied_reason(tool)
        assert reason is not None and "@cao-mcp-server" in reason

    def test_discovery_grant_does_not_widen(self, either_mode, bound):
        with _with_allowlist(["discovery"]):
            assert server._tool_denied_reason("memory_store") is not None

    def test_the_exception_sets_are_the_ruled_ones(self):
        assert CALLBACK_TOOLS == {
            "send_message",
            "complete_assignment",
            "workflow_return",
            "answer_user_prompt",
        }
        assert DISCOVERY_TOOLS == {"list_siblings", "update_metadata"}
        # #972's module-level names are these same sets, not copies.
        assert server.CALLBACK_EXEMPT_TOOLS is CALLBACK_TOOLS
        assert server.DISCOVERY_GATED_TOOLS is DISCOVERY_TOOLS

    @pytest.mark.parametrize("tool", sorted(EXPECTED_CAO_TOOLS - CALLBACK_TOOLS))
    def test_every_other_tool_is_denied(self, either_mode, bound, tool):
        with _with_allowlist(["fs_read"]):
            reason = server._tool_denied_reason(tool)
        assert reason is not None and "tool:default-deny" in reason


class TestServerSelector:
    @pytest.mark.parametrize("tool", sorted(EXPECTED_CAO_TOOLS))
    def test_server_selector_allows_everything(self, either_mode, bound, tool):
        with _with_allowlist(["fs_read", "@cao-mcp-server"]):
            assert server._tool_denied_reason(tool) is None

    def test_per_tool_form_grants_one_tool(self, either_mode, bound):
        with _with_allowlist(["@cao-mcp-server/memory_forget"]):
            assert server._tool_denied_reason("memory_forget") is None
            assert server._tool_denied_reason("memory_store") is not None

    def test_bare_tool_name_does_not_grant(self, either_mode, bound):
        with _with_allowlist(["memory_forget"]):
            assert server._tool_denied_reason("memory_forget") is not None


# --- hard on this server, whatever the flag says ------------------------------------


class TestHardWhateverTheFlag:
    """#972 shipped the whole-surface gate as behaviour; the flag must not relax it."""

    def test_denial_is_refused_and_audited_as_enforced_in_warn_mode(self, warn, bound):
        with _with_allowlist(["fs_read"]):
            assert server._tool_denied_reason("memory_forget") is not None
        records = audit.read_recent()
        assert len(records) == 1
        rec = records[0]
        assert rec["allowed"] is False
        assert rec["enforced"] is True
        assert rec["rule"] == "tool:default-deny"
        assert rec["resource"] == f"{CAO_MCP_SERVER}/memory_forget"
        assert rec["terminal_id"] == TERMINAL_ID
        assert rec["kind"] == "terminal"

    def test_an_allowed_agent_call_is_audited_as_allowed(self, warn, bound):
        """An agent's successful call leaves a line, so a bypass is visible.

        Before, only refusals were recorded, so an agent that reached a tool it
        should not have reached left nothing behind -- the gap all four reviews
        named.
        """
        with _with_allowlist(["@cao-mcp-server"]):
            assert server._tool_denied_reason("memory_forget") is None
        rec = audit.read_recent()[-1]
        assert rec["kind"] == "terminal"
        assert rec["allowed"] is True and rec["outcome"] == "allowed"
        assert rec["rule"] == "tool:allowlist"

    def test_hard_table(self, warn):
        assert tool_gate.hard("memory_forget", CAO_MCP_SERVER)
        assert tool_gate.hard("tool_from_a_later_pr", CAO_MCP_SERVER)
        assert tool_gate.hard("assign")
        assert not tool_gate.hard("launch_session", "cao-ops-mcp-server")

    @pytest.mark.asyncio
    async def test_granted_tool_runs_its_body(self, warn, bound):
        """The gate lets a granted call through; the body then behaves exactly as today."""
        # memory_forget's body talks to the memory service; stub the service layer.
        from cli_agent_orchestrator.services import memory_service

        class _Deleted:
            action = "none"
            path = None

            def __bool__(self):
                return False

        async def _forget(self, **kwargs):
            return _Deleted()

        with _with_allowlist(["@cao-mcp-server"]):
            await _adispatch("memory_forget")
            with patch.object(memory_service.MemoryService, "forget", _forget):
                with patch(
                    "cli_agent_orchestrator.services.memory_gateway.remote_memory_url",
                    return_value=None,
                ):
                    result = await server.memory_forget(key="k")
        assert result["success"] is True

    @pytest.mark.parametrize("tool", sorted(DELEGATION_TOOLS))
    def test_legacy_tools_stay_hard_in_warn_mode(self, warn, bound, tool):
        """These were refused on main before the flag existed; the flag does not relax them."""
        with _with_allowlist(["fs_read"]):
            reason = server._tool_denied_reason(tool)
        assert reason is not None and "@cao-mcp-server" in reason

    def test_unresolvable_identity_fails_closed_for_every_tool(self, either_mode, bound):
        with _unresolvable():
            for tool in ("memory_forget", "assign", "tool_from_a_later_pr"):
                reason = server._tool_denied_reason(tool)
                assert reason is not None and "could not be resolved" in reason, tool


# --- through #972's middleware ----------------------------------------------------------


class TestThroughTheMiddleware:
    def test_refuses_with_the_decision_reason(self, either_mode, bound):
        principal = tool_gate.principal_for(identity_body(["fs_read"], terminal_id=TERMINAL_ID))
        expected = authorize(principal, TOOL_CALL, "memory_forget", server=CAO_MCP_SERVER)
        with _with_allowlist(["fs_read"]):
            with pytest.raises(ToolError) as ei:
                _dispatch("memory_forget")
        assert expected.reason in str(ei.value)
        assert expected.rule in str(ei.value)
        rec = audit.read_recent()[-1]
        assert rec["enforced"] is True and rec["allowed"] is False

    def test_sync_tool_refuses_too(self, either_mode, bound):
        with _with_allowlist(["fs_read"]):
            with pytest.raises(ToolError):
                _dispatch("find_profiles")

    def test_unresolvable_identity_fails_closed(self, either_mode, bound):
        with _unresolvable():
            with pytest.raises(ToolError, match="could not be resolved"):
                _dispatch("memory_forget")

    def test_operator_context_is_untouched(self, either_mode, monkeypatch):
        monkeypatch.delenv("CAO_TERMINAL_ID", raising=False)
        with patch.object(server, "_caller_principal") as lookup:
            assert server._tool_denied_reason("memory_forget") is None
            _dispatch("memory_forget")
        lookup.assert_not_called()
        assert audit.read_recent() == []

    @pytest.mark.parametrize("tool", sorted(CALLBACK_TOOLS))
    def test_callbacks_pass_without_consulting_the_policy(self, either_mode, bound, tool):
        with patch.object(server, "_tool_denied_reason") as policy:
            _dispatch(tool)
        policy.assert_not_called()


# --- the legacy envelopes, produced by the decorator on a direct call -----------------


class TestLegacyEnvelopes:
    """The six pre-flag refusals keep the shapes their callers and tests pin."""

    @pytest.mark.asyncio
    async def test_assign(self, warn, bound):
        with _with_allowlist(["fs_read"]):
            result = await server.assign("developer", "task")
        assert result["success"] is False and "@cao-mcp-server" in result["error"]

    @pytest.mark.asyncio
    async def test_handoff(self, warn, bound):
        with _with_allowlist(["fs_read"]):
            result = await server.handoff("developer", "task")
        assert isinstance(result, HandoffResult)
        assert result.success is False and "@cao-mcp-server" in result.message

    @pytest.mark.asyncio
    async def test_assign_elastic(self, warn, bound):
        with _with_allowlist(["fs_read"]):
            result = await server.assign_elastic("developer", "task")
        assert result == {
            "success": False,
            "terminal_id": None,
            "elastic": True,
            "message": result["message"],
        }
        assert "@cao-mcp-server" in result["message"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool", ["workflow_run", "workflow_start"])
    async def test_workflow_dispatch(self, warn, bound, tool):
        with _with_allowlist(["fs_read"]):
            result = await getattr(server, tool)("some-workflow")
        assert result["ok"] is False and "@cao-mcp-server" in result["error"]

    @pytest.mark.asyncio
    async def test_workflow_resume(self, warn, bound):
        with _with_allowlist(["fs_read"]):
            result = await server.workflow_resume("run-1")
        assert result["ok"] is False and "@cao-mcp-server" in result["error"]


# --- the decorator: six tools, and only six ------------------------------------------


class TestDecorator:
    def test_only_the_delegation_tools_carry_the_decorator(self):
        """#972's middleware is the gate; deciding twice would double the record fetch."""
        for name in EXPECTED_CAO_TOOLS:
            marked = tool_gate.is_gated(getattr(server, name), CAO_MCP_SERVER)
            assert marked == (name in DELEGATION_TOOLS), name

    def test_the_middleware_is_installed_on_the_real_server(self):
        assert _gate() is not None

    def test_wrapper_keeps_signature_and_doc(self):
        import inspect

        params = list(inspect.signature(server.assign_elastic).parameters)
        assert params[:2] == ["agent_profile", "message"]
        assert server.assign_elastic.__doc__ and "worker" in server.assign_elastic.__doc__

    def test_missing_required_argument_raises_at_the_call(self):
        """Same TypeError, at the call, as the undecorated function (no coroutine is created)."""
        with pytest.raises(TypeError):
            server.workflow_run()  # type: ignore[call-arg]

    @pytest.mark.asyncio
    async def test_monkeypatched_gate_is_honoured_by_both_halves(self, monkeypatch, warn, bound):
        """Tests that stub ``_tool_denied_reason`` keep working: both look it up by name."""
        monkeypatch.setattr(server, "_tool_denied_reason", lambda name: f"blocked {name}")
        result = await server.assign("developer", "task")
        assert result == {"success": False, "error": "blocked assign"}
        with pytest.raises(ToolError, match="blocked memory_forget"):
            await _adispatch("memory_forget")

    def test_bound_and_credential_read_from_env(self, monkeypatch):
        monkeypatch.delenv("CAO_TERMINAL_ID", raising=False)
        monkeypatch.delenv("CAO_TERMINAL_TOKEN", raising=False)
        assert tool_gate.bound_terminal_id() is None
        assert terminal_token() is None
        monkeypatch.setenv("CAO_TERMINAL_ID", "abcd1234")
        monkeypatch.setenv("CAO_TERMINAL_TOKEN", "cao_t_x")
        assert tool_gate.bound_terminal_id() == "abcd1234"
        assert terminal_token() == "cao_t_x"
        assert "CAO_TERMINAL_ID" in os.environ
