"""The host-layer tool gate on ``cao-mcp-server`` (#671, WS3 of the agent-principal demo).

What these pin down:

* The decision is :func:`security.authz.check` on a ``terminal`` principal
  built from the terminal record, with the #671 ruling encoded there: default
  deny without ``@cao-mcp-server``; the callback and discovery tools always
  allowed; the per-tool form ``@cao-mcp-server/<tool>`` grants one tool.
* Warn mode (``CAO_PRINCIPAL_ENFORCE`` unset) audits and does not refuse, for
  the tools this gate newly covers. The six tools that were already refused on
  main stay refused in warn mode, with their pinned envelopes.
* Enforce mode refuses with the Decision's rule and reason, through the
  decorator, as an MCP ``ToolError``.

The seam is the same as ``test_tool_allowlist_enforcement.py``: the terminal
record is stubbed at ``_get_terminal_context_from_env`` and the recorded
``allowed_tools`` is the effective list.
"""

from __future__ import annotations

import os
from test.security.test_tool_gate_census import EXPECTED_CAO_TOOLS
from unittest.mock import patch

import pytest
from fastmcp.exceptions import ToolError

from cli_agent_orchestrator.mcp_server import server
from cli_agent_orchestrator.mcp_server.models import HandoffResult
from cli_agent_orchestrator.security import audit, tool_gate
from cli_agent_orchestrator.security.authz import (
    ALWAYS_ALLOWED_TOOLS,
    CAO_MCP_SERVER,
    TOOL_CALL,
    authorize,
)

TERMINAL_ID = "a1b2c3d4"


def _ctx(allowed_tools):
    return {
        "terminal_id": TERMINAL_ID,
        "session_name": "cao-session",
        "provider": "codex",
        "agent_profile": "worker",
        "allowed_tools": allowed_tools,
    }


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Per-test CAO home so the audit log is observable and isolated."""
    monkeypatch.setenv("CAO_HOME_DIR", str(tmp_path / "cao-home"))
    monkeypatch.delenv("CAO_AUTHZ_AUDIT_ALLOWS", raising=False)
    return tmp_path


@pytest.fixture
def warn(home, monkeypatch):
    monkeypatch.delenv("CAO_PRINCIPAL_ENFORCE", raising=False)


@pytest.fixture
def enforce(home, monkeypatch):
    monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")


@pytest.fixture
def bound(monkeypatch):
    monkeypatch.setenv("CAO_TERMINAL_ID", TERMINAL_ID)


def _with_allowlist(allowed):
    return patch.object(server, "_get_terminal_context_from_env", return_value=_ctx(allowed))


# --- the ruling, through the shim --------------------------------------------------


class TestRestrictedTerminal:
    """``tools: [fs_read]``: everything on the server is denied except the ruled exceptions."""

    def test_memory_forget_denied_by_default_deny_rule(self, enforce, bound):
        with _with_allowlist(["fs_read"]):
            reason = server._tool_denied_reason("memory_forget")
        assert reason is not None
        assert "tool:default-deny" in reason
        assert "memory_forget" in reason
        assert "@cao-mcp-server" in reason

    @pytest.mark.parametrize("tool", sorted(ALWAYS_ALLOWED_TOOLS))
    def test_callbacks_and_discovery_always_allowed(self, enforce, bound, tool):
        with _with_allowlist(["fs_read"]):
            assert server._tool_denied_reason(tool) is None

    def test_the_exception_set_is_the_ruled_one(self):
        assert ALWAYS_ALLOWED_TOOLS == {
            "send_message",
            "complete_assignment",
            "workflow_return",
            "answer_user_prompt",
            "list_siblings",
            "update_metadata",
        }

    @pytest.mark.parametrize("tool", sorted(EXPECTED_CAO_TOOLS - ALWAYS_ALLOWED_TOOLS))
    def test_every_other_tool_is_denied(self, enforce, bound, tool):
        with _with_allowlist(["fs_read"]):
            reason = server._tool_denied_reason(tool)
        assert reason is not None and "tool:default-deny" in reason


class TestServerSelector:
    @pytest.mark.parametrize("tool", sorted(EXPECTED_CAO_TOOLS))
    def test_server_selector_allows_everything(self, enforce, bound, tool):
        with _with_allowlist(["fs_read", "@cao-mcp-server"]):
            assert server._tool_denied_reason(tool) is None

    def test_per_tool_form_grants_one_tool(self, enforce, bound):
        with _with_allowlist(["@cao-mcp-server/memory_forget"]):
            assert server._tool_denied_reason("memory_forget") is None
            assert server._tool_denied_reason("memory_store") is not None

    def test_bare_tool_name_does_not_grant(self, enforce, bound):
        with _with_allowlist(["memory_forget"]):
            assert server._tool_denied_reason("memory_forget") is not None


# --- warn vs enforce -------------------------------------------------------------


class TestWarnMode:
    def test_newly_gated_tool_proceeds_and_is_audited(self, warn, bound):
        with _with_allowlist(["fs_read"]):
            assert server._tool_denied_reason("memory_forget") is None
        records = audit.read_recent()
        assert len(records) == 1
        rec = records[0]
        assert rec["allowed"] is False
        assert rec["enforced"] is False
        assert rec["rule"] == "tool:default-deny"
        assert rec["resource"] == f"{CAO_MCP_SERVER}/memory_forget"
        assert rec["terminal_id"] == TERMINAL_ID
        assert rec["kind"] == "terminal"

    def test_allowed_call_is_not_audited_by_default(self, warn, bound):
        with _with_allowlist(["@cao-mcp-server"]):
            assert server._tool_denied_reason("memory_forget") is None
        assert audit.read_recent() == []

    @pytest.mark.asyncio
    async def test_decorated_tool_runs_its_body_in_warn_mode(self, warn, bound):
        """The gate lets the call through; the body then behaves exactly as today."""
        # memory_forget's body talks to the memory service; stub the service layer.
        from cli_agent_orchestrator.services import memory_service

        class _Deleted:
            action = "none"
            path = None

            def __bool__(self):
                return False

        async def _forget(self, **kwargs):
            return _Deleted()

        with _with_allowlist(["fs_read"]):
            with patch.object(memory_service.MemoryService, "forget", _forget):
                with patch(
                    "cli_agent_orchestrator.services.memory_gateway.remote_memory_url",
                    return_value=None,
                ):
                    result = await server.memory_forget(key="k")
        assert result["success"] is True
        assert audit.read_recent()[-1]["rule"] == "tool:default-deny"

    @pytest.mark.parametrize(
        "tool", sorted(tool_gate.LEGACY_HARD_GATED - {"create_ephemeral_agent"})
    )
    def test_legacy_tools_stay_hard_in_warn_mode(self, warn, bound, tool):
        """These were refused on main before the flag existed; the flag does not relax them."""
        with _with_allowlist(["fs_read"]):
            reason = server._tool_denied_reason(tool)
        assert reason is not None and "@cao-mcp-server" in reason

    def test_unresolvable_identity_proceeds_for_new_tools(self, warn, bound):
        with patch.object(server, "_get_terminal_context_from_env", return_value=None):
            assert server._tool_denied_reason("memory_forget") is None
            assert server._tool_denied_reason("assign") is not None


class TestEnforceMode:
    @pytest.mark.asyncio
    async def test_refuses_with_the_decision_reason(self, enforce, bound):
        principal = tool_gate.principal_for(_ctx(["fs_read"]), ["fs_read"])
        expected = authorize(principal, TOOL_CALL, "memory_forget", server=CAO_MCP_SERVER)
        with _with_allowlist(["fs_read"]):
            with pytest.raises(ToolError) as ei:
                await server.memory_forget(key="k")
        assert expected.reason in str(ei.value)
        assert expected.rule in str(ei.value)
        rec = audit.read_recent()[-1]
        assert rec["enforced"] is True and rec["allowed"] is False

    @pytest.mark.asyncio
    async def test_sync_tool_refuses_too(self, enforce, bound):
        with _with_allowlist(["fs_read"]):
            with pytest.raises(ToolError):
                server.find_profiles(query="x")

    def test_unresolvable_identity_fails_closed(self, enforce, bound):
        with patch.object(server, "_get_terminal_context_from_env", return_value=None):
            reason = server._tool_denied_reason("memory_forget")
        assert reason is not None and "CAO_TERMINAL_ID" in reason

    def test_operator_context_is_untouched(self, enforce, monkeypatch):
        monkeypatch.delenv("CAO_TERMINAL_ID", raising=False)
        with patch.object(server, "_get_terminal_context_from_env") as lookup:
            assert server._tool_denied_reason("memory_forget") is None
        lookup.assert_not_called()
        assert audit.read_recent() == []


# --- the legacy envelopes, now produced by the decorator -------------------------------


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


# --- the decorator itself ----------------------------------------------------------


class TestDecorator:
    def test_every_tool_is_marked_for_this_server(self):
        for name in EXPECTED_CAO_TOOLS:
            assert tool_gate.is_gated(getattr(server, name), CAO_MCP_SERVER), name

    def test_wrapper_keeps_signature_and_doc(self):
        import inspect

        sig = inspect.signature(server.memory_forget)
        assert list(sig.parameters) == ["key", "scope"]
        assert server.memory_forget.__doc__.startswith("Remove a memory by key and scope.")

    def test_missing_required_argument_raises_at_the_call(self):
        """Same TypeError, at the call, as the undecorated function (no coroutine is created)."""
        with pytest.raises(TypeError):
            server.workflow_create()  # type: ignore[call-arg]

    @pytest.mark.asyncio
    async def test_monkeypatched_gate_is_honoured(self, monkeypatch, warn, bound):
        """Tests that stub ``_tool_denied_reason`` keep working: the wrapper looks it up by name."""
        monkeypatch.setattr(server, "_tool_denied_reason", lambda name: f"blocked {name}")
        with pytest.raises(ToolError, match="blocked memory_forget"):
            await server.memory_forget(key="k")

    def test_bound_and_credential_read_from_env(self, monkeypatch):
        monkeypatch.delenv("CAO_TERMINAL_ID", raising=False)
        monkeypatch.delenv("CAO_TERMINAL_TOKEN", raising=False)
        assert tool_gate.bound_terminal_id() is None
        assert tool_gate.agent_credential() is None
        monkeypatch.setenv("CAO_TERMINAL_ID", "abcd1234")
        monkeypatch.setenv("CAO_TERMINAL_TOKEN", "cao_t_x")
        assert tool_gate.bound_terminal_id() == "abcd1234"
        assert tool_gate.agent_credential() == "cao_t_x"
        assert "CAO_TERMINAL_ID" in os.environ
