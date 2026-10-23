"""Every ``cao-ops-mcp-server`` tool is operator-only at the host layer (#671, WS3).

``authorize`` refuses every ``tool:call`` on ``cao-ops-mcp-server`` for a
``terminal`` principal (rule ``fleet:operator-only``) whatever its allowlist,
and allows operators. The gate reads boundness from ``CAO_TERMINAL_ID`` exactly
as ``cao-mcp-server`` does, so a human driving the ops server from outside a
session (the supported use) is never looked up and the default-off wire bytes
are unchanged. These tools were not gated on main, so a denial refuses only
under ``CAO_PRINCIPAL_ENFORCE``; warn mode audits and proceeds.

The identity is the BEARER's principal from ``GET /me/principal``, not the row
``CAO_TERMINAL_ID`` names: this gate reached that row through the same
``GET /terminals/{id}`` hop that made the substitution possible on the CAO
server, so it is bound the same way.
"""

from __future__ import annotations

from test.security.test_tool_gate_census import EXPECTED_OPS_TOOLS
from unittest.mock import patch

import pytest
from fastmcp.exceptions import ToolError

from cli_agent_orchestrator.ops_mcp_server import decision_tools, gate
from cli_agent_orchestrator.ops_mcp_server import server as ops
from cli_agent_orchestrator.ops_mcp_server.models import ProfileListResult
from cli_agent_orchestrator.security import audit, tool_gate
from cli_agent_orchestrator.security.authz import CAO_OPS_MCP_SERVER

TERMINAL_ID = "a1b2c3d4"


def _body(**kwargs):
    """A ``GET /me/principal`` body, via the shared builder the CAO gate's tests use."""
    from test.mcp_server.conftest import identity_body

    return identity_body(["*"], terminal_id=TERMINAL_ID, **kwargs)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CAO_HOME_DIR", str(tmp_path / "cao-home"))
    monkeypatch.delenv("CAO_AUTHZ_AUDIT_ALLOWS", raising=False)


@pytest.fixture
def warn(home, monkeypatch):
    monkeypatch.delenv("CAO_PRINCIPAL_ENFORCE", raising=False)


@pytest.fixture
def enforce(home, monkeypatch):
    monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")


@pytest.fixture
def terminal(monkeypatch):
    monkeypatch.setenv("CAO_TERMINAL_ID", TERMINAL_ID)
    with patch.object(gate, "_fetch_caller_principal", return_value=_body()):
        yield


@pytest.fixture
def operator(monkeypatch):
    monkeypatch.delenv("CAO_TERMINAL_ID", raising=False)


class TestOperator:
    @pytest.mark.parametrize("tool", sorted(EXPECTED_OPS_TOOLS))
    def test_allowed_without_a_lookup(self, enforce, operator, tool):
        with patch.object(gate, "_fetch_caller_principal") as fetch:
            assert gate._tool_denied_reason(tool) is None
        fetch.assert_not_called()
        assert audit.read_recent() == []

    @pytest.mark.asyncio
    async def test_tool_body_runs(self, enforce, operator):
        with patch.object(ops, "_request_json", return_value=([], None)):
            result = await ops.list_profiles()
        assert isinstance(result, ProfileListResult) and result.success is True


class TestTerminalPrincipal:
    @pytest.mark.parametrize("tool", sorted(EXPECTED_OPS_TOOLS))
    def test_denied_even_with_a_wildcard_allowlist(self, enforce, terminal, tool):
        reason = gate._tool_denied_reason(tool)
        assert reason is not None
        assert "fleet:operator-only" in reason and tool in reason

    def test_warn_mode_audits_and_proceeds(self, warn, terminal):
        assert gate._tool_denied_reason("launch_session") is None
        rec = audit.read_recent()[-1]
        assert rec["allowed"] is False and rec["enforced"] is False
        assert rec["rule"] == "fleet:operator-only"
        assert rec["resource"] == f"{CAO_OPS_MCP_SERVER}/launch_session"
        assert rec["terminal_id"] == TERMINAL_ID

    @pytest.mark.asyncio
    async def test_enforce_mode_refuses_through_the_decorator(self, enforce, terminal):
        with patch.object(ops, "_request_json") as request:
            with pytest.raises(ToolError) as ei:
                await ops.launch_session(agent_profile="developer")
        request.assert_not_called()
        assert "fleet:operator-only" in str(ei.value)
        assert audit.read_recent()[-1]["enforced"] is True

    @pytest.mark.asyncio
    async def test_warn_mode_still_calls_through(self, warn, terminal):
        with patch.object(ops, "_request_json", return_value=([], None)):
            result = await ops.list_profiles()
        assert result.success is True

    def test_unresolvable_identity_fails_closed_when_enforcing(self, enforce, monkeypatch):
        monkeypatch.setenv("CAO_TERMINAL_ID", TERMINAL_ID)
        with patch.object(gate, "_fetch_caller_principal", side_effect=RuntimeError("down")):
            reason = gate._tool_denied_reason("shutdown_session")
        assert reason is not None and "cannot authorize" in reason

    def test_unresolvable_identity_proceeds_in_warn_mode(self, warn, monkeypatch):
        monkeypatch.setenv("CAO_TERMINAL_ID", TERMINAL_ID)
        with patch.object(gate, "_fetch_caller_principal", side_effect=RuntimeError("down")):
            assert gate._tool_denied_reason("shutdown_session") is None

    def test_a_rejected_payload_fails_closed_when_enforcing(self, enforce, monkeypatch):
        """A body the deserializer cannot read is an unknown, not an operator."""
        monkeypatch.setenv("CAO_TERMINAL_ID", TERMINAL_ID)
        with patch.object(gate, "_fetch_caller_principal", return_value={"identity_bound": True}):
            reason = gate._tool_denied_reason("shutdown_session")
        assert reason is not None and "cannot authorize" in reason

    def test_the_fetch_uses_the_servers_request_helper_and_sends_the_claim(self, monkeypatch):
        body = _body()
        with patch.object(ops, "_request_json", return_value=(body, None)) as request:
            assert gate._fetch_caller_principal(TERMINAL_ID) == body
        assert request.call_args.args == ("get", "/me/principal")
        assert request.call_args.kwargs["params"] == {"claimed_terminal_id": TERMINAL_ID}
        with patch.object(ops, "_request_json", return_value=(None, "boom")):
            with pytest.raises(RuntimeError):
                gate._fetch_caller_principal(TERMINAL_ID)


class TestDecisionTools:
    """Registered through ``register_decision_tools(surface)``; gated on the way in."""

    def _surface(self):
        class Surface:
            def __init__(self):
                self.tools = {}

            def tool(self, fn):
                self.tools[fn.__name__] = fn
                return fn

        surface = Surface()
        decision_tools.register_decision_tools(surface)
        return surface.tools

    def test_registered_functions_are_gated(self):
        tools = self._surface()
        assert set(tools) == {n for n in EXPECTED_OPS_TOOLS if n.startswith("decisions_")}
        for fn in tools.values():
            assert tool_gate.is_gated(fn, CAO_OPS_MCP_SERVER)

    def test_terminal_principal_is_refused(self, enforce, terminal):
        tools = self._surface()
        with pytest.raises(ToolError):
            tools["decisions_status"]()


class TestDecorator:
    def test_every_live_tool_is_marked(self):
        for name in EXPECTED_OPS_TOOLS - {
            n for n in EXPECTED_OPS_TOOLS if n.startswith("decisions_")
        }:
            assert tool_gate.is_gated(getattr(ops, name), CAO_OPS_MCP_SERVER), name

    def test_missing_required_argument_raises_at_the_call(self):
        with pytest.raises(TypeError):
            ops.get_profile_details()  # type: ignore[call-arg]
