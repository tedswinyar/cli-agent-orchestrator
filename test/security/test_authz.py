"""Every ``authorize`` rule with allow and deny cases, plus ``check`` semantics (#965)."""

import pytest
from fastapi import HTTPException

from cli_agent_orchestrator.security import audit, authz
from cli_agent_orchestrator.security.authz import (
    ACTIONS,
    ALWAYS_ALLOWED_TOOLS,
    CALLBACK_TOOLS,
    CAO_MCP_SERVER,
    CAO_OPS_MCP_SERVER,
    DISCOVERY_TOOLS,
    FLEET,
    OPERATOR_ROUTE,
    RUN_CANCEL,
    RUN_REPLAY,
    RUN_RESUME,
    TERMINAL_ACT_AS,
    TERMINAL_CREATE,
    TOOL_CALL,
    Decision,
    RunRef,
    authorize,
    check,
    enforcing,
)
from cli_agent_orchestrator.security.principal import Principal

RW = frozenset({"cao:read", "cao:write"})


def term(tid="t1", allowed=(), delegate=(), ancestors=()):
    return Principal(
        kind="terminal",
        scopes=RW,
        terminal_id=tid,
        allowed_tools=tuple(allowed),
        delegate_tools=tuple(delegate),
        ancestors=tuple(ancestors),
    )


def run_p(run_id="r1", tid="t1"):
    return Principal(kind="run", scopes=RW, terminal_id=tid, run_id=run_id)


OPERATOR = Principal(kind="operator", scopes=frozenset({"cao:admin"}))
ANON = Principal(kind="anonymous", scopes=frozenset({"cao:read", "cao:write", "cao:admin"}))

_RESOURCE_FOR = {
    TOOL_CALL: "assign",
    TERMINAL_CREATE: ("*",),
    TERMINAL_ACT_AS: "someone-else",
    RUN_CANCEL: RunRef("r", "other"),
    RUN_RESUME: RunRef("r", "other"),
    RUN_REPLAY: RunRef("r", "other"),
    FLEET: "launch_session",
    OPERATOR_ROUTE: "shutdown",
}


class TestActionsExport:
    def test_actions_frozenset_matches_constants(self):
        assert ACTIONS == frozenset(_RESOURCE_FOR)
        assert isinstance(ACTIONS, frozenset)

    def test_unknown_action_denied(self):
        d = authorize(OPERATOR, "nope:x", None)
        assert d == Decision(False, "unknown-action", d.reason)
        assert not authorize(term(), "tool:cal", "x").allowed


class TestOperatorPosture:
    @pytest.mark.parametrize("action", sorted(ACTIONS))
    @pytest.mark.parametrize("p", [OPERATOR, ANON], ids=["operator", "anonymous"])
    def test_operator_and_anonymous_allowed_everything(self, p, action):
        d = authorize(p, action, _RESOURCE_FOR[action], server=CAO_OPS_MCP_SERVER)
        assert d.allowed and d.rule == "operator"


class TestToolCall:
    @pytest.mark.parametrize("tool", sorted(ALWAYS_ALLOWED_TOOLS))
    def test_callback_and_discovery_always_allowed_for_terminal(self, tool):
        d = authorize(term(allowed=()), TOOL_CALL, tool, server=CAO_MCP_SERVER)
        assert d.allowed
        assert d.rule == ("tool:callback" if tool in CALLBACK_TOOLS else "tool:discovery")

    @pytest.mark.parametrize("tool", sorted(ALWAYS_ALLOWED_TOOLS))
    def test_exception_set_does_not_leak_to_ops_server(self, tool):
        assert not authorize(
            term(allowed=("*",)), TOOL_CALL, tool, server=CAO_OPS_MCP_SERVER
        ).allowed

    def test_exception_set_is_the_671_ruling(self):
        assert CALLBACK_TOOLS == {
            "send_message",
            "complete_assignment",
            "workflow_return",
            "answer_user_prompt",
        }
        assert DISCOVERY_TOOLS == {"list_siblings", "update_metadata"}

    @pytest.mark.parametrize(
        "allowed",
        [(), ("fs_read",), ("@other-server",), ("@cao-mcp-server/handoff",), ("assign",)],
    )
    def test_default_deny(self, allowed):
        d = authorize(term(allowed=allowed), TOOL_CALL, "assign", server=CAO_MCP_SERVER)
        assert not d.allowed and d.rule == "tool:default-deny"
        assert "assign" in d.reason and "t1" in d.reason

    @pytest.mark.parametrize(
        "allowed",
        [
            ("*",),
            ("@cao-mcp-server",),
            ("@cao-mcp-server/assign",),
            ("fs_read", "@cao-*"),
        ],
    )
    def test_allowlist_coverage_forms(self, allowed):
        d = authorize(term(allowed=allowed), TOOL_CALL, "assign", server=CAO_MCP_SERVER)
        assert d.allowed and d.rule == "tool:allowlist"

    def test_server_defaults_to_cao_mcp_server(self):
        assert authorize(term(allowed=("@cao-mcp-server",)), TOOL_CALL, "assign").allowed

    def test_ops_server_denied_for_terminal_and_run(self):
        for p in (term(allowed=("*",)), run_p()):
            d = authorize(p, TOOL_CALL, "launch_session", server=CAO_OPS_MCP_SERVER)
            assert not d.allowed and d.rule == "fleet:operator-only"

    def test_builtin_selector_does_not_cover(self):
        assert not authorize(term(allowed=("@builtin",)), TOOL_CALL, "assign").allowed


class TestTerminalCreate:
    def test_within_own_allowlist(self):
        d = authorize(term(allowed=("fs_read", "@cao-mcp-server")), TERMINAL_CREATE, ("fs_read",))
        assert d.allowed and d.rule == "terminal:within-ceiling"

    def test_empty_request_allowed(self):
        assert authorize(term(allowed=()), TERMINAL_CREATE, ()).allowed

    def test_outside_ceiling_denied_names_offender(self):
        d = authorize(term(allowed=("fs_read",)), TERMINAL_CREATE, ("fs_read", "execute_bash"))
        assert not d.allowed and d.rule == "terminal:ceiling"
        assert "execute_bash" in d.reason and "fs_read" not in d.reason.split("[")[1]

    def test_star_ceiling_grants_all(self):
        assert authorize(term(allowed=("*",)), TERMINAL_CREATE, ("execute_bash", "@x")).allowed

    def test_star_requested_needs_star_ceiling(self):
        assert not authorize(term(allowed=("fs_read",)), TERMINAL_CREATE, ("*",)).allowed

    def test_server_selector_covers_per_tool_form(self):
        assert authorize(
            term(allowed=("@cao-mcp-server",)), TERMINAL_CREATE, ("@cao-mcp-server/assign",)
        ).allowed
        assert not authorize(
            term(allowed=("@cao-mcp-server/assign",)), TERMINAL_CREATE, ("@cao-mcp-server",)
        ).allowed

    def test_delegate_tools_is_the_ceiling_when_set(self):
        p = term(allowed=("*",), delegate=("fs_read",))
        assert authorize(p, TERMINAL_CREATE, ("fs_read",)).allowed
        assert not authorize(p, TERMINAL_CREATE, ("execute_bash",)).allowed

    def test_ceiling_of(self):
        assert authz.ceiling_of(term(allowed=("a",), delegate=())) == ("a",)
        assert authz.ceiling_of(term(allowed=("a",), delegate=("b",))) == ("b",)


class TestActAs:
    def test_self_allowed(self):
        d = authorize(term("t1"), TERMINAL_ACT_AS, "t1")
        assert d.allowed and d.rule == "terminal:self"

    @pytest.mark.parametrize("claimed", ["t2", "", None])
    def test_other_denied(self, claimed):
        d = authorize(term("t1"), TERMINAL_ACT_AS, claimed)
        assert not d.allowed and d.rule == "terminal:impersonation"

    def test_operator_may_act_as_anyone(self):
        assert authorize(OPERATOR, TERMINAL_ACT_AS, "t9").allowed


class TestRunActions:
    REF = RunRef("r1", "owner", ("gp", "root"))

    @pytest.mark.parametrize("action", [RUN_CANCEL, RUN_RESUME, RUN_REPLAY])
    def test_owner(self, action):
        d = authorize(term("owner"), action, self.REF)
        assert d.allowed and d.rule == "run:owner"

    @pytest.mark.parametrize("action", [RUN_CANCEL, RUN_RESUME, RUN_REPLAY])
    def test_ancestor(self, action):
        d = authorize(term("root"), action, self.REF)
        assert d.allowed and d.rule == "run:ancestor"

    @pytest.mark.parametrize("action", [RUN_CANCEL, RUN_RESUME, RUN_REPLAY])
    def test_stranger_denied(self, action):
        d = authorize(term("stranger"), action, self.REF)
        assert not d.allowed and d.rule == "run:not-owner"
        assert "r1" in d.reason

    def test_run_principal_own_run(self):
        assert authorize(run_p("r1", tid=None), RUN_CANCEL, self.REF).rule == "run:self"
        assert not authorize(run_p("r2", tid=None), RUN_CANCEL, self.REF).allowed

    def test_run_principal_inherits_terminal_ownership(self):
        assert authorize(run_p("r2", tid="owner"), RUN_CANCEL, self.REF).rule == "run:owner"

    def test_none_owner_does_not_match_none_terminal(self):
        p = Principal(kind="run", scopes=RW, run_id="other")
        assert not authorize(p, RUN_CANCEL, RunRef("r1", None)).allowed

    def test_bad_resource_denied(self):
        assert authorize(term(), RUN_CANCEL, "r1").rule == "run:bad-resource"


class TestOperatorOnly:
    def test_fleet(self):
        d = authorize(term(allowed=("*",)), FLEET, "launch_session")
        assert not d.allowed and d.rule == "fleet:operator-only"
        assert not authorize(run_p(), FLEET, "x").allowed

    def test_operator_route(self):
        d = authorize(term(allowed=("*",)), OPERATOR_ROUTE, "shutdown")
        assert not d.allowed and d.rule == "operator:route"


class TestEnforcing:
    def test_default_off(self):
        assert enforcing() is False

    @pytest.mark.parametrize(
        "value,expected",
        [("1", True), ("true", True), ("TRUE", True), ("0", False), ("yes", False), ("", False)],
    )
    def test_values(self, monkeypatch, value, expected):
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", value)
        assert enforcing() is expected


class TestCheck:
    def test_warn_mode_returns_denial_without_raising_and_audits(self):
        d = check(term(allowed=()), TOOL_CALL, "assign", server=CAO_MCP_SERVER)
        assert not d.allowed
        recs = audit.read_recent()
        assert len(recs) == 1
        assert recs[0]["allowed"] is False and recs[0]["enforced"] is False
        assert recs[0]["resource"] == "cao-mcp-server/assign"

    def test_enforce_mode_raises_403_with_reason(self, monkeypatch):
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
        with pytest.raises(HTTPException) as ei:
            check(term(allowed=()), TOOL_CALL, "assign", server=CAO_MCP_SERVER)
        assert ei.value.status_code == 403
        assert ei.value.detail == authorize(term(allowed=()), TOOL_CALL, "assign").reason
        assert audit.read_recent()[0]["enforced"] is True

    def test_enforce_mode_allow_returns_decision(self, monkeypatch):
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
        d = check(term(allowed=("*",)), TOOL_CALL, "assign")
        assert d.allowed
        assert audit.read_recent() == []  # allows not audited unless flagged

    def test_run_resource_repr(self):
        check(term("x"), RUN_CANCEL, RunRef("r1", "o"))
        assert audit.read_recent()[0]["resource"] == "run:r1"
