"""``agent_credential()`` precedence and the three thin aliases over it (#965, #990)."""

from unittest.mock import patch

import pytest

from cli_agent_orchestrator.mcp_server import app_tools
from cli_agent_orchestrator.mcp_server import utils as mcp_utils
from cli_agent_orchestrator.security import agent_credential as cred
from cli_agent_orchestrator.security.agent_credential import (
    TERMINAL_TOKEN_ENV,
    agent_credential,
    terminal_token,
)
from cli_agent_orchestrator.utils import orchestration


@pytest.mark.parametrize(
    ("terminal", "operator", "expected"),
    [
        # terminal token > operator token > none
        ("cao_t_abc", "op-tok", {"Authorization": "Bearer cao_t_abc"}),
        ("cao_t_abc", None, {"Authorization": "Bearer cao_t_abc"}),
        (None, "op-tok", {"Authorization": "Bearer op-tok"}),
        (None, None, {}),
        # whitespace-only is "not set", exactly like get_local_bearer treats its own
        ("   ", "op-tok", {"Authorization": "Bearer op-tok"}),
        ("", None, {}),
    ],
    ids=["both", "terminal-only", "operator-only", "neither", "blank-terminal", "empty-terminal"],
)
def test_precedence_table(monkeypatch, terminal, operator, expected):
    if terminal is None:
        monkeypatch.delenv(TERMINAL_TOKEN_ENV, raising=False)
    else:
        monkeypatch.setenv(TERMINAL_TOKEN_ENV, terminal)
    assert agent_credential(operator_bearer=lambda: operator) == expected


def test_default_fallback_is_get_local_bearer_looked_up_at_call_time(monkeypatch):
    monkeypatch.delenv(TERMINAL_TOKEN_ENV, raising=False)
    monkeypatch.setattr(cred, "get_local_bearer", lambda: "patched")
    assert agent_credential() == {"Authorization": "Bearer patched"}


def test_default_off_is_byte_identical(monkeypatch):
    """No terminal token, auth layer off: no header at all, not an empty one."""
    monkeypatch.delenv(TERMINAL_TOKEN_ENV, raising=False)
    assert agent_credential() == {}
    assert terminal_token() is None


def test_terminal_token_is_stripped(monkeypatch):
    monkeypatch.setenv(TERMINAL_TOKEN_ENV, "  cao_t_xyz\n")
    assert terminal_token() == "cao_t_xyz"


class TestAliases:
    """The old names still exist, still honour their module's patched fallback,
    and now prefer the terminal token."""

    ALIASES = [
        (mcp_utils, "cli_agent_orchestrator.mcp_server.utils.get_local_bearer"),
        (app_tools, "cli_agent_orchestrator.mcp_server.app_tools.get_local_bearer"),
        (orchestration, "cli_agent_orchestrator.utils.orchestration.get_local_bearer"),
    ]

    @pytest.mark.parametrize("module,target", ALIASES, ids=lambda m: getattr(m, "__name__", m))
    def test_alias_prefers_terminal_token(self, monkeypatch, module, target):
        monkeypatch.setenv(TERMINAL_TOKEN_ENV, "cao_t_mine")
        with patch(target, return_value="op-tok"):
            assert module._auth_headers() == {"Authorization": "Bearer cao_t_mine"}

    @pytest.mark.parametrize("module,target", ALIASES, ids=lambda m: getattr(m, "__name__", m))
    def test_alias_falls_back_to_its_own_patched_operator_bearer(self, monkeypatch, module, target):
        monkeypatch.delenv(TERMINAL_TOKEN_ENV, raising=False)
        with patch(target, return_value="op-tok"):
            assert module._auth_headers() == {"Authorization": "Bearer op-tok"}
        with patch(target, return_value=None):
            assert module._auth_headers() == {}

    def test_scoped_companions_still_scope(self, monkeypatch):
        """``_auth_headers_for`` must not leak the TERMINAL token to another node either."""
        from cli_agent_orchestrator.constants import API_BASE_URL

        monkeypatch.setenv(TERMINAL_TOKEN_ENV, "cao_t_mine")
        for helper in (mcp_utils._auth_headers_for, orchestration._auth_headers_for):
            assert helper(API_BASE_URL) == {"Authorization": "Bearer cao_t_mine"}
            assert helper("http://worker-7:9889") == {}
