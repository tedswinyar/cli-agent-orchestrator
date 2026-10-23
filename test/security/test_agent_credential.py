"""``agent_credential()`` precedence and the three thin aliases over it (#965, #990)."""

from unittest.mock import Mock, patch

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


@pytest.fixture(autouse=True)
def _unbound(monkeypatch):
    """No claimed terminal id by default: the operator-shell path.

    The precedence table below is about an UNBOUND process (an operator shell,
    the ``cao`` CLI outside a pane, an external MCP client). A process that
    claims a ``CAO_TERMINAL_ID`` has its own rule -- see
    ``TestBoundProcessNeverFallsBack``.
    """
    monkeypatch.delenv("CAO_TERMINAL_ID", raising=False)


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


@pytest.mark.unpaired_terminal_credential
class TestBoundProcessNeverFallsBack:
    """A process that claims a terminal identity must not present the OPERATOR's token.

    The credential-fallback hole every review named. ``CAO_TERMINAL_ID`` set and
    ``CAO_TERMINAL_TOKEN`` missing is a CAO-launched agent whose own credential
    did not arrive -- a provider that cannot pass it, a relaunched legacy pane, a
    script that dropped it, or an agent that unset it on purpose. The old
    precedence handed that process ``CAO_AUTH_LOCAL_TOKEN``, so it reached the
    API **as the operator**: unbounded, and attributable to nobody. "Every hop
    carries the terminal's own credential" was false precisely when it mattered.

    Failing closed IN THE AGENT'S OWN PROCESS is what this can fix. It does not
    stop a determined agent (it can unset ``CAO_TERMINAL_ID`` too, and the server
    still answers an anonymous caller when auth is off -- that is the design
    question the proposal has to answer, not something a helper can close). It
    does stop the accidental path, which is the one that silently produced a
    population of operator-authority agents nobody could see.
    """

    BOUND = {"CAO_TERMINAL_ID": "a1b2c3d4"}

    def test_bound_with_no_terminal_token_raises(self, monkeypatch):
        monkeypatch.setenv("CAO_TERMINAL_ID", "a1b2c3d4")
        monkeypatch.delenv(TERMINAL_TOKEN_ENV, raising=False)
        with pytest.raises(cred.MissingTerminalCredential) as excinfo:
            agent_credential(operator_bearer=lambda: "op-tok")
        message = str(excinfo.value)
        assert "a1b2c3d4" in message
        assert TERMINAL_TOKEN_ENV in message

    def test_the_operator_token_is_never_even_consulted(self, monkeypatch):
        """Not just unused: not read. A refusal that still reads the secret is sloppy."""
        monkeypatch.setenv("CAO_TERMINAL_ID", "a1b2c3d4")
        monkeypatch.delenv(TERMINAL_TOKEN_ENV, raising=False)
        bearer = Mock(return_value="op-tok")
        with pytest.raises(cred.MissingTerminalCredential):
            agent_credential(operator_bearer=bearer)
        bearer.assert_not_called()

    def test_it_raises_even_with_no_operator_token_configured(self, monkeypatch):
        """Default-off too: the process is still misconfigured, and loudly so.

        Returning ``{}`` here would be the same silent degradation in a different
        costume -- an anonymous caller with full authority when auth is off.
        """
        monkeypatch.setenv("CAO_TERMINAL_ID", "a1b2c3d4")
        monkeypatch.delenv(TERMINAL_TOKEN_ENV, raising=False)
        with pytest.raises(cred.MissingTerminalCredential):
            agent_credential(operator_bearer=lambda: None)

    def test_a_blank_terminal_token_is_the_same_as_missing(self, monkeypatch):
        monkeypatch.setenv("CAO_TERMINAL_ID", "a1b2c3d4")
        monkeypatch.setenv(TERMINAL_TOKEN_ENV, "   ")
        with pytest.raises(cred.MissingTerminalCredential):
            agent_credential(operator_bearer=lambda: "op-tok")

    def test_a_blank_terminal_id_is_unbound(self, monkeypatch):
        """Whitespace is "not set", the same reading ``terminal_token`` applies."""
        monkeypatch.setenv("CAO_TERMINAL_ID", "  ")
        monkeypatch.delenv(TERMINAL_TOKEN_ENV, raising=False)
        assert agent_credential(operator_bearer=lambda: "op-tok") == {
            "Authorization": "Bearer op-tok"
        }

    def test_bound_with_its_own_token_is_unchanged(self, monkeypatch):
        monkeypatch.setenv("CAO_TERMINAL_ID", "a1b2c3d4")
        monkeypatch.setenv(TERMINAL_TOKEN_ENV, "cao_t_abc")
        assert agent_credential(operator_bearer=lambda: "op-tok") == {
            "Authorization": "Bearer cao_t_abc"
        }

    @pytest.mark.parametrize(
        "alias",
        [
            "cli_agent_orchestrator.mcp_server.utils._auth_headers",
            "cli_agent_orchestrator.mcp_server.app_tools._auth_headers",
            "cli_agent_orchestrator.utils.orchestration._auth_headers",
        ],
    )
    def test_every_alias_fails_closed_too(self, monkeypatch, alias):
        """The three thin aliases are the real call sites; a hole in one is a hole."""
        import importlib

        module_path, _, name = alias.rpartition(".")
        fn = getattr(importlib.import_module(module_path), name)
        monkeypatch.setenv("CAO_TERMINAL_ID", "a1b2c3d4")
        monkeypatch.delenv(TERMINAL_TOKEN_ENV, raising=False)
        monkeypatch.setenv("CAO_AUTH_LOCAL_TOKEN", "op-tok")
        with pytest.raises(cred.MissingTerminalCredential):
            fn()
