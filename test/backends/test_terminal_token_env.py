"""``CAO_TERMINAL_TOKEN`` survives both backends' env filters and herdr's arg sanitizer (#965).

``terminal_service`` hands the token to the backend through the same
``extra_env`` channel as ``cao launch --env``. Both backends filter that
channel (blocked prefixes, byte cap) and herdr additionally runs every argv
token through ``_sanitize_herdr_args``; these tests pin that a minted token
passes all three, and that an inherited token from the server's own
environment cannot shadow the one the service passes.
"""

from unittest.mock import MagicMock, patch

import pytest

from cli_agent_orchestrator.backends.herdr_backend import HerdrBackend, _sanitize_herdr_args
from cli_agent_orchestrator.clients.tmux import TmuxClient
from cli_agent_orchestrator.security.agent_credential import TERMINAL_TOKEN_ENV
from cli_agent_orchestrator.security.principal import mint_terminal_credential


@pytest.fixture
def token():
    return mint_terminal_credential()[0]


class TestTmux:
    def test_merge_extra_env_keeps_the_token(self, token):
        env: dict = {}
        TmuxClient._merge_extra_env(env, {TERMINAL_TOKEN_ENV: token})
        assert env[TERMINAL_TOKEN_ENV] == token
        assert not TmuxClient._is_blocked_env_key(TERMINAL_TOKEN_ENV)

    def test_create_session_passes_the_token_and_overrides_an_inherited_one(
        self, token, tmp_path, monkeypatch
    ):
        """cao-server itself may run inside a CAO terminal (nested); the inherited
        ``CAO_*`` slice must not hand the child the parent's credential."""
        monkeypatch.setenv(TERMINAL_TOKEN_ENV, "cao_t_parents_token")
        monkeypatch.setenv("CAO_TERMINAL_ID", "parent01")
        tmux = TmuxClient.__new__(TmuxClient)
        tmux.server = MagicMock()
        tmux._set_server_exit_empty_off = lambda: None
        window = MagicMock()
        window.name = "w0"
        session = MagicMock()
        session.windows = [window]
        tmux.server.new_session.return_value = session
        with patch.object(
            TmuxClient, "_resolve_and_validate_working_directory", return_value=str(tmp_path)
        ):
            tmux.create_session(
                "cao-x", "w0", "child001", str(tmp_path), extra_env={TERMINAL_TOKEN_ENV: token}
            )
        env = tmux.server.new_session.call_args.kwargs["environment"]
        assert env[TERMINAL_TOKEN_ENV] == token
        assert env["CAO_TERMINAL_ID"] == "child001"


class TestHerdr:
    def test_build_env_args_carries_the_token(self, token):
        backend = HerdrBackend.__new__(HerdrBackend)
        args = backend._build_env_args("tid00001", "cao-x", {TERMINAL_TOKEN_ENV: token})
        pairs = [args[i + 1] for i in range(0, len(args), 2)]
        assert f"{TERMINAL_TOKEN_ENV}={token}" in pairs
        assert "CAO_TERMINAL_ID=tid00001" in pairs

    def test_minted_tokens_are_sanitizer_safe(self):
        """url-safe base64 (A-Z a-z 0-9 - _) never trips the metachar sanitizer."""
        for _ in range(50):
            t, _ = mint_terminal_credential()
            argv = ["workspace", "create", "--label", "cao-x", "--env", f"{TERMINAL_TOKEN_ENV}={t}"]
            assert _sanitize_herdr_args(argv) == argv
