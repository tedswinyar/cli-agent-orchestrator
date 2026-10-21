"""The two UI handshakes accept per-terminal / per-run bearers (#965, WS2).

``GET /agui/v1/stream`` (SSE, ``?access_token=``) and the terminal WebSocket
attach verify their bearer directly rather than through ``get_current_scopes``,
so WS1's fix there did not reach them: with auth enabled a ``cao_t_`` bearer
was still refused as ``invalid token``. Both now try
``security.auth._agent_bearer_scopes`` first and fall back to the operator / IdP
verifier, so an agent credential is admitted with the agent scope set (read and
write) while operator tokens and the default-off posture are byte-for-byte
unchanged.

SSE: ``since=invalid`` is the tell (borrowed from ``test_local_token_auth``): a
400 for the bad timestamp proves the request got PAST auth. WebSocket: the
admitted path stops at the terminal-metadata lookup (mocked to ``None``), so a
4004 close proves the handshake passed and a 4401 proves it did not.
"""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cli_agent_orchestrator.security import auth
from cli_agent_orchestrator.security.principal import mint_terminal_credential

LOCAL_TOKEN = "s3cret-local-token"
TERMINAL_A = "aaaa1111"


@pytest.fixture(autouse=True)
def _clear_auth_env(monkeypatch, tmp_path):
    for var in (
        "AUTH0_DOMAIN",
        "CAO_AUTH_JWKS_URI",
        "AUTH0_AUDIENCE",
        "CAO_AUTH_AUDIENCE",
        "CAO_AUTH_ISSUER",
        "CAO_AUTH_LOCAL_TOKEN",
        "CAO_PRINCIPAL_ENFORCE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CAO_HOME_DIR", str(tmp_path / "cao-home"))
    auth.get_jwks_cache().clear()
    yield
    auth.get_jwks_cache().clear()


@pytest.fixture
def local_token_mode(monkeypatch):
    monkeypatch.setenv("CAO_AUTH_LOCAL_TOKEN", LOCAL_TOKEN)


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from cli_agent_orchestrator.clients import database

    engine = create_engine(
        f"sqlite:///{tmp_path / 'handshakes.db'}",
        connect_args={"check_same_thread": False},
    )
    database.Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(
        database,
        "SessionLocal",
        sessionmaker(autocommit=False, autoflush=False, bind=engine),
    )
    yield database
    engine.dispose()


@pytest.fixture
def agent_token(fresh_db):
    """A live terminal row with a minted credential; returns the plaintext token."""
    fresh_db.create_terminal(
        TERMINAL_A, "cao-sess", "w", "claude_code", "developer", allowed_tools=["fs_read"]
    )
    token, digest = mint_terminal_credential()
    assert fresh_db.set_terminal_credential_digest(TERMINAL_A, digest)
    return token


@pytest.fixture
def revoked_token(fresh_db):
    """A well-formed ``cao_t_`` bearer no row carries (revoked / never issued)."""
    return mint_terminal_credential()[0]


# --- SSE: GET /agui/v1/stream?access_token= -----------------------------------


class TestAguiStreamAgentBearer:
    @pytest.fixture(autouse=True)
    def _agui_on(self, monkeypatch):
        monkeypatch.setenv("CAO_AGUI_ENABLED", "true")

    def _get(self, client, **params):
        return client.get("/agui/v1/stream", params={"since": "invalid", **params})

    def test_agent_bearer_admitted_under_local_token_mode(
        self, client, local_token_mode, agent_token
    ):
        resp = self._get(client, access_token=agent_token)
        assert resp.status_code == 400  # past auth; rejected on the timestamp, not the token

    def test_revoked_agent_bearer_is_401(self, client, local_token_mode, revoked_token):
        resp = self._get(client, access_token=revoked_token)
        assert resp.status_code == 401
        assert resp.json()["detail"] == "terminal credential revoked"

    def test_operator_token_unchanged(self, client, local_token_mode, fresh_db):
        assert self._get(client, access_token=LOCAL_TOKEN).status_code == 400
        assert self._get(client, access_token="nope").status_code == 401
        assert self._get(client).status_code == 401

    def test_default_off_unchanged(self, client, agent_token):
        assert self._get(client).status_code == 400
        assert self._get(client, access_token=agent_token).status_code == 400
        assert self._get(client, access_token="whatever").status_code == 400


# --- WebSocket: /terminals/{terminal_id}/ws -----------------------------------


def _make_ws(**overrides):
    ws = MagicMock()
    ws.client = MagicMock(host="127.0.0.1")
    ws.headers = {}
    ws.query_params = {}
    ws.accept = AsyncMock()
    ws.close = AsyncMock()
    for key, value in overrides.items():
        setattr(ws, key, value)
    return ws


@contextmanager
def _admitted_patches():
    with (
        patch("cli_agent_orchestrator.api.main.WS_ALLOWED_CLIENTS", ["127.0.0.1"]),
        patch("cli_agent_orchestrator.api.main.get_terminal_metadata", return_value=None),
    ):
        yield


async def _attach(ws):
    from cli_agent_orchestrator.api.main import terminal_ws

    with _admitted_patches():
        await terminal_ws(ws, "abcd1234")
    return ws.close.call_args.kwargs.get("code")


class TestTerminalWsAgentBearer:
    @pytest.mark.asyncio
    async def test_agent_bearer_header_admitted_under_local_token_mode(
        self, local_token_mode, agent_token
    ):
        ws = _make_ws(headers={"authorization": f"Bearer {agent_token}"})
        assert await _attach(ws) == 4004  # past auth; stopped at terminal-not-found
        ws.accept.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_agent_bearer_query_param_admitted_under_local_token_mode(
        self, local_token_mode, agent_token
    ):
        ws = _make_ws(query_params={"token": agent_token})
        assert await _attach(ws) == 4004
        ws.accept.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_revoked_agent_bearer_rejected(self, local_token_mode, revoked_token):
        ws = _make_ws(headers={"authorization": f"Bearer {revoked_token}"})
        assert await _attach(ws) == 4401
        ws.accept.assert_not_called()

    @pytest.mark.asyncio
    async def test_operator_token_unchanged(self, local_token_mode, fresh_db):
        assert await _attach(_make_ws(headers={"authorization": f"Bearer {LOCAL_TOKEN}"})) == 4004
        assert await _attach(_make_ws(headers={"authorization": "Bearer wrong"})) == 4401
        assert await _attach(_make_ws()) == 4401

    @pytest.mark.asyncio
    async def test_default_off_unchanged(self, agent_token):
        assert await _attach(_make_ws()) == 4004
        assert await _attach(_make_ws(headers={"authorization": f"Bearer {agent_token}"})) == 4004
