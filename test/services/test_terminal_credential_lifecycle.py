"""A terminal's credential is minted at create, lives only in its pane env, and dies with it (#965).

Drives the real ``create_terminal`` / ``delete_terminal`` against a fresh SQLite
database and a recording fake backend, with the provider, FIFO and status
plumbing stubbed, then resolves the minted token through the real
``get_current_principal`` dependency the API will use.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from cli_agent_orchestrator.backends.base import (
    TerminalCleanupOutcome,
    TerminalCleanupResult,
)
from cli_agent_orchestrator.models.agent_profile import AgentProfile
from cli_agent_orchestrator.security.agent_credential import TERMINAL_TOKEN_ENV
from cli_agent_orchestrator.security.principal import (
    TERMINAL_TOKEN_PREFIX,
    Principal,
    digest_of,
    get_current_principal,
)
from cli_agent_orchestrator.services import terminal_service
from cli_agent_orchestrator.services.session_env import clear_session_env, get_session_env
from cli_agent_orchestrator.services.terminal_service import create_terminal, delete_terminal

pytestmark = pytest.mark.usefixtures("isolated_memory_db")


class RecordingBackend:
    """Records the env each create call hands the pane, like tmux/herdr would."""

    def __init__(self):
        self.sessions: dict[str, dict] = {}
        self.create_calls: list[tuple[str, str, str, dict | None]] = []
        self.dismantle_result = TerminalCleanupResult(TerminalCleanupOutcome.DELETED, "ok")

    # --- create ------------------------------------------------------------
    def session_exists(self, session_name):
        return session_name in self.sessions

    def create_session(
        self, session_name, window_name, terminal_id, working_directory=None, extra_env=None
    ):
        self.sessions[session_name] = {window_name: terminal_id}
        self.create_calls.append(("session", session_name, terminal_id, dict(extra_env or {})))
        return window_name

    def create_window(
        self,
        session_name,
        window_name,
        terminal_id,
        working_directory=None,
        window_shell=None,
        extra_env=None,
    ):
        self.sessions[session_name][window_name] = terminal_id
        self.create_calls.append(("window", session_name, terminal_id, dict(extra_env or {})))
        return window_name

    def supports_event_inbox(self):
        return True  # skips the FIFO / pipe-pane plumbing

    def get_pane_id(self, *a, **k):
        return "%1"

    # --- teardown ----------------------------------------------------------
    def cleanup_terminal_exact(
        self, terminal_id, session_name=None, window_name=None, *, close=True
    ):
        return self.dismantle_result

    def kill_window(self, session_name, window_name):
        return True

    def kill_session(self, session_name):
        self.sessions.pop(session_name, None)
        return True

    def stop_pipe_pane(self, *a, **k):
        return None

    def env_for(self, terminal_id) -> dict:
        return next(env for _, _, tid, env in self.create_calls if tid == terminal_id)


@pytest.fixture
def backend(monkeypatch):
    import cli_agent_orchestrator.backends.registry as registry

    be = RecordingBackend()
    monkeypatch.setattr(registry, "_backend", be)
    return be


@pytest.fixture
def plumbing(monkeypatch):
    """Stub everything around the row + backend so the credential path is what runs."""
    monkeypatch.setattr(
        terminal_service.agent_profiles,
        "load_agent_profile",
        lambda *a, **k: AgentProfile(name="developer", description="Developer"),
    )
    provider = AsyncMock()
    provider.initialize.return_value = True
    provider.shell_baseline = None
    monkeypatch.setattr(
        terminal_service.provider_manager, "create_provider", MagicMock(return_value=provider)
    )
    monkeypatch.setattr(terminal_service.provider_manager, "cleanup_provider", lambda tid: True)
    monkeypatch.setattr(terminal_service, "get_herdr_inbox_service", lambda: None)
    monkeypatch.setattr(terminal_service.fifo_manager, "stop_reader", lambda tid: True)
    monkeypatch.setattr(terminal_service.status_monitor, "clear_terminal", lambda tid: None)
    monkeypatch.delenv("CAO_ELASTIC_WORKER_ID", raising=False)
    yield
    clear_session_env("cao-cred-test")


def _who_client() -> TestClient:
    app = FastAPI()

    @app.get("/who")
    async def who(p: Principal = Depends(get_current_principal)):
        return {
            "kind": p.kind,
            "terminal_id": p.terminal_id,
            "session_name": p.session_name,
            "agent_profile": p.agent_profile,
            "allowed_tools": list(p.allowed_tools),
            "delegate_tools": list(p.delegate_tools),
            "creator_id": p.creator_id,
            "ancestors": list(p.ancestors),
        }

    return TestClient(app)


def _row(terminal_id):
    from cli_agent_orchestrator.clients import database

    with database.SessionLocal() as s:
        return (
            s.query(database.TerminalModel).filter(database.TerminalModel.id == terminal_id).first()
        )


async def _create(backend, **kw):
    kw.setdefault("session_name", "cao-cred-test")
    return await create_terminal("claude_code", "developer", **kw)


# --- mint + inject ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_reaches_the_backend_env_next_to_the_terminal_id(backend, plumbing):
    t = await _create(backend, new_session=True, allowed_tools=["fs_read", "@cao-mcp-server"])

    kind, session, tid, env = backend.create_calls[0]
    assert (kind, tid) == ("session", t.id)
    token = env[TERMINAL_TOKEN_ENV]
    assert token.startswith(TERMINAL_TOKEN_PREFIX) and len(token) > len(TERMINAL_TOKEN_PREFIX) + 40
    # The backend forces CAO_TERMINAL_ID itself; terminal_service passes the token.
    assert "CAO_TERMINAL_ID" not in env or env["CAO_TERMINAL_ID"] == t.id


@pytest.mark.asyncio
async def test_minted_digest_is_stored_and_resolves_to_this_terminal(backend, plumbing):
    sup = await _create(backend, new_session=True)
    t = await _create(backend, new_session=False, allowed_tools=["fs_read"], caller_id=sup.id)

    token = backend.env_for(t.id)[TERMINAL_TOKEN_ENV]
    assert _row(t.id).credential_digest == digest_of(token)

    r = _who_client().get("/who", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "terminal"
    assert body["terminal_id"] == t.id
    assert body["session_name"] == "cao-cred-test"
    assert body["agent_profile"] == "developer"
    assert body["allowed_tools"] == ["fs_read"]
    assert body["creator_id"] == sup.id
    assert body["ancestors"] == [sup.id]


@pytest.mark.asyncio
async def test_every_terminal_gets_its_own_token(backend, plumbing):
    a = await _create(backend, new_session=True)
    b = await _create(backend, new_session=False)
    c = await _create(backend, new_session=False)

    tokens = {backend.env_for(x.id)[TERMINAL_TOKEN_ENV] for x in (a, b, c)}
    assert len(tokens) == 3
    digests = {_row(x.id).credential_digest for x in (a, b, c)}
    assert len(digests) == 3 and None not in digests


@pytest.mark.asyncio
async def test_window_in_existing_session_gets_a_fresh_token_not_the_sessions(backend, plumbing):
    """The persisted session env and a per-step env cannot smuggle a sibling's token in."""
    from cli_agent_orchestrator.services.session_env import set_session_env

    first = await _create(backend, new_session=True, env_vars={"AWS_REGION": "us-west-2"})
    first_token = backend.env_for(first.id)[TERMINAL_TOKEN_ENV]
    # Poison both channels with the first terminal's token.
    set_session_env("cao-cred-test", {TERMINAL_TOKEN_ENV: first_token, "AWS_REGION": "us-west-2"})
    second = await _create(backend, new_session=False, env_vars={TERMINAL_TOKEN_ENV: first_token})

    env = backend.env_for(second.id)
    assert env["AWS_REGION"] == "us-west-2"  # operator env still flows
    assert env[TERMINAL_TOKEN_ENV] != first_token
    assert _row(second.id).credential_digest == digest_of(env[TERMINAL_TOKEN_ENV])


@pytest.mark.asyncio
async def test_token_is_not_persisted_in_the_session_env_store(backend, plumbing):
    t = await _create(backend, new_session=True, env_vars={"AWS_REGION": "us-west-2"})
    stored = get_session_env("cao-cred-test")
    assert stored == {"AWS_REGION": "us-west-2"}
    assert TERMINAL_TOKEN_ENV not in stored
    assert backend.env_for(t.id)[TERMINAL_TOKEN_ENV]  # but it did reach the pane


@pytest.mark.asyncio
async def test_operator_env_without_vars_still_carries_the_token(backend, plumbing):
    """``extra_env`` used to be ``None`` with no ``--env``; it must now carry the token."""
    t = await _create(backend, new_session=True)
    env = backend.env_for(t.id)
    assert set(env) == {TERMINAL_TOKEN_ENV}


@pytest.mark.asyncio
async def test_digest_is_written_in_the_same_insert_as_the_row(backend, plumbing, monkeypatch):
    """No committed row ever exists without its digest: it travels in the INSERT."""
    real = terminal_service.db_create_terminal
    seen: dict = {}

    def spy(*a, **k):
        seen.update(k)
        return real(*a, **k)

    monkeypatch.setattr(terminal_service, "db_create_terminal", spy)
    t = await _create(backend, new_session=True)
    token = backend.env_for(t.id)[TERMINAL_TOKEN_ENV]
    assert seen["credential_digest"] == digest_of(token)
    assert _row(t.id).credential_digest == digest_of(token)


# --- revoke --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_terminal_revokes_the_token(backend, plumbing):
    t = await _create(backend, new_session=True)
    token = backend.env_for(t.id)[TERMINAL_TOKEN_ENV]
    client = _who_client()
    assert client.get("/who", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    assert delete_terminal(t.id) is True

    r = client.get("/who", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json()["detail"] == "terminal credential revoked"
    assert _row(t.id) is None  # row removal is the backstop


@pytest.mark.asyncio
async def test_deferred_teardown_still_revokes_while_the_row_is_retained(
    backend, plumbing, monkeypatch
):
    """An unproven kill keeps the row for a retry; the credential must not outlive the intent."""
    t = await _create(backend, new_session=True)
    token = backend.env_for(t.id)[TERMINAL_TOKEN_ENV]
    # ``dismantle_terminal_runtime`` reports "could not prove the kill" -> deferred.
    monkeypatch.setattr(terminal_service, "dismantle_terminal_runtime", lambda *a, **k: False)

    assert delete_terminal(t.id) is False  # deferred
    assert _row(t.id) is not None and _row(t.id).credential_digest is None

    r = _who_client().get("/who", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_row_removal_alone_revokes(backend, plumbing):
    """Session teardown never calls ``delete_terminal``; deleting the row is enough."""
    from cli_agent_orchestrator.clients.database import delete_terminals_by_session

    t = await _create(backend, new_session=True)
    token = backend.env_for(t.id)[TERMINAL_TOKEN_ENV]
    assert delete_terminals_by_session("cao-cred-test") == 1
    r = _who_client().get("/who", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


# --- default-off --------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_off_surface_is_unchanged(backend, plumbing):
    """Warn mode, auth off: the Terminal the caller gets back is what it always was."""
    t = await _create(backend, new_session=True)
    assert t.id and t.session_name == "cao-cred-test" and t.agent_profile == "developer"
    # Nothing credential-shaped leaks onto the public Terminal model.
    assert "credential" not in " ".join(t.model_dump().keys())
    assert "token" not in " ".join(t.model_dump().keys())
