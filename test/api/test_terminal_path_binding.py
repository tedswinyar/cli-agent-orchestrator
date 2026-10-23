"""A ``/terminals/{terminal_id}`` path id is bound to the bearer (#965).

The second half of the substitution defect the reviews found. Every route under
``/terminals/{terminal_id}`` was scope-gated and nothing more, and a terminal
credential carries ``cao:read`` + ``cao:write``, so any agent on the node could
read, type into, key or exit ANY terminal -- including its own supervisor's. A
scope tier answers "may this caller use this kind of route"; it cannot answer
"on this object", which is the only question an object-addressed route asks.

Two tiers, because CAO's own documented flows need them to differ:

* **steering** (input, key, exit, delete, the PATCHes): the caller's own
  terminal, or one it created directly or transitively. Typing into your
  supervisor's pane is not something ancestry licenses.
* **reads** (the record, output, siblings, inbox, working directory): the same,
  widened with the caller's own ancestors and -- with the ``discovery`` grant --
  its group peers. ``utils.orchestration._target_binding_denial`` reads a
  parent's and a discovered sibling's record as part of the ``send_message``
  flows #432 and ``cao-worker-protocols`` document; refusing those reads would
  break the callback protocol to enforce a rule about *acting*.

Operator and the default-off anonymous caller are unbounded, so an
operator-driven UI, CLI or script sees no change at all.
"""

from __future__ import annotations

from typing import Dict
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cli_agent_orchestrator.security import audit
from cli_agent_orchestrator.security.principal import mint_terminal_credential

#: A created B, B created D; C is unrelated. One chain deep enough to tell
#: "direct child" from "descendant" apart, which a two-row fixture cannot.
#: Real rows, real digests, real bearers: production credential behaviour, not
#: the suite-wide legacy fallback in ``test/conftest.py``.
pytestmark = pytest.mark.unpaired_terminal_credential

ROOT = "aaaa1111"
CHILD = "bbbb2222"
GRANDCHILD = "dddd4444"
STRANGER = "cccc3333"

_TERMINAL_SERVICE = "cli_agent_orchestrator.api.main.terminal_service"


@pytest.fixture(autouse=True)
def _authz_env(monkeypatch, tmp_path):
    for var in (
        "AUTH0_DOMAIN",
        "CAO_AUTH_JWKS_URI",
        "CAO_AUTH_AUDIENCE",
        "AUTH0_AUDIENCE",
        "CAO_AUTH_LOCAL_TOKEN",
        "CAO_AUTH_ISSUER",
        "CAO_PRINCIPAL_ENFORCE",
        "CAO_AUTHZ_AUDIT_ALLOWS",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CAO_HOME_DIR", str(tmp_path / "cao-home"))


@pytest.fixture
def enforce(monkeypatch):
    monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from cli_agent_orchestrator.clients import database

    engine = create_engine(
        f"sqlite:///{tmp_path / 'binding.db'}",
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
def tokens(fresh_db) -> Dict[str, str]:
    """ROOT -> CHILD -> GRANDCHILD, plus an unrelated STRANGER. Returns tokens."""
    rows = (
        (ROOT, None, ["*"]),
        (CHILD, ROOT, ["*"]),
        (GRANDCHILD, CHILD, ["*"]),
        (STRANGER, None, ["*"]),
    )
    out: Dict[str, str] = {}
    for tid, caller, tools in rows:
        fresh_db.create_terminal(
            tid,
            "cao-sess",
            f"w-{tid}",
            "claude_code",
            "developer",
            allowed_tools=tools,
            caller_id=caller,
        )
        token, digest = mint_terminal_credential()
        assert fresh_db.set_terminal_credential_digest(tid, digest)
        out[tid] = token
    return out


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _audit_rules() -> list:
    return [(r["rule"], r["allowed"], r["enforced"]) for r in audit.read_recent()]


def _get(client, token, path):
    """A record read with the downstream service stubbed: the route body is the subject."""
    with patch(_TERMINAL_SERVICE) as svc:
        svc.get_terminal.return_value = {
            "id": "x",
            "name": "w",
            "provider": "claude_code",
            "session_name": "cao-sess",
            "agent_profile": "developer",
            "status": "idle",
            "last_active": "2026-01-01T00:00:00",
        }
        return client.get(path, headers=_bearer(token))


def _input(client, token, target):
    with patch(_TERMINAL_SERVICE) as svc:
        svc.send_input.return_value = True
        response = client.post(
            f"/terminals/{target}/input",
            params={"message": "hi"},
            headers=_bearer(token),
        )
        return response, svc.send_input


# --- steering: self or a descendant, nothing else -----------------------------


class TestSteering:
    def test_own_terminal_is_allowed(self, client, tokens, enforce):
        response, send = _input(client, tokens[ROOT], ROOT)
        assert response.status_code == 200
        send.assert_called_once()

    def test_a_direct_child_is_allowed(self, client, tokens, enforce):
        response, send = _input(client, tokens[ROOT], CHILD)
        assert response.status_code == 200
        send.assert_called_once()

    def test_a_grandchild_is_allowed(self, client, tokens, enforce):
        """Ancestry, not parenthood: ROOT created CHILD which created GRANDCHILD."""
        response, send = _input(client, tokens[ROOT], GRANDCHILD)
        assert response.status_code == 200
        send.assert_called_once()

    def test_a_stranger_is_refused(self, client, tokens, enforce):
        response, send = _input(client, tokens[ROOT], STRANGER)
        assert response.status_code == 403
        assert response.json()["detail"] == (
            f"terminal {ROOT} neither is nor created terminal {STRANGER}"
        )
        send.assert_not_called()
        assert ("terminal:not-owner", False, True) in _audit_rules()

    def test_a_child_may_not_type_into_its_supervisor(self, client, tokens, enforce):
        """Reading up is allowed; steering up is the whole point of the rule."""
        response, send = _input(client, tokens[CHILD], ROOT)
        assert response.status_code == 403
        send.assert_not_called()

    def test_warn_mode_audits_and_proceeds(self, client, tokens):
        response, send = _input(client, tokens[ROOT], STRANGER)
        assert response.status_code == 200
        send.assert_called_once()
        assert ("terminal:not-owner", False, False) in _audit_rules()

    @pytest.mark.parametrize("verb,path", [("key", "key"), ("exit", "exit")])
    def test_key_and_exit_are_bound_too(self, client, tokens, enforce, verb, path):
        response = client.post(
            f"/terminals/{STRANGER}/{path}",
            params={"key": "Enter"} if verb == "key" else None,
            headers=_bearer(tokens[ROOT]),
        )
        assert response.status_code == 403

    def test_delete_is_bound(self, client, tokens, enforce):
        with patch(_TERMINAL_SERVICE) as svc:
            svc.delete_terminal = AsyncMock(return_value=True)
            response = client.delete(f"/terminals/{STRANGER}", headers=_bearer(tokens[ROOT]))
        assert response.status_code == 403


# --- reads: self, descendant, or the caller's own ancestors -------------------


class TestReads:
    def test_own_record(self, client, tokens, enforce):
        assert _get(client, tokens[ROOT], f"/terminals/{ROOT}").status_code == 200

    def test_a_descendants_record(self, client, tokens, enforce):
        assert _get(client, tokens[ROOT], f"/terminals/{GRANDCHILD}").status_code == 200

    def test_an_ancestors_record_is_readable(self, client, tokens, enforce):
        """``_target_binding_denial(allow_parent=True)`` reads it for send_message."""
        assert _get(client, tokens[GRANDCHILD], f"/terminals/{ROOT}").status_code == 200
        # Recorded, not silent: an agent's allowed call leaves a line now, and
        # "a worker read its supervisor's record" is exactly the kind of thing
        # an operator reviewing a warn-mode release wants to see.
        assert ("terminal:ancestor", True, True) in _audit_rules()

    def test_a_strangers_record_is_refused(self, client, tokens, enforce):
        response = _get(client, tokens[ROOT], f"/terminals/{STRANGER}")
        assert response.status_code == 403
        assert ("terminal:not-owner", False, True) in _audit_rules()

    def test_output_is_bound(self, client, tokens, enforce):
        with patch(_TERMINAL_SERVICE) as svc:
            svc.get_output.return_value = "secret transcript"
            response = client.get(f"/terminals/{STRANGER}/output", headers=_bearer(tokens[ROOT]))
        assert response.status_code == 403
        assert "secret transcript" not in response.text


# --- operators are untouched --------------------------------------------------


class TestOperatorUnchanged:
    def test_anonymous_default_off_may_steer_anything(self, client, tokens, enforce):
        """No bearer at all, auth disabled: today's behaviour, byte for byte."""
        with patch(_TERMINAL_SERVICE) as svc:
            svc.send_input.return_value = True
            response = client.post(f"/terminals/{STRANGER}/input", params={"message": "hi"})
        assert response.status_code == 200
        assert _audit_rules() == []

    def test_a_revoked_terminal_token_is_401_before_any_binding(self, client, fresh_db, enforce):
        orphan, _ = mint_terminal_credential()
        response = _get(client, orphan, f"/terminals/{STRANGER}")
        assert response.status_code == 401
