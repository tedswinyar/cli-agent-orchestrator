"""Caller identity is derived from the principal, not the request (#965, WS2).

The acceptance criteria of #965, verbatim:

(a) a client holding only terminal A's credential cannot create a terminal
    bounded by terminal B's ceiling: naming B as ``caller_id`` is refused with
    403 naming the mismatch under ``CAO_PRINCIPAL_ENFORCE=1``, and in warn mode
    it is audited while the credential's own identity is what the create uses;
(b) a terminal-credentialed client cannot use the operator create routes
    (403 under enforce), even with no identity fields in the request;
(c) operator clients (shared bearer / default-off) behave exactly as today.

Plus the ceiling hook in ``terminal_service.create_terminal`` (Step 0c): a
terminal principal's requested ``allowed_tools`` must fit inside its own row.

All HTTP tests run the real app through ``TestClient`` with the downstream
service mocked, so the thing under test is the route body. The terminal rows
and their credential digests live in a per-test SQLite file.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cli_agent_orchestrator.constants import TERMINALS_RUN_STEP_ROUTE
from cli_agent_orchestrator.models.terminal import AgentStepResult, Terminal, TerminalStatus
from cli_agent_orchestrator.security import audit
from cli_agent_orchestrator.security.principal import Principal, mint_terminal_credential

TERMINAL_A = "aaaa1111"
TERMINAL_B = "bbbb2222"

_RESOLVE_PROVIDER = "cli_agent_orchestrator.api.main.resolve_provider"
_TERMINAL_SERVICE = "cli_agent_orchestrator.api.main.terminal_service"
_SESSION_SERVICE = "cli_agent_orchestrator.api.main.session_service"
_RUN_STEP = "cli_agent_orchestrator.api.main.run_agent_step"


# --- fixtures -----------------------------------------------------------------


@pytest.fixture(autouse=True)
def _authz_env(monkeypatch, tmp_path):
    """Default-off auth, warn mode, audit log routed to a per-test home."""
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
    """Route ``clients.database`` at a fresh per-test SQLite file."""
    from cli_agent_orchestrator.clients import database

    engine = create_engine(
        f"sqlite:///{tmp_path / 'identity.db'}",
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
def tokens(fresh_db):
    """Two terminal rows, A and B, each with its own credential. Returns tokens."""
    out = {}
    for tid, tools in ((TERMINAL_A, ["fs_read"]), (TERMINAL_B, ["*"])):
        fresh_db.create_terminal(
            tid, "cao-sess", "w", "claude_code", "developer", allowed_tools=tools
        )
        token, digest = mint_terminal_credential()
        assert fresh_db.set_terminal_credential_digest(tid, digest)
        out[tid] = token
    return out


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _terminal(caller_id=None) -> Terminal:
    return Terminal(
        id="cccc3333",
        name="w2",
        session_name="test-session",
        provider="claude_code",
        agent_profile="developer",
        caller_id=caller_id,
    )


def _audit_rules() -> list:
    return [(r["rule"], r["allowed"], r["enforced"]) for r in audit.read_recent()]


# --- (a) substitution on POST /sessions/{name}/terminals -----------------------


class TestSubstitution:
    def _post(self, client, headers, **params):
        with (
            patch(_RESOLVE_PROVIDER, side_effect=lambda _, fallback_provider: fallback_provider),
            patch(_TERMINAL_SERVICE) as svc,
        ):
            svc.create_terminal = AsyncMock(return_value=_terminal(params.get("caller_id")))
            response = client.post(
                "/sessions/test-session/terminals",
                params={"provider": "claude_code", "agent_profile": "developer", **params},
                headers=headers,
            )
            return response, svc.create_terminal

    def test_a_cannot_name_b_under_enforce(self, client, tokens, enforce):
        response, create = self._post(client, _bearer(tokens[TERMINAL_A]), caller_id=TERMINAL_B)
        assert response.status_code == 403
        assert response.json()["detail"] == (
            f"terminal {TERMINAL_A} may not act as terminal {TERMINAL_B}"
        )
        create.assert_not_called()
        assert _audit_rules() == [("terminal:impersonation", False, True)]

    def test_a_naming_b_is_audited_and_a_is_recorded_in_warn_mode(self, client, tokens):
        response, create = self._post(client, _bearer(tokens[TERMINAL_A]), caller_id=TERMINAL_B)
        assert response.status_code == 201
        assert create.call_args.kwargs["caller_id"] == TERMINAL_A
        assert _audit_rules() == [("terminal:impersonation", False, False)]

    def test_omitted_caller_is_filled_from_the_credential(self, client, tokens, enforce):
        response, create = self._post(client, _bearer(tokens[TERMINAL_A]))
        assert response.status_code == 201
        assert create.call_args.kwargs["caller_id"] == TERMINAL_A
        assert _audit_rules() == []  # allows are not recorded by default

    def test_self_claim_is_allowed_under_enforce(self, client, tokens, enforce):
        response, create = self._post(client, _bearer(tokens[TERMINAL_A]), caller_id=TERMINAL_A)
        assert response.status_code == 201
        assert create.call_args.kwargs["caller_id"] == TERMINAL_A

    def test_the_principal_reaches_terminal_service_for_the_ceiling(self, client, tokens):
        _, create = self._post(client, _bearer(tokens[TERMINAL_A]))
        principal = create.call_args.kwargs["principal"]
        assert isinstance(principal, Principal)
        assert principal.kind == "terminal"
        assert principal.terminal_id == TERMINAL_A
        assert principal.allowed_tools == ("fs_read",)

    def test_revoked_credential_is_401_before_any_identity_logic(self, client, fresh_db, enforce):
        token, _ = mint_terminal_credential()  # never stored on a row
        response, create = self._post(client, _bearer(token), caller_id=TERMINAL_B)
        assert response.status_code == 401
        create.assert_not_called()


# --- (b) operator create route ----------------------------------------------


class TestOperatorRoute:
    def _post_session(self, client, headers):
        with patch(_SESSION_SERVICE) as svc:
            svc.create_session = AsyncMock(return_value=_terminal())
            response = client.post(
                "/sessions",
                params={"provider": "claude_code", "agent_profile": "developer"},
                headers=headers,
            )
            return response, svc.create_session

    def test_terminal_credential_refused_under_enforce(self, client, tokens, enforce):
        response, create = self._post_session(client, _bearer(tokens[TERMINAL_A]))
        assert response.status_code == 403
        assert response.json()["detail"] == (
            f"terminal {TERMINAL_A} may not call operator route POST /sessions"
        )
        create.assert_not_called()
        assert _audit_rules() == [("operator:route", False, True)]

    def test_terminal_credential_audited_in_warn_mode(self, client, tokens):
        response, create = self._post_session(client, _bearer(tokens[TERMINAL_A]))
        assert response.status_code == 201
        create.assert_called_once()
        assert _audit_rules() == [("operator:route", False, False)]


# --- (c) operators are unchanged ---------------------------------------------


class TestOperatorsUnchanged:
    @pytest.mark.parametrize("flag", ["", "1"])
    def test_default_off_caller_id_passes_through_verbatim(self, client, monkeypatch, flag):
        if flag:
            monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", flag)
        with (
            patch(_RESOLVE_PROVIDER, side_effect=lambda _, fallback_provider: fallback_provider),
            patch(_TERMINAL_SERVICE) as svc,
        ):
            svc.create_terminal = AsyncMock(return_value=_terminal(TERMINAL_B))
            response = client.post(
                "/sessions/test-session/terminals",
                params={
                    "provider": "claude_code",
                    "agent_profile": "developer",
                    "caller_id": TERMINAL_B,
                },
            )
        assert response.status_code == 201
        assert svc.create_terminal.call_args.kwargs["caller_id"] == TERMINAL_B
        assert svc.create_terminal.call_args.kwargs["principal"].kind == "anonymous"
        assert not audit.audit_path().exists()

    @pytest.mark.parametrize("flag", ["", "1"])
    def test_default_off_operator_create_route_unchanged(self, client, monkeypatch, flag):
        if flag:
            monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", flag)
        with patch(_SESSION_SERVICE) as svc:
            svc.create_session = AsyncMock(return_value=_terminal())
            response = client.post(
                "/sessions", params={"provider": "claude_code", "agent_profile": "developer"}
            )
        assert response.status_code == 201
        assert not audit.audit_path().exists()

    def test_shared_bearer_operator_is_unbounded_under_enforce(self, client, monkeypatch, enforce):
        monkeypatch.setenv("CAO_AUTH_LOCAL_TOKEN", "operator-secret")
        with (
            patch(_RESOLVE_PROVIDER, side_effect=lambda _, fallback_provider: fallback_provider),
            patch(_TERMINAL_SERVICE) as svc,
        ):
            svc.create_terminal = AsyncMock(return_value=_terminal(TERMINAL_B))
            response = client.post(
                "/sessions/test-session/terminals",
                params={
                    "provider": "claude_code",
                    "agent_profile": "developer",
                    "caller_id": TERMINAL_B,
                },
                headers=_bearer("operator-secret"),
            )
        assert response.status_code == 201
        assert svc.create_terminal.call_args.kwargs["caller_id"] == TERMINAL_B
        assert svc.create_terminal.call_args.kwargs["principal"].kind == "operator"
        assert not audit.audit_path().exists()


# --- the other identity-reading routes --------------------------------------


class TestEphemeralRoutes:
    @pytest.fixture(autouse=True)
    def _ephemeral_on(self, monkeypatch):
        from cli_agent_orchestrator.services import ephemeral_service

        monkeypatch.setattr(ephemeral_service, "read_settings", lambda: {"enabled": True})
        monkeypatch.setattr(ephemeral_service, "require_enabled", lambda settings: None)

    @pytest.mark.parametrize("path", ["/ephemeral-agents", "/ephemeral-agents/some-agent/claim"])
    def test_substitution_refused_under_enforce(self, client, tokens, enforce, path):
        from cli_agent_orchestrator.services import ephemeral_service

        with (
            patch.object(ephemeral_service, "create_ephemeral_agent") as create,
            patch.object(ephemeral_service, "claim_ephemeral_agent") as claim,
        ):
            response = client.post(
                path,
                params={"caller_id": TERMINAL_B},
                json={},
                headers=_bearer(tokens[TERMINAL_A]),
            )
        assert response.status_code == 403
        assert TERMINAL_A in response.json()["detail"]
        assert TERMINAL_B in response.json()["detail"]
        create.assert_not_called()
        claim.assert_not_called()

    def test_credential_identity_is_what_the_service_sees(self, client, tokens):
        from cli_agent_orchestrator.services import ephemeral_service

        with patch.object(ephemeral_service, "create_ephemeral_agent", return_value={}) as create:
            response = client.post(
                "/ephemeral-agents",
                params={"caller_id": TERMINAL_B},
                json={},
                headers=_bearer(tokens[TERMINAL_A]),
            )
        assert response.status_code == 201
        assert create.call_args.args[1] == TERMINAL_A
        assert _audit_rules() == [("terminal:impersonation", False, False)]


class TestRunStep:
    def _body(self, **overrides):
        base = {"provider": "claude_code", "agent": "developer", "prompt": "do it"}
        base.update(overrides)
        return base

    def test_substitution_refused_under_enforce(self, client, tokens, enforce):
        with patch(_RUN_STEP, new=AsyncMock()) as run:
            response = client.post(
                TERMINALS_RUN_STEP_ROUTE,
                json=self._body(caller_id=TERMINAL_B),
                headers=_bearer(tokens[TERMINAL_A]),
            )
        assert response.status_code == 403
        assert response.json()["detail"] == (
            f"terminal {TERMINAL_A} may not act as terminal {TERMINAL_B}"
        )
        run.assert_not_awaited()

    def test_credential_identity_reaches_the_substrate(self, client, tokens):
        result = AgentStepResult(
            terminal_id="cccc3333", last_message="ok", status=TerminalStatus.COMPLETED
        )
        with patch(_RUN_STEP, new=AsyncMock(return_value=result)) as run:
            response = client.post(
                TERMINALS_RUN_STEP_ROUTE,
                json=self._body(caller_id=TERMINAL_B),
                headers=_bearer(tokens[TERMINAL_A]),
            )
        assert response.status_code == 200
        assert run.await_args.kwargs["caller_id"] == TERMINAL_A
        assert run.await_args.kwargs["principal"].terminal_id == TERMINAL_A
        assert _audit_rules() == [("terminal:impersonation", False, False)]

    def test_operator_body_caller_id_unchanged(self, client):
        result = AgentStepResult(
            terminal_id="cccc3333", last_message="ok", status=TerminalStatus.COMPLETED
        )
        with patch(_RUN_STEP, new=AsyncMock(return_value=result)) as run:
            response = client.post(TERMINALS_RUN_STEP_ROUTE, json=self._body(caller_id=TERMINAL_B))
        assert response.status_code == 200
        assert run.await_args.kwargs["caller_id"] == TERMINAL_B


# --- terminal_service Step 0c: ceiling from the principal ---------------------


_UNGUARDED = "cli_agent_orchestrator.services.terminal_service._create_terminal_unguarded"


def _terminal_principal(allowed=("fs_read",), delegate=None):
    """``delegate=None`` is "no ceiling recorded", which falls back to ``allowed``.

    NOT ``()``: an empty recorded ceiling is an explicit "may delegate nothing"
    and does not fall back (``authz.ceiling_of``).
    """
    return Principal(
        kind="terminal",
        scopes=frozenset({"cao:read", "cao:write"}),
        terminal_id=TERMINAL_A,
        allowed_tools=tuple(allowed),
        delegate_tools=None if delegate is None else tuple(delegate),
    )


class TestCeilingFromPrincipal:
    @pytest.mark.asyncio
    async def test_outside_own_ceiling_refused_under_enforce_before_any_allocation(self, enforce):
        from cli_agent_orchestrator.services import terminal_service

        with patch(_UNGUARDED, new=AsyncMock()) as unguarded:
            with pytest.raises(HTTPException) as exc:
                await terminal_service.create_terminal(
                    "claude_code",
                    "developer",
                    session_name="cao-sess",
                    allowed_tools=["memory_forget"],
                    principal=_terminal_principal(),
                )
        assert exc.value.status_code == 403
        assert "memory_forget" in exc.value.detail
        unguarded.assert_not_awaited()
        assert _audit_rules() == [("terminal:ceiling", False, True)]

    @pytest.mark.asyncio
    async def test_outside_own_ceiling_audited_in_warn_mode(self):
        from cli_agent_orchestrator.services import terminal_service

        with patch(_UNGUARDED, new=AsyncMock(return_value=_terminal())) as unguarded:
            await terminal_service.create_terminal(
                "claude_code",
                "developer",
                session_name="cao-sess",
                allowed_tools=["memory_forget"],
                principal=_terminal_principal(),
            )
        unguarded.assert_awaited_once()
        assert _audit_rules() == [("terminal:ceiling", False, False)]

    @pytest.mark.asyncio
    async def test_within_own_ceiling_proceeds_under_enforce(self, enforce):
        from cli_agent_orchestrator.services import terminal_service

        with patch(_UNGUARDED, new=AsyncMock(return_value=_terminal())) as unguarded:
            await terminal_service.create_terminal(
                "claude_code",
                "developer",
                session_name="cao-sess",
                allowed_tools=["fs_read"],
                principal=_terminal_principal(),
            )
        unguarded.assert_awaited_once()
        # An AGENT principal's allowed decision IS recorded now (the audit
        # change in #965: warn mode cannot reveal a bypass if success leaves no
        # line). An operator's still is not.
        assert _audit_rules() == [("terminal:within-ceiling", True, True)]

    @pytest.mark.asyncio
    async def test_delegate_tools_is_the_ceiling_when_set(self, enforce):
        """#948's column, when present on the row, bounds the create instead."""
        from cli_agent_orchestrator.services import terminal_service

        with patch(_UNGUARDED, new=AsyncMock(return_value=_terminal())) as unguarded:
            await terminal_service.create_terminal(
                "claude_code",
                "developer",
                session_name="cao-sess",
                allowed_tools=["memory_forget"],
                principal=_terminal_principal(allowed=("fs_read",), delegate=("*",)),
            )
        unguarded.assert_awaited_once()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "principal",
        [
            None,
            Principal(kind="anonymous", scopes=frozenset({"cao:admin"})),
            Principal(kind="operator", scopes=frozenset({"cao:admin"})),
        ],
    )
    async def test_operators_and_in_process_callers_take_todays_path(self, enforce, principal):
        from cli_agent_orchestrator.services import terminal_service

        with patch(_UNGUARDED, new=AsyncMock(return_value=_terminal())) as unguarded:
            await terminal_service.create_terminal(
                "claude_code",
                "developer",
                session_name="cao-sess",
                allowed_tools=["anything", "*"],
                principal=principal,
            )
        unguarded.assert_awaited_once()
        assert not audit.audit_path().exists()


def test_audit_line_names_the_principal_action_and_resource(client, tokens, enforce):
    """The refusal line carries what the demo transcript (WS6) reads out."""
    with (
        patch(_RESOLVE_PROVIDER, side_effect=lambda _, fallback_provider: fallback_provider),
        patch(_TERMINAL_SERVICE),
    ):
        client.post(
            "/sessions/test-session/terminals",
            params={
                "provider": "claude_code",
                "agent_profile": "developer",
                "caller_id": TERMINAL_B,
            },
            headers=_bearer(tokens[TERMINAL_A]),
        )
    lines = audit.audit_path().read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["kind"] == "terminal"
    assert record["terminal_id"] == TERMINAL_A
    assert record["action"] == "terminal:act_as"
    assert record["resource"] == TERMINAL_B
    assert record["allowed"] is False
    assert record["enforced"] is True
    assert record["rule"] == "terminal:impersonation"
