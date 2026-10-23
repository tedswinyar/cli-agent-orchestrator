"""``GET /me/principal``: the route where a claimed identity is bound to the bearer (#965).

The gate's own fail-closed path (``agent_credential`` refusing to present the
operator's token for a process that claims an identity it cannot prove) means a
CAO-launched agent never reaches this route unproven. A caller that builds the
request by hand still can -- a shell inside a pane holding
``CAO_AUTH_LOCAL_TOKEN``, or any client that sets the query parameter -- so the
server-side rule is the backstop, not a formality.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cli_agent_orchestrator.security import audit
from cli_agent_orchestrator.security.principal import (
    mint_terminal_credential,
    principal_from_payload,
)

pytestmark = pytest.mark.unpaired_terminal_credential

TERMINAL_A = "aaaa1111"
TERMINAL_B = "bbbb2222"


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
def tokens(tmp_path, monkeypatch):
    from cli_agent_orchestrator.clients import database

    engine = create_engine(
        f"sqlite:///{tmp_path / 'me.db'}", connect_args={"check_same_thread": False}
    )
    database.Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(
        database,
        "SessionLocal",
        sessionmaker(autocommit=False, autoflush=False, bind=engine),
    )
    out = {}
    for tid, tools, delegate in (
        (TERMINAL_A, ["fs_read"], ["fs_read"]),
        (TERMINAL_B, ["@cao-mcp-server"], None),
    ):
        database.create_terminal(
            tid,
            "cao-sess",
            f"w-{tid}",
            "claude_code",
            "developer",
            allowed_tools=tools,
            delegate_tools=delegate,
        )
        token, digest = mint_terminal_credential()
        assert database.set_terminal_credential_digest(tid, digest)
        out[tid] = token
    yield out
    engine.dispose()


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _audit_rules():
    return [(r["rule"], r["allowed"], r["enforced"]) for r in audit.read_recent()]


class TestOwnIdentity:
    def test_no_claim_returns_the_bearers_principal(self, client, tokens):
        body = client.get("/me/principal", headers=_bearer(tokens[TERMINAL_A])).json()
        assert body["identity_bound"] is True
        assert body["principal"]["terminal_id"] == TERMINAL_A
        assert body["principal"]["allowed_tools"] == ["fs_read"]

    def test_a_self_claim_is_bound(self, client, tokens, enforce):
        body = client.get(
            "/me/principal",
            params={"claimed_terminal_id": TERMINAL_A},
            headers=_bearer(tokens[TERMINAL_A]),
        ).json()
        assert body["identity_bound"] is True
        assert body["rule"] == "identity:proven"

    def test_the_body_deserializes_to_the_same_principal(self, client, tokens):
        body = client.get("/me/principal", headers=_bearer(tokens[TERMINAL_A])).json()
        principal = principal_from_payload(body["principal"])
        assert principal.kind == "terminal"
        assert principal.terminal_id == TERMINAL_A
        assert principal.delegate_tools == ("fs_read",)

    def test_the_delegation_ceiling_is_the_same_over_http_and_over_mcp(self, client, tokens):
        """One construction path: the serialized ceiling equals the row's ceiling."""
        from cli_agent_orchestrator.clients import database
        from cli_agent_orchestrator.security.authz import ceiling_of
        from cli_agent_orchestrator.security.principal import principal_from_terminal_row

        body = client.get("/me/principal", headers=_bearer(tokens[TERMINAL_A])).json()
        over_mcp = ceiling_of(principal_from_payload(body["principal"]))
        with database.SessionLocal() as s:
            row = (
                s.query(database.TerminalModel)
                .filter(database.TerminalModel.id == TERMINAL_A)
                .first()
            )
            over_http = ceiling_of(principal_from_terminal_row(row))
        assert over_mcp == over_http == ("fs_read",)

    def test_a_revoked_credential_is_401(self, client, tokens):
        orphan, _ = mint_terminal_credential()
        response = client.get("/me/principal", headers=_bearer(orphan))
        assert response.status_code == 401


class TestImpersonation:
    def test_enforce_refuses_a_claim_naming_another_terminal(self, client, tokens, enforce):
        response = client.get(
            "/me/principal",
            params={"claimed_terminal_id": TERMINAL_B},
            headers=_bearer(tokens[TERMINAL_A]),
        )
        assert response.status_code == 403
        assert TERMINAL_A in response.json()["detail"]
        assert TERMINAL_B in response.json()["detail"]
        assert ("terminal:impersonation", False, True) in _audit_rules()

    def test_warn_mode_audits_and_returns_the_claimed_principal(self, client, tokens):
        """Behaviour-preserving by design, and no longer silent."""
        body = client.get(
            "/me/principal",
            params={"claimed_terminal_id": TERMINAL_B},
            headers=_bearer(tokens[TERMINAL_A]),
        ).json()
        assert body["identity_bound"] is False
        assert body["principal"]["terminal_id"] == TERMINAL_B
        assert ("terminal:impersonation", False, False) in _audit_rules()

    def test_a_claim_naming_an_unknown_terminal_is_404_in_warn_mode(self, client, tokens):
        response = client.get(
            "/me/principal",
            params={"claimed_terminal_id": "no-such-id"},
            headers=_bearer(tokens[TERMINAL_A]),
        )
        assert response.status_code == 404


class TestUnprovenClaim:
    """An operator or anonymous bearer proves no TERMINAL identity."""

    def test_enforce_refuses_an_anonymous_bearer_with_a_claim(self, client, tokens, enforce):
        response = client.get("/me/principal", params={"claimed_terminal_id": TERMINAL_B})
        assert response.status_code == 403
        assert ("identity:unproven", False, True) in _audit_rules()

    def test_warn_mode_audits_and_falls_back(self, client, tokens):
        body = client.get("/me/principal", params={"claimed_terminal_id": TERMINAL_B}).json()
        assert body["identity_bound"] is False
        assert body["principal"]["terminal_id"] == TERMINAL_B
        assert ("identity:unproven", False, False) in _audit_rules()

    def test_an_operator_with_no_claim_is_unbounded_as_today(self, client, tokens, enforce):
        body = client.get("/me/principal").json()
        assert body["identity_bound"] is True
        assert body["rule"] == "identity:unbound"
        assert body["principal"]["kind"] == "anonymous"
        assert _audit_rules() == []

    def test_a_blank_claim_is_no_claim(self, client, tokens, enforce):
        body = client.get("/me/principal", params={"claimed_terminal_id": "   "}).json()
        assert body["identity_bound"] is True
        assert body["claimed_terminal_id"] is None
