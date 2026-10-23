"""Every authorization decision in one HTTP request shares one ``request_id`` (#965).

``audit.request_scope`` is only useful if something opens it on the real request
path. ``AuthzRequestIdMiddleware`` is that something: without it the field is
always ``None`` in production and the correlation the reviewers asked for exists
only in unit tests of the audit module.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cli_agent_orchestrator.api.main import AuthzRequestIdMiddleware
from cli_agent_orchestrator.security import audit
from cli_agent_orchestrator.security.principal import mint_terminal_credential

pytestmark = pytest.mark.unpaired_terminal_credential

TERMINAL_A = "aaaa1111"
STRANGER = "cccc3333"


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
def tokens(tmp_path, monkeypatch):
    from cli_agent_orchestrator.clients import database

    engine = create_engine(
        f"sqlite:///{tmp_path / 'reqid.db'}", connect_args={"check_same_thread": False}
    )
    database.Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(
        database,
        "SessionLocal",
        sessionmaker(autocommit=False, autoflush=False, bind=engine),
    )
    out = {}
    for tid in (TERMINAL_A, STRANGER):
        database.create_terminal(
            tid, "cao-sess", f"w-{tid}", "claude_code", "developer", allowed_tools=["*"]
        )
        token, digest = mint_terminal_credential()
        assert database.set_terminal_credential_digest(tid, digest)
        out[tid] = token
    yield out
    engine.dispose()


def _refuse(client, token, request_id=None):
    """One refused request: terminal A reading an unrelated terminal's record."""
    headers = {"Authorization": f"Bearer {token}"}
    if request_id is not None:
        headers["X-Request-Id"] = request_id
    return client.get(f"/terminals/{STRANGER}", headers=headers)


class TestRequestId:
    def test_an_audit_line_carries_the_responses_request_id(self, client, tokens):
        response = _refuse(client, tokens[TERMINAL_A])
        echoed = response.headers["x-request-id"]
        assert echoed
        records = audit.read_recent()
        assert records
        assert {r["request_id"] for r in records} == {echoed}

    def test_two_requests_get_two_ids(self, client, tokens):
        _refuse(client, tokens[TERMINAL_A])
        _refuse(client, tokens[TERMINAL_A])
        ids = {r["request_id"] for r in audit.read_recent()}
        assert len(ids) == 2

    def test_an_inbound_request_id_is_honoured(self, client, tokens):
        """A trace that already exists upstream must not be replaced."""
        response = _refuse(client, tokens[TERMINAL_A], request_id="upstream-trace-1")
        assert response.headers["x-request-id"] == "upstream-trace-1"
        assert {r["request_id"] for r in audit.read_recent()} == {"upstream-trace-1"}

    @pytest.mark.parametrize(
        "hostile",
        [
            "x" * 65,
            "has space",
            "newline\ninjected",
            "semi;colon",
            "",
            "   ",
        ],
    )
    def test_a_hostile_inbound_id_is_replaced_not_echoed(self, client, tokens, hostile):
        """The value lands in a log line and a response header; both are injectable."""
        response = _refuse(client, tokens[TERMINAL_A], request_id=hostile)
        echoed = response.headers["x-request-id"]
        assert echoed != hostile
        assert all(c.isalnum() or c in "-_." for c in echoed)
        assert len(echoed) <= AuthzRequestIdMiddleware.MAX_LEN

    def test_the_scope_does_not_leak_between_requests(self, client, tokens):
        """A 403 raised inside the scope must not leave the id set for the next task."""
        _refuse(client, tokens[TERMINAL_A], request_id="first-one")
        _refuse(client, tokens[TERMINAL_A], request_id="second-one")
        ids = [r["request_id"] for r in audit.read_recent()]
        assert "first-one" in ids and "second-one" in ids
        assert audit.current_request_id() is None

    def test_an_unaudited_request_still_gets_the_header(self, client):
        """The middleware is not conditional on a decision being recorded."""
        response = client.get("/health")
        assert response.headers.get("x-request-id")


class TestSanitize:
    """The classmethod directly, for the cases a client cannot easily send."""

    @pytest.mark.parametrize("value", [None, "", "  ", "a" * 65, "bad value", "a\rb"])
    def test_rejected(self, value):
        assert AuthzRequestIdMiddleware._sanitize(value) is None

    @pytest.mark.parametrize("value", ["abc123", "trace-1_2.3", "A" * 64])
    def test_accepted(self, value):
        assert AuthzRequestIdMiddleware._sanitize(value) == value

    def test_surrounding_whitespace_is_stripped(self):
        assert AuthzRequestIdMiddleware._sanitize("  trace-1  ") == "trace-1"
