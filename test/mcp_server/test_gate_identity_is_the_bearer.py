"""The MCP gate's subject is the BEARER's row, not the row ``CAO_TERMINAL_ID`` names.

Codex's finding 1 on this branch, reproduced: ``_tool_denied_reason`` fetched
``GET /terminals/{CAO_TERMINAL_ID}`` and authorized with *that* row's allowlist. The
bearer was only the means of reaching the route, so terminal A -- holding a valid
credential for A and nothing else -- could start an MCP process with
``CAO_TERMINAL_ID=B`` and be authorized as B, in warn mode and in enforce mode alike.
The branch's central promise ("server-known identity at one chokepoint") was false in
exactly this spot.

The tests drive the REAL API through ``TestClient`` with the MCP process's HTTP egress
bridged onto it, because the defect lived in the seam between the two: either half
alone looks correct. ``_Bridge`` is the only fake, and it fakes transport only --
every status code, body and header below is produced by ``api.main.app``.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional
from unittest.mock import patch

import pytest
import requests
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cli_agent_orchestrator.api.main import app
from cli_agent_orchestrator.constants import API_BASE_URL
from cli_agent_orchestrator.mcp_server import server
from cli_agent_orchestrator.mcp_server import utils as mcp_utils
from cli_agent_orchestrator.plugins import PluginRegistry
from cli_agent_orchestrator.security import audit
from cli_agent_orchestrator.security.principal import mint_terminal_credential

TERMINAL_A = "aaaa1111"
TERMINAL_B = "bbbb2222"


# --- the transport bridge ------------------------------------------------------


class _Resp:
    """A ``requests``-shaped view of a ``TestClient`` response."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.status_code = inner.status_code
        self.text = inner.text

    def json(self) -> Any:
        return self._inner.json()

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} for {self._inner.url}", response=self)


class _Bridge:
    """Stands in for the ``requests`` module inside the MCP process.

    Only ``get``/``post`` are routed; the exception classes are the real ones so the
    production ``except requests.HTTPError`` arms behave normally.
    """

    HTTPError = requests.HTTPError
    RequestException = requests.RequestException

    def __init__(self, client: TestClient) -> None:
        self._client = client

    def _path(self, url: str) -> str:
        return url[len(API_BASE_URL) :] if url.startswith(API_BASE_URL) else url

    def get(self, url: str, headers: Optional[Dict] = None, params: Any = None, **_: Any) -> _Resp:
        return _Resp(self._client.get(self._path(url), headers=headers, params=params))

    def post(self, url: str, headers: Optional[Dict] = None, params: Any = None, **_: Any) -> _Resp:
        return _Resp(self._client.post(self._path(url), headers=headers, params=params))


# --- fixtures -----------------------------------------------------------------


#: These tests seed real rows with real credential digests and drive the real
#: credential helper, so they want production behaviour, not the suite-wide
#: legacy fallback (``test/conftest.py::legacy_operator_token_fallback``).
pytestmark = pytest.mark.unpaired_terminal_credential


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
        "CAO_TERMINAL_ID",
        "CAO_TERMINAL_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CAO_HOME_DIR", str(tmp_path / "cao-home"))


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from cli_agent_orchestrator.clients import database

    engine = create_engine(
        f"sqlite:///{tmp_path / 'gate-identity.db'}",
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
    """A: ``fs_read`` only. B: ``@cao-mcp-server``. Each with its own credential."""
    out = {}
    for tid, tools in ((TERMINAL_A, ["fs_read"]), (TERMINAL_B, ["@cao-mcp-server"])):
        fresh_db.create_terminal(
            tid, "cao-sess", f"w-{tid}", "claude_code", "developer", allowed_tools=tools
        )
        token, digest = mint_terminal_credential()
        assert fresh_db.set_terminal_credential_digest(tid, digest)
        out[tid] = token
    return out


@pytest.fixture
def bridged(monkeypatch):
    """Route the MCP process's HTTP egress at the real app."""
    app.state.plugin_registry = PluginRegistry()
    client = TestClient(app, base_url="http://localhost")
    bridge = _Bridge(client)
    monkeypatch.setattr(mcp_utils, "requests", bridge)
    monkeypatch.setattr(server, "requests", bridge)
    return client


def _as(terminal_id: str, token: str) -> Dict[str, str]:
    return {"CAO_TERMINAL_ID": terminal_id, "CAO_TERMINAL_TOKEN": token}


def _audit_rules() -> list:
    return [(r["rule"], r["allowed"], r["enforced"]) for r in audit.read_recent()]


# --- the substitution ----------------------------------------------------------


class TestClaimedIdIsNotTheBearer:
    """A's token with B's id must never be authorized as B."""

    def test_enforce_refuses_memory_forget(self, bridged, tokens, monkeypatch):
        """Codex's sketch, verbatim: the call that returned ``None`` must be refused."""
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
        with patch.dict(os.environ, _as(TERMINAL_B, tokens[TERMINAL_A])):
            denial = server._tool_denied_reason("memory_forget")
        assert denial is not None
        assert TERMINAL_B in denial

    def test_enforce_names_the_binding_rule(self, bridged, tokens, monkeypatch):
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
        with patch.dict(os.environ, _as(TERMINAL_B, tokens[TERMINAL_A])):
            server._tool_denied_reason("memory_forget")
        assert ("terminal:impersonation", False, True) in _audit_rules()

    def test_warn_mode_audits_the_substitution(self, bridged, tokens):
        """Warn mode is behaviour-preserving by design -- but no longer silent."""
        with patch.dict(os.environ, _as(TERMINAL_B, tokens[TERMINAL_A])):
            server._tool_denied_reason("memory_forget")
        assert ("terminal:impersonation", False, False) in _audit_rules()


class TestOwnIdentityStillWorks:
    """The fix must not break the case the gate exists for."""

    def test_b_with_its_own_token_is_allowed(self, bridged, tokens, monkeypatch):
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
        with patch.dict(os.environ, _as(TERMINAL_B, tokens[TERMINAL_B])):
            assert server._tool_denied_reason("memory_forget") is None

    def test_a_with_its_own_token_is_denied_by_its_own_allowlist(self, bridged, tokens):
        with patch.dict(os.environ, _as(TERMINAL_A, tokens[TERMINAL_A])):
            denial = server._tool_denied_reason("memory_forget")
        assert denial is not None
        assert "tool:default-deny" in denial

    def test_a_callback_tool_is_still_exempt(self, bridged, tokens, monkeypatch):
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
        with patch.dict(os.environ, _as(TERMINAL_A, tokens[TERMINAL_A])):
            assert server._tool_denied_reason("send_message") is None

    def test_an_unbound_process_is_the_operator_path(self, bridged, tokens):
        assert server._tool_denied_reason("memory_forget") is None


class TestUnprovenIdentity:
    """``CAO_TERMINAL_ID`` set with no terminal credential cannot prove anything.

    This now fails IN THE AGENT'S OWN PROCESS, before a request is made:
    ``agent_credential`` refuses to present the operator's token for a process
    that claims an identity it holds no credential for. The gate sees that as
    any other failure to resolve an identity -- an unknown, which does not
    dispatch -- and the refusal names the misconfiguration.

    The server-side ``identity:unproven`` rule is still the backstop for a
    caller that builds the request itself (a shell with the operator's token and
    a claimed id); that path is tested at the route in
    ``test/api/test_me_principal.py``.
    """

    @pytest.mark.parametrize("enforce", ["1", ""], ids=["enforce", "warn"])
    def test_it_fails_closed_in_both_modes(self, bridged, tokens, monkeypatch, enforce):
        """Hard regardless of the flag: #972 made the whole cao-mcp-server surface so."""
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", enforce)
        with patch.dict(os.environ, {"CAO_TERMINAL_ID": TERMINAL_B}):
            denial = server._tool_denied_reason("memory_forget")
        assert denial is not None
        assert "could not be resolved" in denial

    def test_the_refusal_names_the_missing_variable(self, bridged, tokens):
        with patch.dict(os.environ, {"CAO_TERMINAL_ID": TERMINAL_B}):
            denial = server._tool_denied_reason("memory_forget")
        assert "CAO_TERMINAL_TOKEN" in denial
        assert TERMINAL_B in denial

    def test_the_operator_token_is_never_put_on_the_wire(self, bridged, tokens, monkeypatch):
        """The whole point: the header is never built, so no request can carry it.

        ``get_json`` IS entered -- the refusal happens while it assembles the
        headers -- so the assertion is on the transport, which is where an
        escalation would actually become one.
        """
        monkeypatch.setenv("CAO_AUTH_LOCAL_TOKEN", "operator-secret")
        with patch.dict(os.environ, {"CAO_TERMINAL_ID": TERMINAL_B}):
            with patch.object(mcp_utils.requests, "get") as transport:
                assert server._tool_denied_reason("memory_forget") is not None
        transport.assert_not_called()

    def test_a_revoked_credential_fails_closed(self, bridged, tokens, monkeypatch):
        orphan, _ = mint_terminal_credential()  # never written to a row
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
        with patch.dict(os.environ, _as(TERMINAL_B, orphan)):
            denial = server._tool_denied_reason("memory_forget")
        assert denial is not None
        assert "could not be resolved" in denial
