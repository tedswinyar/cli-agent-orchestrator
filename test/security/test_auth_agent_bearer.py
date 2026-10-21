"""With auth ENABLED, agent bearers reach the principal resolver instead of dying as "invalid token" (#965).

``security.auth.get_current_scopes`` is the dependency every scope-gated route
and ``require_any_scope`` sit on. Before this, a ``cao_t_`` bearer under
local-token mode (or an IdP) was compared to the operator token / verified as a
JWT and refused with 401, so terminal credentials only worked default-off.
"""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from cli_agent_orchestrator.security import auth
from cli_agent_orchestrator.security.principal import mint_terminal_credential

OPERATOR = "operator-secret-token"


def _row(db, terminal_id="t1"):
    db.create_terminal(terminal_id, "cao-sess", "w", "claude_code", "developer")


def _client() -> TestClient:
    app = FastAPI()

    @app.get("/scopes")
    async def scopes(s: list = Depends(auth.get_current_scopes)):
        return {"scopes": sorted(s)}

    @app.delete("/admin")
    async def admin(s: list = Depends(auth.require_any_scope(auth.SCOPE_ADMIN))):
        return {"ok": True}

    @app.post("/write")
    async def write(s: list = Depends(auth.require_any_scope(auth.SCOPE_WRITE))):
        return {"ok": True}

    return TestClient(app)


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def local_token_mode(monkeypatch):
    monkeypatch.setenv("CAO_AUTH_LOCAL_TOKEN", OPERATOR)
    assert auth.is_local_token_mode() and auth.is_auth_enabled()


class TestLocalTokenMode:
    def test_terminal_bearer_gets_agent_scopes(self, fresh_db, local_token_mode):
        _row(fresh_db)
        token, digest = mint_terminal_credential()
        fresh_db.set_terminal_credential_digest("t1", digest)
        r = _client().get("/scopes", headers=_bearer(token))
        assert r.status_code == 200, r.text
        assert r.json()["scopes"] == sorted([auth.SCOPE_READ, auth.SCOPE_WRITE])

    def test_terminal_bearer_passes_write_but_never_admin(self, fresh_db, local_token_mode):
        _row(fresh_db)
        token, digest = mint_terminal_credential()
        fresh_db.set_terminal_credential_digest("t1", digest)
        c = _client()
        assert c.post("/write", headers=_bearer(token)).status_code == 200
        assert c.delete("/admin", headers=_bearer(token)).status_code == 403

    def test_revoked_terminal_bearer_is_401(self, fresh_db, local_token_mode):
        _row(fresh_db)
        token, digest = mint_terminal_credential()
        fresh_db.set_terminal_credential_digest("t1", digest)
        fresh_db.delete_terminal("t1")
        r = _client().get("/scopes", headers=_bearer(token))
        assert r.status_code == 401
        assert r.json()["detail"] == "terminal credential revoked"

    def test_unknown_terminal_bearer_is_401_revoked_not_invalid(self, fresh_db, local_token_mode):
        token, _ = mint_terminal_credential()
        r = _client().get("/scopes", headers=_bearer(token))
        assert r.status_code == 401
        assert r.json()["detail"] == "terminal credential revoked"

    def test_run_bearer_without_registry_is_401(self, fresh_db, local_token_mode):
        r = _client().get("/scopes", headers=_bearer("cao_r_whatever"))
        assert r.status_code == 401
        assert "run credential" in r.json()["detail"]

    def test_operator_token_still_full_scopes(self, fresh_db, local_token_mode):
        r = _client().get("/scopes", headers=_bearer(OPERATOR))
        assert r.status_code == 200
        assert r.json()["scopes"] == sorted(auth.FULL_SCOPE_SET)
        assert _client().delete("/admin", headers=_bearer(OPERATOR)).status_code == 200

    def test_wrong_operator_token_still_invalid(self, fresh_db, local_token_mode):
        r = _client().get("/scopes", headers=_bearer("not-the-token"))
        assert r.status_code == 401
        assert r.json()["detail"].startswith("invalid token")

    def test_missing_bearer_still_401(self, local_token_mode):
        assert _client().get("/scopes").status_code == 401


class TestDefaultOff:
    def test_any_or_no_bearer_is_full_scopes(self, fresh_db):
        assert not auth.is_auth_enabled()
        c = _client()
        for headers in ({}, _bearer("whatever"), _bearer("cao_t_unknown")):
            r = c.get("/scopes", headers=headers)
            assert r.status_code == 200
            assert r.json()["scopes"] == sorted(auth.FULL_SCOPE_SET)
        assert c.delete("/admin", headers=_bearer("cao_t_unknown")).status_code == 200


def test_helper_returns_none_for_non_agent_bearers(fresh_db):
    assert auth._agent_bearer_scopes("eyJhbGciOi.jwt.ish") is None
    assert auth._agent_bearer_scopes(OPERATOR) is None
