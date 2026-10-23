"""Principal construction, ancestry, credentials and bearer resolution (#965)."""

import hashlib
import sys
import types
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from cli_agent_orchestrator.models.agent_profile import AgentProfile
from cli_agent_orchestrator.security import auth
from cli_agent_orchestrator.security import principal as principal_mod
from cli_agent_orchestrator.security.principal import (
    ANCESTRY_MAX_HOPS,
    RUN_TOKEN_PREFIX,
    TERMINAL_TOKEN_PREFIX,
    Principal,
    digest_of,
    get_current_principal,
    mint_terminal_credential,
    principal_from_payload,
    principal_from_terminal_row,
    principal_payload,
    require_principal,
)


def _row(db, terminal_id, caller_id=None, allowed_tools=None, profile="developer"):
    db.create_terminal(
        terminal_id,
        "cao-sess",
        "w",
        "claude_code",
        profile,
        allowed_tools=allowed_tools,
        caller_id=caller_id,
    )
    with db.SessionLocal() as s:
        return s.query(db.TerminalModel).filter(db.TerminalModel.id == terminal_id).first()


# --- construction -------------------------------------------------------------


class TestPrincipalDataclass:
    def test_is_operator_for_operator_and_anonymous_only(self):
        for kind in ("operator", "anonymous"):
            assert Principal(kind=kind, scopes=frozenset()).is_operator
        for kind in ("terminal", "run"):
            assert not Principal(kind=kind, scopes=frozenset()).is_operator

    def test_frozen(self):
        p = Principal(kind="terminal", scopes=frozenset())
        with pytest.raises(Exception):
            p.kind = "operator"  # type: ignore[misc]


class TestEffectiveAllowlist:
    """A recorded ``None`` means "resolve from the agent profile" -- here, once.

    This resolution used to live only in the MCP gate
    (``utils.caller_tools.caller_effective_allowed_tools``, called by
    ``_tool_denied_reason``), so the same row was unrestricted on the MCP
    surface and a bare ``()`` -- deny-all -- to every HTTP route that built a
    principal from it. One constructor, one answer.

    ``allowlist_resolved`` carries the difference between "the list is empty"
    and "we could not read the list": the first is a legitimate deny-all an
    operator can ask for, the second is an unknown, and ``authorize`` refuses
    it with ``identity:unresolved`` rather than deciding on a list it never saw.
    """

    def test_recorded_list_is_the_effective_list(self, fresh_db):
        p = principal_from_terminal_row(_row(fresh_db, "t1", allowed_tools=["fs_read"]))
        assert p.allowed_tools == ("fs_read",)
        assert p.allowlist_resolved is True

    def test_recorded_empty_list_is_deny_all_and_resolved(self, fresh_db):
        """``[]`` round-trips as ``[]``: an explicit deny-all, not an unknown."""
        p = principal_from_terminal_row(_row(fresh_db, "t1", allowed_tools=[]))
        assert p.allowed_tools == ()
        assert p.allowlist_resolved is True

    def test_null_resolves_from_the_profile(self, fresh_db):
        row = _row(fresh_db, "t1", profile="worker")
        with patch(
            "cli_agent_orchestrator.utils.agent_profiles.load_agent_profile",
            return_value=AgentProfile(
                name="worker", description="t", allowedTools=["@cao-mcp-server"]
            ),
        ):
            p = principal_from_terminal_row(row)
        assert p.allowed_tools == ("@cao-mcp-server",)
        assert p.allowlist_resolved is True

    def test_null_resolves_from_the_role_default(self, fresh_db):
        """ROLE_TOOL_DEFAULTS gives ``developer`` ``@cao-mcp-server``."""
        row = _row(fresh_db, "t1", profile="worker")
        with patch(
            "cli_agent_orchestrator.utils.agent_profiles.load_agent_profile",
            return_value=AgentProfile(name="worker", description="t", role="developer"),
        ):
            p = principal_from_terminal_row(row)
        assert "@cao-mcp-server" in p.allowed_tools
        assert p.allowlist_resolved is True

    def test_unreadable_profile_is_unresolved(self, fresh_db):
        row = _row(fresh_db, "t1", profile="worker")
        with patch(
            "cli_agent_orchestrator.utils.agent_profiles.load_agent_profile",
            side_effect=FileNotFoundError("no such profile"),
        ):
            p = principal_from_terminal_row(row)
        assert p.allowed_tools == ()
        assert p.allowlist_resolved is False

    def test_null_with_no_profile_is_unresolved(self, fresh_db):
        p = principal_from_terminal_row(_row(fresh_db, "t1", profile=None))
        assert p.allowed_tools == ()
        assert p.allowlist_resolved is False

    def test_an_unresolved_allowlist_is_refused_not_treated_as_deny_all(self, fresh_db):
        """The reason the flag exists, stated as policy rather than data."""
        from cli_agent_orchestrator.security.authz import TOOL_CALL, authorize

        p = principal_from_terminal_row(_row(fresh_db, "t1", profile=None))
        decision = authorize(p, TOOL_CALL, "send_message")
        assert not decision.allowed
        assert decision.rule == "identity:unresolved"


class TestSerialization:
    """``principal_payload`` / ``principal_from_payload`` are the API -> MCP wire.

    The MCP boundary never touches ``clients.database``, so the only way it can
    have the same principal an HTTP route has is to be handed one. A round-trip
    that loses a field is the ``delegate_tools``-missing-on-MCP defect in a new
    costume, so the test enumerates the dataclass rather than a hand-written
    list of fields to check.
    """

    @staticmethod
    def _full() -> Principal:
        return Principal(
            kind="terminal",
            scopes=frozenset({auth.SCOPE_READ, auth.SCOPE_WRITE}),
            terminal_id="t1",
            session_name="cao-sess",
            agent_profile="developer",
            role="developer",
            allowed_tools=("fs_read", "@cao-mcp-server"),
            delegate_tools=("fs_read",),
            creator_id="c1",
            ancestors=("c1", "root"),
            run_id=None,
            ephemeral=True,
            allowlist_resolved=False,
        )

    def test_round_trip_is_identity(self):
        original = self._full()
        assert principal_from_payload(principal_payload(original)) == original

    def test_every_dataclass_field_is_on_the_wire_or_derived(self):
        """A field added to ``Principal`` must be serialized or named as derived."""
        import dataclasses

        from cli_agent_orchestrator.security.principal import _PAYLOAD_FIELDS

        derived = {"scopes"}
        declared = {f.name for f in dataclasses.fields(Principal)}
        assert declared == set(_PAYLOAD_FIELDS) | derived, (
            "Principal gained or lost a field: add it to _PAYLOAD_FIELDS (so the MCP "
            "boundary sees it) or to this test's `derived` set with a reason."
        )

    def test_payload_is_plain_json(self):
        import json

        payload = principal_payload(self._full())
        assert json.loads(json.dumps(payload)) == payload

    def test_scopes_are_not_read_from_the_wire(self):
        """A caller must not be able to name its own scope set."""
        payload = principal_payload(self._full())
        payload["scopes"] = ["cao:admin"]
        assert principal_from_payload(payload).scopes == frozenset(
            {auth.SCOPE_READ, auth.SCOPE_WRITE}
        )

    @pytest.mark.parametrize("kind", ["operator", "anonymous"])
    def test_an_unbounded_kind_gets_the_full_scope_set(self, kind):
        rebuilt = principal_from_payload({"kind": kind})
        assert rebuilt.scopes == frozenset(auth.FULL_SCOPE_SET)
        assert rebuilt.is_operator

    @pytest.mark.parametrize("kind", ["", None, "admin", "Terminal"])
    def test_an_unknown_kind_is_refused(self, kind):
        with pytest.raises(ValueError, match="unknown principal kind"):
            principal_from_payload({"kind": kind})


class TestFromTerminalRow:
    def test_fields_copied_from_row(self, fresh_db):
        row = _row(fresh_db, "t1", allowed_tools=["fs_read", "@cao-mcp-server"])
        p = principal_from_terminal_row(row)
        assert p.kind == "terminal"
        assert p.terminal_id == "t1"
        assert p.session_name == "cao-sess"
        assert p.agent_profile == "developer"
        assert p.allowed_tools == ("fs_read", "@cao-mcp-server")
        assert p.delegate_tools == ()
        assert p.creator_id is None
        assert p.ancestors == ()
        assert p.scopes == frozenset({auth.SCOPE_READ, auth.SCOPE_WRITE})
        assert auth.SCOPE_ADMIN not in p.scopes

    def test_delegate_tools_read_when_row_has_it(self, fresh_db):
        row = types.SimpleNamespace(
            id="x",
            caller_id=None,
            tmux_session="s",
            agent_profile=None,
            allowed_tools='["*"]',
            delegate_tools='["fs_read"]',
        )
        p = principal_from_terminal_row(row)
        assert p.delegate_tools == ("fs_read",)
        assert p.allowed_tools == ("*",)

    def test_ancestry_chain_root_last(self, fresh_db):
        _row(fresh_db, "root")
        _row(fresh_db, "mid", caller_id="root")
        leaf = _row(fresh_db, "leaf", caller_id="mid")
        p = principal_from_terminal_row(leaf)
        assert p.creator_id == "mid"
        assert p.ancestors == ("mid", "root")

    def test_ancestry_bounded(self, fresh_db):
        _row(fresh_db, "t0")
        for i in range(1, ANCESTRY_MAX_HOPS + 10):
            _row(fresh_db, f"t{i}", caller_id=f"t{i - 1}")
        leaf = _row(fresh_db, "leaf", caller_id=f"t{ANCESTRY_MAX_HOPS + 9}")
        p = principal_from_terminal_row(leaf)
        assert len(p.ancestors) == ANCESTRY_MAX_HOPS

    def test_ancestry_cycle_broken(self, fresh_db):
        _row(fresh_db, "a", caller_id="b")
        b = _row(fresh_db, "b", caller_id="a")
        p = principal_from_terminal_row(b)
        assert p.ancestors == ("a",)

    def test_ancestry_self_reference(self, fresh_db):
        a = _row(fresh_db, "a", caller_id="a")
        assert principal_from_terminal_row(a).ancestors == ()

    def test_dangling_caller_kept_as_creator(self, fresh_db):
        leaf = _row(fresh_db, "leaf", caller_id="gone")
        p = principal_from_terminal_row(leaf)
        assert p.creator_id == "gone"
        assert p.ancestors == ("gone",)


# --- credentials --------------------------------------------------------------


class TestCredential:
    def test_mint_shape(self):
        token, digest = mint_terminal_credential()
        assert token.startswith(TERMINAL_TOKEN_PREFIX)
        assert len(token) == len(TERMINAL_TOKEN_PREFIX) + 43
        assert digest == hashlib.sha256(token.encode()).hexdigest()
        assert digest == digest_of(token)

    def test_mint_unique(self):
        assert mint_terminal_credential()[0] != mint_terminal_credential()[0]

    def test_digest_deterministic_and_prefix_sensitive(self):
        assert digest_of("cao_t_abc") == digest_of("cao_t_abc")
        assert digest_of("cao_t_abc") != digest_of("abc")


# --- resolution ---------------------------------------------------------------


def _app():
    app = FastAPI()

    @app.get("/who")
    async def who(p: Principal = Depends(get_current_principal)):
        return {
            "kind": p.kind,
            "scopes": sorted(p.scopes),
            "terminal_id": p.terminal_id,
            "run_id": p.run_id,
            "ancestors": list(p.ancestors),
        }

    @app.get("/who2")
    async def who2(p: Principal = Depends(require_principal())):
        return {"kind": p.kind}

    return TestClient(app)


class TestResolution:
    def test_default_off_no_bearer_is_anonymous_full_scopes(self):
        r = _app().get("/who")
        assert r.status_code == 200
        assert r.json()["kind"] == "anonymous"
        assert r.json()["scopes"] == sorted(auth.FULL_SCOPE_SET)

    def test_default_off_random_bearer_is_still_anonymous(self):
        r = _app().get("/who", headers={"Authorization": "Bearer whatever"})
        assert r.status_code == 200
        assert r.json()["kind"] == "anonymous"

    def test_require_principal_wrapper(self):
        assert _app().get("/who2").json() == {"kind": "anonymous"}

    def test_terminal_token_resolves(self, fresh_db):
        _row(fresh_db, "root")
        _row(fresh_db, "t1", caller_id="root")
        token, digest = mint_terminal_credential()
        assert fresh_db.set_terminal_credential_digest("t1", digest)
        r = _app().get("/who", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        body = r.json()
        assert body["kind"] == "terminal"
        assert body["terminal_id"] == "t1"
        assert body["ancestors"] == ["root"]
        assert body["scopes"] == sorted([auth.SCOPE_READ, auth.SCOPE_WRITE])

    def test_terminal_token_wins_over_enabled_auth(self, fresh_db, monkeypatch):
        monkeypatch.setenv("CAO_AUTH_LOCAL_TOKEN", "operator-secret")
        _row(fresh_db, "t1")
        token, digest = mint_terminal_credential()
        fresh_db.set_terminal_credential_digest("t1", digest)
        r = _app().get("/who", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200 and r.json()["kind"] == "terminal"

    def test_unknown_terminal_token_is_401_revoked(self, fresh_db):
        token, _ = mint_terminal_credential()
        r = _app().get("/who", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401
        assert r.json()["detail"] == "terminal credential revoked"

    def test_deleted_terminal_token_is_401_revoked(self, fresh_db):
        _row(fresh_db, "t1")
        token, digest = mint_terminal_credential()
        fresh_db.set_terminal_credential_digest("t1", digest)
        fresh_db.delete_terminal("t1")
        r = _app().get("/who", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401
        assert r.json()["detail"] == "terminal credential revoked"

    def test_reclaimed_tombstone_is_401_revoked(self, fresh_db):
        _row(fresh_db, "t1")
        token, digest = mint_terminal_credential()
        fresh_db.set_terminal_credential_digest("t1", digest)
        fresh_db.update_terminal_deferred_init_runtime_reclaimed("t1", True)
        r = _app().get("/who", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401

    def test_run_token_without_module_is_401(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "cli_agent_orchestrator.security.run_tokens", None)
        r = _app().get("/who", headers={"Authorization": f"Bearer {RUN_TOKEN_PREFIX}abc"})
        assert r.status_code == 401

    def test_run_token_with_module(self, fresh_db, monkeypatch):
        _row(fresh_db, "spawner", allowed_tools=["fs_read"])
        fake = types.ModuleType("run_tokens")
        fake.resolve = lambda tok: "run-9" if tok == "abc" else None  # type: ignore[attr-defined]
        fake.terminal_id_for = lambda run_id: "spawner"  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "cli_agent_orchestrator.security.run_tokens", fake)
        r = _app().get("/who", headers={"Authorization": f"Bearer {RUN_TOKEN_PREFIX}abc"})
        assert r.status_code == 200
        assert r.json()["kind"] == "run"
        assert r.json()["run_id"] == "run-9"
        assert r.json()["terminal_id"] == "spawner"
        bad = _app().get("/who", headers={"Authorization": f"Bearer {RUN_TOKEN_PREFIX}zzz"})
        assert bad.status_code == 401

    def test_auth_enabled_operator_token_is_operator(self, monkeypatch):
        monkeypatch.setenv("CAO_AUTH_LOCAL_TOKEN", "operator-secret")
        r = _app().get("/who", headers={"Authorization": "Bearer operator-secret"})
        assert r.status_code == 200
        assert r.json()["kind"] == "operator"
        assert r.json()["scopes"] == sorted(auth.FULL_SCOPE_SET)

    def test_auth_enabled_wrong_or_missing_bearer_401_like_today(self, monkeypatch):
        monkeypatch.setenv("CAO_AUTH_LOCAL_TOKEN", "operator-secret")
        assert _app().get("/who").status_code == 401
        assert _app().get("/who", headers={"Authorization": "Bearer nope"}).status_code == 401

    def test_module_constants(self):
        assert principal_mod.TERMINAL_TOKEN_PREFIX == "cao_t_"
        assert principal_mod.RUN_TOKEN_PREFIX == "cao_r_"
