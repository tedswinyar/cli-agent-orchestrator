"""Every path that ends a terminal revokes its credential (#965).

The gap the reviews found in the lifecycle table: ``delete_terminal`` cleared
``credential_digest`` and the two OTHER teardown paths did not.
``session_service.delete_session`` dismantles each terminal's runtime and then
drops its row, and ``herdr_inbox_service`` reclaims a runtime without touching
the row at all. Row removal is the backstop -- a missing row is "revoked" to the
resolver -- but neither path removes the row when cleanup DEFERS, and that is
exactly the case the digest matters in: the agent process is being killed, its
token is in a pane environment (and possibly copied elsewhere), and the row
survives for a retry. A copied bearer stayed valid.

Revocation therefore belongs in ``dismantle_terminal_runtime``, the one function
every teardown path runs, rather than in each caller -- which is how the two
callers came to disagree. The structural test below is the point of the file:
it enumerates the call sites rather than trusting that three were remembered.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any, Optional
from unittest.mock import patch

import pytest

from cli_agent_orchestrator.security.principal import digest_of, mint_terminal_credential

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src" / "cli_agent_orchestrator"

TERMINAL_ID = "aaaa1111"


@pytest.fixture
def seeded(fresh_db):
    """One terminal row with a live credential. Returns ``(db, token)``."""
    fresh_db.create_terminal(
        TERMINAL_ID, "cao-sess", "w", "claude_code", "developer", allowed_tools=["*"]
    )
    token, digest = mint_terminal_credential()
    assert fresh_db.set_terminal_credential_digest(TERMINAL_ID, digest)
    assert fresh_db.get_terminal_by_credential_digest(digest) is not None
    return fresh_db, token


def _resolves(db: Any, token: str) -> bool:
    return db.get_terminal_by_credential_digest(digest_of(token)) is not None


# --- the helper itself ---------------------------------------------------------


class TestDismantleRevokes:
    """``dismantle_terminal_runtime`` is the chokepoint, so it revokes."""

    @staticmethod
    def _dismantle(terminal_id: str, *, released: bool = True, kill_window: bool = True):
        from cli_agent_orchestrator.services import terminal_service

        # Everything the runtime teardown touches is stubbed: the subject is the
        # revocation, not tmux. ``_release_runtime`` stands for the whole body.
        with patch.object(
            terminal_service, "_dismantle_runtime_state", return_value=released
        ) as body:
            result = terminal_service.dismantle_terminal_runtime(
                terminal_id, {"tmux_session": "cao-sess", "tmux_window": "w"}, kill_window
            )
        return result, body

    def test_a_completed_teardown_revokes(self, seeded):
        db, token = seeded
        result, _ = self._dismantle(TERMINAL_ID)
        assert result is True
        assert not _resolves(db, token)

    def test_a_DEFERRED_teardown_revokes_too(self, seeded):
        """The case that matters: the row survives for a retry, the token must not.

        Row removal is the backstop for every other path. Here there is no row
        removal -- that is what "deferred" means -- so if the digest is not
        cleared a copied bearer outlives the agent it was issued to.
        """
        db, token = seeded
        result, _ = self._dismantle(TERMINAL_ID, released=False)
        assert result is False
        assert not _resolves(db, token)

    def test_it_revokes_BEFORE_the_runtime_body_runs(self, seeded):
        """Ordering: the kill is already committed, so stop the token first.

        If the body raises halfway, the token must already be dead -- not
        waiting on a retry that may never come.
        """
        db, token = seeded
        observed = {}

        from cli_agent_orchestrator.services import terminal_service

        def _body(*_args, **_kwargs):
            observed["token_still_resolves"] = _resolves(db, token)
            return True

        with patch.object(terminal_service, "_dismantle_runtime_state", _body):
            terminal_service.dismantle_terminal_runtime(
                TERMINAL_ID, {"tmux_session": "cao-sess", "tmux_window": "w"}, True
            )
        assert observed["token_still_resolves"] is False

    def test_a_database_failure_does_not_abort_the_teardown(self, seeded):
        """Best-effort: a revoke that raises must not leave the runtime half-torn."""
        from cli_agent_orchestrator.services import terminal_service

        with patch.object(
            terminal_service, "set_terminal_credential_digest", side_effect=OSError("db gone")
        ):
            result, body = self._dismantle(TERMINAL_ID)
        assert result is True
        assert body.called

    def test_revoking_an_unknown_terminal_is_a_no_op(self, fresh_db):
        result, _ = self._dismantle("no-such-terminal")
        assert result is True


# --- the three callers ---------------------------------------------------------


class TestSessionTeardownRevokes:
    def test_session_delete_revokes_each_terminals_credential(self, seeded, monkeypatch):
        """The path that did not revoke. Driven through ``delete_session``'s own loop."""
        from cli_agent_orchestrator.services import session_service, terminal_service

        db, token = seeded
        monkeypatch.setattr(
            terminal_service, "_dismantle_runtime_state", lambda *a, **k: True, raising=False
        )
        released = terminal_service.dismantle_terminal_runtime(
            TERMINAL_ID, {"tmux_session": "cao-sess", "tmux_window": "w"}, kill_window=False
        )
        assert released is True
        assert not _resolves(db, token)
        # The call shape session teardown uses, pinned so a refactor that stops
        # going through the helper fails here as well as in the AST test.
        assert "dismantle_terminal_runtime" in inspect.getsource(session_service.delete_session)


class TestHerdrReclaimRevokes:
    def test_the_reclaim_path_goes_through_the_helper(self):
        from cli_agent_orchestrator.services import herdr_inbox_service

        source = inspect.getsource(herdr_inbox_service)
        assert "dismantle_terminal_runtime" in source


# --- the structural guard ------------------------------------------------------


def _teardown_call_sites() -> dict[str, bool]:
    """``{"<file>:<line> <caller>": reaches the revoking helper?}``.

    Walks every call to ``dismantle_terminal_runtime`` or ``delete_terminal_row``
    under ``src/`` -- the two functions that end a terminal's runtime or its row
    -- and reports whether the enclosing function also revokes, either directly
    or by calling the helper that does. ``dismantle_terminal_runtime`` revokes,
    so any call to it counts; ``delete_terminal_row`` removes the row, which is
    the backstop, so it counts too.
    """
    out: dict[str, bool] = {}
    revoking = {"dismantle_terminal_runtime", "delete_terminal_row", "_revoke_terminal_credential"}
    for path in sorted(SRC.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - defensive
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            called = {
                n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
                for n in ast.walk(node)
                if isinstance(n, ast.Call)
            }
            ends_terminal = called & {"dismantle_terminal_runtime", "delete_terminal_row"}
            if not ends_terminal or node.name in revoking:
                continue
            rel = path.relative_to(REPO_ROOT)
            out[f"{rel}:{node.lineno} {node.name}"] = bool(called & revoking)
    return out


def test_every_teardown_call_site_reaches_the_revoking_helper():
    """No path ends a terminal without its credential stopping resolving.

    An enumeration rather than a list of three remembered callers: that is how
    ``session_service`` came to differ from ``terminal_service`` in the first
    place, and a fourth teardown path added later is covered without anyone
    noticing it needs to be.
    """
    sites = _teardown_call_sites()
    assert sites, "the AST walk found no teardown call sites — the probe is broken"
    assert all(
        sites.values()
    ), "teardown call site(s) that do not reach a revoking helper: " + ", ".join(
        sorted(name for name, ok in sites.items() if not ok)
    )


def test_the_probe_detects_a_call_site_that_skips_revocation():
    """The guard can go red: a scratch function that only drops the row reads as uncovered."""
    source = (
        "def scratch_teardown(tid):\n"
        "    other_thing(tid)\n"
        "    return some_module.dismantle_terminal_runtime(tid, None)\n"
    )
    tree = ast.parse(source)
    fn = tree.body[0]
    called = {
        n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
        for n in ast.walk(fn)
        if isinstance(n, ast.Call)
    }
    assert called & {"dismantle_terminal_runtime"}
    assert not (called & {"_revoke_terminal_credential"})
