"""A child's delegation ceiling can never be wider than its creator's (#948, #965).

The escalation-by-omission the reviews found. ``authz.ceiling_of`` reads
``delegate_tools`` when the row has it and falls back to the row's OWN
``allowed_tools`` when it does not -- and on this branch no row ever had it,
because the column did not exist. So A, holding ``allowed_tools=["*"]`` and
intending its delegates to be capped at ``fs_read``, created B with
``allowed_tools=["fs_read"]`` and B's ceiling became ``["fs_read"]`` -- correct
by accident, one level deep. Give B a wider allowlist for any legitimate reason
and the cap evaporates: B's ceiling is B's own list, and C can be anything B is.
A's intent never reached C, and nothing refused.

Two properties:

1. A ceiling on the creator's row is ENFORCED: a request outside it is refused
   (``terminal:ceiling``), which the gate already did and could never see.
2. A ceiling PROPAGATES: a child's recorded ``delegate_tools`` is the
   intersection of what was asked for and the creator's ceiling, never wider,
   so the cap survives the hop that used to lose it.

The second is what makes the first worth anything: a rule that only binds
direct children bounds one level of a tree whose whole point is depth.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from cli_agent_orchestrator.security.authz import (
    TERMINAL_CREATE,
    authorize,
    ceiling_of,
    narrow_to_ceiling,
)
from cli_agent_orchestrator.security.principal import principal_from_terminal_row

pytestmark = pytest.mark.usefixtures("fresh_db")


def _row(
    db: Any,
    terminal_id: str,
    *,
    caller_id: Optional[str] = None,
    allowed_tools: Optional[List[str]] = None,
    delegate_tools: Optional[List[str]] = None,
) -> Any:
    db.create_terminal(
        terminal_id,
        "cao-sess",
        f"w-{terminal_id}",
        "claude_code",
        "developer",
        allowed_tools=allowed_tools,
        caller_id=caller_id,
        delegate_tools=delegate_tools,
    )
    with db.SessionLocal() as s:
        return s.query(db.TerminalModel).filter(db.TerminalModel.id == terminal_id).first()


def _principal(db: Any, terminal_id: str):
    with db.SessionLocal() as s:
        row = s.query(db.TerminalModel).filter(db.TerminalModel.id == terminal_id).first()
        return principal_from_terminal_row(row)


def _recorded_delegate(db: Any, terminal_id: str) -> Optional[list]:
    with db.SessionLocal() as s:
        row = s.query(db.TerminalModel).filter(db.TerminalModel.id == terminal_id).first()
        raw = row.delegate_tools
    return None if raw is None else json.loads(raw)


# --- the column exists and round-trips ----------------------------------------


class TestColumn:
    def test_delegate_tools_round_trips(self, fresh_db):
        _row(fresh_db, "a", allowed_tools=["*"], delegate_tools=["fs_read"])
        assert _recorded_delegate(fresh_db, "a") == ["fs_read"]

    def test_an_empty_ceiling_round_trips_as_empty(self, fresh_db):
        """``[]`` is "may delegate nothing" and must not become SQL NULL."""
        _row(fresh_db, "a", allowed_tools=["*"], delegate_tools=[])
        assert _recorded_delegate(fresh_db, "a") == []
        assert ceiling_of(_principal(fresh_db, "a")) == ()

    def test_unset_falls_back_to_the_rows_own_allowlist(self, fresh_db):
        """Operator-created rows keep today's semantics: no ceiling = own list."""
        _row(fresh_db, "a", allowed_tools=["fs_read"])
        assert _recorded_delegate(fresh_db, "a") is None
        assert ceiling_of(_principal(fresh_db, "a")) == ("fs_read",)

    def test_recorded_empty_and_unrecorded_are_not_the_same_thing(self, fresh_db):
        """The escalation one level further in: ``[]`` must not fall back to ``*``.

        ``ceiling_of`` tests ``is None``, not falsiness. A falsiness test makes
        a row that may delegate NOTHING fall back to its own allowlist, which
        for a ``*`` row is unbounded -- the same mistake the fix is about.
        """
        _row(fresh_db, "empty", allowed_tools=["*"], delegate_tools=[])
        _row(fresh_db, "unset", allowed_tools=["*"])
        assert _principal(fresh_db, "empty").delegate_tools == ()
        assert _principal(fresh_db, "unset").delegate_tools is None
        assert ceiling_of(_principal(fresh_db, "empty")) == ()
        assert ceiling_of(_principal(fresh_db, "unset")) == ("*",)
        assert not authorize(_principal(fresh_db, "empty"), TERMINAL_CREATE, ("fs_read",)).allowed

    def test_the_distinction_survives_the_wire(self, fresh_db):
        """And over the API -> MCP hop, where a tuple round-trip could lose it."""
        from cli_agent_orchestrator.security.principal import (
            principal_from_payload,
            principal_payload,
        )

        for terminal_id, expected in (("empty", ()), ("unset", None)):
            _row(
                fresh_db,
                terminal_id,
                allowed_tools=["*"],
                delegate_tools=list(expected or []) if expected is not None else None,
            )
        for terminal_id, expected in (("empty", ()), ("unset", None)):
            p = _principal(fresh_db, terminal_id)
            assert principal_from_payload(principal_payload(p)).delegate_tools == expected

    def test_the_ceiling_reaches_the_principal(self, fresh_db):
        _row(fresh_db, "a", allowed_tools=["*"], delegate_tools=["fs_read"])
        p = _principal(fresh_db, "a")
        assert p.delegate_tools == ("fs_read",)
        assert p.allowed_tools == ("*",)
        assert ceiling_of(p) == ("fs_read",)


# --- property 1: a recorded ceiling is enforced -------------------------------


class TestCeilingIsEnforced:
    def test_a_request_outside_the_ceiling_is_refused(self, fresh_db):
        """A holds ``*`` but may only delegate ``fs_read``."""
        _row(fresh_db, "a", allowed_tools=["*"], delegate_tools=["fs_read"])
        decision = authorize(_principal(fresh_db, "a"), TERMINAL_CREATE, ("@cao-mcp-server",))
        assert not decision.allowed
        assert decision.rule == "terminal:ceiling"

    def test_a_request_inside_the_ceiling_is_allowed(self, fresh_db):
        _row(fresh_db, "a", allowed_tools=["*"], delegate_tools=["fs_read"])
        decision = authorize(_principal(fresh_db, "a"), TERMINAL_CREATE, ("fs_read",))
        assert decision.allowed and decision.rule == "terminal:within-ceiling"


# --- property 2: the ceiling propagates ---------------------------------------


class TestNarrowToCeiling:
    """The pure function the create path records, tested as a function.

    ``None`` requested means "no explicit ceiling was asked for", which is the
    only case there is today -- no client parameter carries one -- and it must
    mean "inherit the creator's", not "unbounded".
    """

    @pytest.mark.parametrize(
        "requested,ceiling,expected",
        [
            (None, ("fs_read",), ("fs_read",)),
            (None, ("*",), ("*",)),
            (None, (), ()),
            (("fs_read", "@cao-mcp-server"), ("fs_read",), ("fs_read",)),
            (("fs_read",), ("*",), ("fs_read",)),
            (("@cao-mcp-server",), ("fs_read",), ()),
            (("*",), ("fs_read",), ()),
            (("@cao-mcp-server/assign",), ("@cao-mcp-server",), ("@cao-mcp-server/assign",)),
        ],
    )
    def test_never_wider_than_the_ceiling(self, requested, ceiling, expected):
        assert narrow_to_ceiling(requested, ceiling) == expected

    def test_order_and_duplicates_follow_the_request(self):
        assert narrow_to_ceiling(("b", "a", "b"), ("*",)) == ("b", "a", "b")


class TestCeilingPropagatesThroughTheCreatePath:
    """A(*, ceiling X) -> B -> C: C must not exceed X.

    Drives ``terminal_service.create_terminal``'s ceiling step rather than the
    pure function, because the defect was that nothing wrote the column at all:
    a test of the arithmetic alone would have passed on the broken tree.
    """

    @staticmethod
    def _child_ceiling(creator_principal, requested_delegate=None) -> tuple:
        from cli_agent_orchestrator.services.terminal_service import child_delegate_tools

        return child_delegate_tools(creator_principal, requested_delegate)

    def test_a_child_inherits_its_creators_ceiling(self, fresh_db):
        _row(fresh_db, "a", allowed_tools=["*"], delegate_tools=["fs_read"])
        assert self._child_ceiling(_principal(fresh_db, "a")) == ("fs_read",)

    def test_the_grandchild_still_cannot_exceed_it(self, fresh_db):
        """The hop the old code lost: B's allowlist is wider than A's ceiling."""
        _row(fresh_db, "a", allowed_tools=["*"], delegate_tools=["fs_read"])
        a_ceiling = self._child_ceiling(_principal(fresh_db, "a"))
        _row(
            fresh_db,
            "b",
            caller_id="a",
            allowed_tools=["*"],
            delegate_tools=list(a_ceiling),
        )
        b = _principal(fresh_db, "b")
        # Without the column B's ceiling would be B's own ``["*"]`` and this
        # create would be allowed.
        assert ceiling_of(b) == ("fs_read",)
        assert not authorize(b, TERMINAL_CREATE, ("@cao-mcp-server",)).allowed
        assert self._child_ceiling(b) == ("fs_read",)

    def test_an_operator_creator_records_no_ceiling(self, fresh_db):
        """``principal is None`` (in-process) and operators are unbounded, as today."""
        assert self._child_ceiling(None) is None

    def test_an_operator_principal_records_no_ceiling(self, fresh_db):
        from cli_agent_orchestrator.security.principal import Principal

        operator = Principal(kind="operator", scopes=frozenset())
        assert self._child_ceiling(operator) is None

    def test_a_requested_ceiling_is_intersected_not_trusted(self, fresh_db):
        _row(fresh_db, "a", allowed_tools=["*"], delegate_tools=["fs_read"])
        narrowed = self._child_ceiling(_principal(fresh_db, "a"), ["fs_read", "@cao-mcp-server"])
        assert narrowed == ("fs_read",)


class TestEndToEndThroughCreateTerminal:
    """The recorded column, through ``create_terminal`` itself."""

    @pytest.mark.asyncio
    async def test_the_child_row_records_the_narrowed_ceiling(self, fresh_db, monkeypatch):
        from unittest.mock import AsyncMock, patch

        from cli_agent_orchestrator.services import terminal_service

        _row(fresh_db, "a", allowed_tools=["*"], delegate_tools=["fs_read"])
        captured: Dict[str, Any] = {}

        async def _fake_unguarded(**kwargs):
            captured.update(kwargs)
            return AsyncMock()

        with patch.object(terminal_service, "_create_terminal_unguarded", _fake_unguarded):
            await terminal_service.create_terminal(
                provider="claude_code",
                agent_profile="developer",
                session_name="cao-sess",
                allowed_tools=["fs_read"],
                caller_id="a",
                principal=_principal(fresh_db, "a"),
            )
        assert captured["delegate_tools"] == ("fs_read",)
