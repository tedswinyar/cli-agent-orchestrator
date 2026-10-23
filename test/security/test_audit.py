"""Audit line shape, agent-allow logging, rotation and write-failure accounting (#965).

What the reviews said this file was missing, all four of them agreeing: the log
was an append-only debugging artifact, not an operable control. No rotation, so
it grows without bound and ``read_recent`` reads the whole file to slice a tail;
allowed calls unrecorded by default, so a SUCCESSFUL bypass left no trace at all
and warn mode could not reveal the population it exists to reveal; no request id
or outcome, so two lines from one request could not be correlated; write failures
swallowed at debug, so the trail could stop and nothing would say so.
"""

import json
import os

import pytest

from cli_agent_orchestrator.security import audit
from cli_agent_orchestrator.security.authz import Decision
from cli_agent_orchestrator.security.principal import Principal

P = Principal(kind="terminal", scopes=frozenset(), terminal_id="t1")
RUN = Principal(kind="run", scopes=frozenset(), terminal_id="t1", run_id="r9")
OPERATOR = Principal(kind="operator", scopes=frozenset())
ANON = Principal(kind="anonymous", scopes=frozenset())
DENY = Decision(False, "tool:default-deny", "no")
ALLOW = Decision(True, "tool:allowlist", "yes")

EXPECTED_KEYS = {
    "ts",
    "kind",
    "terminal_id",
    "run_id",
    "action",
    "resource",
    "allowed",
    "enforced",
    "rule",
    "reason",
    "request_id",
    "outcome",
}


@pytest.fixture(autouse=True)
def _reset_counters():
    audit.reset_write_failures()
    yield
    audit.reset_write_failures()


def test_refusal_written_with_shape(tmp_path):
    audit.record(P, "tool:call", "cao-mcp-server/assign", DENY, False)
    path = audit.audit_path()
    assert path == tmp_path / "cao-home" / "logs" / "authz.jsonl"
    lines = path.read_text().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert set(rec) == EXPECTED_KEYS
    assert rec["kind"] == "terminal" and rec["terminal_id"] == "t1" and rec["run_id"] is None
    assert rec["action"] == "tool:call" and rec["resource"] == "cao-mcp-server/assign"
    assert rec["allowed"] is False and rec["enforced"] is False
    assert rec["rule"] == "tool:default-deny" and rec["reason"] == "no"
    assert rec["ts"].endswith("+00:00")


def test_an_operator_allow_is_not_written_by_default():
    """Allows are filtered by KIND now, not suppressed wholesale.

    An operator's allowed call is still unrecorded by default -- the web UI
    polls these routes, and burying the agent signal under that traffic is
    exactly what makes a log unreadable. An AGENT's allowed call IS recorded;
    see ``TestAgentAllowsAreLogged`` for why that asymmetry is the fix.
    """
    audit.record(OPERATOR, "tool:call", "x", ALLOW, False)
    assert not audit.audit_path().exists()
    assert audit.read_recent() == []


def test_allow_written_when_flagged(monkeypatch):
    monkeypatch.setenv("CAO_AUTHZ_AUDIT_ALLOWS", "1")
    audit.record(P, "tool:call", "x", ALLOW, True)
    recs = audit.read_recent()
    assert len(recs) == 1 and recs[0]["allowed"] is True and recs[0]["enforced"] is True


def test_read_recent_tail_and_order():
    for i in range(5):
        audit.record(P, "tool:call", f"r{i}", DENY, False)
    recs = audit.read_recent(2)
    assert [r["resource"] for r in recs] == ["r3", "r4"]
    assert audit.read_recent(0) == []


def test_never_raises(tmp_path, monkeypatch):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir")
    monkeypatch.setenv("CAO_HOME_DIR", str(blocker))
    audit.record(P, "tool:call", "x", DENY, False)  # mkdir under a file fails; must not raise
    assert audit.read_recent() == []


class TestAgentAllowsAreLogged:
    """An ALLOWED agent call is recorded by default; an operator's is not.

    The asymmetry the reviews asked for, and it is the whole point: warn mode is
    supposed to answer "what would enforcement refuse, and what is legitimately
    happening today". With only refusals recorded, an agent that dropped its
    credential and sailed through produced no line at all, and the population of
    operator-authority agents nobody could see stayed invisible. Logging every
    operator call instead would bury that signal in the operator's own traffic
    (the UI polls these routes), so the rule is per-kind, not global.
    """

    def test_an_allowed_terminal_call_is_recorded(self):
        audit.record(P, "tool:call", "cao-mcp-server/send_message", ALLOW, False)
        recs = audit.read_recent()
        assert len(recs) == 1
        assert recs[0]["allowed"] is True and recs[0]["kind"] == "terminal"

    def test_an_allowed_run_call_is_recorded(self):
        audit.record(RUN, "run:cancel", "run:r9", ALLOW, False)
        assert len(audit.read_recent()) == 1

    @pytest.mark.parametrize("principal", [OPERATOR, ANON], ids=["operator", "anonymous"])
    def test_an_allowed_operator_call_is_not(self, principal):
        audit.record(principal, "tool:call", "x", ALLOW, False)
        assert audit.read_recent() == []

    @pytest.mark.parametrize("principal", [OPERATOR, ANON], ids=["operator", "anonymous"])
    def test_a_REFUSED_operator_call_still_is(self, principal):
        """Refusals are unconditional whatever the kind; only allows are filtered."""
        audit.record(principal, "tool:call", "x", DENY, False)
        assert len(audit.read_recent()) == 1

    def test_the_flag_still_forces_operator_allows_on(self, monkeypatch):
        monkeypatch.setenv("CAO_AUTHZ_AUDIT_ALLOWS", "1")
        audit.record(OPERATOR, "tool:call", "x", ALLOW, False)
        assert len(audit.read_recent()) == 1


class TestRequestIdAndOutcome:
    """Two lines from one request must be correlatable, and say what happened."""

    def test_the_outcome_names_what_actually_happened(self):
        audit.record(P, "tool:call", "x", DENY, True)
        audit.record(P, "tool:call", "y", DENY, False)
        audit.record(P, "tool:call", "z", ALLOW, False)
        assert [r["outcome"] for r in audit.read_recent()] == ["refused", "audited", "allowed"]

    def test_a_refusal_that_was_not_enforced_is_audited_not_refused(self):
        """``allowed: false`` alone cannot distinguish warn mode from enforcement."""
        audit.record(P, "tool:call", "x", DENY, False)
        rec = audit.read_recent()[0]
        assert rec["allowed"] is False and rec["enforced"] is False
        assert rec["outcome"] == "audited"

    def test_lines_in_one_request_share_a_request_id(self):
        with audit.request_scope() as request_id:
            audit.record(P, "tool:call", "x", DENY, False)
            audit.record(P, "terminal:create", "y", DENY, False)
        recs = audit.read_recent()
        assert {r["request_id"] for r in recs} == {request_id}
        assert request_id

    def test_separate_requests_get_separate_ids(self):
        with audit.request_scope():
            audit.record(P, "tool:call", "x", DENY, False)
        with audit.request_scope():
            audit.record(P, "tool:call", "y", DENY, False)
        ids = [r["request_id"] for r in audit.read_recent()]
        assert len(set(ids)) == 2

    def test_outside_a_scope_the_id_is_null_not_invented(self):
        """An in-process call site is not a request; a synthetic id would be a lie."""
        audit.record(P, "tool:call", "x", DENY, False)
        assert audit.read_recent()[0]["request_id"] is None

    def test_the_scope_is_restored_on_an_exception(self):
        with pytest.raises(RuntimeError):
            with audit.request_scope():
                raise RuntimeError("boom")
        audit.record(P, "tool:call", "x", DENY, False)
        assert audit.read_recent()[0]["request_id"] is None


class TestRotation:
    """A control with unbounded growth is an outage waiting for a full disk."""

    @staticmethod
    def _fill(byte_cap: int) -> None:
        # Each line is a few hundred bytes; write enough to cross the cap twice.
        for i in range(400):
            audit.record(P, "tool:call", f"resource-{i}-" + "x" * 200, DENY, False)

    def test_the_live_file_stays_under_the_cap(self, monkeypatch):
        monkeypatch.setenv("CAO_AUTHZ_AUDIT_MAX_BYTES", "4096")
        self._fill(4096)
        assert audit.audit_path().stat().st_size <= 4096 + audit.MAX_LINE_SLACK

    def test_rotation_keeps_a_bounded_number_of_generations(self, monkeypatch):
        monkeypatch.setenv("CAO_AUTHZ_AUDIT_MAX_BYTES", "4096")
        monkeypatch.setenv("CAO_AUTHZ_AUDIT_KEEP", "3")
        self._fill(4096)
        rotated = sorted(audit.audit_path().parent.glob(audit.AUDIT_FILE_NAME + ".*"))
        assert 1 <= len(rotated) <= 3
        assert all(p.name.endswith((".1", ".2", ".3")) for p in rotated)

    def test_total_disk_use_is_bounded(self, monkeypatch):
        monkeypatch.setenv("CAO_AUTHZ_AUDIT_MAX_BYTES", "4096")
        monkeypatch.setenv("CAO_AUTHZ_AUDIT_KEEP", "2")
        self._fill(4096)
        folder = audit.audit_path().parent
        total = sum(p.stat().st_size for p in folder.glob(audit.AUDIT_FILE_NAME + "*"))
        assert total <= 3 * (4096 + audit.MAX_LINE_SLACK)

    def test_the_newest_lines_survive_rotation(self, monkeypatch):
        monkeypatch.setenv("CAO_AUTHZ_AUDIT_MAX_BYTES", "4096")
        self._fill(4096)
        assert "resource-399-" in audit.read_recent(1)[0]["resource"]

    def test_rotation_is_off_when_the_cap_is_zero(self, monkeypatch):
        monkeypatch.setenv("CAO_AUTHZ_AUDIT_MAX_BYTES", "0")
        self._fill(0)
        assert not list(audit.audit_path().parent.glob(audit.AUDIT_FILE_NAME + ".*"))
        assert len(audit.read_recent(500)) == 400

    def test_a_malformed_cap_falls_back_to_the_default(self, monkeypatch):
        monkeypatch.setenv("CAO_AUTHZ_AUDIT_MAX_BYTES", "not-a-number")
        assert audit.max_bytes() == audit.DEFAULT_MAX_BYTES

    def test_the_default_cap_is_ten_megabytes_keeping_three(self, monkeypatch):
        monkeypatch.delenv("CAO_AUTHZ_AUDIT_MAX_BYTES", raising=False)
        monkeypatch.delenv("CAO_AUTHZ_AUDIT_KEEP", raising=False)
        assert audit.max_bytes() == 10 * 1024 * 1024
        assert audit.keep_generations() == 3


class TestWriteFailuresAreCounted:
    """A trail that stops must say so. Swallowed at debug, it just stops."""

    def test_a_failure_increments_the_counter(self, tmp_path, monkeypatch):
        blocker = tmp_path / "blocker"
        blocker.write_text("not a dir")
        monkeypatch.setenv("CAO_HOME_DIR", str(blocker))
        audit.record(P, "tool:call", "x", DENY, False)
        assert audit.write_failures() == 1

    def test_it_still_never_raises(self, tmp_path, monkeypatch):
        blocker = tmp_path / "blocker"
        blocker.write_text("not a dir")
        monkeypatch.setenv("CAO_HOME_DIR", str(blocker))
        audit.record(P, "tool:call", "x", DENY, False)  # must not raise
        assert audit.read_recent() == []

    def test_a_rotation_failure_is_counted_and_does_not_lose_the_line(self, monkeypatch, tmp_path):
        monkeypatch.setenv("CAO_AUTHZ_AUDIT_MAX_BYTES", "256")
        audit.record(P, "tool:call", "x" * 400, DENY, False)
        with monkeypatch.context() as m:
            m.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("nope")))
            audit.record(P, "tool:call", "second", DENY, False)
        assert audit.write_failures() >= 1
        assert any(r["resource"] == "second" for r in audit.read_recent())

    def test_a_healthy_run_counts_nothing(self):
        audit.record(P, "tool:call", "x", DENY, False)
        assert audit.write_failures() == 0

    def test_the_counter_is_surfaced_for_a_health_reader(self):
        """A number nothing can read is the same as no number."""
        assert audit.stats() == {"write_failures": 0, "path": str(audit.audit_path())}
