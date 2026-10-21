"""Audit line shape and the allows-only-when-flagged rule (#965)."""

import json

from cli_agent_orchestrator.security import audit
from cli_agent_orchestrator.security.authz import Decision
from cli_agent_orchestrator.security.principal import Principal

P = Principal(kind="terminal", scopes=frozenset(), terminal_id="t1")
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
}


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


def test_allow_not_written_by_default():
    audit.record(P, "tool:call", "x", ALLOW, False)
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
