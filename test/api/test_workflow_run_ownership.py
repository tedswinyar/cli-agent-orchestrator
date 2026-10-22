"""Run ownership on the workflow run routes (#965 WS4).

Who may cancel, resume or replay a run is an OBJECT-level decision (OWASP API1): the
write scope says a caller may cancel runs at all; these tests pin that it may cancel
*this* run only as its owner, as a frozen ancestor of the owner, as an operator, or as
the run's own principal. Everything else is a 403 naming the owner under
``CAO_PRINCIPAL_ENFORCE=1`` and an audit line plus the old behaviour in warn mode.

The principal is injected through FastAPI's dependency override rather than a real
``cao_t_`` bearer: the bearer-to-principal path is WS0's and is tested in
``test/security/test_principal.py``; what is under test here is what the routes DO with
the principal they are handed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import pytest

from cli_agent_orchestrator.api import main as api_main
from cli_agent_orchestrator.api.main import app
from cli_agent_orchestrator.clients.database import (
    _migrate_workflow_index,
    _migrate_workflow_run,
    _migrate_workflow_run_step,
)
from cli_agent_orchestrator.models.workflow_runtime import RunState, WorkflowRunResult
from cli_agent_orchestrator.security import audit
from cli_agent_orchestrator.security.principal import Principal, get_current_principal
from cli_agent_orchestrator.services import script_runner, workflow_journal, workflow_service

RW = frozenset({"cao:read", "cao:write"})

OWNER = "term-A"
CREATOR = "term-P"  # created OWNER; in OWNER's frozen ancestor list
GRANDPARENT = "term-G"
STRANGER = "term-B"
RESUMER = "term-C"

#: Text that must never leak into a 403 detail.
SECRET = "PROMPT-TEXT-MUST-NOT-LEAK"
_SNAPSHOT = (
    '{"name": "wf", "mode": "sequential", "steps": [{"id": "s1", "provider": "claude_code", '
    '"agent": "dev", "prompt": "' + SECRET + '"}]}'
)


def terminal(tid: str, ancestors=()) -> Principal:
    return Principal(kind="terminal", scopes=RW, terminal_id=tid, ancestors=tuple(ancestors))


OPERATOR = Principal(kind="operator", scopes=frozenset({"cao:admin"}))


def run_principal(run_id: str, tid: Optional[str] = None) -> Principal:
    return Principal(kind="run", scopes=RW, terminal_id=tid, run_id=run_id)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Fresh journal DB, empty registry, warn mode, audit routed to a per-test home."""
    db_path = tmp_path / "wf.db"
    monkeypatch.setattr("cli_agent_orchestrator.constants.DATABASE_FILE", db_path, raising=True)
    _migrate_workflow_run()
    _migrate_workflow_run_step()
    _migrate_workflow_index()  # spec resolution on the start routes reads it
    monkeypatch.setattr(workflow_service, "run_registry", {})
    monkeypatch.setattr(workflow_service, "_active_drives", set())
    monkeypatch.delenv("CAO_PRINCIPAL_ENFORCE", raising=False)
    monkeypatch.delenv("CAO_AUTHZ_AUDIT_ALLOWS", raising=False)
    monkeypatch.setenv("CAO_HOME_DIR", str(tmp_path / "cao-home"))
    yield db_path


@pytest.fixture
def as_principal():
    """Install a principal for the request and remove the override afterwards."""

    def _install(p: Principal) -> None:
        app.dependency_overrides[get_current_principal] = lambda: p

    yield _install
    app.dependency_overrides.pop(get_current_principal, None)


@pytest.fixture
def enforce(monkeypatch):
    monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")


def seed(run_id: str, state: str = "running", owner=OWNER, ancestors=(CREATOR, GRANDPARENT)):
    workflow_journal.insert_run(
        run_id,
        "wf",
        _SNAPSHOT,
        "{}",
        state,
        "2026-01-01T00:00:00Z",
        owner_terminal_id=owner,
        ancestor_terminal_ids=ancestors,
    )


def _ok_result(run_id: str) -> WorkflowRunResult:
    return WorkflowRunResult(
        run_id=run_id, workflow_name="wf", state=RunState.COMPLETED, started_at="t"
    )


def _refusals():
    return [line for line in audit.read_recent(50) if not line["allowed"]]


# ---------------------------------------------------------------------------
# cancel
# ---------------------------------------------------------------------------
class TestCancelOwnership:
    """Cancel goes through the journal-fallback arm (no live record), so the whole path
    is real: the row is seeded, the gate decides, the row is marked CANCELLED."""

    def test_stranger_is_refused_naming_the_owner_under_enforce(
        self, client, isolated, as_principal, enforce
    ):
        seed("r1")
        as_principal(terminal(STRANGER))
        resp = client.post("/workflows/runs/r1/cancel")
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert OWNER in detail
        assert STRANGER in detail
        assert "r1" in detail
        assert SECRET not in detail
        # Nothing was cancelled.
        assert workflow_journal.get_run("r1").state == "running"
        # And the refusal is in the audit log, as enforced.
        (line,) = _refusals()
        assert line["action"] == "run:cancel"
        assert line["rule"] == "run:not-owner"
        assert line["enforced"] is True
        assert line["terminal_id"] == STRANGER
        assert line["resource"] == "run:r1"

    def test_stranger_proceeds_in_warn_mode_with_an_audit_line(
        self, client, isolated, as_principal
    ):
        seed("r2")
        as_principal(terminal(STRANGER))
        resp = client.post("/workflows/runs/r2/cancel")
        assert resp.status_code == 200
        assert workflow_journal.get_run("r2").state == "cancelled"
        (line,) = _refusals()
        assert line["action"] == "run:cancel"
        assert line["allowed"] is False
        assert line["enforced"] is False
        assert line["rule"] == "run:not-owner"

    def test_owner_cancels_its_own_run(self, client, isolated, as_principal, enforce):
        seed("r3")
        as_principal(terminal(OWNER, ancestors=(CREATOR,)))
        resp = client.post("/workflows/runs/r3/cancel")
        assert resp.status_code == 200
        assert workflow_journal.get_run("r3").state == "cancelled"
        assert _refusals() == []

    def test_creator_of_the_owner_cancels(self, client, isolated, as_principal, enforce):
        """The frozen ancestor list, not the live terminal tree, is what admits the creator."""
        seed("r4")
        as_principal(terminal(CREATOR))
        resp = client.post("/workflows/runs/r4/cancel")
        assert resp.status_code == 200
        assert workflow_journal.get_run("r4").state == "cancelled"

    def test_grandparent_cancels(self, client, isolated, as_principal, enforce):
        seed("r4b")
        as_principal(terminal(GRANDPARENT))
        assert client.post("/workflows/runs/r4b/cancel").status_code == 200

    def test_operator_cancels_anything(self, client, isolated, as_principal, enforce):
        seed("r5")
        as_principal(OPERATOR)
        resp = client.post("/workflows/runs/r5/cancel")
        assert resp.status_code == 200
        assert workflow_journal.get_run("r5").state == "cancelled"

    def test_run_principal_cancels_its_own_run_only(self, client, isolated, as_principal, enforce):
        seed("r6")
        seed("r7")
        as_principal(run_principal("r6"))
        assert client.post("/workflows/runs/r6/cancel").status_code == 200
        resp = client.post("/workflows/runs/r7/cancel")
        assert resp.status_code == 403
        assert OWNER in resp.json()["detail"]

    def test_operator_started_run_is_refused_to_every_terminal(
        self, client, isolated, as_principal, enforce
    ):
        """A run with no owning terminal (operator start, or a pre-WS4 row) is operator-only."""
        seed("r8", owner=None, ancestors=())
        as_principal(terminal(STRANGER))
        resp = client.post("/workflows/runs/r8/cancel")
        assert resp.status_code == 403
        assert "no owning terminal" in resp.json()["detail"]
        as_principal(OPERATOR)
        assert client.post("/workflows/runs/r8/cancel").status_code == 200

    def test_unknown_run_is_still_404_not_403(self, client, isolated, as_principal, enforce):
        as_principal(terminal(STRANGER))
        resp = client.post("/workflows/runs/ghost/cancel")
        assert resp.status_code == 404

    def test_live_record_without_journal_row_falls_back_to_the_record(
        self, client, isolated, as_principal, enforce, monkeypatch
    ):
        """The best-effort journal insert can fail; the live record carries the same stamp."""
        record = workflow_service.RunRecord(
            run_id="live-1",
            workflow_name="wf",
            spec=None,  # type: ignore[arg-type]
            inputs={},
            owner_terminal_id=OWNER,
            ancestor_terminal_ids=(CREATOR,),
        )
        workflow_service.run_registry["live-1"] = record
        called = []
        monkeypatch.setattr(workflow_service, "cancel_run", lambda rid: called.append(rid))

        as_principal(terminal(STRANGER))
        assert client.post("/workflows/runs/live-1/cancel").status_code == 403
        assert called == []
        as_principal(terminal(CREATOR))
        assert client.post("/workflows/runs/live-1/cancel").status_code == 200
        assert called == ["live-1"]

    def test_anonymous_caller_with_auth_off_is_unchanged(self, client, isolated, enforce):
        """No override: the real dependency yields the anonymous principal (auth off), which the
        rules treat as an operator. Existing behaviour and existing tests are untouched."""
        seed("r9")
        resp = client.post("/workflows/runs/r9/cancel")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# resume
# ---------------------------------------------------------------------------
class TestResumeOwnership:
    @pytest.fixture(autouse=True)
    def _stub_engines(self, monkeypatch):
        self.resumed = []

        async def _yaml(run_id):
            self.resumed.append(("yaml", run_id))
            return _ok_result(run_id)

        async def _script(run_id, decisions=None):
            self.resumed.append(("script", run_id))
            return _ok_result(run_id)

        monkeypatch.setattr(workflow_service, "resume_from_last_completed", _yaml)
        monkeypatch.setattr(script_runner, "resume_script_run", _script)

    def test_stranger_refused_under_enforce(self, client, isolated, as_principal, enforce):
        seed("r10", state="failed")
        as_principal(terminal(STRANGER))
        resp = client.post("/workflows/runs/r10/resume")
        assert resp.status_code == 403
        assert OWNER in resp.json()["detail"]
        assert SECRET not in resp.json()["detail"]
        assert self.resumed == []
        (line,) = _refusals()
        assert line["action"] == "run:resume"

    @pytest.mark.parametrize("who", [OWNER, CREATOR, GRANDPARENT])
    def test_owner_and_ancestors_resume(self, client, isolated, as_principal, enforce, who):
        seed("r11", state="failed")
        as_principal(terminal(who))
        assert client.post("/workflows/runs/r11/resume").status_code == 200
        assert self.resumed == [("yaml", "r11")]

    def test_operator_resumes(self, client, isolated, as_principal, enforce):
        seed("r12", state="failed")
        as_principal(OPERATOR)
        assert client.post("/workflows/runs/r12/resume").status_code == 200

    def test_resume_by_another_terminal_does_not_transfer_ownership(
        self, client, isolated, as_principal, monkeypatch
    ):
        """Warn mode lets RESUMER resume (audited). Afterwards the run still belongs to OWNER
        and RESUMER is not in its ancestry: under enforcement it cannot cancel what it resumed.
        That is the documented decision — a resume is a new caller, not a handoff."""
        seed("r13", state="failed")
        as_principal(terminal(RESUMER))
        assert client.post("/workflows/runs/r13/resume").status_code == 200
        assert self.resumed == [("yaml", "r13")]

        row = workflow_journal.get_run("r13")
        assert row.owner_terminal_id == OWNER
        assert row.ancestor_terminal_ids == (CREATOR, GRANDPARENT)
        assert RESUMER not in row.ancestor_terminal_ids

        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
        resp = client.post("/workflows/runs/r13/cancel")
        assert resp.status_code == 403
        assert OWNER in resp.json()["detail"]

    def test_ancestor_resume_does_not_restamp_the_owner(
        self, client, isolated, as_principal, enforce
    ):
        seed("r14", state="failed")
        as_principal(terminal(CREATOR))
        assert client.post("/workflows/runs/r14/resume").status_code == 200
        row = workflow_journal.get_run("r14")
        assert row.owner_terminal_id == OWNER
        assert row.ancestor_terminal_ids == (CREATOR, GRANDPARENT)

    def test_script_tier_resume_is_gated_too(self, client, isolated, as_principal, enforce):
        workflow_journal.insert_run(
            "r15",
            "wf",
            "{}",
            "{}",
            "failed",
            "t",
            "script",
            "1",
            None,
            OWNER,
            (CREATOR,),
        )
        as_principal(terminal(STRANGER))
        assert client.post("/workflows/runs/r15/resume").status_code == 403
        as_principal(terminal(OWNER))
        assert client.post("/workflows/runs/r15/resume").status_code == 200
        assert self.resumed == [("script", "r15")]

    def test_unknown_run_is_404(self, client, isolated, as_principal, enforce):
        as_principal(terminal(STRANGER))
        assert client.post("/workflows/runs/ghost/resume").status_code == 404


# ---------------------------------------------------------------------------
# single-step replay
# ---------------------------------------------------------------------------
class TestReplayOwnership:
    @pytest.fixture(autouse=True)
    def _stub_service(self, monkeypatch):
        self.replayed = []

        async def _replay(run_id, step_id, prompt_override=None):
            self.replayed.append((run_id, step_id))
            return {"run_id": run_id, "step_id": step_id, "prompt": "p", "error": None}

        monkeypatch.setattr(workflow_service, "replay_single_step", _replay)

    def test_stranger_refused_under_enforce(self, client, isolated, as_principal, enforce):
        seed("r20", state="completed")
        as_principal(terminal(STRANGER))
        resp = client.post("/workflows/runs/r20/steps/s1:replay")
        assert resp.status_code == 403
        assert OWNER in resp.json()["detail"]
        assert SECRET not in resp.json()["detail"]
        assert self.replayed == []
        (line,) = _refusals()
        assert line["action"] == "run:replay"

    def test_stranger_proceeds_in_warn_mode_with_audit(self, client, isolated, as_principal):
        seed("r21", state="completed")
        as_principal(terminal(STRANGER))
        assert client.post("/workflows/runs/r21/steps/s1:replay").status_code == 200
        assert self.replayed == [("r21", "s1")]
        (line,) = _refusals()
        assert line["enforced"] is False

    @pytest.mark.parametrize("who", [OWNER, CREATOR, GRANDPARENT])
    def test_owner_and_ancestors_replay(self, client, isolated, as_principal, enforce, who):
        seed("r22", state="completed")
        as_principal(terminal(who))
        assert client.post("/workflows/runs/r22/steps/s1:replay").status_code == 200

    def test_operator_replays(self, client, isolated, as_principal, enforce):
        seed("r23", state="completed")
        as_principal(OPERATOR)
        assert client.post("/workflows/runs/r23/steps/s1:replay").status_code == 200

    def test_run_principal_replays_its_own_run(self, client, isolated, as_principal, enforce):
        seed("r24", state="completed")
        as_principal(run_principal("r24"))
        assert client.post("/workflows/runs/r24/steps/s1:replay").status_code == 200

    def test_unknown_run_is_left_to_the_service_404(
        self, client, isolated, as_principal, enforce, monkeypatch
    ):
        async def _raise(run_id, step_id, prompt_override=None):
            raise KeyError(f"unknown run '{run_id}'")

        monkeypatch.setattr(workflow_service, "replay_single_step", _raise)
        as_principal(terminal(STRANGER))
        resp = client.post("/workflows/runs/ghost/steps/s1:replay")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "unknown run 'ghost'"


# ---------------------------------------------------------------------------
# the stamp: run start
# ---------------------------------------------------------------------------
_GOOD_SPEC = """\
name: {name}
description: a workflow
mode: sequential
steps:
  - id: only-step
    provider: claude_code
    agent: developer
    prompt: do it
"""


@pytest.fixture
def spec_dir(monkeypatch: pytest.MonkeyPatch):
    import shutil
    import uuid

    from cli_agent_orchestrator.clients.tmux import tmux_client

    base = Path.home() / ".cao-test-wf-api" / uuid.uuid4().hex
    base.mkdir(parents=True, exist_ok=True)
    tmux_client._resolve_and_validate_working_directory(str(base))
    monkeypatch.setattr(
        "cli_agent_orchestrator.services.workflow_spec_service.WORKFLOW_SPEC_DIR",
        base,
        raising=True,
    )
    try:
        yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


class TestRunStartStampsOwnership:
    def test_async_submit_stamps_the_principal_on_the_journal_row(
        self, client, isolated, as_principal, spec_dir, monkeypatch
    ):
        (spec_dir / "own.yaml").write_text(_GOOD_SPEC.format(name="own"))
        monkeypatch.setattr(api_main, "_schedule_background_drive", lambda *a, **k: None)
        as_principal(terminal(OWNER, ancestors=(CREATOR, GRANDPARENT)))

        resp = client.post("/workflows/runs:submit", json={"name_or_path": "own"})
        assert resp.status_code == 202, resp.text
        run_id = resp.json()["run_id"]

        row = workflow_journal.get_run(run_id)
        assert row.owner_terminal_id == OWNER
        assert row.ancestor_terminal_ids == (CREATOR, GRANDPARENT)
        record = workflow_service.run_registry[run_id]
        assert record.owner_terminal_id == OWNER
        assert record.ancestor_terminal_ids == (CREATOR, GRANDPARENT)

    def test_async_submit_by_an_operator_stamps_nothing(
        self, client, isolated, as_principal, spec_dir, monkeypatch
    ):
        (spec_dir / "op.yaml").write_text(_GOOD_SPEC.format(name="op"))
        monkeypatch.setattr(api_main, "_schedule_background_drive", lambda *a, **k: None)
        as_principal(OPERATOR)
        resp = client.post("/workflows/runs:submit", json={"name_or_path": "op"})
        assert resp.status_code == 202, resp.text
        row = workflow_journal.get_run(resp.json()["run_id"])
        assert row.owner_terminal_id is None
        assert row.ancestor_terminal_ids == ()

    def test_blocking_yaml_start_forwards_the_stamp_to_the_engine(
        self, client, isolated, as_principal, spec_dir, monkeypatch
    ):
        (spec_dir / "blk.yaml").write_text(_GOOD_SPEC.format(name="blk"))
        seen = {}

        async def _start(spec, inputs, run_id, **kw):
            seen.update(kw)
            return _ok_result(run_id)

        monkeypatch.setattr(workflow_service, "start_run", _start)
        as_principal(terminal(OWNER, ancestors=(CREATOR,)))
        resp = client.post("/workflows/runs", json={"name_or_path": "blk"})
        assert resp.status_code == 200, resp.text
        assert seen == {"owner_terminal_id": OWNER, "ancestor_terminal_ids": (CREATOR,)}

    @pytest.mark.asyncio
    async def test_start_run_stamps_the_journal_row(self, isolated, monkeypatch):
        """The YAML engine entry, with the drive stubbed: the row the gate later reads carries
        the stamp the route handed in."""
        from cli_agent_orchestrator.models.workflow import WorkflowSpec, WorkflowStep

        spec = WorkflowSpec(
            name="wf",
            steps=[WorkflowStep(id="s1", provider="claude_code", agent="dev", prompt="go")],
        )

        async def _drive(record, order):
            return _ok_result(record.run_id)

        monkeypatch.setattr(workflow_service, "_drive", _drive)
        await workflow_service.start_run(
            spec,
            {},
            "eng-1",
            owner_terminal_id=OWNER,
            ancestor_terminal_ids=(CREATOR,),
        )
        row = workflow_journal.get_run("eng-1")
        assert row.owner_terminal_id == OWNER
        assert row.ancestor_terminal_ids == (CREATOR,)

    @pytest.mark.asyncio
    async def test_start_run_default_is_unowned(self, isolated, monkeypatch):
        from cli_agent_orchestrator.models.workflow import WorkflowSpec, WorkflowStep

        spec = WorkflowSpec(
            name="wf",
            steps=[WorkflowStep(id="s1", provider="claude_code", agent="dev", prompt="go")],
        )

        async def _drive(record, order):
            return _ok_result(record.run_id)

        monkeypatch.setattr(workflow_service, "_drive", _drive)
        await workflow_service.start_run(spec, {}, "eng-2")
        row = workflow_journal.get_run("eng-2")
        assert row.owner_terminal_id is None
        assert row.ancestor_terminal_ids == ()

    @pytest.mark.asyncio
    async def test_script_run_stamps_the_journal_row(self, isolated, monkeypatch, tmp_path):
        """The script engine entry, with lint/approval/freeze/drive stubbed."""

        class _Spec:
            source = "print('hi')"
            path = "/tmp/wf.py"
            name = "wf"
            content_hash = "deadbeef"

        monkeypatch.setattr(
            script_runner,
            "lint_script",
            lambda source, path: type("L", (), {"status": "pass", "findings": []})(),
        )
        monkeypatch.setattr(
            script_runner.manifest_freeze,
            "freeze_manifest",
            lambda **kw: script_runner.manifest_freeze.FrozenManifest(None),
        )
        monkeypatch.setattr(script_runner.approval_gate, "ensure_plan_approved", lambda **kw: None)
        monkeypatch.setattr(script_runner.launch_guard, "capture", lambda: None)

        async def _drive_frozen(record, source, env, *, working_directory):
            return _ok_result(record.run_id)

        monkeypatch.setattr(script_runner, "_drive_frozen", _drive_frozen)

        await script_runner.run_script_workflow(
            _Spec(),
            {},
            "scr-1",
            working_directory=str(tmp_path),
            owner_terminal_id=OWNER,
            ancestor_terminal_ids=(CREATOR,),
        )
        row = workflow_journal.get_run("scr-1")
        assert row.tier == "script"
        assert row.owner_terminal_id == OWNER
        assert row.ancestor_terminal_ids == (CREATOR,)
        # script_runner binds the registry by name at import, so the record lands there.
        record = script_runner.run_registry["scr-1"]
        assert record.owner_terminal_id == OWNER
        assert record.ancestor_terminal_ids == (CREATOR,)

    def test_rebuilt_record_carries_the_stamp(self, isolated):
        """A registry miss rebuilds the record from the journal; ownership must survive it."""
        seed("rb-1", state="failed")
        record = workflow_service._rebuild_record_from_journal("rb-1")
        assert record is not None
        assert record.owner_terminal_id == OWNER
        assert record.ancestor_terminal_ids == (CREATOR, GRANDPARENT)
