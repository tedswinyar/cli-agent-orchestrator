"""Run ownership columns on ``workflow_run`` (#965 WS4).

``owner_terminal_id`` and ``ancestor_terminal_ids`` are stamped by the two INSERT
helpers and read back by ``get_run``. These tests pin the round trip, the defaults
every pre-WS4 caller relies on, the additive migration of a legacy database, and
the total decoder (a corrupt cell reads as "no ancestors", never as a 500).
"""

import json
import sqlite3
from pathlib import Path

import pytest

from cli_agent_orchestrator.clients.database import (
    _migrate_workflow_run,
    _migrate_workflow_run_step,
)
from cli_agent_orchestrator.services import workflow_journal


@pytest.fixture
def db_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "wf.db"
    monkeypatch.setattr("cli_agent_orchestrator.constants.DATABASE_FILE", path, raising=True)
    _migrate_workflow_run()
    _migrate_workflow_run_step()
    return path


def _insert(run_id: str, **kw) -> None:
    workflow_journal.insert_run(
        run_id,
        "wf",
        "{}",
        "{}",
        "running",
        "2026-01-01T00:00:00Z",
        **kw,
    )


class TestInsertRunStampsOwnership:
    def test_owner_and_ancestors_round_trip(self, db_path):
        _insert("r1", owner_terminal_id="term-A", ancestor_terminal_ids=("term-P", "term-G"))
        row = workflow_journal.get_run("r1")
        assert row is not None
        assert row.owner_terminal_id == "term-A"
        assert row.ancestor_terminal_ids == ("term-P", "term-G")

    def test_defaults_record_an_operator_owned_run(self, db_path):
        """Every pre-WS4 caller passes neither kwarg and must read back as unowned."""
        _insert("r2")
        row = workflow_journal.get_run("r2")
        assert row.owner_terminal_id is None
        assert row.ancestor_terminal_ids == ()

    def test_empty_ancestry_is_stored_as_null_not_empty_list(self, db_path):
        _insert("r3", owner_terminal_id="term-A", ancestor_terminal_ids=())
        with sqlite3.connect(str(db_path)) as conn:
            cell = conn.execute(
                "SELECT ancestor_terminal_ids FROM workflow_run WHERE run_id = 'r3'"
            ).fetchone()[0]
        assert cell is None

    def test_ancestors_are_stored_as_a_json_array(self, db_path):
        _insert("r4", owner_terminal_id="term-A", ancestor_terminal_ids=["term-P"])
        with sqlite3.connect(str(db_path)) as conn:
            cell = conn.execute(
                "SELECT ancestor_terminal_ids FROM workflow_run WHERE run_id = 'r4'"
            ).fetchone()[0]
        assert json.loads(cell) == ["term-P"]


class TestInsertRunWithStepsStampsOwnership:
    def test_atomic_insert_carries_ownership(self, db_path):
        workflow_journal.insert_run_with_steps(
            "r5",
            "wf",
            "{}",
            "{}",
            "running",
            "2026-01-01T00:00:00Z",
            [("s1", "pending")],
            "2026-01-01T00:00:00Z",
            owner_terminal_id="term-A",
            ancestor_terminal_ids=("term-P",),
        )
        row = workflow_journal.get_run("r5")
        assert row.owner_terminal_id == "term-A"
        assert row.ancestor_terminal_ids == ("term-P",)
        assert [s.step_id for s in workflow_journal.get_steps("r5")] == ["s1"]

    def test_atomic_insert_defaults_are_unowned(self, db_path):
        workflow_journal.insert_run_with_steps(
            "r6", "wf", "{}", "{}", "running", "t", [("s1", "pending")], "t"
        )
        row = workflow_journal.get_run("r6")
        assert row.owner_terminal_id is None
        assert row.ancestor_terminal_ids == ()


class TestLegacyDatabaseMigration:
    def test_pre_ws4_table_gains_both_columns_and_old_rows_read_unowned(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A database created before WS4 has neither column; the additive migrator adds them
        and a row written before the migration reads back as operator-owned."""
        path = tmp_path / "legacy.db"
        with sqlite3.connect(str(path)) as conn:
            conn.execute(
                "CREATE TABLE workflow_run ("
                "run_id TEXT PRIMARY KEY, workflow_name TEXT NOT NULL, "
                "spec_snapshot TEXT NOT NULL, inputs_json TEXT NOT NULL, state TEXT NOT NULL, "
                "current_step_id TEXT, started_at TEXT NOT NULL, finished_at TEXT, "
                "tier TEXT NOT NULL DEFAULT 'yaml', generation TEXT NOT NULL DEFAULT '1', "
                "manifest_json TEXT DEFAULT NULL, error TEXT DEFAULT NULL, kind TEXT DEFAULT NULL)"
            )
            conn.execute(
                "INSERT INTO workflow_run (run_id, workflow_name, spec_snapshot, inputs_json, "
                "state, started_at) VALUES ('old', 'wf', '{}', '{}', 'completed', 't')"
            )
        monkeypatch.setattr("cli_agent_orchestrator.constants.DATABASE_FILE", path, raising=True)
        _migrate_workflow_run()
        with sqlite3.connect(str(path)) as conn:
            cols = {r[1]: r for r in conn.execute("PRAGMA table_info(workflow_run)")}
        assert cols["owner_terminal_id"][2] == "TEXT"
        assert cols["owner_terminal_id"][3] == 0  # nullable
        assert cols["ancestor_terminal_ids"][2] == "TEXT"
        assert cols["ancestor_terminal_ids"][3] == 0
        row = workflow_journal.get_run("old")
        assert row is not None
        assert row.owner_terminal_id is None
        assert row.ancestor_terminal_ids == ()

    def test_migrator_is_idempotent(self, db_path):
        _migrate_workflow_run()
        _migrate_workflow_run()
        with sqlite3.connect(str(db_path)) as conn:
            names = [r[1] for r in conn.execute("PRAGMA table_info(workflow_run)")]
        assert names.count("owner_terminal_id") == 1
        assert names.count("ancestor_terminal_ids") == 1


class TestAncestorDecoderIsTotal:
    @pytest.mark.parametrize(
        "cell",
        [None, "", "not json", "{}", '{"a": 1}', "42", '["ok", 7, null, ""]'],
    )
    def test_corrupt_or_foreign_cells_read_as_no_ancestors(self, db_path, cell):
        _insert("r7", owner_terminal_id="term-A")
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "UPDATE workflow_run SET ancestor_terminal_ids = ? WHERE run_id = 'r7'", (cell,)
            )
        row = workflow_journal.get_run("r7")
        expected = ("ok",) if cell == '["ok", 7, null, ""]' else ()
        assert row.ancestor_terminal_ids == expected

    def test_decoder_unit(self):
        assert workflow_journal._decode_ancestors(None) == ()
        assert workflow_journal._decode_ancestors('["a","b"]') == ("a", "b")
        assert workflow_journal._decode_ancestors("[1, 2]") == ()
        assert workflow_journal._encode_ancestors(()) is None
        assert workflow_journal._encode_ancestors(("a", "", "b")) == '["a","b"]'


class TestNothingUpdatesOwnership:
    def test_update_run_state_leaves_ownership_untouched(self, db_path):
        """Resume and settle go through UPDATEs; none of them may touch the stamp."""
        _insert("r8", owner_terminal_id="term-A", ancestor_terminal_ids=("term-P",))
        workflow_journal.update_run_state("r8", "failed", "2026-01-01T00:01:00Z")
        workflow_journal.update_run_state("r8", "running", None)
        row = workflow_journal.get_run("r8")
        assert row.state == "running"
        assert row.owner_terminal_id == "term-A"
        assert row.ancestor_terminal_ids == ("term-P",)
