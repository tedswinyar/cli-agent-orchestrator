"""``credential_digest`` storage and lookup on the terminals table (#965)."""

import sqlite3

from cli_agent_orchestrator.security.principal import mint_terminal_credential


def test_set_and_get_by_digest(fresh_db):
    fresh_db.create_terminal("t1", "s", "w", "claude_code")
    token, digest = mint_terminal_credential()
    assert fresh_db.get_terminal_by_credential_digest(digest) is None
    assert fresh_db.set_terminal_credential_digest("t1", digest) is True
    row = fresh_db.get_terminal_by_credential_digest(digest)
    assert row is not None and row.id == "t1" and row.credential_digest == digest
    assert row.tmux_session == "s"  # columns readable after the session closed


def test_unknown_or_empty_digest(fresh_db):
    assert fresh_db.get_terminal_by_credential_digest("deadbeef") is None
    assert fresh_db.get_terminal_by_credential_digest("") is None


def test_set_on_missing_terminal_false(fresh_db):
    assert fresh_db.set_terminal_credential_digest("ghost", "abc") is False


def test_clear_digest(fresh_db):
    fresh_db.create_terminal("t1", "s", "w", "claude_code")
    fresh_db.set_terminal_credential_digest("t1", "abc")
    assert fresh_db.set_terminal_credential_digest("t1", None) is True
    assert fresh_db.get_terminal_by_credential_digest("abc") is None


def test_deleted_terminal_not_found(fresh_db):
    fresh_db.create_terminal("t1", "s", "w", "claude_code")
    fresh_db.set_terminal_credential_digest("t1", "abc")
    fresh_db.delete_terminal("t1")
    assert fresh_db.get_terminal_by_credential_digest("abc") is None


def test_migration_adds_column(tmp_path, monkeypatch):
    from cli_agent_orchestrator import constants
    from cli_agent_orchestrator.clients import database

    db_file = tmp_path / "old.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute(
        "CREATE TABLE terminals (id TEXT PRIMARY KEY, tmux_session TEXT NOT NULL, "
        "tmux_window TEXT NOT NULL, provider TEXT NOT NULL)"
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(constants, "DATABASE_FILE", db_file)
    database._migrate_terminals_schema()
    conn = sqlite3.connect(str(db_file))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(terminals)")}
    conn.close()
    assert "credential_digest" in cols
    database._migrate_terminals_schema()  # idempotent
