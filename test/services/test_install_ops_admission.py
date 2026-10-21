"""``install_agent`` refuses (or warns about) a profile that pairs ``cao-ops-mcp-server``
with a restricted allowlist and no explicit operator grant (WS5 of #965).

The ops server is CAO's control plane. Before this rule a profile that merely listed
it under ``mcpServers`` got fleet-wide session control whatever its ``allowedTools``
said, because the allowlist was only ever enforced inside ``cao-mcp-server``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cli_agent_orchestrator.security import audit
from cli_agent_orchestrator.services.install_service import install_agent
from cli_agent_orchestrator.services.profile_validator import (
    OPS_GRANT,
    PROFILE_INSTALL_ACTION,
    OpsAdmission,
    ops_admission_message,
)

OPS_ENTRY = "  cao-ops-mcp-server:\n    command: cao-ops-mcp-server\n"
PLUGIN_SHAPED_ENTRY = (
    "  cao-ops:\n"
    "    type: stdio\n"
    "    command: uvx\n"
    "    args: ['--from', 'cli-agent-orchestrator==2.5.3', 'cao-ops-mcp-server']\n"
)
EXPECTED_REFUSAL = (
    "Profile 'ops-worker' pairs the control-plane MCP server 'cao-ops-mcp-server' "
    "(mcpServers entry 'cao-ops-mcp-server') with a restricted allowlist and no operator "
    "grant. Add '@cao-ops-mcp-server' to allowedTools to grant fleet-wide session "
    "control explicitly, or remove the server from mcpServers."
)


def _profile(
    *,
    name: str = "ops-worker",
    role: str | None = "developer",
    allowed: list[str] | None = None,
    servers: str = OPS_ENTRY,
) -> str:
    role_line = f"role: {role}\n" if role else ""
    allowed_line = f"allowedTools: {allowed!r}\n" if allowed is not None else ""
    servers_block = f"mcpServers:\n{servers}" if servers else ""
    return (
        "---\n"
        f"name: {name}\n"
        "description: Test agent\n"
        f"{role_line}{allowed_line}{servers_block}"
        "---\n"
        "Do the task.\n"
    )


@pytest.fixture
def stores(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Path]:
    """Isolated store, context dir, settings and audit home for one install."""
    from cli_agent_orchestrator.services import settings_service

    local_store = tmp_path / "agent-store"
    context_dir = tmp_path / "agent-context"
    provider_dir = tmp_path / "provider"
    for path in (local_store, context_dir, provider_dir):
        path.mkdir(parents=True)

    monkeypatch.setattr(
        "cli_agent_orchestrator.services.profile_store.LOCAL_AGENT_STORE_DIR", local_store
    )
    monkeypatch.setattr(
        "cli_agent_orchestrator.utils.agent_profiles.LOCAL_AGENT_STORE_DIR", local_store
    )
    monkeypatch.setattr(
        "cli_agent_orchestrator.services.install_service.AGENT_CONTEXT_DIR", context_dir
    )
    monkeypatch.setattr("cli_agent_orchestrator.utils.env.CAO_ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(settings_service, "get_agent_dirs", lambda: {"kiro_cli": str(provider_dir)})
    monkeypatch.setattr(settings_service, "get_extra_agent_dirs", lambda: [])
    monkeypatch.setattr(settings_service, "get_disabled_agent_dirs", lambda: [])
    monkeypatch.setattr(settings_service, "_load", lambda: {})
    monkeypatch.setenv("CAO_HOME_DIR", str(tmp_path / "cao-home"))
    monkeypatch.delenv("CAO_PRINCIPAL_ENFORCE", raising=False)
    monkeypatch.delenv("CAO_AUTHZ_AUDIT_ALLOWS", raising=False)
    return {"local_store": local_store, "context_dir": context_dir}


def _put(stores: dict[str, Path], text: str, name: str = "ops-worker") -> Path:
    path = stores["local_store"] / f"{name}.md"
    path.write_text(text, encoding="utf-8")
    return path


def _refusals() -> list[dict]:
    return [line for line in audit.read_recent() if line["allowed"] is False]


class TestEnforceMode:
    def test_refuses_with_the_exact_message_and_writes_nothing(
        self, stores: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
        source = _put(stores, _profile())
        before = source.read_bytes()

        result = install_agent("ops-worker", "claude_code")

        assert result.success is False
        assert result.message == EXPECTED_REFUSAL
        assert result.message == ops_admission_message(
            "ops-worker", OpsAdmission(("cao-ops-mcp-server",), False)
        )
        assert result.agent_name == "ops-worker"
        assert result.context_file is None
        assert not (stores["context_dir"] / "ops-worker.md").exists()
        assert (
            source.read_bytes() == before
        ), "a refused install must leave the store byte-identical"

    def test_refusal_is_audited_as_enforced(
        self, stores: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "true")
        _put(stores, _profile())

        install_agent("ops-worker", "claude_code")

        [line] = _refusals()
        assert line["kind"] == "operator"
        assert line["action"] == PROFILE_INSTALL_ACTION
        assert line["resource"] == "cao-ops-mcp-server/ops-worker"
        assert line["enforced"] is True
        assert line["rule"] == "profile:ops-admission"
        assert line["reason"] == EXPECTED_REFUSAL

    def test_command_form_under_another_key_is_caught(
        self, stores: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ``cao`` operator plugin's exact shape: key ``cao-ops``, uvx launches the server."""
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
        _put(stores, _profile(servers=PLUGIN_SHAPED_ENTRY))

        result = install_agent("ops-worker", "claude_code")

        assert result.success is False
        assert "(mcpServers entry 'cao-ops')" in result.message
        assert "'cao-ops-mcp-server'" in result.message

    def test_role_only_profile_is_refused(
        self, stores: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A built-in role never carries the grant; ``supervisor`` is as restricted as any."""
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
        _put(stores, _profile(role="supervisor"))

        assert install_agent("ops-worker", "claude_code").success is False

    def test_glob_selector_is_not_a_grant(
        self, stores: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
        _put(stores, _profile(role=None, allowed=["fs_read", "@cao-*"]))

        result = install_agent("ops-worker", "claude_code")

        assert result.success is False
        assert result.message == EXPECTED_REFUSAL

    def test_import_by_content_is_refused_before_the_store_write(
        self, stores: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")

        result = install_agent("ops-worker", "claude_code", profile_content=_profile())

        assert result.success is False
        assert not (stores["local_store"] / "ops-worker.md").exists()


class TestWarnMode:
    def test_installs_with_a_visible_warning_and_an_audit_line(
        self, stores: dict[str, Path]
    ) -> None:
        _put(stores, _profile())

        result = install_agent("ops-worker", "claude_code")

        assert result.success is True
        assert result.warnings == [EXPECTED_REFUSAL]
        assert result.message.startswith("Agent 'ops-worker' installed successfully. WARNING: ")
        assert EXPECTED_REFUSAL in result.message
        assert (stores["context_dir"] / "ops-worker.md").exists()
        [line] = _refusals()
        assert line["action"] == PROFILE_INSTALL_ACTION
        assert line["enforced"] is False
        assert line["allowed"] is False
        assert line["reason"] == EXPECTED_REFUSAL

    def test_warning_is_logged(
        self, stores: dict[str, Path], caplog: pytest.LogCaptureFixture
    ) -> None:
        _put(stores, _profile())
        with caplog.at_level("WARNING", logger="cli_agent_orchestrator.services.profile_validator"):
            install_agent("ops-worker", "claude_code")
        assert any(EXPECTED_REFUSAL in rec.getMessage() for rec in caplog.records)


@pytest.mark.parametrize("enforce", ["", "1"], ids=["warn", "enforce"])
class TestCleanProfiles:
    def test_granted_profile_installs_cleanly(
        self, stores: dict[str, Path], monkeypatch: pytest.MonkeyPatch, enforce: str
    ) -> None:
        if enforce:
            monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", enforce)
        _put(stores, _profile(role=None, allowed=["fs_read", OPS_GRANT]))

        result = install_agent("ops-worker", "claude_code")

        assert result.success is True
        assert result.warnings is None
        assert result.message == "Agent 'ops-worker' installed successfully"
        assert _refusals() == []

    def test_per_tool_grant_installs_cleanly(
        self, stores: dict[str, Path], monkeypatch: pytest.MonkeyPatch, enforce: str
    ) -> None:
        if enforce:
            monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", enforce)
        _put(stores, _profile(role=None, allowed=[f"{OPS_GRANT}/list_sessions"]))

        result = install_agent("ops-worker", "claude_code")

        assert result.success is True
        assert result.warnings is None

    def test_unrestricted_allowlist_installs_cleanly(
        self, stores: dict[str, Path], monkeypatch: pytest.MonkeyPatch, enforce: str
    ) -> None:
        if enforce:
            monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", enforce)
        _put(stores, _profile(role=None, allowed=["*"]))

        assert install_agent("ops-worker", "claude_code").success is True

    def test_profile_without_the_ops_server_is_untouched(
        self, stores: dict[str, Path], monkeypatch: pytest.MonkeyPatch, enforce: str
    ) -> None:
        if enforce:
            monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", enforce)
        _put(
            stores,
            _profile(servers="  cao-mcp-server:\n    command: cao-mcp-server\n    args: []\n"),
        )

        result = install_agent("ops-worker", "claude_code")

        assert result.success is True
        assert result.warnings is None
        assert result.message == "Agent 'ops-worker' installed successfully"
        assert not audit.audit_path().exists(), "a clean profile must not produce audit lines"
