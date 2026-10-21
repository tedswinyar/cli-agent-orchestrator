"""The launch loader re-checks the ``cao-ops-mcp-server`` admission rule (WS5 of #965).

Install-time refusal alone is bypassable: a hand-edited store file or a profile
installed before the rule existed never passed through ``install_agent``. Every
launch resolves its profile through ``load_launch_profile``, so the same question
is asked there of what is on disk now. The read-only loader is left alone so an
operator can still inspect the profile they have to fix.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cli_agent_orchestrator.security import audit
from cli_agent_orchestrator.services.profile_validator import (
    PROFILE_LOAD_ACTION,
    OpsAdmissionRefused,
)
from cli_agent_orchestrator.utils import agent_profiles as profiles

VIOLATING = (
    "---\n"
    "name: hand-edited\n"
    "description: d\n"
    "role: developer\n"
    "mcpServers:\n"
    "  ops:\n"
    "    command: uvx\n"
    "    args: ['--from', 'cli-agent-orchestrator', 'cao-ops-mcp-server']\n"
    "---\n"
    "Body.\n"
)
GRANTED = VIOLATING.replace(
    "role: developer\n", "allowedTools: ['fs_read', '@cao-ops-mcp-server']\n"
)
CLEAN = (
    "---\nname: hand-edited\ndescription: d\nrole: developer\n"
    "mcpServers:\n  cao-mcp-server:\n    command: cao-mcp-server\n---\nBody.\n"
)


@pytest.fixture
def stores(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from cli_agent_orchestrator.services import settings_service

    local = tmp_path / "installed"
    local.mkdir()
    monkeypatch.setattr(profiles, "LOCAL_AGENT_STORE_DIR", local)
    monkeypatch.setattr(profiles, "resolve_env_vars", lambda content: content)
    monkeypatch.setattr(settings_service, "get_agent_dirs", lambda: {})
    monkeypatch.setattr(settings_service, "get_extra_agent_dirs", lambda: [])
    monkeypatch.setattr(settings_service, "get_disabled_agent_dirs", lambda: [])
    monkeypatch.setattr(settings_service, "_load", lambda: {})
    monkeypatch.setenv("CAO_HOME_DIR", str(tmp_path / "cao-home"))
    monkeypatch.delenv("CAO_PRINCIPAL_ENFORCE", raising=False)
    monkeypatch.delenv("CAO_AUTHZ_AUDIT_ALLOWS", raising=False)
    return local


def test_enforce_refuses_a_hand_edited_profile_at_launch(stores: Path, monkeypatch) -> None:
    monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
    (stores / "hand-edited.md").write_text(VIOLATING)

    with pytest.raises(OpsAdmissionRefused) as exc_info:
        profiles.load_launch_profile("hand-edited")

    message = str(exc_info.value)
    assert message.startswith("Profile 'hand-edited' pairs the control-plane MCP server")
    assert "(mcpServers entry 'ops')" in message
    assert "Add '@cao-ops-mcp-server' to allowedTools" in message
    assert isinstance(exc_info.value, ValueError)
    [line] = [l for l in audit.read_recent() if l["allowed"] is False]
    assert line["action"] == PROFILE_LOAD_ACTION
    assert line["enforced"] is True


def test_warn_mode_loads_and_audits(stores: Path) -> None:
    (stores / "hand-edited.md").write_text(VIOLATING)

    profile, source = profiles.load_launch_profile("hand-edited")

    assert profile.name == "hand-edited"
    assert source is profiles.ProfileSource.INSTALLED
    [line] = [l for l in audit.read_recent() if l["allowed"] is False]
    assert line["action"] == PROFILE_LOAD_ACTION
    assert line["enforced"] is False
    assert line["resource"] == "cao-ops-mcp-server/hand-edited"


@pytest.mark.parametrize("enforce", ["", "1"], ids=["warn", "enforce"])
def test_granted_profile_loads_cleanly(stores: Path, monkeypatch, enforce: str) -> None:
    if enforce:
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", enforce)
    (stores / "hand-edited.md").write_text(GRANTED)

    profile, _ = profiles.load_launch_profile("hand-edited")

    assert profile.allowedTools == ["fs_read", "@cao-ops-mcp-server"]
    assert [l for l in audit.read_recent() if l["allowed"] is False] == []


@pytest.mark.parametrize("enforce", ["", "1"], ids=["warn", "enforce"])
def test_profile_without_the_ops_server_is_untouched(
    stores: Path, monkeypatch, enforce: str
) -> None:
    if enforce:
        monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", enforce)
    (stores / "hand-edited.md").write_text(CLEAN)

    profile, _ = profiles.load_launch_profile("hand-edited")

    assert profile.name == "hand-edited"
    assert not audit.audit_path().exists()


def test_read_only_loader_still_serves_a_violating_profile(stores: Path, monkeypatch) -> None:
    """``cao profile show`` and the GET route must keep working so the operator can fix it."""
    monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
    (stores / "hand-edited.md").write_text(VIOLATING)

    profile = profiles.load_agent_profile("hand-edited")

    assert profile.mcpServers is not None and "ops" in profile.mcpServers
    assert not audit.audit_path().exists()


def test_resolve_provider_falls_back_instead_of_raising(stores: Path, monkeypatch) -> None:
    """Provider resolution precedes the launch; the launch is where the refusal lands."""
    monkeypatch.setenv("CAO_PRINCIPAL_ENFORCE", "1")
    (stores / "hand-edited.md").write_text(
        VIOLATING.replace("description: d\n", "description: d\nprovider: codex\n")
    )

    assert profiles.resolve_provider("hand-edited", "claude_code") == "claude_code"
