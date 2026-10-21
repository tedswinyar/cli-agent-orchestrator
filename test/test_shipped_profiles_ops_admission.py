"""No shipped profile pairs ``cao-ops-mcp-server`` with a restricted allowlist (WS5 of #965).

Structural guard over every bundled profile in ``agent_store/`` and every
frontmattered example under ``examples/``: none may name the control-plane MCP
server (by key or by launching command) without the explicit ``@cao-ops-mcp-server``
grant. A new profile is guarded automatically by being enumerated, not listed.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Iterator, Tuple

import frontmatter
import pytest

from cli_agent_orchestrator.services.profile_validator import (
    check_ops_admission,
    entry_launches_ops_server,
    ops_admission_message,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPO_ROOT / "examples"


def _shipped_profiles() -> Iterator[Tuple[str, dict]]:
    store = resources.files("cli_agent_orchestrator.agent_store")
    for item in sorted(store.iterdir(), key=lambda i: i.name):
        if item.name.endswith(".md"):
            yield f"agent_store/{item.name}", frontmatter.loads(item.read_text()).metadata
    for path in sorted(EXAMPLES_DIR.rglob("*.md")):
        if path.name == "README.md":
            continue
        post = frontmatter.load(path)
        if post.metadata:
            yield f"examples/{path.relative_to(EXAMPLES_DIR)}", post.metadata


_PROFILES = list(_shipped_profiles())


def test_enumeration_found_both_stores() -> None:
    assert any(p.startswith("agent_store/") for p, _ in _PROFILES)
    assert any(p.startswith("examples/") for p, _ in _PROFILES)


@pytest.mark.parametrize("rel_path,meta", _PROFILES, ids=[p for p, _ in _PROFILES])
def test_shipped_profile_does_not_pair_ops_server_with_restricted_allowlist(
    rel_path: str, meta: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cli_agent_orchestrator.services import settings_service

    # Shipped profiles must pass on a machine with no custom roles.
    monkeypatch.setattr(settings_service, "_load", lambda: {})
    admission = check_ops_admission(
        meta.get("mcpServers"), meta.get("allowedTools"), meta.get("role")
    )
    assert (
        not admission.violates
    ), f"{rel_path}: {ops_admission_message(meta.get('name'), admission)}"


def test_detector_catches_the_operator_plugins_real_declaration() -> None:
    """Evidence the command-form detection matches the one shipped shape that hides the name."""
    declared = json.loads((REPO_ROOT / "agent-plugin" / "cao" / "mcp.json").read_text())[
        "mcpServers"
    ]
    assert (
        "cao-ops-mcp-server" not in declared
    ), "plugin renamed its key to the full name; update this test"
    assert any(entry_launches_ops_server(entry) for entry in declared.values())
