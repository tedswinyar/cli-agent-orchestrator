"""The ``examples/aws`` profiles that configure ``cao-mcp-server`` also grant it (#671).

At the explicit-``allowedTools`` level the list you write is the list you get:
a profile that declares a server in ``mcpServers`` and also sets
``allowedTools`` has to name ``@<server>`` for it to be granted
(docs/tool-restrictions.md, "How Overrides Work"). Under the host-layer gate
that is no longer only a launch-time policy: a bound terminal whose allowlist
omits ``@cao-mcp-server`` is refused every tool on the server except the ruled
callbacks. The seven cloud-ops examples paired ``[execute_bash, fs_read]`` with
a ``cao-mcp-server`` block; this test keeps them (and any example added later)
working under default deny.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

import frontmatter
import pytest

from cli_agent_orchestrator.security.authz import CAO_MCP_SERVER, tool_covered

EXAMPLES_AWS = Path(__file__).resolve().parents[1] / "examples" / "aws"

#: A representative tool outside the always-allowed set; granting the server
#: grants it, granting nothing does not.
PROBE_TOOL = "assign"


def _profiles() -> List[Tuple[Path, dict]]:
    found = []
    for path in sorted(EXAMPLES_AWS.glob("*/*.md")):
        meta = frontmatter.loads(path.read_text(encoding="utf-8")).metadata
        if "name" in meta:
            found.append((path, meta))
    return found


def _pairs_restricted_allowlist_with_cao_server(meta: dict) -> bool:
    servers = meta.get("mcpServers") or {}
    return CAO_MCP_SERVER in servers and isinstance(meta.get("allowedTools"), list)


PAIRED = [(p, m) for p, m in _profiles() if _pairs_restricted_allowlist_with_cao_server(m)]


def test_the_seven_paired_profiles_are_the_ones_the_ruling_named() -> None:
    names = sorted(p.parent.name for p, _ in PAIRED)
    assert names == [
        "cloudwatch-logs",
        "dynamodb-delete",
        "dynamodb-query",
        "sqs-dlq-check",
        "sqs-monitor",
        "sqs-send",
        "stepfunction",
    ]


@pytest.mark.parametrize("path, meta", PAIRED, ids=[p.parent.name for p, _ in PAIRED])
def test_paired_profile_grants_the_server_it_configures(path: Path, meta: dict) -> None:
    allowed = meta["allowedTools"]
    assert tool_covered(allowed, PROBE_TOOL, CAO_MCP_SERVER), (
        f"{path.relative_to(EXAMPLES_AWS.parent.parent)} declares mcpServers.{CAO_MCP_SERVER} "
        f"but its allowedTools {allowed} does not grant it; add '@{CAO_MCP_SERVER}' "
        "(or the specific '@cao-mcp-server/<tool>' entries)"
    )
