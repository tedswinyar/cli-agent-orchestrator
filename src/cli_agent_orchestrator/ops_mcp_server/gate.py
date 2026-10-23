"""Host-layer gate for every ``cao-ops-mcp-server`` tool (#671, fleet tools are operator-only).

``cao-ops-mcp-server`` is the fleet control plane: it installs profiles,
launches and shuts down sessions, and reads any terminal's output. It is meant
to be driven by an operator from outside a CAO session. An agent terminal that
finds the ops server in its ``mcpServers`` block must not be able to use it,
whatever its allowlist says: :func:`security.authz.authorize` refuses every
``tool:call`` on this server for ``terminal`` and ``run`` principals with rule
``fleet:operator-only`` and allows operator and anonymous principals.

Identity comes from the BEARER, the same way as on ``cao-mcp-server``: an unset
``CAO_TERMINAL_ID`` is the operator context and is never looked up, so the
default-off posture (no credential at all) is byte-identical on the wire. A
bound caller asks ``GET /me/principal`` with its claimed ``CAO_TERMINAL_ID``,
the API refuses or audits a claim the bearer does not prove, and the decision
is :func:`check` on the principal the API serialized. Fetching the row the
claimed id names would authorize whoever that row belongs to, which is the
substitution #965 exists to close -- and this module reached it through exactly
the same ``GET /terminals/{id}`` hop that made it possible on the CAO server.

Every ``@mcp.tool`` registration on this server (``server.py`` and
``decision_tools.py``) stacks ``@gated`` directly under it; the AST census in
``test/security/test_tool_gate_census.py`` fails for any that does not.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from cli_agent_orchestrator.security import tool_gate
from cli_agent_orchestrator.security.authz import CAO_OPS_MCP_SERVER

logger = logging.getLogger(__name__)


def _fetch_caller_principal(claimed: str) -> Dict[str, Any]:
    """``GET /me/principal?claimed_terminal_id=<claimed>`` via the server's helper.

    Imported lazily: ``server.py`` imports this module, so a top-level import
    here would be circular. ``_request_json`` returns errors rather than
    raising, so any error becomes a ``RuntimeError`` the caller turns into a
    fail-closed ``tool_gate.unresolved``.
    """

    from cli_agent_orchestrator.ops_mcp_server.server import _request_json

    data, error = _request_json(
        "get",
        "/me/principal",
        params={"claimed_terminal_id": claimed},
        operation="Resolve calling principal",
    )
    if error or not isinstance(data, dict):
        raise RuntimeError(error or "invalid principal payload")
    return data


def _tool_denied_reason(tool_name: str) -> Optional[str]:
    """Reason the caller may not use ops tool ``tool_name``, or None to proceed.

    Hard refusal only under ``CAO_PRINCIPAL_ENFORCE`` (these tools were not
    gated on main, so warn mode must leave them exactly as they are); in warn
    mode the would-be refusal is audited by ``check`` and the call proceeds.
    """

    terminal_id = tool_gate.bound_terminal_id()
    if not terminal_id:
        return None

    try:
        principal = tool_gate.principal_for(_fetch_caller_principal(terminal_id))
    except Exception as e:  # noqa: BLE001  (an unknown result must not dispatch)
        logger.warning("authorization lookup failed for ops tool '%s': %s", tool_name, e)
        return tool_gate.unresolved(
            tool_name,
            f"cannot authorize '{tool_name}': the calling terminal could not be resolved ({e})",
            server=CAO_OPS_MCP_SERVER,
        )

    return tool_gate.denial_for(principal, tool_name, server=CAO_OPS_MCP_SERVER)


# Resolves ``_tool_denied_reason`` by name at call time so a test that
# monkeypatches ``gate._tool_denied_reason`` is honoured.
gated = tool_gate.gated(lambda name: _tool_denied_reason(name), server=CAO_OPS_MCP_SERVER)

__all__ = ["gated", "_tool_denied_reason"]
