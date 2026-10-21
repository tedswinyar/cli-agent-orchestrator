"""Host-layer gate for every ``cao-ops-mcp-server`` tool (#671, fleet tools are operator-only).

``cao-ops-mcp-server`` is the fleet control plane: it installs profiles,
launches and shuts down sessions, and reads any terminal's output. It is meant
to be driven by an operator from outside a CAO session. An agent terminal that
finds the ops server in its ``mcpServers`` block must not be able to use it,
whatever its allowlist says: :func:`security.authz.authorize` refuses every
``tool:call`` on this server for ``terminal`` and ``run`` principals with rule
``fleet:operator-only`` and allows operator and anonymous principals.

Identity comes from the environment the same way as on ``cao-mcp-server``: an
unset ``CAO_TERMINAL_ID`` is the operator context and is never looked up, so
the default-off posture (no credential at all) is byte-identical on the wire.
A bound caller's terminal record is fetched over the same ``GET /terminals/{id}``
hop the server already uses, and the decision is :func:`check` on the
resulting principal.

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


def _fetch_terminal_record(terminal_id: str) -> Optional[Dict[str, Any]]:
    """``GET /terminals/{id}`` through the server's own request helper.

    Imported lazily: ``server.py`` imports this module, so a top-level import
    here would be circular. ``_request_json`` returns errors rather than
    raising; a ``None`` record with an error means the caller is unresolved.
    """

    from cli_agent_orchestrator.ops_mcp_server.server import _request_json

    data, error = _request_json(
        "get", f"/terminals/{terminal_id}", operation="Resolve calling terminal"
    )
    if error or not isinstance(data, dict):
        raise RuntimeError(error or "invalid terminal record")
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
        record = _fetch_terminal_record(terminal_id)
    except Exception as e:  # noqa: BLE001  (an unknown result must not dispatch)
        logger.warning("authorization lookup failed for ops tool '%s': %s", tool_name, e)
        return tool_gate.unresolved(
            tool_name,
            f"cannot authorize '{tool_name}': the calling terminal could not be resolved ({e})",
        )
    if record is None:
        return tool_gate.unresolved(
            tool_name,
            f"cannot authorize '{tool_name}': CAO_TERMINAL_ID is set but the calling "
            "terminal could not be resolved",
        )

    context = {
        "terminal_id": record.get("id") or terminal_id,
        "session_name": record.get("session_name"),
        "agent_profile": record.get("agent_profile"),
    }
    # The ops rule does not read the allowlist (every terminal principal is
    # refused), so the recorded list is passed as-is; a ``None`` is not resolved
    # through the profile here because it cannot change the decision.
    allowed = record.get("allowed_tools") or ()
    principal = tool_gate.principal_for(context, allowed)
    return tool_gate.denial_for(principal, tool_name, server=CAO_OPS_MCP_SERVER)


# Resolves ``_tool_denied_reason`` by name at call time so a test that
# monkeypatches ``gate._tool_denied_reason`` is honoured.
gated = tool_gate.gated(lambda name: _tool_denied_reason(name), server=CAO_OPS_MCP_SERVER)

__all__ = ["gated", "_tool_denied_reason"]
