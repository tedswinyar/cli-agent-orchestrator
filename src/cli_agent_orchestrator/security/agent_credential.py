"""The ONE credential helper for every agent->API hop (#965, #990).

Before this module there were three copies of the same seven-line
``_auth_headers()`` (``mcp_server/utils.py``, ``mcp_server/app_tools.py``,
``utils/orchestration.py``), each attaching the operator's
``CAO_AUTH_LOCAL_TOKEN``. Every agent therefore spoke to the API *as the
operator*, and a route that wanted to know which terminal was calling had to
trust a self-asserted ``caller_id`` / ``CAO_TERMINAL_ID`` (#990's class).

:func:`agent_credential` is the single replacement. Precedence:

1. ``CAO_TERMINAL_TOKEN`` -- the per-terminal credential
   ``services.terminal_service.create_terminal`` mints and injects into the
   agent's environment next to ``CAO_TERMINAL_ID``. ``security.principal``
   resolves it to a ``terminal`` principal with the row's allowed tools,
   creator and ancestry.
2. The operator token path, exactly as before, when no terminal token is
   present (an operator shell, an external MCP client, the ``cao`` CLI run
   from outside a CAO terminal).
3. ``{}`` when neither -- default-off stays byte-for-byte unchanged: no
   ``Authorization`` header is attached at all.

The three old names remain as thin aliases over this function so their call
sites, and the tests that patch each module's own ``get_local_bearer``, keep
working. ``test/security/test_agent_credential_guard.py`` walks every
``requests`` call to ``API_BASE_URL`` under ``mcp_server/``,
``utils/orchestration.py`` and ``cli/commands/agent.py`` and fails on any that
does not take its headers from here (directly or through an alias).
"""

from __future__ import annotations

import os
from typing import Callable, Dict, Optional

from cli_agent_orchestrator.security.auth import get_local_bearer

__all__ = ["TERMINAL_TOKEN_ENV", "agent_credential", "terminal_token"]

# The environment variable the agent process (and, through it, the MCP server
# subprocess and ``cao agent`` CLI invocations) reads its own credential from.
TERMINAL_TOKEN_ENV = "CAO_TERMINAL_TOKEN"


def terminal_token() -> Optional[str]:
    """Return this process's terminal credential, or ``None`` when not launched by CAO."""

    return os.environ.get(TERMINAL_TOKEN_ENV, "").strip() or None


def agent_credential(
    operator_bearer: Optional[Callable[[], Optional[str]]] = None,
) -> Dict[str, str]:
    """Return the ``Authorization`` header for an agent->API hop, or ``{}``.

    ``operator_bearer`` is the fallback used when no terminal token is present.
    It defaults to :func:`security.auth.get_local_bearer`, looked up at call
    time; the per-module aliases pass their own module-level reference so the
    existing tests that patch ``<module>.get_local_bearer`` still steer them.
    """

    token = terminal_token()
    if token:
        return {"Authorization": f"Bearer {token}"}
    bearer = (operator_bearer or get_local_bearer)()
    return {"Authorization": f"Bearer {bearer}"} if bearer else {}
