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
2. :class:`MissingTerminalCredential` when ``CAO_TERMINAL_ID`` IS set and the
   terminal token is not -- see below.
3. Otherwise the operator token path, exactly as before (an operator shell, an
   external MCP client, the ``cao`` CLI run from outside a CAO terminal).
4. ``{}`` when neither -- default-off stays byte-for-byte unchanged: no
   ``Authorization`` header is attached at all.

**Why step 2 exists.** The original precedence fell straight from 1 to 3, so a
CAO-launched agent whose own credential did not arrive -- a provider that
cannot pass it, a relaunched legacy pane, a script that dropped it -- reached
the API presenting ``CAO_AUTH_LOCAL_TOKEN``, i.e. **as the operator**:
unbounded, and attributable to nobody. The claim that every hop carries the
terminal's own credential was false in exactly the case that mattered, and
nothing recorded it. A process that claims a terminal identity it cannot prove
now fails closed in its OWN process, loudly, with the terminal id in the
message.

What this does NOT fix, stated so nobody mistakes it for the whole answer: a
determined agent can unset ``CAO_TERMINAL_ID`` as well, and with auth disabled
the server still answers an unauthenticated caller as ``anonymous`` with the
full scope set. Closing that is a design decision about what
``CAO_PRINCIPAL_ENFORCE`` requires, not something a credential helper can do.
What it closes is the ACCIDENTAL path -- the one that silently produced a
population of operator-authority agents no audit line could distinguish from
the operator.

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

__all__ = [
    "TERMINAL_ID_ENV",
    "TERMINAL_TOKEN_ENV",
    "MissingTerminalCredential",
    "agent_credential",
    "claimed_terminal_id",
    "terminal_token",
]

# The environment variable the agent process (and, through it, the MCP server
# subprocess and ``cao agent`` CLI invocations) reads its own credential from.
TERMINAL_TOKEN_ENV = "CAO_TERMINAL_TOKEN"
#: The terminal identity a CAO-launched process claims. Its presence is what
#: makes a missing :data:`TERMINAL_TOKEN_ENV` an error rather than the operator
#: path, so the two names belong next to each other.
TERMINAL_ID_ENV = "CAO_TERMINAL_ID"


class MissingTerminalCredential(RuntimeError):
    """A process claims a terminal identity but holds no credential for it.

    Raised rather than returned so no call site can mistake it for "no header
    needed": every ``requests`` call that takes its headers from
    :func:`agent_credential` fails loudly instead of silently escalating to the
    operator's authority.
    """


def terminal_token() -> Optional[str]:
    """Return this process's terminal credential, or ``None`` when not launched by CAO."""

    return os.environ.get(TERMINAL_TOKEN_ENV, "").strip() or None


def claimed_terminal_id() -> Optional[str]:
    """The terminal identity this process claims, or ``None`` for an operator context.

    Same reading of "not set" as :func:`terminal_token` (whitespace is unset),
    and the same reading ``security.tool_gate.bound_terminal_id`` uses, so a
    process is bound or unbound consistently wherever it is asked.
    """

    return os.environ.get(TERMINAL_ID_ENV, "").strip() or None


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
    claimed = claimed_terminal_id()
    if claimed:
        # Fail closed BEFORE reading the operator token: a refusal that still
        # reads the secret it is refusing to present is sloppy, and the test
        # asserts the fallback is never even called.
        raise MissingTerminalCredential(
            f"this process claims {TERMINAL_ID_ENV}={claimed} but {TERMINAL_TOKEN_ENV} is not "
            "set, so it has no credential of its own. Presenting the operator's token here "
            "would reach the API with operator authority attributable to nobody. Relaunch the "
            "terminal so CAO injects its credential, or unset "
            f"{TERMINAL_ID_ENV} to act as the operator deliberately."
        )
    bearer = (operator_bearer or get_local_bearer)()
    return {"Authorization": f"Bearer {bearer}"} if bearer else {}
