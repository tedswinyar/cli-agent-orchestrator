"""The host-layer tool gate shared by ``cao-mcp-server`` and ``cao-ops-mcp-server`` (#671).

Provider-native restrictions cannot reach CAO's own MCP tools: ``TOOL_MAPPING``
translates the CAO vocabulary into native tool names and MCP server references
have none, so ``get_disallowed_tools`` skips every ``@``-prefixed entry. The only
place a declared restriction can be shown to hold is the MCP boundary itself,
with the identity read from the terminal record and the policy computed by
:func:`security.authz.check`. This module is that boundary's plumbing; the
policy stays in :mod:`security.authz`.

Three pieces:

* :func:`principal_for` turns the terminal record a server fetched over HTTP
  (plus the effective allowlist resolved the way ``create_terminal`` does) into
  a ``terminal`` :class:`Principal`.
* :func:`denial_for` asks :func:`check` and translates the ``Decision`` into
  the string the tool hands back (``None`` = proceed). It owns the warn/enforce
  split (:func:`hard`): every denial on ``cao-mcp-server`` is hard, because
  #972 shipped that whole-surface gate on main as behaviour before the flag
  existed; ``cao-ops-mcp-server`` tools were not gated on main, so they refuse
  only under ``CAO_PRINCIPAL_ENFORCE`` and are audited in warn mode.
* :func:`gated` builds the decorator a server stacks under ``@mcp.tool``. On
  ``cao-ops-mcp-server`` every registration carries it. On ``cao-mcp-server``
  the gate is #972's ``_AllowlistGate`` middleware (one decision per dispatch)
  and the decorator sits only on the six delegation tools whose refusal
  envelope callers pin; the census in ``test/security/test_tool_gate_census.py``
  asserts both arrangements.

The decision runs in the MCP process. That is where the tool executes, and for
the memory tools it is the only place the effect can be stopped at all (they
touch the filesystem from this process, not through an API route). The
identity is the terminal record the API serves for ``CAO_TERMINAL_ID``; the
record fetch presents the per-terminal ``CAO_TERMINAL_TOKEN`` through
:func:`security.agent_credential.agent_credential` (the one credential helper
for every agent->API hop) and the API binds the id to the bearer.

Nothing here imports ``clients.database``: the MCP boundary stays HTTP-only.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import os
from typing import Any, Callable, Iterable, Mapping, Optional, TypeVar

from fastapi import HTTPException
from fastmcp.exceptions import ToolError

from cli_agent_orchestrator.security.authz import (
    CAO_MCP_SERVER,
    CAO_OPS_MCP_SERVER,
    TOOL_CALL,
    Decision,
    authorize,
    check,
    enforcing,
)
from cli_agent_orchestrator.security.principal import AGENT_SCOPES, Principal

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

#: Attribute stamped on every wrapper so a runtime census can tell a gated
#: function from a bare one without parsing source.
GATED_ATTR = "__cao_gated_server__"

#: Tools that ``_tool_denied_reason`` already refused on main before
#: ``CAO_PRINCIPAL_ENFORCE`` existed (#671 via #769, ephemeral via #827). Their
#: refusals are behaviour today, so they stay hard regardless of the flag. Since
#: #972 the same is true of every tool on ``cao-mcp-server`` (see :func:`hard`),
#: so this table now only documents the pre-#972 set and keeps the
#: ``create_ephemeral_agent`` binder's contract explicit. This is an enforcement
#: mode table, not an authorization rule: the decision itself always comes
#: from :func:`check`.
LEGACY_HARD_GATED: frozenset[str] = frozenset(
    {
        "assign",
        "handoff",
        "assign_elastic",
        "workflow_run",
        "workflow_resume",
        "workflow_start",
        "create_ephemeral_agent",
    }
)


# --- identity -----------------------------------------------------------------


def bound_terminal_id() -> Optional[str]:
    """The terminal id this process claims, or ``None`` for the operator context.

    An unset ``CAO_TERMINAL_ID`` is the supported operator path (``cao assign``
    and ``cao handoff`` on the command line, ``cao-ops-mcp-server`` driven by a
    human) and is never looked up, which keeps the default-off wire bytes
    identical. Boundness is read from the environment, not inferred from a
    failed lookup, so a malformed id still counts as "bound" and fails closed.
    """

    return os.environ.get("CAO_TERMINAL_ID") or None


def principal_for(context: Mapping[str, Any], allowed: Iterable[str]) -> Principal:
    """Build the ``terminal`` principal for a fetched terminal record.

    ``allowed`` is the EFFECTIVE allowlist: the recorded ``allowed_tools`` or
    the profile resolution ``None`` stands for, exactly as
    ``utils.caller_tools.caller_effective_allowed_tools`` computes it. The
    record alone is not enough because a recorded ``None`` means "resolve from
    the profile", not "nothing".
    """

    return Principal(
        kind="terminal",
        scopes=AGENT_SCOPES,
        terminal_id=str(context.get("terminal_id") or ""),
        session_name=context.get("session_name"),
        agent_profile=context.get("agent_profile"),
        allowed_tools=tuple(str(a) for a in allowed),
    )


# --- the decision, as the tool sees it ------------------------------------------


def hard(tool_name: str, server: Optional[str] = None) -> bool:
    """Whether a denial of ``tool_name`` on ``server`` refuses the call rather than only auditing it.

    Hard when enforcing, for every tool on ``cao-mcp-server`` (#972 made the
    whole-surface allowlist gate behaviour on main, so the flag must not relax
    it), and for :data:`LEGACY_HARD_GATED` whatever the server. Everything else
    (today: ``cao-ops-mcp-server``) is warn-mode by default.
    """

    return enforcing() or server == CAO_MCP_SERVER or tool_name in LEGACY_HARD_GATED


def decide(principal: Principal, tool_name: str, *, server: str) -> Decision:
    """Run ``check()`` for one tool call and return the ``Decision`` either way.

    ``check`` audits, logs in warn mode, and raises ``HTTPException(403)`` in
    enforce mode. The MCP boundary cannot propagate an HTTP exception to an
    agent, so the refusal is recovered as the same pure decision (``authorize``
    is deterministic) and delivered by the caller as the tool's denial.
    """

    try:
        return check(principal, TOOL_CALL, tool_name, server=server, hard=hard(tool_name, server))
    except HTTPException:
        return authorize(principal, TOOL_CALL, tool_name, server=server)


def denial_text(tool_name: str, server: str, decision: Decision) -> str:
    """The reason string a refused tool hands back. Carries the rule and the Decision reason."""

    text = f"'{tool_name}' is not permitted ({decision.rule}): {decision.reason}"
    if server == CAO_MCP_SERVER and decision.rule == "tool:default-deny":
        text += (
            f". Grant '@{CAO_MCP_SERVER}' (or '@{CAO_MCP_SERVER}/{tool_name}') in the calling "
            "terminal's allowed tools"
        )
    elif server == CAO_OPS_MCP_SERVER:
        text += f". {CAO_OPS_MCP_SERVER} tools are operator-only"
    return text


def denial_for(
    principal: Principal,
    tool_name: str,
    *,
    server: str,
) -> Optional[str]:
    """``None`` to proceed, else the denial the tool returns or raises.

    A denied decision proceeds in warn mode (already audited and logged by
    ``check``) unless :func:`hard` says otherwise: every ``cao-mcp-server``
    tool, :data:`LEGACY_HARD_GATED`, or ``CAO_PRINCIPAL_ENFORCE`` on.
    """

    decision = decide(principal, tool_name, server=server)
    if decision.allowed:
        return None
    if hard(tool_name, server):
        return denial_text(tool_name, server, decision)
    return None


def unresolved(tool_name: str, text: str, *, server: Optional[str] = None) -> Optional[str]:
    """Fail-closed helper for an identity that could not be resolved.

    A bound caller whose record cannot be fetched (or whose allowlist cannot
    be resolved) is an unknown, and an unknown must not dispatch. That is
    today's behaviour on ``cao-mcp-server`` (#972) and enforce-mode behaviour
    for ``cao-ops-mcp-server``; in warn mode an ops tool proceeds and the
    failure is logged, so warn mode stays behaviour-preserving there.
    """

    if hard(tool_name, server):
        return text
    logger.warning("authz warn-mode: would refuse %s: %s", tool_name, text)
    return None


# --- the decorator ---------------------------------------------------------------


def gated(
    decide_fn: Callable[[str], Optional[str]],
    *,
    server: str,
) -> Callable[..., Any]:
    """Build the ``@_gated`` decorator a server stacks under ``@mcp.tool``.

    ``decide_fn(tool_name)`` is the server's ``_tool_denied_reason``: ``None``
    to proceed, else the denial. It is called by name at call time, so a test
    that monkeypatches the module attribute is honoured.

    The returned decorator is used bare (``@_gated``) or with a per-tool
    ``refuse`` builder (``@_gated(refuse=lambda reason: {...})``) for tools
    whose refusal envelope is pinned by callers and tests. Without ``refuse``
    a denial raises :class:`fastmcp.exceptions.ToolError`, which FastMCP
    delivers as an MCP error result regardless of the tool's declared return
    type. Async tools evaluate the (blocking HTTP) decision off the event loop.
    """

    def _wrap(fn: F, refuse: Optional[Callable[[str], Any]]) -> F:
        name = fn.__name__
        # Bound eagerly so a direct call that omits a required argument raises
        # ``TypeError`` at the call, exactly as the undecorated function does.
        # The suite calls these tools as plain functions and pins that property
        # (``test_workflow_required_parameters``); a ``*args, **kwargs`` wrapper
        # would otherwise defer the error into the coroutine.
        signature = inspect.signature(fn)

        def _refuse(reason: str) -> Any:
            if refuse is not None:
                return refuse(reason)
            raise ToolError(reason)

        if inspect.iscoroutinefunction(fn):

            async def _run(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
                denied = await asyncio.to_thread(decide_fn, name)
                if denied:
                    return _refuse(denied)
                return await fn(*args, **kwargs)

            @functools.wraps(fn)
            def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                signature.bind(*args, **kwargs)
                return _run(args, kwargs)

            # Python 3.12+: keep ``inspect.iscoroutinefunction`` true for the
            # wrapper, which returns a coroutine from a plain function.
            mark = getattr(inspect, "markcoroutinefunction", None)
            if mark is not None:
                mark(async_wrapper)
            setattr(async_wrapper, GATED_ATTR, server)
            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            signature.bind(*args, **kwargs)
            denied = decide_fn(name)
            if denied:
                return _refuse(denied)
            return fn(*args, **kwargs)

        setattr(sync_wrapper, GATED_ATTR, server)
        return sync_wrapper  # type: ignore[return-value]

    def decorator(fn: Optional[F] = None, *, refuse: Optional[Callable[[str], Any]] = None) -> Any:
        if fn is not None:
            return _wrap(fn, refuse)
        return lambda inner: _wrap(inner, refuse)

    return decorator


def is_gated(fn: Any, server: str) -> bool:
    """Whether ``fn`` is a wrapper this module produced for ``server``."""

    return getattr(fn, GATED_ATTR, None) == server


__all__ = [
    "GATED_ATTR",
    "LEGACY_HARD_GATED",
    "bound_terminal_id",
    "decide",
    "denial_for",
    "denial_text",
    "gated",
    "hard",
    "is_gated",
    "principal_for",
    "unresolved",
]
