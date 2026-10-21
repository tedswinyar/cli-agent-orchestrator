"""``authorize(principal, action, resource)``: the one policy decision point (#965).

Every surface that bounds an *agent* (HTTP routes, ``cao-mcp-server``,
``cao-ops-mcp-server``, WebSocket, plugins) asks this module the same question
and gets a :class:`Decision` back. The function is pure: it reads the principal
and the resource and touches nothing else, so it is trivially testable and the
audit log (:mod:`security.audit`) can record exactly what it decided.

Posture today: operator and anonymous principals are allowed everything; the
rules below bound ``terminal`` and ``run`` principals only. Enforcement is
behind ``CAO_PRINCIPAL_ENFORCE``; the default is **warn mode**, where
:func:`check` records the decision and returns it without refusing.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from fastapi import HTTPException, status

from cli_agent_orchestrator.security.principal import Principal

logger = logging.getLogger(__name__)

CAO_MCP_SERVER = "cao-mcp-server"
CAO_OPS_MCP_SERVER = "cao-ops-mcp-server"

# --- actions ----------------------------------------------------------------

TOOL_CALL = "tool:call"
TERMINAL_CREATE = "terminal:create"
TERMINAL_ACT_AS = "terminal:act_as"
RUN_CANCEL = "run:cancel"
RUN_RESUME = "run:resume"
RUN_REPLAY = "run:replay"
FLEET = "fleet:*"
OPERATOR_ROUTE = "operator:route"

ACTIONS: frozenset[str] = frozenset(
    {
        TOOL_CALL,
        TERMINAL_CREATE,
        TERMINAL_ACT_AS,
        RUN_CANCEL,
        RUN_RESUME,
        RUN_REPLAY,
        FLEET,
        OPERATOR_ROUTE,
    }
)
_RUN_ACTIONS: frozenset[str] = frozenset({RUN_CANCEL, RUN_RESUME, RUN_REPLAY})

#: Tools a terminal principal may always call on ``cao-mcp-server`` regardless
#: of its allowlist: the callbacks a bounded agent needs to report back to its
#: creator, and the discovery pair (#671 ruling, 2026-10-21).
CALLBACK_TOOLS: frozenset[str] = frozenset(
    {"send_message", "complete_assignment", "workflow_return", "answer_user_prompt"}
)
DISCOVERY_TOOLS: frozenset[str] = frozenset({"list_siblings", "update_metadata"})
ALWAYS_ALLOWED_TOOLS: frozenset[str] = CALLBACK_TOOLS | DISCOVERY_TOOLS


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule: str
    reason: str


@dataclass(frozen=True)
class RunRef:
    run_id: str
    owner_terminal_id: Optional[str]
    ancestor_terminal_ids: tuple[str, ...] = ()


# --- selector coverage ------------------------------------------------------


def _selector_covers_server(entry: str, server: str) -> bool:
    """``@<pattern>`` grants ``server`` by exact name or case-sensitive glob.

    Same matching rule as ``utils.tool_mapping.granted_mcp_servers``, applied
    to one entry so callers can also test the ``@server/tool`` form.
    """

    if not entry.startswith("@"):
        return False
    pattern = entry[1:]
    if not pattern or pattern == "builtin":
        return False
    return server == pattern or fnmatch.fnmatchcase(server, pattern)


def tool_covered(allowed: Iterable[str], tool: str, server: str) -> bool:
    """Whether a CAO allowlist grants ``tool`` on MCP ``server``.

    Covered by ``*``, by a server selector (``@cao-mcp-server`` or a glob that
    matches it), by the per-tool form ``@cao-mcp-server/<tool>``, or by the
    bare tool name.
    """

    for entry in allowed:
        if not isinstance(entry, str):
            continue
        if entry == "*" or entry == tool:
            return True
        if "/" in entry and entry.startswith("@"):
            srv, _, name = entry[1:].partition("/")
            if name == tool and (server == srv or fnmatch.fnmatchcase(server, srv)):
                return True
            continue
        if _selector_covers_server(entry, server):
            return True
    return False


def _entry_within_ceiling(entry: str, ceiling: Iterable[str]) -> bool:
    """Whether one requested allowlist entry is granted by ``ceiling``."""

    ceiling_list = [c for c in ceiling if isinstance(c, str)]
    if "*" in ceiling_list or entry in ceiling_list:
        return True
    if entry.startswith("@"):
        body = entry[1:]
        srv, slash, name = body.partition("/")
        for c in ceiling_list:
            if not c.startswith("@"):
                continue
            c_body = c[1:]
            if "/" in c_body:
                # A per-tool ceiling entry only grants that exact entry (handled above).
                continue
            if _selector_covers_server(c, srv):
                return True
        return False
    return False


def ceiling_of(principal: Principal) -> tuple[str, ...]:
    """The allowlist a principal may hand to a child: ``delegate_tools`` else its own."""

    return principal.delegate_tools or principal.allowed_tools


# --- the decision -----------------------------------------------------------


def _who(principal: Principal) -> str:
    if principal.kind == "run":
        return f"run {principal.run_id}"
    if principal.terminal_id:
        return f"terminal {principal.terminal_id}"
    return principal.kind


def authorize(principal: Principal, action: str, resource: Any, **ctx: Any) -> Decision:
    """Decide whether ``principal`` may perform ``action`` on ``resource``.

    Pure. Unknown actions are refused with rule ``unknown-action`` so a typo at
    a call site fails closed rather than open.
    """

    if action not in ACTIONS:
        return Decision(False, "unknown-action", f"unknown action {action!r}")

    if principal.is_operator:
        return Decision(True, "operator", f"{principal.kind} principals are unbounded")

    who = _who(principal)

    if action == TOOL_CALL:
        tool = str(resource)
        server = str(ctx.get("server", CAO_MCP_SERVER))
        if server == CAO_OPS_MCP_SERVER:
            return Decision(False, "fleet:operator-only", f"{who} may not call ops tool {tool}")
        if server == CAO_MCP_SERVER and tool in ALWAYS_ALLOWED_TOOLS:
            rule = "tool:callback" if tool in CALLBACK_TOOLS else "tool:discovery"
            return Decision(True, rule, f"{tool} is always available to {who}")
        if tool_covered(principal.allowed_tools, tool, server):
            return Decision(True, "tool:allowlist", f"{who} allowlist covers {tool}")
        return Decision(
            False,
            "tool:default-deny",
            f"{who} allowed_tools does not cover {tool} on {server}",
        )

    if action == TERMINAL_CREATE:
        requested = tuple(str(r) for r in (resource or ()))
        ceiling = ceiling_of(principal)
        outside = [r for r in requested if not _entry_within_ceiling(r, ceiling)]
        if outside:
            return Decision(
                False,
                "terminal:ceiling",
                f"{who} may not grant {sorted(outside)} beyond its ceiling",
            )
        return Decision(True, "terminal:within-ceiling", f"{who} request is within its ceiling")

    if action == TERMINAL_ACT_AS:
        claimed = str(resource) if resource is not None else None
        if claimed and principal.terminal_id and claimed == principal.terminal_id:
            return Decision(True, "terminal:self", f"{who} acts as itself")
        return Decision(False, "terminal:impersonation", f"{who} may not act as terminal {claimed}")

    if action in _RUN_ACTIONS:
        if not isinstance(resource, RunRef):
            return Decision(False, "run:bad-resource", f"{action} requires a RunRef")
        if principal.kind == "run" and principal.run_id == resource.run_id:
            return Decision(True, "run:self", f"{who} acts on its own run")
        tid = principal.terminal_id
        if tid and tid == resource.owner_terminal_id:
            return Decision(True, "run:owner", f"{who} owns run {resource.run_id}")
        if tid and tid in resource.ancestor_terminal_ids:
            return Decision(True, "run:ancestor", f"{who} is an ancestor of run {resource.run_id}")
        return Decision(
            False,
            "run:not-owner",
            f"{who} neither owns nor is an ancestor of run {resource.run_id}",
        )

    if action == FLEET:
        return Decision(False, "fleet:operator-only", f"{who} may not use fleet tool {resource}")

    if action == OPERATOR_ROUTE:
        return Decision(False, "operator:route", f"{who} may not call operator route {resource}")

    return Decision(False, "unknown-action", f"unknown action {action!r}")  # pragma: no cover


# --- enforcement flag + the call-site entry point ----------------------------


def enforcing() -> bool:
    """True iff ``CAO_PRINCIPAL_ENFORCE`` is ``1``/``true``. Default off = warn mode."""

    return os.getenv("CAO_PRINCIPAL_ENFORCE", "").strip().lower() in ("1", "true")


def check(principal: Principal, action: str, resource: Any, **ctx: Any) -> Decision:
    """Authorize, audit, and (only when enforcing) refuse with HTTP 403.

    This is the call call sites use. In warn mode the decision is recorded and
    returned without raising, so a denied call proceeds exactly as it does
    today while the audit log shows what enforcement *would* have refused.
    """

    from cli_agent_orchestrator.security import audit

    decision = authorize(principal, action, resource, **ctx)
    enforce = enforcing()
    audit.record(principal, action, _resource_repr(resource, ctx), decision, enforce)
    if not decision.allowed:
        if enforce:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)
        logger.warning("authz warn-mode: would refuse %s: %s", action, decision.reason)
    return decision


def _resource_repr(resource: Any, ctx: dict[str, Any]) -> str:
    if isinstance(resource, RunRef):
        base = f"run:{resource.run_id}"
    elif isinstance(resource, (list, tuple)):
        base = ",".join(str(r) for r in resource)
    else:
        base = str(resource)
    server = ctx.get("server")
    return f"{server}/{base}" if server else base
