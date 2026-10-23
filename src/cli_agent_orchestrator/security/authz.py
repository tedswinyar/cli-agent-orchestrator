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

from cli_agent_orchestrator.constants import DISCOVERY_TOOL_MARKER
from cli_agent_orchestrator.security.principal import Principal

logger = logging.getLogger(__name__)

CAO_MCP_SERVER = "cao-mcp-server"
CAO_OPS_MCP_SERVER = "cao-ops-mcp-server"

# --- actions ----------------------------------------------------------------

TOOL_CALL = "tool:call"
TERMINAL_CREATE = "terminal:create"
TERMINAL_ACT_AS = "terminal:act_as"
TERMINAL_TARGET = "terminal:target"
RUN_CANCEL = "run:cancel"
RUN_RESUME = "run:resume"
RUN_REPLAY = "run:replay"
FLEET = "fleet:*"
OPERATOR_ROUTE = "operator:route"
#: An ``CAO_TERMINAL_ID`` claimed by a process whose bearer resolves to no
#: terminal at all. Separate from :data:`TERMINAL_ACT_AS` (which compares two
#: known identities) because the failure is different: nothing was proven, so
#: there is no "from" identity to name in the refusal.
IDENTITY_PROVE = "identity:prove"
#: The two ephemeral-launch policy rules (``ephemeral.max_depth``,
#: ``ephemeral.child_may_delegate``). They were enforced before
#: ``CAO_PRINCIPAL_ENFORCE`` existed and are unchanged in effect; routing them
#: through :func:`check` is what puts them in the audit log.
EPHEMERAL_DEPTH = "ephemeral:depth"
EPHEMERAL_DELEGATE = "ephemeral:delegate"

ACTIONS: frozenset[str] = frozenset(
    {
        TOOL_CALL,
        TERMINAL_CREATE,
        TERMINAL_ACT_AS,
        TERMINAL_TARGET,
        RUN_CANCEL,
        RUN_RESUME,
        RUN_REPLAY,
        FLEET,
        OPERATOR_ROUTE,
        IDENTITY_PROVE,
        EPHEMERAL_DEPTH,
        EPHEMERAL_DELEGATE,
    }
)
_RUN_ACTIONS: frozenset[str] = frozenset({RUN_CANCEL, RUN_RESUME, RUN_REPLAY})
#: Actions whose decision reads ``principal.allowed_tools``. An unresolved
#: allowlist is refused for these and only these: a run-ownership or
#: identity-binding question does not consult the list, so failing those closed
#: would turn an unreadable agent profile into a lockout.
_ALLOWLIST_ACTIONS: frozenset[str] = frozenset({TOOL_CALL, TERMINAL_CREATE})

#: Tools a terminal principal may always call on ``cao-mcp-server`` regardless
#: of its allowlist: the callbacks a bounded agent needs to report back to its
#: creator (#671 ruling, 2026-10-21; ``mcp_server.server.CALLBACK_EXEMPT_TOOLS``
#: is this set).
CALLBACK_TOOLS: frozenset[str] = frozenset(
    {"send_message", "complete_assignment", "workflow_return", "answer_user_prompt"}
)
#: The two tools the separate ``discovery`` grant covers independently of
#: ``@cao-mcp-server`` (docs/tool-restrictions.md, "discovery is a separate
#: opt-in"; #972's carve-out). They pass on that grant alone, and on nothing
#: less: ``_require_discovery_marker`` still does the live check when they run.
DISCOVERY_TOOLS: frozenset[str] = frozenset({"list_siblings", "update_metadata"})
#: The allowlist entry that is the ``discovery`` grant, spelled the same way
#: ``utils.orchestration.has_discovery_grant`` reads it.
DISCOVERY_GRANT = DISCOVERY_TOOL_MARKER


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


@dataclass(frozen=True)
class TerminalRef:
    """A terminal named as the TARGET of a request, with the facts the rule needs.

    ``ancestor_terminal_ids`` is the TARGET's ``caller_id`` chain (creator,
    creator's creator, ... root) as ``principal._ancestry`` computes it, so
    "a descendant the caller created" is a membership test rather than a
    downward walk. The caller's own chain is already on its principal.

    ``peer_terminal_ids`` is the CALLER's sibling set at the widest scope
    ``list_siblings`` serves, and is populated only for reads (see the
    ``terminal:discovery-peer`` rule). Carried on the ref rather than looked up
    in the rule so :func:`authorize` stays pure.
    """

    terminal_id: str
    ancestor_terminal_ids: tuple[str, ...] = ()
    peer_terminal_ids: tuple[str, ...] = ()


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
    matches it), or by the per-tool form ``@cao-mcp-server/<tool>``. A bare
    tool name never grants an MCP tool: bare names are provider-native
    vocabulary (``fs_read``, ``execute_bash``), and the #671/#769 policy on
    main pins that ``allowedTools: [assign]`` does not reach ``assign``.
    """

    for entry in allowed:
        if not isinstance(entry, str):
            continue
        if entry == "*":
            return True
        if "/" in entry and entry.startswith("@"):
            srv, _, name = entry[1:].partition("/")
            if name == tool and (server == srv or fnmatch.fnmatchcase(server, srv)):
                return True
            continue
        if _selector_covers_server(entry, server):
            return True
    return False


def discovery_granted(allowed: Iterable[str]) -> bool:
    """Whether an effective allowlist carries the ``discovery`` grant (or ``*``).

    The same test as ``utils.orchestration.has_discovery_grant`` for a resolved
    list; ``None`` never reaches here because the gate treats an unresolvable
    allowlist as unknown before building a principal.
    """

    entries = [a for a in allowed if isinstance(a, str)]
    return "*" in entries or DISCOVERY_GRANT in entries


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

    if action == IDENTITY_PROVE:
        # Asked BEFORE the operator short-circuit on purpose: the question is
        # "did the bearer prove the identity this process claims", and an
        # operator or anonymous bearer proves no terminal identity at all. That
        # is the credential-fallback hole (an agent launched without
        # CAO_TERMINAL_TOKEN reaching the API as the operator), so it must not
        # be answered "allowed, operators are unbounded".
        claimed = str(resource) if resource is not None else None
        if not claimed:
            return Decision(True, "identity:unbound", "no terminal identity is claimed")
        if principal.terminal_id == claimed:
            return Decision(True, "identity:proven", f"the bearer is terminal {claimed}")
        if principal.terminal_id:
            return Decision(
                False,
                "terminal:impersonation",
                f"terminal {principal.terminal_id} may not act as terminal {claimed}",
            )
        return Decision(
            False,
            "identity:unproven",
            f"a {principal.kind} bearer does not prove the claimed identity {claimed}",
        )

    if principal.is_operator:
        return Decision(True, "operator", f"{principal.kind} principals are unbounded")

    who = _who(principal)

    if action in _ALLOWLIST_ACTIONS and not principal.allowlist_resolved:
        return Decision(
            False,
            "identity:unresolved",
            f"{who} effective allowed_tools could not be resolved from its agent profile",
        )

    if action == TOOL_CALL:
        tool = str(resource)
        server = str(ctx.get("server", CAO_MCP_SERVER))
        if server == CAO_OPS_MCP_SERVER:
            return Decision(False, "fleet:operator-only", f"{who} may not call ops tool {tool}")
        if server == CAO_MCP_SERVER and tool in CALLBACK_TOOLS:
            return Decision(True, "tool:callback", f"{tool} is always available to {who}")
        if (
            server == CAO_MCP_SERVER
            and tool in DISCOVERY_TOOLS
            and discovery_granted(principal.allowed_tools)
        ):
            return Decision(True, "tool:discovery", f"{who} holds the discovery grant for {tool}")
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

    if action == TERMINAL_TARGET:
        if not isinstance(resource, TerminalRef):
            return Decision(False, "terminal:bad-resource", f"{action} requires a TerminalRef")
        tid = principal.terminal_id
        target = resource.terminal_id
        if tid and tid == target:
            return Decision(True, "terminal:self", f"{who} acts on itself")
        if tid and tid in resource.ancestor_terminal_ids:
            return Decision(
                True,
                "terminal:descendant",
                f"{who} created terminal {target} (directly or transitively)",
            )
        # The two READ-ONLY widenings. Both exist because CAO's own documented
        # flows read a record the caller does not own, and refusing those reads
        # would break the callback protocol to enforce a rule about *acting*:
        # ``_target_binding_denial(allow_parent=True)`` reads the supervisor's
        # record for ``send_message`` with no receiver, and
        # ``allow_discovered_sibling=True`` reads a peer's for the #432 flow
        # ("find siblings with list_siblings, then message them"). Reading up or
        # sideways is not steering up or sideways, which stays refused.
        if ctx.get("read"):
            if target in principal.ancestors:
                return Decision(True, "terminal:ancestor", f"{who} may read its ancestor {target}")
            if target in resource.peer_terminal_ids and discovery_granted(principal.allowed_tools):
                return Decision(
                    True,
                    "terminal:discovery-peer",
                    f"{who} holds the discovery grant and {target} is one of its peers",
                )
        return Decision(
            False,
            "terminal:not-owner",
            f"{who} neither is nor created terminal {target}",
        )

    if action == EPHEMERAL_DEPTH:
        if principal.ephemeral:
            return Decision(
                False,
                "ephemeral:max-depth",
                f"{who} is ephemeral and may not create ephemeral agents "
                "(ephemeral.max_depth=1)",
            )
        return Decision(True, "ephemeral:within-depth", f"{who} is not an ephemeral agent")

    if action == EPHEMERAL_DELEGATE:
        # ``resource`` is the tool name; ``ctx['child_may_delegate']`` the setting.
        if principal.ephemeral and not bool(ctx.get("child_may_delegate")):
            return Decision(
                False,
                "ephemeral:child-delegation",
                f"{who} is ephemeral and ephemeral.child_may_delegate is off, so "
                f"{resource} is not permitted",
            )
        return Decision(True, "ephemeral:may-delegate", f"{who} may delegate {resource}")

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


def check(
    principal: Principal, action: str, resource: Any, *, hard: bool = False, **ctx: Any
) -> Decision:
    """Authorize, audit, and (only when enforcing) refuse with HTTP 403.

    This is the call call sites use. In warn mode the decision is recorded and
    returned without raising, so a denied call proceeds exactly as it does
    today while the audit log shows what enforcement *would* have refused.

    ``hard=True`` enforces this one call whatever the flag says, and the audit
    line records ``enforced: true``. It is for rules that were already behaviour
    before ``CAO_PRINCIPAL_ENFORCE`` existed (the ``cao-mcp-server`` allowlist
    gate #972 shipped), so the flag never relaxes them; see ``tool_gate.hard``.
    """

    from cli_agent_orchestrator.security import audit

    decision = authorize(principal, action, resource, **ctx)
    enforce = hard or enforcing()
    audit.record(principal, action, _resource_repr(resource, ctx), decision, enforce)
    if not decision.allowed:
        if enforce:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)
        logger.warning("authz warn-mode: would refuse %s: %s", action, decision.reason)
    return decision


def _resource_repr(resource: Any, ctx: dict[str, Any]) -> str:
    if isinstance(resource, RunRef):
        base = f"run:{resource.run_id}"
    elif isinstance(resource, TerminalRef):
        base = f"terminal:{resource.terminal_id}"
    elif isinstance(resource, (list, tuple)):
        base = ",".join(str(r) for r in resource)
    else:
        base = str(resource)
    server = ctx.get("server")
    return f"{server}/{base}" if server else base
