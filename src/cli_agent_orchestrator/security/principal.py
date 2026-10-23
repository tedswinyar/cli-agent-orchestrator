"""Per-terminal principal: who is calling, resolved once at one chokepoint (#965).

Today every CAO surface shares one bearer (or none) and "who is calling" is a
self-asserted ``caller_id`` / ``CAO_TERMINAL_ID``. This module gives each
terminal an identity the *server* issued and can verify:

* :func:`mint_terminal_credential` returns a ``cao_t_`` token and its SHA-256
  digest; only the digest is stored (``terminals.credential_digest``), so a
  database read never yields a usable credential.
* :func:`principal_from_terminal_row` turns a terminal row into a frozen
  :class:`Principal` carrying the row's EFFECTIVE allowlist, delegation
  ceiling, creator and ancestry (``caller_id`` followed up the table, bounded,
  cycle-safe). It is the **only** function in the tree that builds a
  ``terminal`` principal: :func:`principal_payload` /
  :func:`principal_from_payload` carry its result over HTTP to the MCP
  boundary, which therefore cannot construct a second, differently-populated
  one (the seam that let ``delegate_tools`` go missing on the MCP side).
* :func:`get_current_principal` is the FastAPI dependency that resolves a
  request's bearer to a principal. Anything today's
  :func:`security.auth.get_current_scopes` accepts is still accepted here and
  becomes an ``operator`` (auth on) or ``anonymous`` (auth off) principal, so
  the default-off posture is byte-identical.

Policy lives in :mod:`security.authz`; this module only answers *who*.

**Boundary note:** ``clients.database`` is imported lazily inside the two
functions that need it so that importing this module stays as cheap and
side-effect free as :mod:`security.auth`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from dataclasses import dataclass
from typing import Any, Callable, Literal, Mapping, Optional, Tuple

from fastapi import Depends, HTTPException, Request, status

from cli_agent_orchestrator.security import auth
from cli_agent_orchestrator.security.auth import FULL_SCOPE_SET, SCOPE_READ, SCOPE_WRITE

logger = logging.getLogger(__name__)

Kind = Literal["operator", "terminal", "run", "anonymous"]

TERMINAL_TOKEN_PREFIX = "cao_t_"
RUN_TOKEN_PREFIX = "cao_r_"

#: Upper bound on ``caller_id`` hops followed when computing ancestry.
ANCESTRY_MAX_HOPS = 32

#: Scopes a terminal or run credential grants. Never ``cao:admin``.
AGENT_SCOPES: frozenset[str] = frozenset({SCOPE_READ, SCOPE_WRITE})


@dataclass(frozen=True)
class Principal:
    """The resolved caller. Frozen: a principal is a fact about one request."""

    kind: Kind
    scopes: frozenset[str]
    terminal_id: Optional[str] = None
    session_name: Optional[str] = None
    agent_profile: Optional[str] = None
    role: Optional[str] = None
    allowed_tools: tuple[str, ...] = ()
    delegate_tools: tuple[str, ...] = ()
    creator_id: Optional[str] = None
    ancestors: tuple[str, ...] = ()
    run_id: Optional[str] = None
    #: Ephemeral-registry membership of the terminal (``terminals.ephemeral`` as
    #: the API publishes it). Policy, not decoration: the ``ephemeral:*`` rules
    #: in :mod:`security.authz` read it, so those refusals go through
    #: :func:`security.authz.check` and are audited like every other decision.
    ephemeral: bool = False
    #: False when the row said "resolve the allowlist from the agent profile"
    #: and that resolution failed. ``allowed_tools`` is then ``()``, which the
    #: policy layer would otherwise read as a legitimate deny-all; the flag
    #: lets :func:`security.authz.authorize` refuse with ``identity:unresolved``
    #: instead of silently deciding on a list it never read.
    allowlist_resolved: bool = True

    @property
    def is_operator(self) -> bool:
        """Operators (and the default-off anonymous caller) are unbounded today."""

        return self.kind in ("operator", "anonymous")


# --- credentials ----------------------------------------------------------


def digest_of(token: str) -> str:
    """SHA-256 hex digest of the full token string (prefix included)."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def mint_terminal_credential() -> Tuple[str, str]:
    """Return ``(token, digest)`` for a fresh terminal credential.

    ``token`` is :data:`TERMINAL_TOKEN_PREFIX` followed by the 43 URL-safe
    characters of ``secrets.token_urlsafe(32)`` (256 bits). ``digest`` is what
    the terminals table stores; the plaintext goes only into the agent's
    environment.
    """

    token = TERMINAL_TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, digest_of(token)


# --- principal construction -----------------------------------------------


def _as_tuple(value: Any) -> tuple[str, ...]:
    """Decode a JSON-encoded list column (or an already-decoded list) to a tuple."""

    if value is None:
        return ()
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return ()


def _caller_of(terminal_id: str) -> Optional[str]:
    """Return the ``caller_id`` recorded for ``terminal_id``, or ``None``."""

    from cli_agent_orchestrator.clients import database

    with database.SessionLocal() as db:
        row = (
            db.query(database.TerminalModel.caller_id)
            .filter(database.TerminalModel.id == terminal_id)
            .first()
        )
    if row is None:
        return None
    caller = row[0]
    return str(caller) if caller else None


def _row_by_id(terminal_id: str) -> Any:
    """Return the ``TerminalModel`` row for ``terminal_id``, or ``None``."""

    from cli_agent_orchestrator.clients import database

    with database.SessionLocal() as db:
        return (
            db.query(database.TerminalModel)
            .filter(database.TerminalModel.id == terminal_id)
            .first()
        )


def _ancestry(terminal_id: Optional[str], first_caller: Optional[str]) -> tuple[str, ...]:
    """Follow ``caller_id`` up the terminal table: creator, creator's creator, ... root.

    Bounded at :data:`ANCESTRY_MAX_HOPS`; a cycle (or a self-reference) stops
    the walk at the first repeated id rather than looping.
    """

    chain: list[str] = []
    seen: set[str] = set()
    if terminal_id:
        seen.add(terminal_id)
    current = first_caller
    while current and len(chain) < ANCESTRY_MAX_HOPS:
        if current in seen:
            break
        seen.add(current)
        chain.append(current)
        current = _caller_of(current)
    return tuple(chain)


def _is_ephemeral(terminal_id: str) -> bool:
    """Ephemeral-registry membership for ``terminal_id``.

    Deliberately NOT guarded. A registry that cannot answer is an unknown, and
    "not ephemeral" is the permissive answer -- it is what lifts the
    ``ephemeral.max_depth`` and ``ephemeral.child_may_delegate`` refusals. The
    exception therefore propagates: the route 500s, and the MCP gate turns that
    into ``tool_gate.unresolved``, which is what ``GET /terminals/{id}`` did
    before the principal existed (``test_ephemeral_caller_denial.py::
    test_registry_lookup_failure_denies``).
    """

    from cli_agent_orchestrator.clients import database

    return bool(database.is_ephemeral_terminal(terminal_id))


def _effective_allowed(row: Any) -> Tuple[tuple[str, ...], bool]:
    """``(effective allowlist, resolved?)`` for a terminal row.

    A recorded ``allowed_tools`` IS the effective list -- including ``[]``,
    which is an explicit deny-all. A recorded ``None`` means "resolve from the
    agent profile", exactly as ``create_terminal`` and the MCP gate have always
    read it (``utils.caller_tools.caller_effective_allowed_tools``), so the
    resolution happens HERE rather than being repeated by every surface that
    needs a principal. An unreadable profile, or a profile that resolves to
    ``None``, is reported as unresolved so the policy layer can fail closed
    instead of mistaking it for deny-all.
    """

    recorded = getattr(row, "allowed_tools", None)
    if recorded is not None:
        return _as_tuple(recorded), True

    from cli_agent_orchestrator.utils.caller_tools import caller_effective_allowed_tools

    profile = getattr(row, "agent_profile", None)
    try:
        resolved = caller_effective_allowed_tools({"allowed_tools": None, "agent_profile": profile})
    except Exception:  # noqa: BLE001  (an unknown result must not become permission)
        logger.warning("allowlist resolution failed for profile %r", profile, exc_info=True)
        return (), False
    if resolved is None:
        return (), False
    return tuple(str(r) for r in resolved), True


def principal_from_terminal_row(row: Any) -> Principal:
    """Build a ``terminal`` principal from a ``TerminalModel`` row.

    THE one construction path. Fresh each call, no caching: the row is the
    source of truth and a principal is a snapshot of it at resolve time.

    * ``allowed_tools`` is the EFFECTIVE list (see :func:`_effective_allowed`),
      so an HTTP route and the MCP gate bound the same terminal by the same
      list. Before this was centralised the MCP gate resolved the profile and
      the API did not, and a row with ``allowed_tools=None`` was unrestricted
      on one surface and deny-all on the other.
    * ``delegate_tools`` (#948) is the recorded delegation ceiling; empty means
      "ceiling = own allowlist" to :func:`security.authz.ceiling_of`.
    """

    terminal_id = str(row.id)
    caller_id = getattr(row, "caller_id", None)
    creator = str(caller_id) if caller_id else None
    allowed, resolved = _effective_allowed(row)
    return Principal(
        kind="terminal",
        scopes=AGENT_SCOPES,
        terminal_id=terminal_id,
        session_name=getattr(row, "tmux_session", None),
        agent_profile=getattr(row, "agent_profile", None),
        role=getattr(row, "role", None),
        allowed_tools=allowed,
        delegate_tools=_as_tuple(getattr(row, "delegate_tools", None)),
        creator_id=creator,
        ancestors=_ancestry(terminal_id, creator),
        ephemeral=_is_ephemeral(terminal_id),
        allowlist_resolved=resolved,
    )


# --- serialization (the API -> MCP boundary) --------------------------------

#: Field order is the dataclass's own; stated once so the payload keys and the
#: constructor cannot drift. ``scopes`` is excluded on purpose: it is derived
#: (:data:`AGENT_SCOPES` for every agent principal) and a wire-supplied scope
#: set would be a privilege the holder named for itself.
_PAYLOAD_FIELDS: tuple[str, ...] = (
    "kind",
    "terminal_id",
    "session_name",
    "agent_profile",
    "role",
    "allowed_tools",
    "delegate_tools",
    "creator_id",
    "ancestors",
    "run_id",
    "ephemeral",
    "allowlist_resolved",
)


def principal_payload(principal: Principal) -> dict[str, Any]:
    """Serialize a principal for the ``GET /me/principal`` body.

    Lists rather than tuples so the result is plain JSON. ``scopes`` is not on
    the wire; see :data:`_PAYLOAD_FIELDS`.
    """

    out: dict[str, Any] = {}
    for field in _PAYLOAD_FIELDS:
        value = getattr(principal, field)
        out[field] = list(value) if isinstance(value, tuple) else value
    return out


def principal_from_payload(payload: Mapping[str, Any]) -> Principal:
    """Rebuild a principal from :func:`principal_payload`.

    The inverse, used by the MCP boundary, which never touches
    ``clients.database``. ``scopes`` is reconstructed, not read: an agent
    principal always holds exactly :data:`AGENT_SCOPES`, and an ``operator`` or
    ``anonymous`` kind on the wire is the unbounded caller the server itself
    resolved, so it gets :data:`auth.FULL_SCOPE_SET`.

    An unknown ``kind`` is refused rather than defaulted: a payload this
    function cannot interpret must not become a principal.
    """

    kind = str(payload.get("kind") or "")
    if kind not in ("operator", "terminal", "run", "anonymous"):
        raise ValueError(f"unknown principal kind {kind!r}")
    scopes = (
        frozenset(FULL_SCOPE_SET) if kind in ("operator", "anonymous") else frozenset(AGENT_SCOPES)
    )
    return Principal(
        kind=kind,  # type: ignore[arg-type]
        scopes=scopes,
        terminal_id=payload.get("terminal_id"),
        session_name=payload.get("session_name"),
        agent_profile=payload.get("agent_profile"),
        role=payload.get("role"),
        allowed_tools=_as_tuple(payload.get("allowed_tools")),
        delegate_tools=_as_tuple(payload.get("delegate_tools")),
        creator_id=payload.get("creator_id"),
        ancestors=_as_tuple(payload.get("ancestors")),
        run_id=payload.get("run_id"),
        ephemeral=bool(payload.get("ephemeral")),
        allowlist_resolved=bool(payload.get("allowlist_resolved", True)),
    )


# --- FastAPI dependency ---------------------------------------------------


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _resolve_terminal_token(token: str) -> Principal:
    from cli_agent_orchestrator.clients import database

    row = database.get_terminal_by_credential_digest(digest_of(token))
    if row is None or bool(getattr(row, "deferred_init_runtime_reclaimed", False)):
        raise _unauthorized("terminal credential revoked")
    return principal_from_terminal_row(row)


def _resolve_run_token(token: str) -> Principal:
    """Resolve a ``cao_r_`` bearer through ``security.run_tokens`` when present.

    The run-token registry is the #829 branch's module; on a branch without it
    every run bearer is refused. When present, ``resolve(token)`` yields the
    ``run_id``; the spawning terminal is attached when the registry exposes
    ``terminal_id_for(run_id)`` (an attenuation of that terminal's principal),
    otherwise the run principal carries the run id alone.
    """

    try:
        from cli_agent_orchestrator.security import run_tokens  # type: ignore[attr-defined]
    except ImportError:
        raise _unauthorized("run credentials are not supported on this server")

    run_id = run_tokens.resolve(token[len(RUN_TOKEN_PREFIX) :]) or run_tokens.resolve(token)
    if not run_id:
        raise _unauthorized("run credential revoked")

    base: Optional[Principal] = None
    terminal_for = getattr(run_tokens, "terminal_id_for", None)
    if callable(terminal_for):
        spawning = terminal_for(run_id)
        if spawning:
            row = _row_by_id(str(spawning))
            if row is not None:
                base = principal_from_terminal_row(row)

    if base is None:
        return Principal(kind="run", scopes=AGENT_SCOPES, run_id=str(run_id))
    return Principal(
        kind="run",
        scopes=AGENT_SCOPES,
        terminal_id=base.terminal_id,
        session_name=base.session_name,
        agent_profile=base.agent_profile,
        role=base.role,
        allowed_tools=base.allowed_tools,
        delegate_tools=base.delegate_tools,
        creator_id=base.creator_id,
        ancestors=base.ancestors,
        run_id=str(run_id),
        ephemeral=base.ephemeral,
        allowlist_resolved=base.allowlist_resolved,
    )


async def get_current_principal(request: Request) -> Principal:
    """FastAPI dependency resolving the request's bearer to a :class:`Principal`.

    Resolution order:

    1. ``cao_t_`` bearer: terminal row by credential digest; missing or closed
       row is 401 ``terminal credential revoked``. Scopes are read+write,
       never admin.
    2. ``cao_r_`` bearer: via ``security.run_tokens`` when that module exists,
       else 401.
    3. Anything else goes through :func:`security.auth.get_current_scopes`
       unchanged: with auth enabled a valid operator token / IdP JWT is an
       ``operator`` principal with the token's scopes; with auth disabled the
       caller is ``anonymous`` with :data:`FULL_SCOPE_SET`. A request today's
       dependency accepts is never refused here.
    """

    authorization = request.headers.get("authorization")
    token = auth._extract_bearer(authorization)

    if token and token.startswith(TERMINAL_TOKEN_PREFIX):
        return _resolve_terminal_token(token)
    if token and token.startswith(RUN_TOKEN_PREFIX):
        return _resolve_run_token(token)

    scopes = await auth.get_current_scopes(authorization)
    if not auth.is_auth_enabled():
        return Principal(kind="anonymous", scopes=frozenset(FULL_SCOPE_SET))
    return Principal(kind="operator", scopes=frozenset(scopes))


def require_principal() -> Callable[..., Any]:
    """Dependency factory: ``principal: Principal = Depends(require_principal())``."""

    async def _dep(principal: Principal = Depends(get_current_principal)) -> Principal:
        return principal

    return _dep
