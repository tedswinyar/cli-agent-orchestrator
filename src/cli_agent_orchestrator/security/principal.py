"""Per-terminal principal: who is calling, resolved once at one chokepoint (#965).

Today every CAO surface shares one bearer (or none) and "who is calling" is a
self-asserted ``caller_id`` / ``CAO_TERMINAL_ID``. This module gives each
terminal an identity the *server* issued and can verify:

* :func:`mint_terminal_credential` returns a ``cao_t_`` token and its SHA-256
  digest; only the digest is stored (``terminals.credential_digest``), so a
  database read never yields a usable credential.
* :func:`principal_from_terminal_row` turns a terminal row into a frozen
  :class:`Principal` carrying the row's allowlist, delegation ceiling, creator
  and ancestry (``caller_id`` followed up the table, bounded, cycle-safe).
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
from typing import Any, Callable, Literal, Optional, Tuple

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


def principal_from_terminal_row(row: Any) -> Principal:
    """Build a ``terminal`` principal from a ``TerminalModel`` row.

    Fresh each call, no caching: the row is the source of truth and a
    principal is a snapshot of it at resolve time. ``delegate_tools`` (#948) is
    read when the row has it and is empty otherwise, which the policy layer
    reads as "ceiling = own allowlist".
    """

    terminal_id = str(row.id)
    caller_id = getattr(row, "caller_id", None)
    creator = str(caller_id) if caller_id else None
    return Principal(
        kind="terminal",
        scopes=AGENT_SCOPES,
        terminal_id=terminal_id,
        session_name=getattr(row, "tmux_session", None),
        agent_profile=getattr(row, "agent_profile", None),
        role=getattr(row, "role", None),
        allowed_tools=_as_tuple(getattr(row, "allowed_tools", None)),
        delegate_tools=_as_tuple(getattr(row, "delegate_tools", None)),
        creator_id=creator,
        ancestors=_ancestry(terminal_id, creator),
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
