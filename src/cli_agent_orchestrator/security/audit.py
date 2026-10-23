"""Authorization audit log: one JSON line per decision (#965).

The file is ``CAO_HOME_DIR/logs/authz.jsonl``. What it records, and why each
part is there rather than being "nice to have":

* **Refusals always; allows for AGENT principals by default.** The asymmetry is
  the point. Warn mode exists to answer two questions -- what would enforcement
  refuse, and what is legitimately happening today -- and with only refusals
  recorded, an agent that dropped its credential and sailed through as the
  operator produced no line at all. The population of operator-authority agents
  nobody could see stayed invisible precisely because nothing logged success.
  Logging every OPERATOR allow instead would bury that signal under the
  operator's own traffic (the web UI polls these routes continuously), so the
  rule is per-kind. ``CAO_AUTHZ_AUDIT_ALLOWS=1`` still forces everything on.
* **``request_id``** so two decisions from one HTTP request are correlatable
  (``_effective_caller_id`` then ``TERMINAL_CREATE``, say). Set by
  :func:`request_scope`; ``None`` outside one, because an in-process call site
  is not a request and a synthetic id would be a lie.
* **``outcome``** because ``allowed: false`` cannot distinguish "refused" from
  "warn mode recorded what it would have refused and let it through" -- the
  difference between a blocked call and a successful one.
* **Size-capped rotation** (``CAO_AUTHZ_AUDIT_MAX_BYTES``, default 10 MiB,
  ``CAO_AUTHZ_AUDIT_KEEP`` generations, default 3). Unbounded growth makes a
  control into an outage, and :func:`read_recent` reads the file to slice a tail.
* **Counted write failures** (:func:`write_failures`, :func:`stats`) because a
  trail that stops must say so. Swallowed at debug, it just stops.

Writing still never raises: an audit failure must not become a
denial-of-service lever against the thing it observes.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from cli_agent_orchestrator.security.authz import Decision
from cli_agent_orchestrator.security.principal import Principal

logger = logging.getLogger(__name__)

AUDIT_FILE_NAME = "authz.jsonl"

#: Default size cap for the live file before it rotates.
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
#: Default number of rotated generations kept (``authz.jsonl.1`` ... ``.3``).
DEFAULT_KEEP = 3
#: Rotation happens AFTER the line that crossed the cap is written, never
#: mid-line: a half-written JSON object is worse than a slightly oversized
#: file. The live file can therefore exceed the cap by at most one line, and the
#: tests allow for exactly that.
MAX_LINE_SLACK = 64 * 1024

#: Kinds whose ALLOWED decisions are recorded without ``CAO_AUTHZ_AUDIT_ALLOWS``.
_AGENT_KINDS = frozenset({"terminal", "run"})

#: Correlation id for the decisions of one request. A ContextVar rather than a
#: thread local because FastAPI handlers are coroutines and
#: ``asyncio.to_thread`` hops are routine here; a ContextVar follows both.
_request_id: ContextVar[Optional[str]] = ContextVar("cao_authz_request_id", default=None)

#: Write failures since process start (or :func:`reset_write_failures`). Guarded
#: because ``record`` is called from the event loop and from worker threads.
_write_failures = 0
_write_failures_lock = threading.Lock()


def audit_path() -> Path:
    """``CAO_HOME_DIR/logs/authz.jsonl``, honouring the env var at call time."""

    raw = os.environ.get("CAO_HOME_DIR", "").strip()
    if raw:
        home = Path(raw).expanduser()
    else:
        from cli_agent_orchestrator.constants import CAO_HOME_DIR

        home = CAO_HOME_DIR
    return home / "logs" / AUDIT_FILE_NAME


def _int_env(name: str, default: int) -> int:
    """A non-negative integer from the environment, or ``default``.

    A malformed value falls back rather than raising or disabling: an operator
    typo in a rotation setting must not silently turn rotation off, which is the
    failure mode that lets a log eat a disk.
    """

    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("ignoring malformed %s=%r; using %d", name, raw, default)
        return default
    return value if value >= 0 else default


def max_bytes() -> int:
    """Live-file size cap. ``0`` disables rotation."""

    return _int_env("CAO_AUTHZ_AUDIT_MAX_BYTES", DEFAULT_MAX_BYTES)


def keep_generations() -> int:
    """How many rotated generations to keep. ``0`` deletes on rotation."""

    return _int_env("CAO_AUTHZ_AUDIT_KEEP", DEFAULT_KEEP)


def _audit_allows() -> bool:
    return os.getenv("CAO_AUTHZ_AUDIT_ALLOWS", "").strip().lower() in ("1", "true")


# --- request correlation ----------------------------------------------------


@contextmanager
def request_scope(request_id: Optional[str] = None) -> Iterator[str]:
    """Tag every decision recorded inside the block with one ``request_id``.

    Restores the previous value on exit, exception included, so a raised 403
    (the enforcing path) cannot leak the id into whatever runs next on the same
    task.
    """

    value = request_id or secrets.token_hex(8)
    token = _request_id.set(value)
    try:
        yield value
    finally:
        _request_id.reset(token)


def current_request_id() -> Optional[str]:
    """The active :func:`request_scope` id, or ``None``."""

    return _request_id.get()


# --- write-failure accounting -----------------------------------------------


def write_failures() -> int:
    """Audit writes that failed since process start / last reset."""

    with _write_failures_lock:
        return _write_failures


def reset_write_failures() -> None:
    """Zero the counter. For tests and for a reader that has reported it."""

    global _write_failures
    with _write_failures_lock:
        _write_failures = 0


def _note_write_failure() -> None:
    global _write_failures
    with _write_failures_lock:
        _write_failures += 1


def stats() -> Dict[str, Any]:
    """Health summary a caller can surface: failure count and the live path.

    A number nothing can read is the same as no number, which is what the
    previous debug-level swallow amounted to.
    """

    return {"write_failures": write_failures(), "path": str(audit_path())}


# --- the record -------------------------------------------------------------


def _outcome(decision: Decision, enforced: bool) -> str:
    """``allowed`` | ``refused`` | ``audited``.

    ``audited`` is warn mode: the decision was a denial AND the call proceeded.
    Without this field a reader cannot tell a blocked call from a successful one,
    which is the single most important thing a warn-mode trail has to say.
    """

    if decision.allowed:
        return "allowed"
    return "refused" if enforced else "audited"


def _should_record(principal: Principal, decision: Decision) -> bool:
    if not decision.allowed:
        return True
    return principal.kind in _AGENT_KINDS or _audit_allows()


def _rotate(path: Path, keep: int) -> None:
    """``authz.jsonl`` -> ``.1``, ``.1`` -> ``.2``, ... dropping past ``keep``.

    Oldest first so no generation is overwritten before it has been shifted.
    ``keep=0`` means the live file is simply truncated away.
    """

    if keep <= 0:
        path.unlink(missing_ok=True)
        return
    oldest = path.with_name(f"{path.name}.{keep}")
    oldest.unlink(missing_ok=True)
    for index in range(keep - 1, 0, -1):
        source = path.with_name(f"{path.name}.{index}")
        if source.exists():
            os.replace(source, path.with_name(f"{path.name}.{index + 1}"))
    os.replace(path, path.with_name(f"{path.name}.1"))


def _maybe_rotate() -> None:
    """Rotate when the live file has reached :func:`max_bytes`. Never raises.

    A rotation failure (a full disk, a read-only mount, a racing writer) is
    counted and otherwise ignored: the line that follows is worth more than a
    tidy file, and an audit failure must not become a lever against the thing it
    observes.
    """

    cap = max_bytes()
    if cap <= 0:
        return
    try:
        path = audit_path()
        if path.exists() and path.stat().st_size >= cap:
            _rotate(path, keep_generations())
    except Exception:  # noqa: BLE001  (a full disk must not break authorization)
        _note_write_failure()
        logger.debug("authz audit rotation failed", exc_info=True)


def record(
    principal: Principal,
    action: str,
    resource_repr: str,
    decision: Decision,
    enforced: bool,
) -> None:
    """Rotate if the file has reached its cap, then append one line.

    Rotation runs BEFORE the append, not after, so the live file always exists
    and always holds the newest line -- a reader (or :func:`read_recent`) never
    arrives in the window where the log was just renamed away. The cap is
    therefore "rotate once the file has reached this size", and the live file
    exceeds it by at most the one line that crossed it, never mid-line.

    Both halves are guarded independently: a rotation that fails must not lose
    the line, so it is counted and the append still happens.
    """

    if not _should_record(principal, decision):
        return
    _maybe_rotate()
    line = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "request_id": current_request_id(),
        "kind": principal.kind,
        "terminal_id": principal.terminal_id,
        "run_id": principal.run_id,
        "action": action,
        "resource": resource_repr,
        "allowed": decision.allowed,
        "enforced": enforced,
        "outcome": _outcome(decision, enforced),
        "rule": decision.rule,
        "reason": decision.reason,
    }
    try:
        path = audit_path()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, separators=(",", ":")) + "\n")
    except Exception:  # noqa: BLE001  (audit must never take the request down)
        _note_write_failure()
        logger.debug("authz audit write failed", exc_info=True)


def read_recent(n: int = 100) -> List[dict[str, Any]]:
    """Return the last ``n`` audit records (oldest first). Missing file = ``[]``.

    Reads only the LIVE file, not rotated generations: this is a tail for an
    operator or a test, not a query interface, and rotation means the live file
    is bounded by :func:`max_bytes`.
    """

    path = audit_path()
    if n <= 0 or not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out: List[dict[str, Any]] = []
    for raw in lines[-n:]:
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except ValueError:
            continue
    return out
