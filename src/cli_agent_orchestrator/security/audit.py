"""Authorization audit log: one JSON line per decision (#965).

Refusals are always recorded; allows only when ``CAO_AUTHZ_AUDIT_ALLOWS=1``.
The file is ``CAO_HOME_DIR/logs/authz.jsonl``. Writing never raises: an audit
failure is logged at debug and the request proceeds, because the audit trail
must not become a denial-of-service lever against the thing it observes.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List

from cli_agent_orchestrator.security.authz import Decision
from cli_agent_orchestrator.security.principal import Principal

logger = logging.getLogger(__name__)

AUDIT_FILE_NAME = "authz.jsonl"


def audit_path() -> Path:
    """``CAO_HOME_DIR/logs/authz.jsonl``, honouring the env var at call time."""

    raw = os.environ.get("CAO_HOME_DIR", "").strip()
    if raw:
        home = Path(raw).expanduser()
    else:
        from cli_agent_orchestrator.constants import CAO_HOME_DIR

        home = CAO_HOME_DIR
    return home / "logs" / AUDIT_FILE_NAME


def _audit_allows() -> bool:
    return os.getenv("CAO_AUTHZ_AUDIT_ALLOWS", "").strip().lower() in ("1", "true")


def record(
    principal: Principal,
    action: str,
    resource_repr: str,
    decision: Decision,
    enforced: bool,
) -> None:
    """Append one line. Always for refusals; for allows only when flagged."""

    if decision.allowed and not _audit_allows():
        return
    line = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "kind": principal.kind,
        "terminal_id": principal.terminal_id,
        "run_id": principal.run_id,
        "action": action,
        "resource": resource_repr,
        "allowed": decision.allowed,
        "enforced": enforced,
        "rule": decision.rule,
        "reason": decision.reason,
    }
    try:
        path = audit_path()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, separators=(",", ":")) + "\n")
    except Exception:  # noqa: BLE001  (audit must never take the request down)
        logger.debug("authz audit write failed", exc_info=True)


def read_recent(n: int = 100) -> List[dict[str, Any]]:
    """Return the last ``n`` audit records (oldest first). Missing file = ``[]``."""

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
