#!/usr/bin/env python3
"""Agent-principal demo (#965): the six refusals, end to end, against an isolated cao-server.

Starts a real ``cao-server`` in a throwaway ``CAO_HOME_DIR`` on a free port, creates two
terminals through the HTTP API with the credential-free ``mock_cli`` provider (a real tmux
pane each, so the per-terminal ``CAO_TERMINAL_TOKEN`` is minted and injected exactly as it
is for a real agent), reads each terminal's token back out of its pane environment, and then
drives every surface the proposal gates **as those terminals**:

    0  the minted credentials resolve (and a forged one is 401)
    a  terminal A names terminal B as ``caller_id`` on a create      -> terminal:impersonation
    b1 terminal A (tools: [fs_read]) calls ``memory_forget``         -> tool:default-deny (hard)
    b2 terminal A calls ``send_message``                              -> callback, allowed
    c  terminal B cancels a workflow run terminal A started           -> run:not-owner
    d  the operator cancels the same run                              -> allowed
    e  terminal A calls an ops-server tool (``list_sessions``)        -> fleet:operator-only

The whole sequence runs twice, each time against its own fresh server: once with
``CAO_PRINCIPAL_ENFORCE=1`` (refusals) and once with the flag unset (warn mode: audit lines,
no refusals). The one exception is step b1: the ``cao-mcp-server`` allowlist gate is the
``on_call_tool`` middleware main's #972 shipped, so that denial is hard in BOTH modes, and
the audit line says ``enforced: true`` either way. That difference is the talking point.

Steps b1, b2 and e drive the real MCP server processes (``cao-mcp-server`` and
``cao-ops-mcp-server``) over stdio with a FastMCP client, with ``CAO_TERMINAL_ID`` and
``CAO_TERMINAL_TOKEN`` set in their environment exactly as the agent pane would have them.
No real coding agent is involved anywhere.

Every step prints the request, the response and the ``logs/authz.jsonl`` lines it produced,
then compares the observed outcome with the expected one. The process exits non-zero if any
step differs. ``--json`` emits the same information as a JSON array (one object per step).

Usage (from the repository root, inside the project venv)::

    uv run --no-sync python scripts/demo_agent_principal.py            # plain text
    uv run --no-sync python scripts/demo_agent_principal.py --json     # machine-readable
    uv run --no-sync python scripts/demo_agent_principal.py --mode enforce

Requirements: ``tmux`` on PATH (the server creates real panes). Nothing else: the
``mock_cli`` provider needs no credentials, no network and no model.

``test/e2e/test_agent_principal_demo.py`` runs this script and pins every expected outcome;
that test is the structural guard for the demo.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
MOCK_CLI_BIN_DIR = REPO_ROOT / "test" / "providers" / "fixtures" / "bin"

MODES = ("enforce", "warn")
HEALTH_TIMEOUT_S = 30.0
TERMINAL_CREATE_TIMEOUT_S = 90.0
HTTP_TIMEOUT_S = 30.0
AUDIT_SETTLE_S = 1.5
RUN_STATE_SETTLE_S = 8.0

WORKER_PROFILE = "demo_worker"
SUPERVISOR_PROFILE = "demo_supervisor"
HOLD_WORKFLOW = "demo_hold"

# Environment that must never leak from the operator's shell into the demo servers.
_SCRUBBED_ENV = (
    "AUTH0_DOMAIN",
    "AUTH0_AUDIENCE",
    "CAO_AUTH_JWKS_URI",
    "CAO_AUTH_LOCAL_TOKEN",
    "CAO_AUTH_ISSUER",
    "CAO_AUTH_AUDIENCE",
    "CAO_PRINCIPAL_ENFORCE",
    "CAO_AUTHZ_AUDIT_ALLOWS",
    "CAO_TERMINAL_ID",
    "CAO_TERMINAL_TOKEN",
    "CAO_HOME_DIR",
    "CAO_API_PORT",
    "CAO_API_HOST",
    "CAO_TERMINAL_BACKEND",
    "CAO_WORKFLOW_REQUIRE_APPROVAL",
)

_WORKER_PROFILE_MD = f"""---
name: {WORKER_PROFILE}
description: Restricted worker for the agent-principal demo (allowedTools fs_read only)
allowedTools:
  - fs_read
mcpServers:
  cao-mcp-server:
    type: stdio
    command: cao-mcp-server
    args: []
---

# Demo worker

You are a restricted worker. You may read files and report back with send_message.
"""

_SUPERVISOR_PROFILE_MD = f"""---
name: {SUPERVISOR_PROFILE}
description: Supervisor-like profile for the agent-principal demo (grants @cao-mcp-server)
allowedTools:
  - fs_read
  - execute_bash
  - "@cao-mcp-server"
mcpServers:
  cao-mcp-server:
    type: stdio
    command: cao-mcp-server
    args: []
---

# Demo supervisor

You coordinate workers through the cao-mcp-server tools.
"""

# A script-tier workflow that holds so the run is still RUNNING when it is cancelled.
# ``time`` earns a nondeterminism WARNING from the lint gate; warnings never block.
_HOLD_WORKFLOW_PY = "import time\n\ntime.sleep(600)\n"


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class StepResult:
    mode: str
    step: str
    title: str
    request: str
    response: str
    audit: List[Dict[str, Any]]
    expected: Dict[str, Any]
    observed: Dict[str, Any]
    ok: bool
    note: str = ""


def evaluate(expected: Dict[str, Any], observed: Dict[str, Any]) -> bool:
    """A step passes iff every expected key is present in ``observed`` with an equal value."""

    return all(key in observed and observed[key] == value for key, value in expected.items())


def exit_code_for(steps: List[StepResult]) -> int:
    """0 when every step matched its expectation, 1 otherwise."""

    return 0 if steps and all(s.ok for s in steps) else 1


# ---------------------------------------------------------------------------
# The isolated server
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _tail(path: Path, lines: int = 40) -> str:
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-lines:])
    except OSError:
        return "<no log>"


@dataclass
class DemoServer:
    mode: str
    home: Path
    cao_home: Path
    port: int
    url: str
    process: subprocess.Popen  # type: ignore[type-arg]
    log_path: Path
    audit_path: Path
    sessions: List[str] = field(default_factory=list)
    _audit_seen: int = 0

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"

    def child_env(self, terminal_id: str, token: str) -> Dict[str, str]:
        """Environment for an MCP server process launched 'inside' a terminal.

        The MCP stdio client merges this over a minimal default environment, so every
        variable the servers read is spelled out: where the API is, which home the audit
        log lives in, and the identity the pane would carry.
        """

        env = {
            "HOME": str(self.home),
            "PATH": os.environ.get("PATH", ""),
            "CAO_HOME_DIR": str(self.cao_home),
            "CAO_API_HOST": "127.0.0.1",
            "CAO_API_PORT": str(self.port),
            "CAO_A2A_DISABLED": "true",
            "OTEL_SDK_DISABLED": "true",
            "PYTHONUNBUFFERED": "1",
            "CAO_AUTHZ_AUDIT_ALLOWS": "1",
            "CAO_TERMINAL_ID": terminal_id,
            "CAO_TERMINAL_TOKEN": token,
        }
        if self.enforcing:
            env["CAO_PRINCIPAL_ENFORCE"] = "1"
        return env

    def new_audit_lines(self, *, expect_some: bool) -> List[Dict[str, Any]]:
        """Audit records appended since the previous call (the MCP processes share the file)."""

        deadline = time.monotonic() + AUDIT_SETTLE_S
        while True:
            lines = self._read_audit()
            fresh = lines[self._audit_seen :]
            if fresh or not expect_some or time.monotonic() >= deadline:
                if not fresh and not expect_some:
                    time.sleep(0.3)
                    lines = self._read_audit()
                    fresh = lines[self._audit_seen :]
                self._audit_seen = len(lines)
                return fresh
            time.sleep(0.1)

    def _read_audit(self) -> List[Dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        out: List[Dict[str, Any]] = []
        for raw in self.audit_path.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if raw:
                with contextlib.suppress(ValueError):
                    out.append(json.loads(raw))
        return out

    def stop(self, *, keep_home: bool) -> None:
        for name in self.sessions:
            with contextlib.suppress(Exception):
                requests.delete(f"{self.url}/sessions/{name}", timeout=HTTP_TIMEOUT_S)
        if self.process.poll() is None:
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                    os.killpg(self.process.pid, signal.SIGKILL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    self.process.wait(timeout=5)
        for name in self.sessions:  # backstop if the server did not get to it
            with contextlib.suppress(Exception):
                subprocess.run(
                    ["tmux", "kill-session", "-t", name],
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
        if not keep_home:
            shutil.rmtree(self.home, ignore_errors=True)


def _seed_home(cao_home: Path) -> None:
    cao_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Approval enforcement is a plan-identity feature, not what this demo is about; a
    # settings file is the only way to turn it off (the env var can only turn it on).
    (cao_home / "settings.json").write_text(
        json.dumps({"workflow": {"require_approval": False}}, indent=2), encoding="utf-8"
    )
    store = cao_home / "agent-store"
    store.mkdir(parents=True, exist_ok=True)
    (store / f"{WORKER_PROFILE}.md").write_text(_WORKER_PROFILE_MD, encoding="utf-8")
    (store / f"{SUPERVISOR_PROFILE}.md").write_text(_SUPERVISOR_PROFILE_MD, encoding="utf-8")
    workflows = cao_home / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / f"{HOLD_WORKFLOW}.py").write_text(_HOLD_WORKFLOW_PY, encoding="utf-8")


def start_server(mode: str) -> DemoServer:
    """Spawn one isolated cao-server for ``mode`` and wait for ``/health``.

    Mirrors ``test/fixtures/cao_server.py``: redirected ``HOME``, explicit ``CAO_HOME_DIR``,
    free port, A2A and OTel off, operator auth off (the operator is the default-off
    anonymous caller). ``mock_cli`` is put on PATH so the panes can launch it.
    """

    if shutil.which("tmux") is None:
        raise RuntimeError("tmux is required: the server creates a real pane per terminal")
    home = Path(tempfile.mkdtemp(prefix=f"cao-principal-demo-{mode}-"))
    cao_home = home / ".aws" / "cli-agent-orchestrator"
    _seed_home(cao_home)
    port = _free_port()

    env = os.environ.copy()
    for key in _SCRUBBED_ENV:
        env.pop(key, None)
    env.update(
        {
            "HOME": str(home),
            "CAO_HOME_DIR": str(cao_home),
            "CAO_API_HOST": "127.0.0.1",
            "CAO_API_PORT": str(port),
            "CAO_A2A_DISABLED": "true",
            "OTEL_SDK_DISABLED": "true",
            "PYTHONUNBUFFERED": "1",
            "CAO_AUTHZ_AUDIT_ALLOWS": "1",
            "PATH": f"{MOCK_CLI_BIN_DIR}{os.pathsep}{env.get('PATH', '')}",
        }
    )
    if mode == "enforce":
        env["CAO_PRINCIPAL_ENFORCE"] = "1"

    log_path = home / "server.log"
    log_handle = open(log_path, "ab")  # noqa: SIM115 - lifetime is the server's
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "cli_agent_orchestrator.api.main",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    url = f"http://127.0.0.1:{port}"
    server = DemoServer(
        mode=mode,
        home=home,
        cao_home=cao_home,
        port=port,
        url=url,
        process=process,
        log_path=log_path,
        audit_path=cao_home / "logs" / "authz.jsonl",
    )
    deadline = time.monotonic() + HEALTH_TIMEOUT_S
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"cao-server exited with {process.returncode} before /health:\n{_tail(log_path)}"
            )
        try:
            r = requests.get(f"{url}/health", timeout=0.5)
            if r.status_code == 200 and r.json().get("status") == "ok":
                return server
        except (requests.ConnectionError, requests.Timeout):
            pass
        time.sleep(0.1)
    server.stop(keep_home=True)
    raise RuntimeError(f"cao-server not healthy after {HEALTH_TIMEOUT_S}s:\n{_tail(log_path)}")


# ---------------------------------------------------------------------------
# Terminals and credentials
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Term:
    label: str
    terminal_id: str
    session: str
    profile: str
    token: str

    @property
    def headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    @property
    def short(self) -> str:
        return f"{self.label} ({self.terminal_id}, {self.profile})"


def _bearer_repr(token: Optional[str]) -> str:
    if not token:
        return "no bearer (operator, auth off)"
    return f"Bearer {token[:10]}...  (len {len(token)})"


def _token_from_pane(session_name: str) -> str:
    """Read the injected ``CAO_TERMINAL_TOKEN`` from the pane's tmux session environment.

    ``create_session`` sets the token with ``new-session -e``, so for the first terminal of a
    session it is the session environment. That is the same place the agent process reads
    it from; the demo takes the credential from where it was injected, not from the DB.
    """

    out = subprocess.run(
        ["tmux", "show-environment", "-t", session_name, "CAO_TERMINAL_TOKEN"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout.strip()
    key, sep, value = out.partition("=")
    if key != "CAO_TERMINAL_TOKEN" or not sep or not value.startswith("cao_t_"):
        raise RuntimeError(f"no terminal token in tmux session {session_name!r}: {out!r}")
    return value


def create_terminal(server: DemoServer, label: str, profile: str) -> Term:
    """``POST /sessions`` as the operator; one new tmux session with one ``mock_cli`` pane."""

    session_name = f"caodemo-{label.lower()}-{uuid.uuid4().hex[:6]}"
    resp = requests.post(
        f"{server.url}/sessions",
        params={"provider": "mock_cli", "agent_profile": profile, "session_name": session_name},
        timeout=TERMINAL_CREATE_TIMEOUT_S,
    )
    if resp.status_code != 201:
        raise RuntimeError(
            f"creating terminal {label} failed: HTTP {resp.status_code} {resp.text[:300]}\n"
            f"server log tail:\n{_tail(server.log_path)}"
        )
    data = resp.json()
    server.sessions.append(data["session_name"])
    token = _token_from_pane(data["session_name"])
    return Term(label, data["id"], data["session_name"], profile, token)


def create_worker_of(server: DemoServer, creator: Term, label: str) -> str:
    """A terminal whose recorded ``caller_id`` is ``creator`` (what ``assign`` records)."""

    resp = requests.post(
        f"{server.url}/sessions/{creator.session}/terminals",
        params={
            "provider": "mock_cli",
            "agent_profile": WORKER_PROFILE,
            "caller_id": creator.terminal_id,
            "defer_init": "true",
        },
        timeout=TERMINAL_CREATE_TIMEOUT_S,
    )
    if resp.status_code != 201:
        raise RuntimeError(f"creating {label} failed: HTTP {resp.status_code} {resp.text[:300]}")
    return str(resp.json()["id"])


# ---------------------------------------------------------------------------
# MCP calls (real server processes over stdio)
# ---------------------------------------------------------------------------


def _unwrap_tool_result(result: Any) -> Any:
    """The tool's return value as plain JSON data (dict/list/str), whatever FastMCP wrapped it in."""

    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        # FastMCP wraps non-object returns as {"result": ...}; object returns come through as-is.
        return structured["result"] if set(structured) == {"result"} else structured
    data = getattr(result, "data", None)
    if data is not None:
        try:
            json.dumps(data)
            return data
        except TypeError:
            return str(data)
    content = getattr(result, "content", None) or []
    for block in content:
        text = getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except ValueError:
                return text
    return None


def call_mcp_tool(
    server: DemoServer, caller: Term, module: str, tool: str, args: Dict[str, Any]
) -> Tuple[str, Any]:
    """Call ``tool`` on the MCP server ``module`` as ``caller``. Returns ``(verdict, payload)``.

    ``verdict`` is ``"denied"`` when the server answered with a tool error (the gate's
    channel) and ``"allowed"`` when the tool body ran and returned a result.
    """

    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport
    from fastmcp.exceptions import ToolError

    log_file = server.home / f"mcp-{module.rsplit('.', 2)[-2]}-{tool}.log"
    transport = StdioTransport(
        command=sys.executable,
        args=["-m", module],
        env=server.child_env(caller.terminal_id, caller.token),
        log_file=log_file,
    )

    async def go() -> Tuple[str, Any]:
        async with Client(transport) as client:
            try:
                result = await client.call_tool(tool, args)
            except ToolError as exc:
                return "denied", str(exc)
            return "allowed", _unwrap_tool_result(result)

    return asyncio.run(go())


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _http(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
) -> requests.Response:
    return requests.request(
        method, url, headers=headers, params=params, json=json_body, timeout=HTTP_TIMEOUT_S
    )


def _body_excerpt(resp: requests.Response, limit: int = 400) -> str:
    try:
        text = json.dumps(resp.json(), separators=(",", ":"), sort_keys=True)
    except ValueError:
        text = resp.text
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _http_repr(resp: requests.Response) -> str:
    return f"HTTP {resp.status_code} {_body_excerpt(resp)}"


def _first_refusal(lines: List[Dict[str, Any]]) -> Dict[str, Any]:
    for line in lines:
        if not line.get("allowed", True):
            return line
    return {}


def _run_state(server: DemoServer, run_id: str, want: str) -> Optional[str]:
    """Poll the run inspection until ``want`` or the settle budget runs out; return the state."""

    deadline = time.monotonic() + RUN_STATE_SETTLE_S
    state: Optional[str] = None
    while time.monotonic() < deadline:
        resp = _http("GET", f"{server.url}/workflows/runs/{run_id}")
        state = resp.json().get("state") if resp.status_code == 200 else None
        if state == want:
            return state
        time.sleep(0.25)
    return state


# ---------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------


def step_0_credentials(server: DemoServer, a: Term, b: Term) -> StepResult:
    # The row as the API serves it (what the gates read): the recorded allowlists.
    row_a = _http("GET", f"{server.url}/terminals/{a.terminal_id}").json()
    row_b = _http("GET", f"{server.url}/terminals/{b.terminal_id}").json()
    # A route that resolves the principal, on a run that does not exist: a genuine
    # credential gets past authentication to the route's own 404; a forged one is 401.
    probe = f"{server.url}/workflows/runs/does-not-exist/cancel"
    ra = _http("POST", probe, headers=a.headers)
    rb = _http("POST", probe, headers=b.headers)
    forged = a.token[:-4] + ("AAAA" if not a.token.endswith("AAAA") else "BBBB")
    rf = _http("POST", probe, headers={"Authorization": f"Bearer {forged}"})
    audit = server.new_audit_lines(expect_some=False)
    expected = {
        "a_token_accepted": 404,
        "b_token_accepted": 404,
        "forged_token": 401,
        "forged_detail": "terminal credential revoked",
        "audit_lines": 0,
    }
    observed = {
        "a_token_accepted": ra.status_code,
        "b_token_accepted": rb.status_code,
        "forged_token": rf.status_code,
        "forged_detail": rf.json().get("detail") if rf.status_code == 401 else rf.text[:80],
        "audit_lines": len(audit),
    }
    return StepResult(
        mode=server.mode,
        step="0",
        title="The minted credentials resolve; a forged one does not",
        request=(
            f"POST /workflows/runs/does-not-exist/cancel as A [{_bearer_repr(a.token)}], "
            f"as B, and with a forged cao_t_ token (same length, last four characters changed)"
        ),
        response=(
            f"row A: allowed_tools={row_a.get('allowed_tools')} caller_id={row_a.get('caller_id')}"
            f"\nrow B: allowed_tools={row_b.get('allowed_tools')}"
            f"\nas A: {_http_repr(ra)}\nas B: {_http_repr(rb)}\nforged: {_http_repr(rf)}"
        ),
        audit=audit,
        expected=expected,
        observed=observed,
        ok=evaluate(expected, observed),
        note=(
            "Each token was read from the terminal's own tmux pane environment, where "
            "create_terminal injected it next to CAO_TERMINAL_ID; only the SHA-256 digest is in "
            "the terminals table. Resolution is a credential check: same in both modes, no "
            "audit line. The probe is a principal-resolving route on purpose: with operator "
            "auth off, a route that only has the scope dependency (GET /terminals/{id}) accepts "
            "any bearer as the anonymous operator, forged cao_t_ included."
        ),
    )


def step_a_impersonation(server: DemoServer, a: Term, b: Term) -> StepResult:
    resp = _http(
        "POST",
        f"{server.url}/sessions/{a.session}/terminals",
        headers=a.headers,
        params={
            "provider": "mock_cli",
            "agent_profile": WORKER_PROFILE,
            "caller_id": b.terminal_id,
            "defer_init": "true",
        },
    )
    audit = server.new_audit_lines(expect_some=True)
    refusal = _first_refusal(audit)
    mismatch_text = f"terminal {a.terminal_id} may not act as terminal {b.terminal_id}"
    if server.enforcing:
        expected: Dict[str, Any] = {
            "status": 403,
            "detail_names_mismatch": True,
            "audit_rule": "terminal:impersonation",
            "audit_enforced": True,
        }
        observed: Dict[str, Any] = {
            "status": resp.status_code,
            "detail_names_mismatch": mismatch_text in resp.text,
            "audit_rule": refusal.get("rule"),
            "audit_enforced": refusal.get("enforced"),
        }
        note = (
            "The 403 comes from _effective_caller_id before the service runs: nothing was "
            "allocated. The detail names both terminals and nothing else."
        )
    else:
        recorded = resp.json().get("caller_id") if resp.status_code == 201 else None
        expected = {
            "status": 201,
            "recorded_caller_is_A": True,
            "audit_rule": "terminal:impersonation",
            "audit_enforced": False,
        }
        observed = {
            "status": resp.status_code,
            "recorded_caller_is_A": recorded == a.terminal_id,
            "audit_rule": refusal.get("rule"),
            "audit_enforced": refusal.get("enforced"),
        }
        note = (
            "Warn mode: the create proceeds, but the credential wins over the claim: the new "
            "terminal's recorded caller_id is A, not B. The audit line records what enforcement "
            "would have refused (enforced: false)."
        )
    return StepResult(
        mode=server.mode,
        step="a",
        title="Terminal A names terminal B as caller_id on a create",
        request=(
            f"POST /sessions/{a.session}/terminals?provider=mock_cli&agent_profile="
            f"{WORKER_PROFILE}&caller_id={b.terminal_id}&defer_init=true  as A "
            f"[{_bearer_repr(a.token)}]"
        ),
        response=_http_repr(resp),
        audit=audit,
        expected=expected,
        observed=observed,
        ok=evaluate(expected, observed),
        note=note,
    )


def step_b1_memory_forget(server: DemoServer, a: Term) -> StepResult:
    verdict, payload = call_mcp_tool(
        server,
        a,
        "cli_agent_orchestrator.mcp_server.server",
        "memory_forget",
        {"key": "demo-key", "scope": "project"},
    )
    audit = server.new_audit_lines(expect_some=True)
    refusal = _first_refusal(audit)
    text = payload if isinstance(payload, str) else json.dumps(payload)
    expected = {
        "gate": "denied",
        "rule_in_text": True,
        "audit_rule": "tool:default-deny",
        "audit_enforced": True,
    }
    observed = {
        "gate": verdict,
        "rule_in_text": "'memory_forget' is not permitted (tool:default-deny)" in text,
        "audit_rule": refusal.get("rule"),
        "audit_enforced": refusal.get("enforced"),
    }
    return StepResult(
        mode=server.mode,
        step="b1",
        title="Terminal A (allowedTools: [fs_read]) calls memory_forget on cao-mcp-server",
        request=(
            "MCP call memory_forget(key='demo-key', scope='project') on a real cao-mcp-server "
            f"process with CAO_TERMINAL_ID={a.terminal_id} and CAO_TERMINAL_TOKEN set "
            f"[{_bearer_repr(a.token)}]"
        ),
        response=f"ToolError: {text}" if verdict == "denied" else f"result: {text}",
        audit=audit,
        expected=expected,
        observed=observed,
        ok=evaluate(expected, observed),
        note=(
            "HARD IN BOTH MODES. #972's on_call_tool middleware is the gate for every "
            "cao-mcp-server tool; it asks _tool_denied_reason -> tool_gate.denial_for -> "
            "authz.check(hard=True), so CAO_PRINCIPAL_ENFORCE relaxes nothing here and the "
            "audit line says enforced: true even with the flag unset. The record fetch behind "
            "the decision presented A's own token (agent_credential()), not the operator's."
        ),
    )


def step_b2_send_message(server: DemoServer, a: Term, worker_id: str) -> StepResult:
    verdict, payload = call_mcp_tool(
        server,
        a,
        "cli_agent_orchestrator.mcp_server.server",
        "send_message",
        {"message": "hello from the demo", "receiver_id": worker_id},
    )
    audit = server.new_audit_lines(expect_some=True)
    success = isinstance(payload, dict) and payload.get("success") is True
    # The same question, asked of the pure policy function the gate decides with.
    from cli_agent_orchestrator.security.authz import CAO_MCP_SERVER, TOOL_CALL, authorize
    from cli_agent_orchestrator.security.principal import AGENT_SCOPES, Principal

    policy = authorize(
        Principal(
            kind="terminal",
            scopes=AGENT_SCOPES,
            terminal_id=a.terminal_id,
            allowed_tools=("fs_read",),
        ),
        TOOL_CALL,
        "send_message",
        server=CAO_MCP_SERVER,
    )
    text = payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True)
    # An ALLOWED agent call leaves lines now: with only refusals recorded, a
    # successful bypass left no trace at all, so warn mode could not reveal the
    # population it exists to reveal.
    #
    # The line is ``terminal:descendant``: the API binding the path id of
    # ``GET /terminals/{worker}`` -- the read ``_target_binding_denial`` makes
    # before delivering -- to A's credential. A's own terminal created the
    # worker, so the read is allowed and attributable.
    #
    # There is deliberately NO ``tool:callback`` line, and the absence is worth
    # seeing rather than papering over. The four callback tools do not reach
    # ``check()`` at all: #972's ``_AllowlistGate`` SKIPS them before asking
    # (``CALLBACK_EXEMPT_TOOLS``), so the allowance is a middleware skip, not an
    # audited decision. ``policy_rule`` below shows what the policy function
    # WOULD answer if asked. Auditing the skip is a behaviour change to #972's
    # gate, not part of fixing the audit log, so it is left as an open item.
    #
    # Asserting the SET rather than the first line is deliberate: "which line
    # came first" is not a contract.
    allowed_rules = sorted({line.get("rule") for line in audit if line.get("allowed")})
    refused_rules = sorted({line.get("rule") for line in audit if not line.get("allowed")})
    expected = {
        "gate": "allowed",
        "delivered": True,
        "audit_allowed_rules": ["terminal:descendant"],
        "audit_refused_rules": [],
        "policy_rule": "tool:callback",
    }
    observed = {
        "gate": verdict,
        "delivered": success,
        "audit_allowed_rules": allowed_rules,
        "audit_refused_rules": refused_rules,
        "policy_rule": policy.rule,
    }
    return StepResult(
        mode=server.mode,
        step="b2",
        title="Terminal A calls send_message (a worker callback) on cao-mcp-server",
        request=(
            f"MCP call send_message(message='hello from the demo', receiver_id={worker_id}) "
            f"on cao-mcp-server as A; {worker_id} is a terminal A created (caller_id=A)"
        ),
        response=(f"result: {text}" if verdict == "allowed" else f"ToolError: {text}")
        + f"\npolicy: authorize(A, tool:call, send_message) -> {policy.rule}: {policy.reason}",
        audit=audit,
        expected=expected,
        observed=observed,
        ok=evaluate(expected, observed),
        note=(
            "send_message is one of the four callbacks (authz.CALLBACK_TOOLS) a bounded worker "
            "needs to report upward. The middleware exempts them before consulting policy, so "
            "no audit line is written; authorize() answers tool:callback for the same question. "
            "The body then applied its own relationship rule (the receiver is a terminal A "
            "created) and delivered the message to the worker's inbox."
        ),
    )


def step_c_stranger_cancel(server: DemoServer, a: Term, b: Term) -> Tuple[StepResult, str]:
    run_id = f"demo-run-{uuid.uuid4().hex[:8]}"
    submit = _http(
        "POST",
        f"{server.url}/workflows/runs:submit",
        headers=a.headers,
        json_body={"name_or_path": HOLD_WORKFLOW, "inputs": {}, "run_id": run_id},
    )
    cancel = _http("POST", f"{server.url}/workflows/runs/{run_id}/cancel", headers=b.headers)
    audit = server.new_audit_lines(expect_some=True)
    refusal = _first_refusal(audit)
    owner_text = (
        f"run '{run_id}' is owned by terminal '{a.terminal_id}'; "
        f"terminal '{b.terminal_id}' may not cancel it"
    )
    if server.enforcing:
        state = _run_state(server, run_id, "running")
        expected: Dict[str, Any] = {
            "submit": 202,
            "cancel": 403,
            "detail_names_owner": True,
            "audit_rule": "run:not-owner",
            "audit_enforced": True,
            "run_state_after": "running",
        }
        observed: Dict[str, Any] = {
            "submit": submit.status_code,
            "cancel": cancel.status_code,
            "detail_names_owner": owner_text in cancel.text,
            "audit_rule": refusal.get("rule"),
            "audit_enforced": refusal.get("enforced"),
            "run_state_after": state,
        }
        note = (
            "The run row was stamped owner_terminal_id=A at the submit INSERT. B is neither "
            "the owner nor in A's frozen ancestor list, so run:not-owner refuses and the detail "
            "names the owner. The run is still running."
        )
    else:
        state = _run_state(server, run_id, "cancelled")
        expected = {
            "submit": 202,
            "cancel": 200,
            "audit_rule": "run:not-owner",
            "audit_enforced": False,
            "run_state_after": "cancelled",
        }
        observed = {
            "submit": submit.status_code,
            "cancel": cancel.status_code,
            "audit_rule": refusal.get("rule"),
            "audit_enforced": refusal.get("enforced"),
            "run_state_after": state,
        }
        note = (
            "Warn mode: B really cancelled A's run (today's behaviour). The audit line is the "
            "only trace that a stranger did it."
        )
    return (
        StepResult(
            mode=server.mode,
            step="c",
            title="Terminal B cancels a workflow run terminal A started",
            request=(
                f"POST /workflows/runs:submit {{name_or_path: {HOLD_WORKFLOW}, run_id: {run_id}}} "
                f"as A; then POST /workflows/runs/{run_id}/cancel as B [{_bearer_repr(b.token)}]"
            ),
            response=f"submit: {_http_repr(submit)[:160]}\ncancel: {_http_repr(cancel)}",
            audit=audit,
            expected=expected,
            observed=observed,
            ok=evaluate(expected, observed),
            note=note,
        ),
        run_id,
    )


def step_d_operator_cancel(server: DemoServer, run_id: str) -> StepResult:
    resp = _http("POST", f"{server.url}/workflows/runs/{run_id}/cancel")
    if server.enforcing:
        audit = server.new_audit_lines(expect_some=True)
        allow = audit[0] if audit else {}
        state = _run_state(server, run_id, "cancelled")
        expected: Dict[str, Any] = {
            "status": 200,
            "run_state_after": "cancelled",
            "audit_rule": "operator",
            "audit_allowed": True,
        }
        observed: Dict[str, Any] = {
            "status": resp.status_code,
            "run_state_after": state,
            "audit_rule": allow.get("rule"),
            "audit_allowed": allow.get("allowed"),
        }
        note = (
            "The operator (the default-off anonymous caller here; the shared bearer when auth "
            "is on) is unbounded. The same check() decided it, rule 'operator', and because "
            "this demo runs with CAO_AUTHZ_AUDIT_ALLOWS=1 the allow is on the record too."
        )
    else:
        audit = server.new_audit_lines(expect_some=True)
        allow = audit[0] if audit else {}
        expected = {"status": 409, "audit_rule": "operator", "audit_allowed": True}
        observed = {
            "status": resp.status_code,
            "audit_rule": allow.get("rule"),
            "audit_allowed": allow.get("allowed"),
        }
        note = (
            "Warn mode: the operator is allowed (rule 'operator', decided before the route "
            "looks at the run) and then gets 409, because step c already cancelled the run. "
            "There was nothing left for the operator to cancel: that is what 'audit only' costs."
        )
    return StepResult(
        mode=server.mode,
        step="d",
        title="The operator cancels the same run",
        request=f"POST /workflows/runs/{run_id}/cancel  as the operator [{_bearer_repr(None)}]",
        response=_http_repr(resp),
        audit=audit,
        expected=expected,
        observed=observed,
        ok=evaluate(expected, observed),
        note=note,
    )


def step_e_ops_tool(server: DemoServer, a: Term) -> StepResult:
    verdict, payload = call_mcp_tool(
        server, a, "cli_agent_orchestrator.ops_mcp_server.server", "list_sessions", {}
    )
    audit = server.new_audit_lines(expect_some=True)
    refusal = _first_refusal(audit)
    text = payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True)
    if server.enforcing:
        expected: Dict[str, Any] = {
            "gate": "denied",
            "rule_in_text": True,
            "audit_rule": "fleet:operator-only",
            "audit_enforced": True,
        }
        observed: Dict[str, Any] = {
            "gate": verdict,
            "rule_in_text": "'list_sessions' is not permitted (fleet:operator-only)" in text,
            "audit_rule": refusal.get("rule"),
            "audit_enforced": refusal.get("enforced"),
        }
        note = (
            "Every cao-ops-mcp-server tool is fleet:operator-only for a terminal principal, "
            "whatever its allowlist says. The decorator gate (WS3) refuses before the tool body "
            "makes any request."
        )
    else:
        success = isinstance(payload, dict) and payload.get("success") is True
        expected = {
            "gate": "allowed",
            "tool_success": True,
            "audit_rule": "fleet:operator-only",
            "audit_enforced": False,
        }
        observed = {
            "gate": verdict,
            "tool_success": success,
            "audit_rule": refusal.get("rule"),
            "audit_enforced": refusal.get("enforced"),
        }
        note = (
            "Warn mode: main never gated the ops server, so the flag decides here. The worker "
            "listed every session on the fleet; the audit line says enforced: false."
        )
    return StepResult(
        mode=server.mode,
        step="e",
        title="Terminal A calls an ops-server tool (list_sessions on cao-ops-mcp-server)",
        request=(
            "MCP call list_sessions() on a real cao-ops-mcp-server process with "
            f"CAO_TERMINAL_ID={a.terminal_id} and CAO_TERMINAL_TOKEN set"
        ),
        response=f"ToolError: {text}" if verdict == "denied" else f"result: {text[:400]}",
        audit=audit,
        expected=expected,
        observed=observed,
        ok=evaluate(expected, observed),
        note=note,
    )


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def run_mode(mode: str, *, keep_home: bool, log) -> Tuple[List[StepResult], float]:  # type: ignore[no-untyped-def]
    t0 = time.monotonic()
    server = start_server(mode)
    steps: List[StepResult] = []
    try:
        flag = "CAO_PRINCIPAL_ENFORCE=1" if server.enforcing else "CAO_PRINCIPAL_ENFORCE unset"
        log(f"== mode: {mode}  ({flag})  server {server.url}  home {server.home}")
        a = create_terminal(server, "A", WORKER_PROFILE)
        b = create_terminal(server, "B", SUPERVISOR_PROFILE)
        worker = create_worker_of(server, a, "W")
        log(f"   A = {a.short}  allowedTools [fs_read]            session {a.session}")
        log(f"   B = {b.short}  allowedTools [fs_read, execute_bash, @cao-mcp-server]")
        log(f"   W = {worker} (a worker A created; caller_id=A)")
        server.new_audit_lines(expect_some=False)  # baseline: setup wrote nothing we report

        steps.append(step_0_credentials(server, a, b))
        steps.append(step_a_impersonation(server, a, b))
        steps.append(step_b1_memory_forget(server, a))
        steps.append(step_b2_send_message(server, a, worker))
        step_c, run_id = step_c_stranger_cancel(server, a, b)
        steps.append(step_c)
        steps.append(step_d_operator_cancel(server, run_id))
        steps.append(step_e_ops_tool(server, a))
    finally:
        server.stop(keep_home=keep_home)
    return steps, time.monotonic() - t0


def render_step(step: StepResult) -> str:
    lines = [
        f"--- [{step.mode}] step {step.step}: {step.title}",
        f"request:  {step.request}",
    ]
    for i, part in enumerate(step.response.splitlines()):
        lines.append(("response: " if i == 0 else "          ") + part)
    if step.audit:
        for line in step.audit:
            lines.append("authz.jsonl: " + json.dumps(line, separators=(",", ":"), sort_keys=True))
    else:
        lines.append("authz.jsonl: (no new line)")
    lines.append(f"expected: {json.dumps(step.expected, sort_keys=True)}")
    lines.append(f"observed: {json.dumps(step.observed, sort_keys=True)}")
    lines.append(f"verdict:  {'OK' if step.ok else 'MISMATCH'}")
    if step.note:
        lines.append(f"note:     {step.note}")
    return "\n".join(lines)


def render_summary(steps: List[StepResult]) -> str:
    by: Dict[Tuple[str, str], StepResult] = {(s.mode, s.step): s for s in steps}
    order = ["0", "a", "b1", "b2", "c", "d", "e"]
    titles = {s.step: s.title for s in steps}

    def cell(mode: str, step: str) -> str:
        s = by.get((mode, step))
        if s is None:
            return "not run"
        o = s.observed
        if "forged_token" in o:
            return f"tokens accepted, forged {o['forged_token']}"
        head = o.get("status", o.get("cancel", o.get("gate")))
        rule = o.get("audit_rule")
        if rule and "audit_enforced" in o:
            return f"{head} {rule} enforced={o['audit_enforced']}"
        if rule:
            return f"{head} {rule} (allowed)"
        return f"{head}" if head is not None else "ok"

    rows = ["", "== summary (enforce vs warn)"]
    rows.append(f"{'step':<5}{'enforce':<45}{'warn':<45}title")
    for step in order:
        if step not in titles:
            continue
        rows.append(f"{step:<5}{cell('enforce', step):<45}{cell('warn', step):<45}{titles[step]}")
    failures = [s for s in steps if not s.ok]
    rows.append("")
    rows.append(
        "all steps matched their expected outcome"
        if not failures
        else f"{len(failures)} step(s) differ from the expected outcome: "
        + ", ".join(f"[{s.mode}] {s.step}" for s in failures)
    )
    return "\n".join(rows)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--json", action="store_true", help="emit a JSON array instead of text")
    parser.add_argument(
        "--mode",
        choices=("both", *MODES),
        default="both",
        help="which server mode(s) to run (default: both, enforce first)",
    )
    parser.add_argument(
        "--keep", action="store_true", help="keep the temporary homes (server logs, authz.jsonl)"
    )
    args = parser.parse_args(argv)

    text_out = (lambda msg: None) if args.json else (lambda msg: print(msg, flush=True))
    modes = list(MODES) if args.mode == "both" else [args.mode]

    steps: List[StepResult] = []
    timings: Dict[str, float] = {}
    t0 = time.monotonic()
    for mode in modes:
        mode_steps, elapsed = run_mode(mode, keep_home=args.keep, log=text_out)
        timings[mode] = elapsed
        steps.extend(mode_steps)
        for step in mode_steps:
            text_out(render_step(step))
        text_out(f"== mode {mode} done in {elapsed:.1f}s")
    total = time.monotonic() - t0

    if args.json:
        print(json.dumps([asdict(s) for s in steps], indent=2, sort_keys=True))
    else:
        text_out(render_summary(steps))
        text_out(
            f"runtime: {total:.1f}s total ({', '.join(f'{m} {t:.1f}s' for m, t in timings.items())})"
        )
    return exit_code_for(steps)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001 - a setup failure is reported, not traced
        print(f"demo setup failed: {exc}", file=sys.stderr)
        sys.exit(2)
