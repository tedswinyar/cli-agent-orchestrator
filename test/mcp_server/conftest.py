"""Shared fixtures for MCP server tests.

``mcp_over_testclient`` is the seam that keeps MCP tool tests meaningful now that
the memory and outcome tools are HTTP clients. Before, those tests called the
tools in-process against a real SQLite file, which is exactly the coupling the
tools were changed to remove — so a test that keeps doing it would pass while
testing something the production path no longer does.

Instead the tool's real ``requests`` call is routed into an in-process
``TestClient`` over the real FastAPI routes. That exercises both halves that
matter: the request the tool constructs, and the status-code translation it
applies to the response. It also records every request, so a test can assert on
what did NOT travel — no cwd, no scope_id, no forged identity.

Generalized from the single-endpoint pattern in ``test_handoff_equivalence.py``.

``identity_body`` / ``patch_identity`` are the ONE stub shape for the gate's
identity fetch (``GET /me/principal``). Before #965's binding fix every file
that drove ``_tool_denied_reason`` wrote its own ``_ctx()`` terminal-record
literal -- six copies of a dict whose keys only had to satisfy the production
reader, so when that reader changed from "a terminal record" to "a serialized
principal" every copy had to be found and rewritten. One builder, derived from
the real ``security.principal.principal_payload``, means the next change to the
payload breaks the builder rather than fifty call sites.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional
from unittest.mock import patch

import pytest

#: The terminal id the MCP identity stubs speak as, unless a caller overrides it.
STUB_TERMINAL_ID = "a1b2c3d4"


def identity_body(
    allowed_tools: Iterable[str] = (),
    *,
    terminal_id: str = STUB_TERMINAL_ID,
    kind: str = "terminal",
    session_name: str = "cao-session",
    agent_profile: Optional[str] = "worker",
    delegate_tools: Iterable[str] = (),
    creator_id: Optional[str] = None,
    ancestors: Iterable[str] = (),
    ephemeral: bool = False,
    allowlist_resolved: bool = True,
    identity_bound: bool = True,
) -> Dict[str, Any]:
    """A ``GET /me/principal`` response body, built through the real serializer.

    ``allowed_tools`` is the EFFECTIVE list: the API resolves a row's recorded
    ``None`` against the agent profile before serializing, so by the time a
    body reaches the MCP process there is no "resolve this for me" state left.
    Pass ``allowlist_resolved=False`` for the case where that resolution failed.
    """
    from cli_agent_orchestrator.security.principal import (
        AGENT_SCOPES,
        Principal,
        principal_payload,
    )

    principal = Principal(
        kind=kind,  # type: ignore[arg-type]
        scopes=frozenset(AGENT_SCOPES),
        terminal_id=terminal_id,
        session_name=session_name,
        agent_profile=agent_profile,
        allowed_tools=tuple(allowed_tools),
        delegate_tools=tuple(delegate_tools),
        creator_id=creator_id,
        ancestors=tuple(ancestors),
        ephemeral=ephemeral,
        allowlist_resolved=allowlist_resolved,
    )
    return {
        "principal": principal_payload(principal),
        "identity_bound": identity_bound,
        "claimed_terminal_id": terminal_id,
        "rule": "identity:proven" if identity_bound else "terminal:impersonation",
    }


def identity_body_from_db(terminal_id: str, *, identity_bound: bool = True) -> Dict[str, Any]:
    """A ``GET /me/principal`` body built from the LIVE row by the real constructor.

    For tests whose subject is the row (ephemeral-registry truth, a profile
    resolution, an ancestry chain) rather than the gate's arithmetic: they get
    the production ``principal_from_terminal_row`` reading the production
    tables, with only the HTTP hop replaced.

    Raises ``requests.HTTPError`` for a missing row, which is what the route
    would answer and what the gate must fail closed on.
    """
    import requests

    from cli_agent_orchestrator.security.principal import (
        _row_by_id,
        principal_from_terminal_row,
        principal_payload,
    )

    row = _row_by_id(terminal_id)
    if row is None:
        raise requests.HTTPError(f"404 for /me/principal: no terminal {terminal_id}")
    return {
        "principal": principal_payload(principal_from_terminal_row(row)),
        "identity_bound": identity_bound,
        "claimed_terminal_id": terminal_id,
        "rule": "identity:proven" if identity_bound else "terminal:impersonation",
    }


def patch_identity(allowed_tools: Iterable[str] = (), **kwargs: Any):
    """Patch the gate's identity fetch to return :func:`identity_body`.

    ``side_effect=<exception>`` is passed straight through for the fail-closed
    cases (an unreachable server, a 401, a body the deserializer rejects).
    """
    from cli_agent_orchestrator.mcp_server import server

    if "side_effect" in kwargs:
        return patch.object(server, "_caller_principal", side_effect=kwargs["side_effect"])
    return patch.object(
        server, "_caller_principal", return_value=identity_body(allowed_tools, **kwargs)
    )


@dataclass
class RecordedRequest:
    method: str
    path: str
    params: Optional[Dict[str, Any]] = None
    json: Optional[Dict[str, Any]] = None

    def payload_fields(self) -> set:
        """Every field name the tool put on the wire, body or query."""
        return set(self.json or {}) | set(self.params or {})


@dataclass
class MCPSeam:
    """Handle onto the routed HTTP hop."""

    requests: List[RecordedRequest] = field(default_factory=list)
    terminal_record: Optional[Dict[str, Any]] = None
    working_directory: Optional[str] = "/repo"

    @property
    def last(self) -> RecordedRequest:
        assert self.requests, "no HTTP request was issued"
        return self.requests[-1]

    def paths(self) -> List[str]:
        return [r.path for r in self.requests]


@pytest.fixture
def mcp_over_testclient(monkeypatch):
    """Route ``mcp_server.utils.requests`` into an in-process TestClient.

    The patch target is ``utils``, not ``server``: the canonical HTTP helpers
    live there, so that is where the tools' calls actually originate.
    """
    from fastapi.testclient import TestClient

    from cli_agent_orchestrator.api.main import app
    from cli_agent_orchestrator.mcp_server import utils as mcp_utils
    from cli_agent_orchestrator.plugins import PluginRegistry

    app.state.plugin_registry = PluginRegistry()
    client = TestClient(app, headers={"Host": "localhost"})

    seam = MCPSeam(
        terminal_record={
            "id": "abc12345",
            "session_name": "sess-1",
            "provider": "kiro_cli",
            "agent_profile": "developer",
        }
    )
    monkeypatch.setenv("CAO_TERMINAL_ID", "abc12345")

    def _strip(url: str) -> str:
        # helpers build f"{API_BASE_URL}{path}"; TestClient wants just the path
        for marker in ("://",):
            if marker in url:
                return "/" + url.split(marker, 1)[1].split("/", 1)[1]
        return url

    def _dispatch(method: str, url, **kwargs):
        path = _strip(str(url))
        params = kwargs.get("params")
        body = kwargs.get("json")
        seam.requests.append(RecordedRequest(method, path, params, body))

        # The identity lookups are stubbed rather than routed: they read live
        # terminal/tmux state, which no unit test should depend on.
        if path == f"/terminals/{seam.terminal_record['id']}" and method == "GET":
            return _FakeResponse(200, seam.terminal_record)
        if path.endswith("/working-directory"):
            return _FakeResponse(200, {"working_directory": seam.working_directory})
        # Same reasoning for the gate's own identity fetch: routing it would make
        # every tool test depend on a credential digest in a live terminals table.
        # ``*`` so these tests keep exercising the tool bodies, which is what
        # they are for; the gate's decision has its own suites.
        if path == "/me/principal" and method == "GET":
            return _FakeResponse(
                200,
                identity_body(
                    ["*"],
                    terminal_id=str(seam.terminal_record["id"]),
                    session_name=str(seam.terminal_record["session_name"]),
                    agent_profile=seam.terminal_record.get("agent_profile"),
                ),
            )

        return _RequestsLike(client.request(method, path, params=params, json=body))

    for verb in ("get", "post", "delete", "put", "patch"):
        monkeypatch.setattr(
            mcp_utils.requests,
            verb,
            lambda url, _v=verb, **kw: _dispatch(_v.upper(), url, **kw),
            raising=False,
        )
    yield seam


class _RequestsLike:
    """Present an httpx response the way ``requests`` would.

    Fidelity matters here, it is not cosmetic: TestClient is httpx-backed, so its
    ``raise_for_status()`` raises ``httpx.HTTPStatusError``. The tools catch
    ``requests.RequestException``, so an unwrapped httpx response would skip every
    status-code translation under test and fall through to the generic handler —
    the tests would pass while proving nothing about 404 -> disabled or
    409 -> partial_write.
    """

    def __init__(self, response) -> None:
        self._response = response

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def text(self) -> str:
        return self._response.text

    def json(self) -> Any:
        return self._response.json()

    def raise_for_status(self) -> None:
        import requests

        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}", response=self)


class _FakeResponse:
    """Minimal requests.Response stand-in for the stubbed identity lookups."""

    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(f"{self.status_code}", response=self)
