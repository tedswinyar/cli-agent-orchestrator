"""Structural guard for the agent-principal demo (#965, WS6).

Runs ``scripts/demo_agent_principal.py --json`` once (both modes, each against its own
isolated cao-server with real ``mock_cli`` panes and real MCP server processes) and pins
every expected outcome HERE, independently of the expectation table the script carries.
If the script's own comparison and this table ever disagree, one of them changed without
the other and the test fails either way.

Requires tmux (the parent e2e conftest skips the session without it). No provider CLI and
no credentials are needed. Budget: under two minutes for both modes together.

Run explicitly::

    uv run --no-sync pytest -m e2e -p no:cacheprovider --no-cov test/e2e/test_agent_principal_demo.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Tuple

import pytest

pytestmark = pytest.mark.e2e

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "demo_agent_principal.py"

#: The demo must finish both modes inside this budget (seconds); measured ~70s on a laptop.
RUN_BUDGET_S = 115

#: What the demo must observe, per (mode, step). Subsets of each step's ``observed`` dict.
#: Step b1 is deliberately IDENTICAL in both modes: the cao-mcp-server gate is #972's
#: middleware and is hard regardless of the flag.
_CREDENTIALS = {
    "a_token_accepted": 404,
    "b_token_accepted": 404,
    "forged_token": 401,
    "forged_detail": "terminal credential revoked",
    "audit_lines": 0,
}
_MEMORY_FORGET_HARD = {
    "gate": "denied",
    "rule_in_text": True,
    "audit_rule": "tool:default-deny",
    "audit_enforced": True,
}
_SEND_MESSAGE_ALLOWED = {
    "gate": "allowed",
    "delivered": True,
    "audit_lines": 0,
    "policy_rule": "tool:callback",
}
PINNED: Dict[Tuple[str, str], Dict[str, Any]] = {
    ("enforce", "0"): _CREDENTIALS,
    ("enforce", "a"): {
        "status": 403,
        "detail_names_mismatch": True,
        "audit_rule": "terminal:impersonation",
        "audit_enforced": True,
    },
    ("enforce", "b1"): _MEMORY_FORGET_HARD,
    ("enforce", "b2"): _SEND_MESSAGE_ALLOWED,
    ("enforce", "c"): {
        "submit": 202,
        "cancel": 403,
        "detail_names_owner": True,
        "audit_rule": "run:not-owner",
        "audit_enforced": True,
        "run_state_after": "running",
    },
    ("enforce", "d"): {
        "status": 200,
        "run_state_after": "cancelled",
        "audit_rule": "operator",
        "audit_allowed": True,
    },
    ("enforce", "e"): {
        "gate": "denied",
        "rule_in_text": True,
        "audit_rule": "fleet:operator-only",
        "audit_enforced": True,
    },
    ("warn", "0"): _CREDENTIALS,
    ("warn", "a"): {
        "status": 201,
        "recorded_caller_is_A": True,
        "audit_rule": "terminal:impersonation",
        "audit_enforced": False,
    },
    ("warn", "b1"): _MEMORY_FORGET_HARD,
    ("warn", "b2"): _SEND_MESSAGE_ALLOWED,
    ("warn", "c"): {
        "submit": 202,
        "cancel": 200,
        "audit_rule": "run:not-owner",
        "audit_enforced": False,
        "run_state_after": "cancelled",
    },
    ("warn", "d"): {"status": 409, "audit_rule": "operator", "audit_allowed": True},
    ("warn", "e"): {
        "gate": "allowed",
        "tool_success": True,
        "audit_rule": "fleet:operator-only",
        "audit_enforced": False,
    },
}

STEP_ORDER = ["0", "a", "b1", "b2", "c", "d", "e"]


@pytest.fixture(scope="session", autouse=True)
def require_cao_server():  # type: ignore[no-untyped-def]
    """Override of ``test/e2e/conftest.py``'s autouse fixture: the demo starts its own servers."""

    return None


def _scrubbed_env() -> Dict[str, str]:
    env = os.environ.copy()
    for key in (
        "CAO_PRINCIPAL_ENFORCE",
        "CAO_AUTHZ_AUDIT_ALLOWS",
        "CAO_TERMINAL_ID",
        "CAO_TERMINAL_TOKEN",
        "CAO_HOME_DIR",
        "CAO_API_PORT",
        "CAO_AUTH_LOCAL_TOKEN",
    ):
        env.pop(key, None)
    return env


@pytest.fixture(scope="module")
def demo_run() -> Tuple[subprocess.CompletedProcess, List[Dict[str, Any]]]:  # type: ignore[type-arg]
    """One real run of the demo in ``--json`` mode (both server modes)."""

    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        cwd=REPO_ROOT,
        env=_scrubbed_env(),
        capture_output=True,
        text=True,
        timeout=RUN_BUDGET_S,
    )
    assert proc.returncode == 0, (
        f"demo exited {proc.returncode}\n--- stdout ---\n{proc.stdout[-6000:]}"
        f"\n--- stderr ---\n{proc.stderr[-3000:]}"
    )
    steps = json.loads(proc.stdout)
    assert isinstance(steps, list)
    return proc, steps


def _by_key(steps: List[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    return {(s["mode"], s["step"]): s for s in steps}


def test_every_step_matches_the_pinned_outcome(demo_run) -> None:  # type: ignore[no-untyped-def]
    _, steps = demo_run
    by = _by_key(steps)
    assert set(by) == set(PINNED), f"steps run: {sorted(by)}"
    failures = []
    for key, want in PINNED.items():
        observed = by[key]["observed"]
        for field, value in want.items():
            if observed.get(field) != value:
                failures.append(
                    f"[{key[0]}] step {key[1]}: {field}={observed.get(field)!r} != {value!r}"
                )
    assert not failures, "\n".join(failures)


def test_the_script_agrees_with_itself(demo_run) -> None:  # type: ignore[no-untyped-def]
    """Every step's own verdict is OK, and the script's expectation equals this table's."""

    _, steps = demo_run
    assert all(s["ok"] for s in steps), [f"[{s['mode']}] {s['step']}" for s in steps if not s["ok"]]
    for s in steps:
        assert s["expected"] == PINNED[(s["mode"], s["step"])], (s["mode"], s["step"])


def test_both_modes_run_the_same_steps_in_order(demo_run) -> None:  # type: ignore[no-untyped-def]
    _, steps = demo_run
    assert [s["step"] for s in steps if s["mode"] == "enforce"] == STEP_ORDER
    assert [s["step"] for s in steps if s["mode"] == "warn"] == STEP_ORDER


def test_mcp_server_denial_is_hard_in_both_modes(demo_run) -> None:  # type: ignore[no-untyped-def]
    """The talking point: #972's middleware makes memory_forget hard with the flag unset too."""

    _, steps = demo_run
    by = _by_key(steps)
    for mode in ("enforce", "warn"):
        line = next(l for l in by[(mode, "b1")]["audit"] if not l["allowed"])
        assert line["enforced"] is True
        assert line["rule"] == "tool:default-deny"
        assert line["resource"] == "cao-mcp-server/memory_forget"
        assert line["kind"] == "terminal"


def test_refusals_name_the_principal_action_and_resource(demo_run) -> None:  # type: ignore[no-untyped-def]
    """Plan acceptance: one audit line per refusal with principal id, action, resource, rule."""

    _, steps = demo_run
    for s in steps:
        for line in s["audit"]:
            if line["allowed"]:
                continue
            assert line["terminal_id"], (s["mode"], s["step"], line)
            assert line["action"] in {"terminal:act_as", "tool:call", "run:cancel"}
            assert line["resource"]
            assert line["rule"]
            assert line["kind"] == "terminal"


def test_warn_mode_refuses_nothing_the_flag_controls(demo_run) -> None:  # type: ignore[no-untyped-def]
    _, steps = demo_run
    by = _by_key(steps)
    assert by[("warn", "a")]["observed"]["status"] == 201
    assert by[("warn", "c")]["observed"]["cancel"] == 200
    assert by[("warn", "e")]["observed"]["gate"] == "allowed"
    for step in ("a", "c", "e"):
        refusal = next(l for l in by[("warn", step)]["audit"] if not l["allowed"])
        assert refusal["enforced"] is False


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("demo_agent_principal", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before exec: the script's dataclasses resolve their (string) annotations
    # through sys.modules[cls.__module__], which is None for an unregistered module.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def test_exit_status_contract() -> None:
    """A single mismatching step makes the process exit non-zero; an empty run is a failure too."""

    demo = _load_script()
    assert demo.evaluate({"status": 403}, {"status": 403, "extra": 1}) is True
    assert demo.evaluate({"status": 403}, {"status": 200}) is False
    assert demo.evaluate({"status": 403}, {}) is False
    good = demo.StepResult("enforce", "a", "t", "r", "s", [], {"x": 1}, {"x": 1}, ok=True)
    bad = demo.StepResult("enforce", "b1", "t", "r", "s", [], {"x": 1}, {"x": 2}, ok=False)
    assert demo.exit_code_for([good, good]) == 0
    assert demo.exit_code_for([good, bad]) == 1
    assert demo.exit_code_for([]) == 1
