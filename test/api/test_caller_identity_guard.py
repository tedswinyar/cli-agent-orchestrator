"""Structural guard: every route that reads a client-supplied caller identity
derives it from the principal (#965, WS2).

The class this guard enumerates: a route in ``api/main.py`` whose handler
signature or body reads ``caller_id`` or ``caller_ceiling`` (query parameter,
body field, or ``request.query_params.get("caller_id")``), plus the
operator-shaped create routes that carry no identity at all. Each must

1. resolve the principal with ``Depends(get_current_principal)`` (or
   ``Depends(require_principal())``) in its signature, and
2. call ``check(principal, TERMINAL_ACT_AS, ...)`` or
   ``check(principal, OPERATOR_ROUTE, ...)`` in its body -- directly, or
   through a module-level helper that itself makes that call
   (``_effective_caller_id`` today).

A route that reads the claim and never checks it is the substitution gap
#965 closes: the next such route fails here with its path and line.

The walk is over the SOURCE (``ast``), not the live route table, so a route
hidden behind a feature-flag dependency is still enumerated.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pytest

from cli_agent_orchestrator.api import main as api_main

MAIN_PY = Path(api_main.__file__)

IDENTITY_FIELDS = frozenset({"caller_id", "caller_ceiling"})
IDENTITY_ACTIONS = frozenset({"TERMINAL_ACT_AS", "OPERATOR_ROUTE"})
PRINCIPAL_DEPENDENCIES = frozenset({"get_current_principal", "require_principal"})
HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})

#: Operator-shaped create routes (#965 "operator shape"). They carry no
#: ``caller_id``, so the identity walk alone would not find them; they must
#: gate with ``OPERATOR_ROUTE``. ``terminals:operator`` arrives with #948 and
#: is listed so it is gated the day it lands.
OPERATOR_CREATE_ROUTES = frozenset(
    {
        ("POST", "/sessions"),
        ("POST", "/sessions/{session_name}/terminals:operator"),
    }
)

#: Routes the walk is expected to find today. Protects the walk itself: a
#: regression that made it enumerate nothing would otherwise pass vacuously.
EXPECTED_GATED = frozenset(
    {
        ("POST", "/sessions"),
        ("POST", "/sessions/{session_name}/terminals"),
        ("POST", "/ephemeral-agents"),
        ("POST", "/ephemeral-agents/{name}/claim"),
        ("POST", "TERMINALS_RUN_STEP_ROUTE"),
    }
)


FuncDef = ast.FunctionDef | ast.AsyncFunctionDef


def _module() -> ast.Module:
    return ast.parse(MAIN_PY.read_text(encoding="utf-8"), filename=str(MAIN_PY))


def _route_of(func: FuncDef) -> Optional[Tuple[str, str]]:
    """``(METHOD, path)`` for an ``@app.<method>(path, ...)`` decorator, else None."""
    for dec in func.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        target = dec.func
        if not (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "app"
            and target.attr in HTTP_METHODS
        ):
            continue
        if not dec.args:
            continue
        first = dec.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return target.attr.upper(), first.value
        if isinstance(first, ast.Name):
            # e.g. TERMINALS_RUN_STEP_ROUTE; keep the symbol so the failure
            # message is still greppable.
            return target.attr.upper(), first.id
    return None


def _all_args(func: FuncDef) -> List[ast.arg]:
    a = func.args
    return [*a.posonlyargs, *a.args, *a.kwonlyargs]


def _check_actions(body: List[ast.stmt]) -> Set[str]:
    """Identity action constants passed to a direct ``check(...)`` call in ``body``."""
    found: Set[str] = set()
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        name = callee.id if isinstance(callee, ast.Name) else getattr(callee, "attr", None)
        if name != "check":
            continue
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in IDENTITY_ACTIONS:
                found.add(arg.id)
    return found


def _called_names(body: List[ast.stmt]) -> Set[str]:
    names: Set[str] = set()
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            names.add(node.func.id)
    return names


def _reads_identity(func: FuncDef) -> bool:
    if any(arg.arg in IDENTITY_FIELDS for arg in _all_args(func)):
        return True
    for node in ast.walk(ast.Module(body=func.body, type_ignores=[])):
        if isinstance(node, ast.Attribute) and node.attr in IDENTITY_FIELDS:
            return True
        if isinstance(node, ast.Name) and node.id in IDENTITY_FIELDS:
            return True
        if isinstance(node, ast.Constant) and node.value in IDENTITY_FIELDS:
            return True
    return False


def _has_principal_dependency(func: FuncDef) -> bool:
    a = func.args
    defaults = list(a.defaults) + list(a.kw_defaults)
    for default in defaults:
        if not (isinstance(default, ast.Call) and isinstance(default.func, ast.Name)):
            continue
        if default.func.id != "Depends" or not default.args:
            continue
        dep = default.args[0]
        if isinstance(dep, ast.Name) and dep.id in PRINCIPAL_DEPENDENCIES:
            return True
        if (
            isinstance(dep, ast.Call)
            and isinstance(dep.func, ast.Name)
            and dep.func.id in PRINCIPAL_DEPENDENCIES
        ):
            return True
    return False


def _collect() -> Tuple[Dict[str, Set[str]], List[Tuple[Tuple[str, str], FuncDef]]]:
    """``(helpers, routes)``: helpers map name -> identity actions they check."""
    module = _module()
    helpers: Dict[str, Set[str]] = {}
    routes: List[Tuple[Tuple[str, str], FuncDef]] = []
    for node in module.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route = _route_of(node)
        if route is None:
            actions = _check_actions(node.body)
            if actions:
                helpers[node.name] = actions
        else:
            routes.append((route, node))
    return helpers, routes


def _actions_of(func: FuncDef, helpers: Dict[str, Set[str]]) -> Set[str]:
    actions = set(_check_actions(func.body))
    for name in _called_names(func.body):
        actions |= helpers.get(name, set())
    return actions


def _in_scope(route: Tuple[str, str], func: FuncDef) -> bool:
    return route in OPERATOR_CREATE_ROUTES or _reads_identity(func)


def test_every_caller_identity_route_derives_the_caller_from_the_principal():
    helpers, routes = _collect()
    failures: List[str] = []
    gated: Set[Tuple[str, str]] = set()
    for route, func in routes:
        if not _in_scope(route, func):
            continue
        where = f"{route[0]} {route[1]} ({MAIN_PY.name}:{func.lineno})"
        problems = []
        if not _has_principal_dependency(func):
            problems.append("no Depends(get_current_principal) in the signature")
        actions = _actions_of(func, helpers)
        if route in OPERATOR_CREATE_ROUTES and "OPERATOR_ROUTE" not in actions:
            problems.append(
                "operator create route never calls check(principal, OPERATOR_ROUTE, ...)"
            )
        if route not in OPERATOR_CREATE_ROUTES and not (actions & IDENTITY_ACTIONS):
            problems.append(
                "reads caller_id/caller_ceiling but never calls "
                "check(principal, TERMINAL_ACT_AS | OPERATOR_ROUTE, ...)"
            )
        if problems:
            failures.append(f"{where}: " + "; ".join(problems))
        else:
            gated.add(route)
    assert not failures, "caller identity read without the principal (#965):\n  " + "\n  ".join(
        failures
    )
    missing = EXPECTED_GATED - gated
    assert (
        not missing
    ), f"guard walk no longer finds these routes (walk regression?): {sorted(missing)}"


def test_the_helper_itself_checks_the_identity_action():
    """``_effective_caller_id`` is what the routes delegate to; pin that it checks."""
    helpers, _ = _collect()
    assert "TERMINAL_ACT_AS" in helpers.get("_effective_caller_id", set()), helpers


@pytest.mark.parametrize("route", sorted(EXPECTED_GATED))
def test_expected_route_is_present_in_source(route):
    """Each expected route still exists; a rename must update EXPECTED_GATED."""
    _, routes = _collect()
    assert route in {r for r, _ in routes}, route
