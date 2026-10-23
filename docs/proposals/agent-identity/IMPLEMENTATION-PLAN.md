# Implementation plan: agent identity (v2)

Companion to `PROPOSAL.md`. Replaces the five landing PRs in the v1 implementation plan with three. Source material is the demo branch `demo/agent-principal` (base `origin/main` 4e990a9d); file:line citations are to that worktree. Rule carried over from v1 and kept: every PR ships a structural guard that enumerates its class so the next instance fails CI, and every bug fix ships a regression test plus a "how this slipped through" note.

## Demo branch fixes before anyone runs it

All six come from the synthesis "Code defects" list. None is optional; the branch misrepresents the design until they land.

- [ ] **MCP gate resolves the principal from the bearer.** `_tool_denied_reason` fetches the row named by `CAO_TERMINAL_ID` and builds the principal from it (`mcp_server/server.py:1640-1690`, `security/tool_gate.py:108-125`). It must authorize from the bearer's row and refuse a claimed id that is not the bearer's terminal. Failing test: terminal A, A's token, B's id, expect refusal with a named rule in both modes.
- [ ] **Terminal routes bind path id to bearer.** `GET /terminals/{id}` (`api/main.py:4097-4118`) and the input, key and exit routes (`api/main.py:4317-4469`) accept any id from an agent principal. For a terminal principal the path id must equal the principal's terminal id or the request is refused.
- [ ] **One construction path for principals.** `tool_gate.principal_for` never sets `delegate_tools`, so MCP-originated ceilings differ from HTTP ones. Either populate it or add one API route that returns a serialized principal and have the MCP server use that.
- [ ] **No ceiling escalation by omission.** `ceiling_of` returns `delegate_tools or allowed_tools` (`security/authz.py:166-169`); a child created without `delegate_tools` has a ceiling equal to its own allowlist, so a parent's narrower intent does not reach grandchildren. A child's default ceiling becomes the parent's ceiling, or `delegate_tools` is mandatory on create.
- [ ] **Session teardown revokes.** `_revoke_terminal_credential` runs only in `delete_terminal` (`services/terminal_service.py:4842`); `session_service.py` never clears digests. Teardown must clear every digest on the same path.
- [ ] **Audit becomes bounded.** Rotation, outcome, request id, allowed-call logging for agent principals, write-failure counter (`security/audit.py:44-70`).

## PR A: identity plumbing and bearer-bound caller

**Scope.** `security/principal.py`, `security/authz.py` (object-level actions only: `terminal:act_as`, `terminal:create`; `run:*`, `fleet:*` stay defined but unused until B and C), `security/audit.py`, `security/agent_credential.py`, the `credential_digest` column and its two accessors in `clients/database.py`, mint and inject in `services/terminal_service.py`, revoke on single delete and on session teardown, the MCP servers and `cao agent` presenting the token, the codex env-name forwarding (`providers/codex.py:1661`), and a per-provider delivery table in the docs. Startup refuses `CAO_PRINCIPAL_ENFORCE=1` without `CAO_AUTH_LOCAL_TOKEN` or an IdP.

**Defects it must fix.** Bearer-bound MCP gate; path-id binding on the terminal routes; one construction path; session-teardown revocation; bounded audit; `agent_credential()` refusing any fallback when `CAO_TERMINAL_ID` is set.

**Tests it must add.**

- Lifecycle contract rows 1 to 6, 8 and 9 (mint failure, injection failure, close with in-flight calls, session teardown, restart, pane gone, deleted intermediate ancestor, profile edit). Row 7 belongs to PR B.
- Bearer-vs-claimed-id refusal on the MCP gate and on every terminal route that takes an id.
- Enforce-without-auth startup refusal; unauthenticated request under enforce is 401.
- `agent_credential()` with id set and no token raises the named error and sends nothing.
- Principal parity: a terminal resolved over HTTP and over the MCP fetch has the same `allowed_tools`, `delegate_tools` and ceiling.
- Audit: rotation at the threshold, write failure counted, allowed call for an agent principal logged, line carries request id, outcome and the fix hint.

**Structural guards.** The AST walk over every `requests` call to `API_BASE_URL` (reused from `test/security/test_agent_credential_guard.py`). An AST walk over every route whose path takes a terminal id asserting it binds the id to the principal. The registration-table test narrowed to assert only what it can prove: that a dependency exists, with its docstring saying so.

**Exit criteria.** Flag unset: the full suite passes unchanged. Flag set with auth on: the six lifecycle tests and the binding tests pass. #965 closes on merge. A `docs/security/agent-identity.md` replaces the demo doc with the "attribution, not guardrail" framing and the provider table.

## PR B: run ownership

**Scope.** `owner_terminal_id` and `ancestor_terminal_ids` on workflow runs, stamped from the principal at run creation for the YAML and script tiers (`services/workflow_journal.py`, `services/workflow_service.py`). Cancel, resume and replay routes and MCP tools call the check with a `RunRef`. Owner death: a recorded ancestor or the operator may act; the audit line records the actor. Legacy runs with null owner are operator-only.

**Defects it must fix.** Ancestry must come from the frozen list stamped on the row, never recomputed through live rows.

**Tests it must add.** Lifecycle row 7 (run outlives its owner). Owner, ancestor, operator and stranger each attempt cancel, resume and replay under both modes. Legacy run with null owner. Resume from another terminal does not re-stamp ownership.

**Structural guard.** The AST walk over every route and tool that takes a `run_id`, asserting it calls the check (reused from `test/security/test_run_ownership_guard.py`).

**Exit criteria.** Flag unset: suite unchanged. Flag set with auth on: a stranger terminal is refused with `run:not-owner` and the line names the owner. The `workflow_cancel` side issue closes.

## PR C: ops server gate and install lint

**Scope.** `ops_mcp_server/gate.py` refuses agent principals for every ops tool. `install_profile` refuses under enforce, warns under warn, when a profile pairs `cao-ops-mcp-server` with a restricted allowlist, and the message names the fix. `docs/control-planes.md` updated.

**Defects it must fix.** None specific; it inherits PR A's bearer binding.

**Tests it must add.** Terminal principal calling an ops tool refused in enforce and audited in warn. Operator passes. Install lint over every shipped profile in `agent_store/` and `examples/`, plus a user-written profile fixture with the pairing.

**Structural guard.** The test over every `@mcp.tool` registration on the ops server asserting it is reachable only through the gate.

**Exit criteria.** No shipped profile trips the lint. The ops side issue closes.

## Reused versus dropped from the demo branch

| Demo workstream | Fate |
|---|---|
| WS0 core modules | Reused in PR A, minus `OPERATOR_ROUTE` (defined once, used once at `api/main.py:3643`, with no definition of an operator route). Scope checks stay as the documented function-level layer. |
| WS1 mint, inject, revoke, `agent_credential()` | Reused in PR A with the no-fallback rule and teardown revocation added. |
| WS2 caller identity | Reused in PR A, rebuilt on the bearer's row rather than the claimed id. |
| WS3 tool reach at the host layer | Dropped. #972's gate stays as the policy; `_tool_denied_reason` keeps its shape and only gains bearer-bound principal construction. The tool-gate census and `test_tool_gate.py` go with it. The seven `examples/aws` selector lines are a #972 follow-through, not part of this proposal. |
| WS4 run ownership | Reshaped into PR B with frozen ancestry on the row and the owner-death answer. |
| WS5 ops gate and install lint | Becomes PR C. |
| WS6 demo script and transcript | Dropped from the landing set. Kept on the branch for maintainers who want to see refusals end to end. |

## Size

PR A about 3,800 lines (roughly 1,100 source, 2,500 tests, 160 docs). PR B about 1,300. PR C about 1,400. Dropped about 3,100. Against the branch total of 9,613 insertions. These are estimates from the per-file numstat; the plan is to measure them again after the defect fixes.

## Order and gating

PR A first; B and C after A merges, in either order. Each PR goes through one adversarial review pass before it opens on upstream, because v1 did not and four reviewers found the same binding bug the author missed. No PR flips a default, retires a credential or claims a guardrail.
