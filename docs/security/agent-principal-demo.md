# Agent principal: the demo (experimental, #965)

`scripts/demo_agent_principal.py` shows the whole proposal working end to end against a real,
isolated `cao-server`: two terminals with their own credentials, six surfaces gated through the
one `authorize()` chokepoint, the audit line each decision leaves behind, and the difference
between enforce mode and the default warn mode. It is the thing to run before reading
[`agent-principal.md`](agent-principal.md), and the transcript below is what it printed on a
MacBook on 2026-10-22.

`test/e2e/test_agent_principal_demo.py` runs the script and pins every outcome independently;
it is the structural guard for the demo and takes about a minute.

## How to run it

From the repository root, inside the project venv. The only requirement beyond the venv is
`tmux` on `PATH`; no provider CLI, no credentials, no network.

```bash
uv run --no-sync python scripts/demo_agent_principal.py            # plain text, both modes
uv run --no-sync python scripts/demo_agent_principal.py --json     # same content as a JSON array
uv run --no-sync python scripts/demo_agent_principal.py --mode enforce --keep   # one mode, keep the homes
uv run --no-sync pytest -m e2e -p no:cacheprovider --no-cov test/e2e/test_agent_principal_demo.py
```

The exit status is 0 only if every step's observed outcome equals the expected one; 1 if any
step differs; 2 if the setup itself failed (no tmux, server not healthy). `--keep` leaves the
two temporary homes behind, with `server.log`, `logs/authz.jsonl` and one `mcp-*.log` per MCP
call, for inspection.

### What the script sets up

For each mode (`enforce` first, then `warn`) it starts one `cao-server` in a throwaway
`CAO_HOME_DIR` on a free port, with operator auth off (the operator is the default-off anonymous
caller), `CAO_AUTHZ_AUDIT_ALLOWS=1` so allows are recorded as well as refusals, and
`CAO_PRINCIPAL_ENFORCE=1` or unset. It seeds `settings.json` with
`workflow.require_approval: false` (plan approval is a different feature), two agent profiles and
one script-tier workflow:

| name | kind | content |
|---|---|---|
| `demo_worker` | profile | `allowedTools: [fs_read]`, declares `cao-mcp-server` under `mcpServers` but does **not** grant it |
| `demo_supervisor` | profile | `allowedTools: [fs_read, execute_bash, "@cao-mcp-server"]` |
| `demo_hold` | workflow (`.py`) | `time.sleep(600)`, so a run is still RUNNING when someone cancels it |

Then, as the operator, it creates terminal **A** (`demo_worker`) and terminal **B**
(`demo_supervisor`) through `POST /sessions` with the credential-free `mock_cli` provider: each
is a real tmux pane running the mock REPL, so `create_terminal` mints and injects
`CAO_TERMINAL_TOKEN` exactly as it does for a real agent. The script reads each token back out
of the pane's tmux session environment (`tmux show-environment -t <session> CAO_TERMINAL_TOKEN`),
which is where the agent process gets it; nothing is read from the database. It also creates
**W**, a worker in A's session with `caller_id=A`, so A has a legitimate `send_message` target.

Steps b1, b2 and e drive the real `cao-mcp-server` and `cao-ops-mcp-server` processes over
stdio with a FastMCP client, with `CAO_TERMINAL_ID`, `CAO_TERMINAL_TOKEN`, `CAO_API_PORT` and
`CAO_HOME_DIR` in their environment as the pane would have them. The gate that decides is the
one the agent would hit; no check is re-implemented in the script. The one in-process call is
in step b2, where `authorize()` is asked the same question the middleware did not need to ask
(see below).

## What each step proves

| step | request | enforce | warn | proves |
|---|---|---|---|---|
| 0 | `POST /workflows/runs/does-not-exist/cancel` as A, as B, with a forged `cao_t_` token | A, B: 404 (past authentication, unknown run); forged: 401 `terminal credential revoked` | same | The minted credentials resolve to the right rows (A's `allowed_tools=[fs_read]`); a token that is not in the table by digest is refused. Credential resolution is not a policy decision: same in both modes, no audit line. |
| a | `POST /sessions/{A's session}/terminals?caller_id=B` as A | **403** `terminal A may not act as terminal B`; audit `terminal:impersonation enforced:true` | 201, but the new terminal's recorded `caller_id` is **A**; audit `terminal:impersonation enforced:false` plus an allowed `terminal:within-ceiling` line | WS2: the caller is derived from the credential, not the request. Even in warn mode the claim is overridden; the audit line is what enforcement would have refused. |
| b1 | MCP `memory_forget` on `cao-mcp-server` as A | **ToolError** `'memory_forget' is not permitted (tool:default-deny) ... Grant '@cao-mcp-server'`; audit `tool:default-deny enforced:true` | **identical**: ToolError, `enforced:true` | WS3 on top of #972: the whole-surface middleware gate decides through `authz.check(hard=True)`. The flag relaxes nothing on this server. The record fetch behind the decision presented A's own token. |
| b2 | MCP `send_message(receiver_id=W)` on `cao-mcp-server` as A | allowed, `success: true`, message queued in W's inbox; no audit line; `authorize()` says `tool:callback` | same | The callback exception set (`authz.CALLBACK_TOOLS`) keeps a bounded worker able to report upward. The middleware exempts those four tools before consulting policy, which is why no line is written. |
| c | `POST /workflows/runs:submit` as A (202), then `POST .../cancel` as B | **403** `run 'X' is owned by terminal 'A'; terminal 'B' may not cancel it`; audit `run:not-owner enforced:true`; run still `running` | 200, run `cancelled`; audit `run:not-owner enforced:false` | WS4: the owner is stamped in the submit INSERT and the cancel route decides on a `RunRef`. In warn mode a stranger really cancels the run and the audit line is the only trace. |
| d | `POST .../cancel` as the operator | 200, run `cancelled`; audit `operator allowed:true` | **409** `already cancelled` (step c did it); audit `operator allowed:true` | Operators are unbounded and go through the same `check()`. The warn-mode 409 is the cost of audit-only: there was nothing left to protect. |
| e | MCP `list_sessions` on `cao-ops-mcp-server` as A | **ToolError** `'list_sessions' is not permitted (fleet:operator-only)`; audit `fleet:operator-only enforced:true` | allowed, the worker lists every session on the fleet; audit `fleet:operator-only enforced:false` | WS3/WS5: every ops tool is operator-only for a terminal principal, whatever its allowlist. Main never gated this server, so here the flag decides. |

Every refusal line carries `kind`, `terminal_id`, `action`, `resource`, `rule`, `reason` and
`enforced`, which is the plan's acceptance criterion for the audit trail. The e2e test asserts
that shape on every refusal in both modes.

## What is warn-mode only, and what #972 already enforces on main

The default (`CAO_PRINCIPAL_ENFORCE` unset) must be behaviour-preserving, and the transcript
shows exactly where it is and is not:

- **Warn-mode only (audit line, call proceeds):** step a's substitution on the HTTP routes
  (with the one deliberate asymmetry that the credential's identity is recorded, see WS2's
  report), step c's stranger cancel, step e's ops tool. These are the behaviours the demo branch
  adds; none of them refuses anything until the flag is set.
- **Hard regardless of the flag:** step b1. `origin/main` landed #972 on 2026-10-21, a FastMCP
  `on_call_tool` middleware that gates every `cao-mcp-server` tool on the caller's allowlist and
  denies hard. The merged branch keeps that mechanism and feeds it the principal decision
  (`_tool_denied_reason -> tool_gate.denial_for -> authz.check(hard=True)`), so the audit line
  says `enforced: true` with the flag unset. Relaxing it to warn mode would have reopened a hole
  main already closed. The six delegation tools (`assign`, `handoff`, `assign_elastic`,
  `workflow_run`, `workflow_resume`, `workflow_start`) were hard before #972 as well (#769).
- **Not a policy decision at all:** step 0. A `cao_t_` bearer that does not resolve is 401 in
  both modes, because it is a credential check. The one default-off difference WS1 named is
  this: a zombie agent whose row was deleted gets 401 where it used to get 200.

## Observations the demo surfaced

These are facts about the merged branch that the transcript makes visible; they are not bugs
in the demo.

1. **With operator auth off, only principal-resolving routes see a forged token.** Step 0 probes
   a route that has `Depends(get_current_principal)`. A route that has only the scope dependency
   (`GET /terminals/{id}`, for instance) accepts any bearer as the anonymous operator when auth is
   off, forged `cao_t_` included, because `get_current_scopes` returns the full scope set before
   looking at the bearer. That is today's default-off posture, unchanged; it is landing PR 5's
   job (flip the default, retire the shared bearer) to close it.
2. **The callback tools leave no audit trail.** The middleware short-circuits
   `CALLBACK_EXEMPT_TOOLS` before policy, so `send_message` and its three siblings never reach
   `check()`. The pure `authorize()` answers `tool:callback` for them; the demo prints that
   decision in step b2 because nothing else does.
3. **Allows are audited when asked.** With `CAO_AUTHZ_AUDIT_ALLOWS=1` the operator's cancel
   writes `rule: operator, allowed: true`, including in warn mode on an already-cancelled run
   (the check runs before the route looks at the run). Default off, so production logs carry
   refusals only.
4. **The ops server presents the operator bearer, not the terminal token.** `cao-ops-mcp-server`
   keeps its own `_auth_headers()` over `get_local_bearer()` (WS1 open question 3). Its identity
   for the gate still comes from `CAO_TERMINAL_ID` and the record fetch, which is why step e
   refuses correctly with auth off; with auth on, that fetch would carry the operator token.

## Open questions carried from the workstream reports

Collected here so the demo's reader sees them next to the behaviour they qualify. Each is in
the report it came from (`out/principal-ws0.md` to `ws5.md` in the conductor's issue-sweep
folder) with its reasoning.

- **`DELETE /workflows/runs/{run_id}` is ungated** (WS4). There is no `RUN_DELETE` action in the
  WS0 contract; the route is listed in the run-ownership guard's `KNOWN_UNGATED`. Recommended:
  gate it with `RUN_CANCEL` semantics or add `RUN_DELETE` with the same rule in the landing PR.
  `POST .../steps/{step_id}/output` is also ungated; the right check there is caller identity
  (`TERMINAL_ACT_AS`), not ownership.
- **Plugin-delivered ops servers are left to call time** (WS5). The install admission rule runs
  on the profile's own `mcpServers`, before the plugin merge, because the `cao` operator plugin
  hands every managed profile a `cao-ops` entry and checking after the merge would warn or refuse
  every install on that machine. Plugin servers are never auto-granted, so under per-server
  default-deny they are unreachable without a grant, and WS3's call-time gate (step e) is the
  line that holds. The split needs confirming.
- **Providers without a shell baseline for the token** (WS1). Codex forwards
  `CAO_TERMINAL_TOKEN` by name and Claude Code's MCP subprocess inherits the pane environment,
  which is what the demo's stdio processes model. Seven providers (kimi, cursor, copilot,
  antigravity, grok, minimax, omp) write `CAO_TERMINAL_ID`'s value into an on-disk MCP config;
  doing the same for the token puts a secret at rest, so their MCP subprocesses still fall back
  to the operator token until a non-file channel exists.
- **#948's `utils/delegation` comparator replaces `authz._entry_within_ceiling` when it lands**
  (WS0 deviation 2, WS2 integration note 3). The ceiling subset check exists in one place in
  `authz.py` on purpose; `caller_ceiling` and the `terminals:operator` route from #948 are
  pre-listed in the caller-identity guard so they fail the day they land until gated.
- **Run tokens are 401 until #829 lands** (WS0 deviation 1). `security.run_tokens` is on the
  #829 branch only, so a `cao_r_` bearer is refused on this branch; when the module is present it
  also needs a `terminal_id_for(run_id)` accessor for the run principal to inherit the spawning
  terminal's fields, otherwise a nested run started by a run principal is stamped operator-owned
  (WS4 open question 5).
- **Bare tool names never grant an MCP tool** (WS3 deviation). `tool_covered` dropped the
  bare-name branch to match the shipped #769 policy; `@cao-mcp-server/<tool>` is the per-tool
  grant. Confirmed at integration; recorded here because the transcript's step b1 hint text
  depends on it.
- **The reviewer notes from the merge**: #1009's registration-policy table still lists the 28
  identity-local tools as exempt while #972's middleware gates them at dispatch, and #972's
  surface-coverage test still labels `cao-ops-mcp-server` a declared ungated surface although
  WS3's decorator gate now refuses there under the flag. Neither affects behaviour; both are
  labels to reconcile when the demo lands for real.

## Transcript

Verbatim output of `uv run --no-sync python scripts/demo_agent_principal.py` on 2026-10-22
(macOS, tmux 3.8, fastmcp 4.1.0). Terminal ids, ports and run ids differ per run; the temporary
home paths are shortened.

```text
== mode: enforce  (CAO_PRINCIPAL_ENFORCE=1)  server http://127.0.0.1:50475  home .../cao-principal-demo-enforce-lu91f5om
   A = A (fb233d50, demo_worker)  allowedTools [fs_read]            session cao-caodemo-a-59b454
   B = B (429a59f1, demo_supervisor)  allowedTools [fs_read, execute_bash, @cao-mcp-server]
   W = 5eb4c5a3 (a worker A created; caller_id=A)
--- [enforce] step 0: The minted credentials resolve; a forged one does not
request:  POST /workflows/runs/does-not-exist/cancel as A [Bearer cao_t_ADAM...  (len 49)], as B, and with a forged cao_t_ token (same length, last four characters changed)
response: row A: allowed_tools=['fs_read'] caller_id=None
          row B: allowed_tools=['fs_read', 'execute_bash', '@cao-mcp-server']
          as A: HTTP 404 {"detail":"unknown run 'does-not-exist'"}
          as B: HTTP 404 {"detail":"unknown run 'does-not-exist'"}
          forged: HTTP 401 {"detail":"terminal credential revoked"}
authz.jsonl: (no new line)
expected: {"a_token_accepted": 404, "audit_lines": 0, "b_token_accepted": 404, "forged_detail": "terminal credential revoked", "forged_token": 401}
observed: {"a_token_accepted": 404, "audit_lines": 0, "b_token_accepted": 404, "forged_detail": "terminal credential revoked", "forged_token": 401}
verdict:  OK
note:     Each token was read from the terminal's own tmux pane environment, where create_terminal injected it next to CAO_TERMINAL_ID; only the SHA-256 digest is in the terminals table. Resolution is a credential check: same in both modes, no audit line. The probe is a principal-resolving route on purpose: with operator auth off, a route that only has the scope dependency (GET /terminals/{id}) accepts any bearer as the anonymous operator, forged cao_t_ included.
--- [enforce] step a: Terminal A names terminal B as caller_id on a create
request:  POST /sessions/cao-caodemo-a-59b454/terminals?provider=mock_cli&agent_profile=demo_worker&caller_id=429a59f1&defer_init=true  as A [Bearer cao_t_ADAM...  (len 49)]
response: HTTP 403 {"detail":"terminal fb233d50 may not act as terminal 429a59f1"}
authz.jsonl: {"action":"terminal:act_as","allowed":false,"enforced":true,"kind":"terminal","reason":"terminal fb233d50 may not act as terminal 429a59f1","resource":"429a59f1","rule":"terminal:impersonation","run_id":null,"terminal_id":"fb233d50","ts":"2026-10-22T06:21:01.338057+00:00"}
expected: {"audit_enforced": true, "audit_rule": "terminal:impersonation", "detail_names_mismatch": true, "status": 403}
observed: {"audit_enforced": true, "audit_rule": "terminal:impersonation", "detail_names_mismatch": true, "status": 403}
verdict:  OK
note:     The 403 comes from _effective_caller_id before the service runs: nothing was allocated. The detail names both terminals and nothing else.
--- [enforce] step b1: Terminal A (allowedTools: [fs_read]) calls memory_forget on cao-mcp-server
request:  MCP call memory_forget(key='demo-key', scope='project') on a real cao-mcp-server process with CAO_TERMINAL_ID=fb233d50 and CAO_TERMINAL_TOKEN set [Bearer cao_t_ADAM...  (len 49)]
response: ToolError: 'memory_forget' is not permitted (tool:default-deny): terminal fb233d50 allowed_tools does not cover memory_forget on cao-mcp-server. Grant '@cao-mcp-server' (or '@cao-mcp-server/memory_forget') in the calling terminal's allowed tools
authz.jsonl: {"action":"tool:call","allowed":false,"enforced":true,"kind":"terminal","reason":"terminal fb233d50 allowed_tools does not cover memory_forget on cao-mcp-server","resource":"cao-mcp-server/memory_forget","rule":"tool:default-deny","run_id":null,"terminal_id":"fb233d50","ts":"2026-10-22T06:21:13.035982+00:00"}
expected: {"audit_enforced": true, "audit_rule": "tool:default-deny", "gate": "denied", "rule_in_text": true}
observed: {"audit_enforced": true, "audit_rule": "tool:default-deny", "gate": "denied", "rule_in_text": true}
verdict:  OK
note:     HARD IN BOTH MODES. #972's on_call_tool middleware is the gate for every cao-mcp-server tool; it asks _tool_denied_reason -> tool_gate.denial_for -> authz.check(hard=True), so CAO_PRINCIPAL_ENFORCE relaxes nothing here and the audit line says enforced: true even with the flag unset. The record fetch behind the decision presented A's own token (agent_credential()), not the operator's.
--- [enforce] step b2: Terminal A calls send_message (a worker callback) on cao-mcp-server
request:  MCP call send_message(message='hello from the demo', receiver_id=5eb4c5a3) on cao-mcp-server as A; 5eb4c5a3 is a terminal A created (caller_id=A)
response: result: {"created_at": "2026-10-22T06:21:21.522210+00:00", "message_id": 1, "receiver_id": "5eb4c5a3", "sender_id": "fb233d50", "success": true}
          policy: authorize(A, tool:call, send_message) -> tool:callback: send_message is always available to terminal fb233d50
authz.jsonl: (no new line)
expected: {"audit_lines": 0, "delivered": true, "gate": "allowed", "policy_rule": "tool:callback"}
observed: {"audit_lines": 0, "delivered": true, "gate": "allowed", "policy_rule": "tool:callback"}
verdict:  OK
note:     send_message is one of the four callbacks (authz.CALLBACK_TOOLS) a bounded worker needs to report upward. The middleware exempts them before consulting policy, so no audit line is written; authorize() answers tool:callback for the same question. The body then applied its own relationship rule (the receiver is a terminal A created) and delivered the message to the worker's inbox.
--- [enforce] step c: Terminal B cancels a workflow run terminal A started
request:  POST /workflows/runs:submit {name_or_path: demo_hold, run_id: demo-run-5e26b199} as A; then POST /workflows/runs/demo-run-5e26b199/cancel as B [Bearer cao_t_bsV2...  (len 49)]
response: submit: HTTP 202 {"links":{"cancel":"/workflows/runs/demo-run-5e26b199/cancel","events":"/workflows/runs/demo-run-5e26b199/events","result":"/workflows/runs/demo-run-5e
          cancel: HTTP 403 {"detail":"run 'demo-run-5e26b199' is owned by terminal 'fb233d50'; terminal '429a59f1' may not cancel it"}
authz.jsonl: {"action":"run:cancel","allowed":false,"enforced":true,"kind":"terminal","reason":"terminal 429a59f1 neither owns nor is an ancestor of run demo-run-5e26b199","resource":"run:demo-run-5e26b199","rule":"run:not-owner","run_id":null,"terminal_id":"429a59f1","ts":"2026-10-22T06:21:27.311294+00:00"}
expected: {"audit_enforced": true, "audit_rule": "run:not-owner", "cancel": 403, "detail_names_owner": true, "run_state_after": "running", "submit": 202}
observed: {"audit_enforced": true, "audit_rule": "run:not-owner", "cancel": 403, "detail_names_owner": true, "run_state_after": "running", "submit": 202}
verdict:  OK
note:     The run row was stamped owner_terminal_id=A at the submit INSERT. B is neither the owner nor in A's frozen ancestor list, so run:not-owner refuses and the detail names the owner. The run is still running.
--- [enforce] step d: The operator cancels the same run
request:  POST /workflows/runs/demo-run-5e26b199/cancel  as the operator [no bearer (operator, auth off)]
response: HTTP 200 {"run_id":"demo-run-5e26b199","success":true}
authz.jsonl: {"action":"run:cancel","allowed":true,"enforced":true,"kind":"anonymous","reason":"anonymous principals are unbounded","resource":"run:demo-run-5e26b199","rule":"operator","run_id":null,"terminal_id":null,"ts":"2026-10-22T06:21:27.327959+00:00"}
expected: {"audit_allowed": true, "audit_rule": "operator", "run_state_after": "cancelled", "status": 200}
observed: {"audit_allowed": true, "audit_rule": "operator", "run_state_after": "cancelled", "status": 200}
verdict:  OK
note:     The operator (the default-off anonymous caller here; the shared bearer when auth is on) is unbounded. The same check() decided it, rule 'operator', and because this demo runs with CAO_AUTHZ_AUDIT_ALLOWS=1 the allow is on the record too.
--- [enforce] step e: Terminal A calls an ops-server tool (list_sessions on cao-ops-mcp-server)
request:  MCP call list_sessions() on a real cao-ops-mcp-server process with CAO_TERMINAL_ID=fb233d50 and CAO_TERMINAL_TOKEN set
response: ToolError: 'list_sessions' is not permitted (fleet:operator-only): terminal fb233d50 may not call ops tool list_sessions. cao-ops-mcp-server tools are operator-only
authz.jsonl: {"action":"tool:call","allowed":false,"enforced":true,"kind":"terminal","reason":"terminal fb233d50 may not call ops tool list_sessions","resource":"cao-ops-mcp-server/list_sessions","rule":"fleet:operator-only","run_id":null,"terminal_id":"fb233d50","ts":"2026-10-22T06:21:30.325554+00:00"}
expected: {"audit_enforced": true, "audit_rule": "fleet:operator-only", "gate": "denied", "rule_in_text": true}
observed: {"audit_enforced": true, "audit_rule": "fleet:operator-only", "gate": "denied", "rule_in_text": true}
verdict:  OK
note:     Every cao-ops-mcp-server tool is fleet:operator-only for a terminal principal, whatever its allowlist says. The decorator gate (WS3) refuses before the tool body makes any request.
== mode enforce done in 45.0s
== mode: warn  (CAO_PRINCIPAL_ENFORCE unset)  server http://127.0.0.1:50698  home .../cao-principal-demo-warn-1994tkuw
   A = A (84f944d0, demo_worker)  allowedTools [fs_read]            session cao-caodemo-a-83f296
   B = B (d40bc683, demo_supervisor)  allowedTools [fs_read, execute_bash, @cao-mcp-server]
   W = 7869887f (a worker A created; caller_id=A)
--- [warn] step 0: The minted credentials resolve; a forged one does not
request:  POST /workflows/runs/does-not-exist/cancel as A [Bearer cao_t_x6lW...  (len 49)], as B, and with a forged cao_t_ token (same length, last four characters changed)
response: row A: allowed_tools=['fs_read'] caller_id=None
          row B: allowed_tools=['fs_read', 'execute_bash', '@cao-mcp-server']
          as A: HTTP 404 {"detail":"unknown run 'does-not-exist'"}
          as B: HTTP 404 {"detail":"unknown run 'does-not-exist'"}
          forged: HTTP 401 {"detail":"terminal credential revoked"}
authz.jsonl: (no new line)
expected: {"a_token_accepted": 404, "audit_lines": 0, "b_token_accepted": 404, "forged_detail": "terminal credential revoked", "forged_token": 401}
observed: {"a_token_accepted": 404, "audit_lines": 0, "b_token_accepted": 404, "forged_detail": "terminal credential revoked", "forged_token": 401}
verdict:  OK
note:     Each token was read from the terminal's own tmux pane environment, where create_terminal injected it next to CAO_TERMINAL_ID; only the SHA-256 digest is in the terminals table. Resolution is a credential check: same in both modes, no audit line. The probe is a principal-resolving route on purpose: with operator auth off, a route that only has the scope dependency (GET /terminals/{id}) accepts any bearer as the anonymous operator, forged cao_t_ included.
--- [warn] step a: Terminal A names terminal B as caller_id on a create
request:  POST /sessions/cao-caodemo-a-83f296/terminals?provider=mock_cli&agent_profile=demo_worker&caller_id=d40bc683&defer_init=true  as A [Bearer cao_t_x6lW...  (len 49)]
response: HTTP 201 {"agent_profile":"demo_worker","allowed_tools":["fs_read"],"callback_terminal_id":null,"caller_id":"84f944d0","deferred_init_failure":null,"description":null,"engine":null,"ephemeral":false,"group":null,"id":"6173fa75","initial_delivery":null,"last_active":"2026-10-22T06:21:47.102587Z","metadata":null,"model":null,"model_honored":false,"name":"demo_worker-d5e0","provider":"mock_cli","session_in...
authz.jsonl: {"action":"terminal:act_as","allowed":false,"enforced":false,"kind":"terminal","reason":"terminal 84f944d0 may not act as terminal d40bc683","resource":"d40bc683","rule":"terminal:impersonation","run_id":null,"terminal_id":"84f944d0","ts":"2026-10-22T06:21:46.696934+00:00"}
authz.jsonl: {"action":"terminal:create","allowed":true,"enforced":false,"kind":"terminal","reason":"terminal 84f944d0 request is within its ceiling","resource":"","rule":"terminal:within-ceiling","run_id":null,"terminal_id":"84f944d0","ts":"2026-10-22T06:21:46.697937+00:00"}
expected: {"audit_enforced": false, "audit_rule": "terminal:impersonation", "recorded_caller_is_A": true, "status": 201}
observed: {"audit_enforced": false, "audit_rule": "terminal:impersonation", "recorded_caller_is_A": true, "status": 201}
verdict:  OK
note:     Warn mode: the create proceeds, but the credential wins over the claim: the new terminal's recorded caller_id is A, not B. The audit line records what enforcement would have refused (enforced: false).
--- [warn] step b1: Terminal A (allowedTools: [fs_read]) calls memory_forget on cao-mcp-server
request:  MCP call memory_forget(key='demo-key', scope='project') on a real cao-mcp-server process with CAO_TERMINAL_ID=84f944d0 and CAO_TERMINAL_TOKEN set [Bearer cao_t_x6lW...  (len 49)]
response: ToolError: 'memory_forget' is not permitted (tool:default-deny): terminal 84f944d0 allowed_tools does not cover memory_forget on cao-mcp-server. Grant '@cao-mcp-server' (or '@cao-mcp-server/memory_forget') in the calling terminal's allowed tools
authz.jsonl: {"action":"tool:call","allowed":false,"enforced":true,"kind":"terminal","reason":"terminal 84f944d0 allowed_tools does not cover memory_forget on cao-mcp-server","resource":"cao-mcp-server/memory_forget","rule":"tool:default-deny","run_id":null,"terminal_id":"84f944d0","ts":"2026-10-22T06:21:49.462907+00:00"}
expected: {"audit_enforced": true, "audit_rule": "tool:default-deny", "gate": "denied", "rule_in_text": true}
observed: {"audit_enforced": true, "audit_rule": "tool:default-deny", "gate": "denied", "rule_in_text": true}
verdict:  OK
note:     HARD IN BOTH MODES. #972's on_call_tool middleware is the gate for every cao-mcp-server tool; it asks _tool_denied_reason -> tool_gate.denial_for -> authz.check(hard=True), so CAO_PRINCIPAL_ENFORCE relaxes nothing here and the audit line says enforced: true even with the flag unset. The record fetch behind the decision presented A's own token (agent_credential()), not the operator's.
--- [warn] step b2: Terminal A calls send_message (a worker callback) on cao-mcp-server
request:  MCP call send_message(message='hello from the demo', receiver_id=7869887f) on cao-mcp-server as A; 7869887f is a terminal A created (caller_id=A)
response: result: {"created_at": "2026-10-22T06:21:51.879198+00:00", "message_id": 1, "receiver_id": "7869887f", "sender_id": "84f944d0", "success": true}
          policy: authorize(A, tool:call, send_message) -> tool:callback: send_message is always available to terminal 84f944d0
authz.jsonl: (no new line)
expected: {"audit_lines": 0, "delivered": true, "gate": "allowed", "policy_rule": "tool:callback"}
observed: {"audit_lines": 0, "delivered": true, "gate": "allowed", "policy_rule": "tool:callback"}
verdict:  OK
note:     send_message is one of the four callbacks (authz.CALLBACK_TOOLS) a bounded worker needs to report upward. The middleware exempts them before consulting policy, so no audit line is written; authorize() answers tool:callback for the same question. The body then applied its own relationship rule (the receiver is a terminal A created) and delivered the message to the worker's inbox.
--- [warn] step c: Terminal B cancels a workflow run terminal A started
request:  POST /workflows/runs:submit {name_or_path: demo_hold, run_id: demo-run-c6e8269a} as A; then POST /workflows/runs/demo-run-c6e8269a/cancel as B [Bearer cao_t_Apz0...  (len 49)]
response: submit: HTTP 202 {"links":{"cancel":"/workflows/runs/demo-run-c6e8269a/cancel","events":"/workflows/runs/demo-run-c6e8269a/events","result":"/workflows/runs/demo-run-c6
          cancel: HTTP 200 {"run_id":"demo-run-c6e8269a","success":true}
authz.jsonl: {"action":"run:cancel","allowed":false,"enforced":false,"kind":"terminal","reason":"terminal d40bc683 neither owns nor is an ancestor of run demo-run-c6e8269a","resource":"run:demo-run-c6e8269a","rule":"run:not-owner","run_id":null,"terminal_id":"d40bc683","ts":"2026-10-22T06:21:55.190642+00:00"}
expected: {"audit_enforced": false, "audit_rule": "run:not-owner", "cancel": 200, "run_state_after": "cancelled", "submit": 202}
observed: {"audit_enforced": false, "audit_rule": "run:not-owner", "cancel": 200, "run_state_after": "cancelled", "submit": 202}
verdict:  OK
note:     Warn mode: B really cancelled A's run (today's behaviour). The audit line is the only trace that a stranger did it.
--- [warn] step d: The operator cancels the same run
request:  POST /workflows/runs/demo-run-c6e8269a/cancel  as the operator [no bearer (operator, auth off)]
response: HTTP 409 {"detail":"run 'demo-run-c6e8269a' is already cancelled; cannot cancel"}
authz.jsonl: {"action":"run:cancel","allowed":true,"enforced":false,"kind":"anonymous","reason":"anonymous principals are unbounded","resource":"run:demo-run-c6e8269a","rule":"operator","run_id":null,"terminal_id":null,"ts":"2026-10-22T06:21:55.211141+00:00"}
expected: {"audit_allowed": true, "audit_rule": "operator", "status": 409}
observed: {"audit_allowed": true, "audit_rule": "operator", "status": 409}
verdict:  OK
note:     Warn mode: the operator is allowed (rule 'operator', decided before the route looks at the run) and then gets 409, because step c already cancelled the run. There was nothing left for the operator to cancel: that is what 'audit only' costs.
--- [warn] step e: Terminal A calls an ops-server tool (list_sessions on cao-ops-mcp-server)
request:  MCP call list_sessions() on a real cao-ops-mcp-server process with CAO_TERMINAL_ID=84f944d0 and CAO_TERMINAL_TOKEN set
response: result: {"message": null, "sessions": [{"agent_profile": "demo_worker", "id": "cao-caodemo-a-83f296", "name": "cao-caodemo-a-83f296", "status": "detached", "working_directory": "/private/tmp/wt-principal"}, {"agent_profile": "demo_supervisor", "id": "cao-caodemo-b-981622", "name": "cao-caodemo-b-981622", "status": "detached", "working_directory": "/private/tmp/wt-principal"}], "success": true}
authz.jsonl: {"action":"tool:call","allowed":false,"enforced":false,"kind":"terminal","reason":"terminal 84f944d0 may not call ops tool list_sessions","resource":"cao-ops-mcp-server/list_sessions","rule":"fleet:operator-only","run_id":null,"terminal_id":"84f944d0","ts":"2026-10-22T06:21:57.356686+00:00"}
expected: {"audit_enforced": false, "audit_rule": "fleet:operator-only", "gate": "allowed", "tool_success": true}
observed: {"audit_enforced": false, "audit_rule": "fleet:operator-only", "gate": "allowed", "tool_success": true}
verdict:  OK
note:     Warn mode: main never gated the ops server, so the flag decides here. The worker listed every session on the fleet; the audit line says enforced: false.
== mode warn done in 27.0s

== summary (enforce vs warn)
step enforce                                      warn                                         title
0    tokens accepted, forged 401                  tokens accepted, forged 401                  The minted credentials resolve; a forged one does not
a    403 terminal:impersonation enforced=True     201 terminal:impersonation enforced=False    Terminal A names terminal B as caller_id on a create
b1   denied tool:default-deny enforced=True       denied tool:default-deny enforced=True       Terminal A (allowedTools: [fs_read]) calls memory_forget on cao-mcp-server
b2   allowed                                      allowed                                      Terminal A calls send_message (a worker callback) on cao-mcp-server
c    403 run:not-owner enforced=True              200 run:not-owner enforced=False             Terminal B cancels a workflow run terminal A started
d    200 operator (allowed)                       409 operator (allowed)                       The operator cancels the same run
e    denied fleet:operator-only enforced=True     allowed fleet:operator-only enforced=False   Terminal A calls an ops-server tool (list_sessions on cao-ops-mcp-server)

all steps matched their expected outcome
runtime: 72.0s total (enforce 45.0s, warn 27.0s)
```

## What the demo does not show, and why

- **A real agent choosing to call a tool.** The MCP calls come from a FastMCP client with the
  pane's environment, not from a model. The gate is the same code path either way (the
  middleware and the decorator run inside the server process on `call_tool`), and a real agent
  would add nothing but cost and nondeterminism.
- **Operator auth on.** The servers run default-off, so the operator is the anonymous principal.
  WS1 and WS2 cover the auth-on path in `test/security/test_auth_agent_bearer.py` and
  `test/api/test_agent_bearer_handshakes.py`; the demo keeps one configuration so the transcript
  stays readable.
- **The herdr backend.** Token injection on herdr is covered by `test/backends/test_terminal_token_env.py`;
  the demo's panes are tmux.
- **Resume and replay.** Same gate as cancel (`run:resume`, `run:replay`), covered by
  `test/api/test_workflow_run_ownership.py`; cancel is the one with the clearest story.
