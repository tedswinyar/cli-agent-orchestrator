# Agent principal (experimental, #965)

**Status:** experimental, warn mode by default. Nothing is refused unless
`CAO_PRINCIPAL_ENFORCE=1`.

To see it work: `scripts/demo_agent_principal.py` runs the six refusals end to end against an
isolated server in both modes; [`agent-principal-demo.md`](agent-principal-demo.md) has the
transcript and what each step proves.

## What a principal is

Today every CAO surface shares one bearer (or none), and "who is calling" is a
self-asserted `caller_id` or `CAO_TERMINAL_ID`. A **principal** is the caller as
the server knows it: resolved once from the request's **bearer** by one FastAPI
dependency, and handed to one policy function, `authorize()`, that every
surface asks the same question. It is a guardrail with a name on every action,
not a security boundary: an agent with a shell on the same host can still reach
the port.

**The bearer, not the claim.** This is the load-bearing word. A process asserts
an identity through `CAO_TERMINAL_ID`, which is an environment variable it can
set to anything. The principal is built from the row the BEARER resolves to, and
a claimed id that is not the bearer's own terminal is a refusal
(`terminal:impersonation`) rather than a substitution. `GET /me/principal` is
where that decision is made, and it is the only place any surface asks "who am
I" — see [Identity binding](#identity-binding).

```python
from cli_agent_orchestrator.security.authz import TOOL_CALL, check
from cli_agent_orchestrator.security.principal import Principal, get_current_principal

```

## The four kinds

| kind        | how it is resolved                                   | scopes                      |
|-------------|------------------------------------------------------|-----------------------------|
| `terminal`  | bearer `cao_t_...`, looked up by SHA-256 digest in `terminals.credential_digest` | `cao:read`, `cao:write` (never admin) |
| `run`       | bearer `cao_r_...`, resolved through `security.run_tokens` when that module exists (#829); carries the spawning terminal's fields plus `run_id` | `cao:read`, `cao:write` |
| `operator`  | auth enabled, bearer is the operator token or an IdP JWT (today's `get_current_scopes`) | the token's scopes |
| `anonymous` | auth disabled and no agent bearer (default-off)      | full scope set              |

A `terminal` principal carries the row's **effective** `allowed_tools`
(selectors not expanded; a recorded `None` means "resolve from the agent
profile" and is resolved here, so every surface bounds the same row by the same
list), `allowlist_resolved` (False when that resolution failed, which
`authorize()` refuses with `identity:unresolved` rather than mistaking for a
deny-all), `delegate_tools` (the delegation ceiling; **`None` means "no ceiling
recorded" and falls back to the own allowlist, `()` means "may delegate
nothing" and does not** — see [Delegation ceiling](#delegation-ceiling)),
`ephemeral` (the registry bit the `ephemeral:*` rules read), `creator_id` (the
row's `caller_id`) and `ancestors` (creator, creator's creator, ... root,
followed up the terminal table, bounded at 32 hops, cycles broken). A missing or
closed row makes the bearer fail with `401 terminal credential revoked`.

**One construction path.** `principal.principal_from_terminal_row` is the only
function that turns a row into a `terminal` principal. `principal_payload` /
`principal_from_payload` carry its result over HTTP to the two MCP boundaries,
which never touch `clients.database`, so the allowlist and the ceiling a tool
gate computes are the same values an HTTP route computes.
`test_every_dataclass_field_is_on_the_wire_or_derived` fails if `Principal`
gains a field that is neither serialized nor named as derived.

Operator and anonymous principals are allowed everything. The rules bound
agents only.

## Credentials

`mint_terminal_credential()` returns `(token, digest)`. The token is
`cao_t_` plus 43 URL-safe characters (256 bits). Only the digest is stored, so
a database read never yields a usable bearer.

**Minted at create.** `services.terminal_service.create_terminal` mints the
credential before the backend creates the pane and places the token in the
pane's environment as `CAO_TERMINAL_TOKEN`, next to `CAO_TERMINAL_ID`, on both
backends: tmux (`create_session` / `create_window` / pane split, via the same
`extra_env` channel as `cao launch --env`) and herdr (`--env` at create). The
token is assigned last in that mapping, so neither an operator `--env` nor a
persisted session var can hand a window a sibling's credential, and it is
never written to the session-env store. The digest travels in the row
INSERT itself (`create_terminal(..., credential_digest=...)`), so no
committed row ever exists whose token nothing resolves. Every terminal gets
its own, including the memory sidecar from `cao launch --memory`.

**Presented on every hop, and never swapped for the operator's.**
`security.agent_credential.agent_credential()` is the one helper behind every
agent->API request. It prefers `CAO_TERMINAL_TOKEN`; **raises
`MissingTerminalCredential` when `CAO_TERMINAL_ID` is set and the terminal token
is not**; otherwise takes the operator token path (`CAO_AUTH_LOCAL_TOKEN`)
exactly as before; and returns `{}` when neither is set so default-off is
byte-for-byte unchanged.

The refusal is the point. A CAO-launched agent whose own credential did not
arrive — a provider that cannot pass it, a relaunched legacy pane, a script that
dropped it — used to reach the API presenting the operator's token, i.e. **as
the operator**: unbounded, and attributable to nobody. "Every hop carries the
terminal's own credential" was false in exactly the case that mattered, and
nothing recorded it. It now fails closed in the agent's own process, with the
terminal id in the message.

What this does NOT do: a determined agent can unset `CAO_TERMINAL_ID` as well,
and with auth disabled the server still answers an unauthenticated caller as
`anonymous` with the full scope set. Closing that is a decision about what
`CAO_PRINCIPAL_ENFORCE` requires, not something a credential helper can do.
What it closes is the accidental path. The old `_auth_headers()`
names in `mcp_server/utils.py`, `mcp_server/app_tools.py` and
`utils/orchestration.py` are thin aliases over it, which is how the
`cao agent ...` commands present the token too.
`test/security/test_agent_credential_guard.py` walks every `requests` call to
`API_BASE_URL` in those modules and fails, with file and line, on any that
does not take its headers from the helper (the #990 class).

**Revoked on close, on every path.** Revocation lives in
`terminal_service.dismantle_terminal_runtime`, the one function every teardown
path runs (`delete_terminal`, `session_service.delete_session`, and the herdr
runtime reclaim), and it runs BEFORE any runtime step: by then the kill is
committed, so if a step raises halfway the token must already be dead rather
than waiting on a retry that may never come.

It used to live in `delete_terminal` alone, so the other two paths left a live
digest. Row removal is the backstop for the completed cases — a missing row is
already "revoked" to the resolver — but neither of those paths removes the row
when cleanup DEFERS, which is exactly the case the digest matters in: the agent
is being killed, its token is in a pane environment (and possibly copied
elsewhere), and the row survives for a retry. A per-caller step is a step a
caller can omit, which is how they came to disagree;
`test/security/test_credential_revocation.py` enumerates the call sites rather
than trusting that three were remembered.

The `cao_t_` path answers 401 `terminal credential revoked` regardless of
`CAO_PRINCIPAL_ENFORCE`: it is a credential check, not a policy decision.

## Actions and rules

`authorize(principal, action, resource, **ctx) -> Decision(allowed, rule, reason)`
is pure. Unknown actions are refused.

| action            | resource                                   | rule for agent principals |
|-------------------|--------------------------------------------|---------------------------|
| `tool:call`       | tool name, `server=` keyword               | `cao-mcp-server`: default-deny unless `allowed_tools` covers the tool (`*`, `@cao-mcp-server`, a glob such as `@cao-*`, or `@cao-mcp-server/<tool>`; a bare tool name never grants an MCP tool). Always allowed: `send_message`, `complete_assignment`, `workflow_return`, `answer_user_prompt`, `list_siblings`, `update_metadata` (the #671 ruling). `cao-ops-mcp-server`: denied. |
| `terminal:create` | requested child `allowed_tools` tuple      | every entry must be within the ceiling (`delegate_tools` if recorded, else `allowed_tools`) |
| `terminal:act_as` | claimed `caller_id`                        | allowed only for the principal's own `terminal_id` |
| `terminal:target` | `TerminalRef(terminal_id, ancestor_terminal_ids, peer_terminal_ids)`, `read=` keyword | the caller's own terminal (`terminal:self`) or one it created directly or transitively (`terminal:descendant`). For a READ also the caller's own ancestors (`terminal:ancestor`) and, with the `discovery` grant, its group peers (`terminal:discovery-peer`). Else `terminal:not-owner`. |
| `identity:prove`  | the claimed `CAO_TERMINAL_ID`              | the bearer's own terminal (`identity:proven`), or no claim at all (`identity:unbound`). A different terminal is `terminal:impersonation`; a bearer that resolves to no terminal is `identity:unproven`. **The one action an operator principal does not short-circuit.** |
| `ephemeral:depth` | tool name                                  | refused for an ephemeral caller (`ephemeral:max-depth`, i.e. `ephemeral.max_depth=1`) |
| `ephemeral:delegate` | tool name, `child_may_delegate=` keyword | refused for an ephemeral caller unless `ephemeral.child_may_delegate` (`ephemeral:child-delegation`) |
| `run:cancel`, `run:resume`, `run:replay` | `RunRef(run_id, owner_terminal_id, ancestor_terminal_ids)` | owner, ancestor, or a run principal acting on its own run |
| `fleet:*`         | ops tool name                              | denied |
| `operator:route`  | route name                                 | denied |

An agent principal whose `allowlist_resolved` is False is refused
`identity:unresolved` for `tool:call` and `terminal:create` — the two actions
that read `allowed_tools`. Run ownership and identity binding do not consult the
list, so an unreadable agent profile does not lock a terminal out of its own run.

## Identity binding

Two places bind a claimed identity to the bearer. Both were open, and both were
the same defect: a scope tier answers "may this caller use this kind of route"
and says nothing about which object.

**`GET /me/principal?claimed_terminal_id=<id>`** is where a process asks "who am
I". It resolves the principal from the bearer, runs `check(IDENTITY_PROVE)`, and
returns `{"principal": ..., "identity_bound": bool, "claimed_terminal_id",
"rule"}`. Under `CAO_PRINCIPAL_ENFORCE` a mismatch is a 403. In warn mode the
refusal is audited and the body carries the CLAIMED terminal's principal with
`identity_bound: false` — byte-for-byte what every surface did before the route
existed. Warn mode preserving a hole it now records is what warn mode is for;
what it must not do is keep the hole invisible.

Both MCP boundaries (`mcp_server/server.py::_tool_denied_reason` and
`ops_mcp_server/gate.py`) go through it. They used to fetch
`GET /terminals/{CAO_TERMINAL_ID}` and authorize from that row, so a process
holding terminal A's credential and exporting `CAO_TERMINAL_ID=B` was authorized
with B's allowlist, in warn and enforce alike. Any failure to resolve the
identity — an unreachable server, a 401, a 404, a payload the deserializer
rejects — is an unknown, and an unknown does not dispatch. A cao-server too old
to serve the route therefore fails closed: "compatible with an old server" and
"authorizes a forgeable id" were the same property.

**`/terminals/{terminal_id}` routes** carry one of two dependencies, enumerated
by the `terminal-path-routes` row of
`test/security/test_registration_policy_coverage.py` so a route added later is
bound by default:

| dependency | routes | relationships allowed |
|---|---|---|
| `bind_terminal_path_id` | input, key, exit, delete, PATCH group/description/metadata | self, descendant |
| `bind_terminal_path_id_read` | the record, siblings, memory-context, output, output/range, working-directory, inbox | self, descendant, ancestor, discovery peer |

The read tier is wider because CAO's own documented flows read across those
relationships: `utils.orchestration._target_binding_denial(allow_parent=True)`
reads the supervisor's record so a worker can `send_message` upward, and
`allow_discovered_sibling=True` reads a peer's for issue #432's "find siblings
with `list_siblings`, then message them". Refusing those reads would break the
callback protocol in order to enforce a rule about *acting*. Reading up or
sideways is not steering up or sideways, and that stays refused. The WebSocket
route is the one exemption, with its reason: a handshake must be refused before
`accept()`, so the binding belongs in the handler body with its own close code.

## Delegation ceiling

A terminal's `delegate_tools` is the widest `allowed_tools` it may hand to a
terminal it creates. `terminal_service.child_delegate_tools` records it on every
CAO-created child as `authz.narrow_to_ceiling(requested, ceiling_of(creator))` —
the creator's own ceiling when nothing was asked for (the only case today, since
no client parameter carries one), and the intersection when something was. Never
wider than the creator's.

That default is the fix. Without a recorded ceiling, `ceiling_of` falls back to
the row's OWN `allowed_tools`, so a creator's intent to cap its delegates
reached exactly one level and then evaporated: give the child a wider allowlist
for any legitimate reason and the grandchild inherits the child's list, not the
grandparent's cap. `A(*, ceiling fs_read) -> B(*) -> C(anything)` was allowed and
nothing refused.

`None` and `()` are different values and must stay different. `None` means no
ceiling was recorded — the operator-created case and every pre-migration row —
and falls back to the own allowlist. `()` means "may delegate nothing" and does
NOT fall back; collapsing them would make a row that may delegate nothing fall
back to its own, possibly `*`, allowlist, which is the same escalation one level
further in. The distinction survives the API -> MCP serialization hop.

## Run ownership

A workflow run carries its owner from creation. `POST /workflows/runs` and
`POST /workflows/runs:submit` stamp two columns on the `workflow_run` row, in the
same INSERT as the rest of the row, for both the YAML and the script tier:

| column                  | value                                                        |
|-------------------------|--------------------------------------------------------------|
| `owner_terminal_id`     | the starting principal's `terminal_id`; NULL for an operator |
| `ancestor_terminal_ids` | the starting principal's `ancestors` (creator chain, nearest first) as a JSON array; NULL when empty |

Both are **frozen at creation**. They are never recomputed from the live
`terminals` table and the journal has no UPDATE path for either column, so a
later re-parent of the terminal tree cannot widen who may act on the run.

`POST .../cancel`, `POST .../resume` and `POST .../steps/{step_id}:replay`
resolve the caller with `get_current_principal` and call
`check(principal, RUN_*, RunRef(run_id, owner_terminal_id, ancestor_terminal_ids))`
before any tier dispatch. Allowed: the owner, any terminal in the frozen
ancestor list, an operator (CLI or admin bearer; `cao workflow cancel` never
sees a 403), and a run principal acting on its own `run_id`. Anything else is
refused with a 403 whose detail names the run, its **owner's** terminal id and
the caller's terminal id, and nothing else (never prompt text or inputs). A run
with no owning terminal (operator start, or a row written before this column
existed) is operator-only.

**A resume is a new caller, not a handoff.** Resuming does not re-stamp the owner
and does not append the resumer to the ancestor list. A terminal that resumed a
run in warn mode therefore still cannot cancel it under enforcement; a terminal
that may resume (owner, ancestor, operator) could already cancel. Ownership
transfer, if it is ever needed, is a separate explicit and logged call, not a
side effect of resume.

The structural guard is `test/security/test_run_ownership_guard.py`: it walks
the AST of `api/main.py` and `mcp_server/server.py`, and fails CI for any
mutating route that takes a `run_id` and does not call `check()` with a `RUN_*`
action (two routes are listed as known-ungated with reasons), for any MCP tool
whose mutating HTTP call reaches a `{run_id}` path that is not one of the gated
routes, and for any UPDATE statement in the journal that touches an ownership
column.

## Warn mode and the enforce flag

`check(principal, action, resource, **ctx)` is what call sites use. It
authorizes, writes the audit record, and:

- **warn mode** (default, `CAO_PRINCIPAL_ENFORCE` unset): returns the
  `Decision` and never raises, so behaviour is unchanged while the audit log
  shows what enforcement would have refused;
- **enforce mode** (`CAO_PRINCIPAL_ENFORCE=1` or `true`): raises
  `HTTPException(403, detail=decision.reason)` on a denial.

## Audit file

`CAO_HOME_DIR/logs/authz.jsonl`, one JSON object per line: `ts`, `request_id`,
`kind`, `terminal_id`, `run_id`, `action`, `resource`, `allowed`, `enforced`,
`outcome`, `rule`, `reason`.

**What is recorded.** Refusals always, whatever the principal's kind. Allowed
calls for AGENT principals (`terminal`, `run`) by default; for operator and
anonymous principals only under `CAO_AUTHZ_AUDIT_ALLOWS=1`. The asymmetry is the
point: with only refusals recorded, an agent that dropped its credential and
sailed through as the operator produced no line at all, so warn mode could not
reveal the population it exists to reveal. Logging every operator allow instead
would bury that signal under the operator's own traffic — the web UI polls these
routes continuously.

**`outcome`** is `allowed` | `refused` | `audited`. `audited` is warn mode: the
decision was a denial AND the call proceeded. Without it a reader cannot tell a
blocked call from a successful one, which is the single most important thing a
warn-mode trail has to say; `allowed: false` alone does not distinguish them.

**`request_id`** correlates the several decisions one request can produce
(`terminal:act_as` then `terminal:create`, or a path binding then a tool call).
`api.main.AuthzRequestIdMiddleware` opens the scope on every HTTP request,
honours an inbound `X-Request-Id` (bounded to 64 characters of
`[A-Za-z0-9._-]`, since the value lands in a log line and a response header) and
echoes the id back. `None` outside a scope: an in-process call site is not a
request, and a synthetic id would be a lie.

**Rotation.** `CAO_AUTHZ_AUDIT_MAX_BYTES` (default 10 MiB, `0` disables) and
`CAO_AUTHZ_AUDIT_KEEP` generations (default 3, written as `authz.jsonl.1` ...
`.3`). Rotation happens BEFORE an append, so the live file always exists and
always holds the newest line — a reader never arrives in the window where the
log was just renamed away — and the live file exceeds the cap by at most the one
line that crossed it, never mid-line. A malformed setting falls back to the
default rather than disabling rotation, which is the failure mode that lets a
log eat a disk.

**Write failures are counted**, not swallowed: `audit.write_failures()` and
`audit.stats()` (`{"write_failures": n, "path": ...}`). A trail that stops must
say so. Writing still never raises — an audit failure must not become a
denial-of-service lever against the thing it observes — and a rotation failure
is counted while the line that follows is still written.

`audit.read_recent(n)` returns the last `n` records from the LIVE file. It is a
tail for an operator or a test, not a query interface; rotation is what keeps it
cheap.

## Reference

The contract these modules implement is the public interface of
`security/principal.py`, `security/authz.py` and `security/audit.py`; see the
module docstrings and `test/security/test_principal.py`,
`test_authz.py`, `test_audit.py`, `test_credential_db.py`.
