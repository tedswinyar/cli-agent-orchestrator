# Agent principal (experimental, #965)

**Status:** experimental, warn mode by default. Nothing is refused unless
`CAO_PRINCIPAL_ENFORCE=1`.

## What a principal is

Today every CAO surface shares one bearer (or none), and "who is calling" is a
self-asserted `caller_id` or `CAO_TERMINAL_ID`. A **principal** is the caller as
the server knows it: resolved once from the request's bearer by one FastAPI
dependency, and handed to one policy function, `authorize()`, that every
surface asks the same question. It is a guardrail with a name on every action,
not a security boundary: an agent with a shell on the same host can still reach
the port.

```python
from cli_agent_orchestrator.security.principal import Principal, get_current_principal
from cli_agent_orchestrator.security.authz import check, TOOL_CALL
```

## The four kinds

| kind        | how it is resolved                                   | scopes                      |
|-------------|------------------------------------------------------|-----------------------------|
| `terminal`  | bearer `cao_t_...`, looked up by SHA-256 digest in `terminals.credential_digest` | `cao:read`, `cao:write` (never admin) |
| `run`       | bearer `cao_r_...`, resolved through `security.run_tokens` when that module exists (#829); carries the spawning terminal's fields plus `run_id` | `cao:read`, `cao:write` |
| `operator`  | auth enabled, bearer is the operator token or an IdP JWT (today's `get_current_scopes`) | the token's scopes |
| `anonymous` | auth disabled and no agent bearer (default-off)      | full scope set              |

A `terminal` principal carries the row's `allowed_tools` (selectors not
expanded), `delegate_tools` (the #948 ceiling; empty means "own allowlist"),
`creator_id` (the row's `caller_id`) and `ancestors` (creator, creator's
creator, ... root, followed up the terminal table, bounded at 32 hops, cycles
broken). A missing or closed row makes the bearer fail with
`401 terminal credential revoked`.

Operator and anonymous principals are allowed everything. The rules bound
agents only.

## Credentials

`mint_terminal_credential()` returns `(token, digest)`. The token is
`cao_t_` plus 43 URL-safe characters (256 bits). Only the digest is stored, so
a database read never yields a usable bearer. Wiring the mint into
`create_terminal` and the agent environment is a separate workstream; this
module provides the storage (`set_terminal_credential_digest`), the lookup
(`get_terminal_by_credential_digest`) and the resolution.

## Actions and rules

`authorize(principal, action, resource, **ctx) -> Decision(allowed, rule, reason)`
is pure. Unknown actions are refused.

| action            | resource                                   | rule for agent principals |
|-------------------|--------------------------------------------|---------------------------|
| `tool:call`       | tool name, `server=` keyword               | `cao-mcp-server`: default-deny unless `allowed_tools` covers the tool (`*`, `@cao-mcp-server`, a glob such as `@cao-*`, `@cao-mcp-server/<tool>`, or the bare name). Always allowed: `send_message`, `complete_assignment`, `workflow_return`, `answer_user_prompt`, `list_siblings`, `update_metadata` (the #671 ruling). `cao-ops-mcp-server`: denied. |
| `terminal:create` | requested child `allowed_tools` tuple      | every entry must be within the ceiling (`delegate_tools` if set, else `allowed_tools`) |
| `terminal:act_as` | claimed `caller_id`                        | allowed only for the principal's own `terminal_id` |
| `run:cancel`, `run:resume`, `run:replay` | `RunRef(run_id, owner_terminal_id, ancestor_terminal_ids)` | owner, ancestor, or a run principal acting on its own run |
| `fleet:*`         | ops tool name                              | denied |
| `operator:route`  | route name                                 | denied |

## Warn mode and the enforce flag

`check(principal, action, resource, **ctx)` is what call sites use. It
authorizes, writes the audit record, and:

- **warn mode** (default, `CAO_PRINCIPAL_ENFORCE` unset): returns the
  `Decision` and never raises, so behaviour is unchanged while the audit log
  shows what enforcement would have refused;
- **enforce mode** (`CAO_PRINCIPAL_ENFORCE=1` or `true`): raises
  `HTTPException(403, detail=decision.reason)` on a denial.

## Audit file

`CAO_HOME_DIR/logs/authz.jsonl`, one JSON object per line:
`ts`, `kind`, `terminal_id`, `run_id`, `action`, `resource`, `allowed`,
`enforced`, `rule`, `reason`. Refusals are always recorded; allows only when
`CAO_AUTHZ_AUDIT_ALLOWS=1`. Writing never raises. `audit.read_recent(n)`
returns the last `n` records.

## Reference

The contract these modules implement is the public interface of
`security/principal.py`, `security/authz.py` and `security/audit.py`; see the
module docstrings and `test/security/test_principal.py`,
`test_authz.py`, `test_audit.py`, `test_credential_db.py`.
