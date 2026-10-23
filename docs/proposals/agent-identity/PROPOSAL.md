# Proposal: give every CAO agent an attributable identity

Status: DRAFT v2 for maintainer discussion (Haofei, Hongyu, Augusto, Ted). 2026-10-23.
Supersedes the v1 proposal (2026-10-21) after four independent adversarial reviews and a second pass on this text; the diff of claims is in `CHANGES-FROM-V1.md`. Companion: `IMPLEMENTATION-PLAN.md`. Demo code is branch `demo/agent-principal` on the author's fork; `path:line` citations below refer to it. The defects the reviews found in the demo code are fixed on the branch as of dd89c297 (seven commits, each with a failing test first); the open debt they left is listed under Cost.

## The problem in one paragraph

CAO cannot tell its agents apart. Every terminal it launches calls the API and `cao-mcp-server` with either no credential or the operator's shared `CAO_AUTH_LOCAL_TOKEN`, and names itself with `CAO_TERMINAL_ID`, which anything in the pane can read, change or drop. The server has no trustworthy answer to "which terminal sent this", and no audit line can carry a name. That attribution gap is the general problem. Beyond it, exactly two object-level gaps need a caller identity: any terminal can cancel, resume or replay any workflow run because runs have no owner, and `cao-ops-mcp-server` gives fleet-wide session control to any profile that names it. The other issues v1 listed are already fixed without a principal or are orthogonal: #948 put the ceiling on the row, #972 shipped the tool gate for all 34 tools, #829's run token is its own small credential, #990 is one request helper, and #896 is a delivery-safety bug that does not belong here.

## What we propose

**A per-terminal credential.** When `create_terminal` launches an agent, the server mints a random token, stores only its digest on the terminal row, and puts the token in the pane's environment as `CAO_TERMINAL_TOKEN` next to `CAO_TERMINAL_ID` (`services/terminal_service.py:1775-1792`, row INSERT at `:1892`). On close the digest is cleared before the runtime teardown, so the token stops resolving even when the kill is deferred (`services/terminal_service.py:4815-4842`). A missing or closed row is a 401 in every mode. Mint, inject, revoke, resolve: identity plumbing.

**Caller identity bound to the bearer.** The bearer's row is the caller. A request claiming a `caller_id` or `CAO_TERMINAL_ID` that differs from the bearer's terminal is refused. This closes #965, and it needs a fix to the demo code first: the MCP gate authorizes from the row named by `CAO_TERMINAL_ID`, fetched over `GET /terminals/{id}`, and that route never binds the path id to the bearer (`api/main.py:4097-4118`). Terminal A presenting its own token with B's id is authorized with B's allowlist. The review reproduced this with a probe.

**Two targeted object-level gates.** Run ownership for cancel, resume and replay, stamped at run creation, with an answer for the owner dying. A gate on `cao-ops-mcp-server` that only an operator passes, plus an install-time lint. Both are separate small PRs after the plumbing.

## What we are not proposing

- **No guardrail claim against runaway or prompt-injected agents.** Without process or network isolation the policy is bypassed by the workload it restrains: an agent with a shell can read a sibling pane's environment, edit its own profile, or curl port 9889. The honest claim is attribution on every call and protection against accidental misuse by cooperating clients. The Pod Security Admission analogy is withdrawn; it sits on a kernel boundary CAO does not have.
- **No universal chokepoint.** `api/main.py` carries 115 `require_any_scope` checks that decide function-level access, never consult the principal and never audit. They stay as the documented function-level layer. `authorize()` decides object-level questions only.
- **No default flip.** `CAO_PRINCIPAL_ENFORCE` stays off. Turning it on must meet the evidence bar at the end.
- **No shared-bearer retirement.** The operator token keeps working for every caller that presents it. "Retire" has two meanings, neither has a compatibility path, and neither is here.
- **No tool-reach rewrite.** #972's gate stays. The principal makes its refusals attributable, nothing more.

## The design question and the chosen answer

The reviews converged on a design hole, not a bug. With auth off (the default), a request with no agent token becomes an anonymous principal with the full scope set (`security/principal.py:283-286`), and operators are unbounded (`security/authz.py:193-195`). An agent that drops `CAO_TERMINAL_TOKEN` gains authority. Refusals are logged but allows are not by default (`security/audit.py:52-53`), so the bypass leaves no trace. Enforcement would be voluntary.

**Enforce implies auth.** `CAO_PRINCIPAL_ENFORCE=1` is refused at startup unless `CAO_AUTH_LOCAL_TOKEN` or an IdP is configured. Under enforce an unauthenticated request is a 401, never an anonymous operator. Operators who want object-level refusals pay for auth. Default-off installs get attribution only, and the docs say so in those words.

**Agent processes never fall back.** `agent_credential()` prefers the terminal token and falls back to the operator token (`security/agent_credential.py:61-66`). The revision makes it refuse to present any other credential when `CAO_TERMINAL_ID` is set, so a launched agent without a token fails closed in its own process. The error says only that the credential is missing; the remedy (relaunch) is written to the server log and the docs, not to the agent, so the message is not a hint about what to drop. This stops the accidental path, not the deliberate one. It is cheap and worth doing regardless.

**Isolation is the real boundary and is out of scope.** Per-agent process isolation is what would turn refusals into a boundary, and it replaces much of a chokepoint rather than following it. It is a different proposal with its own cost. Nothing here depends on it.

## What the reviews found, and how v2 answers each

| Finding | Answer in v2 |
|---|---|
| Enforcement is voluntary; the bypass is unlogged | Enforce implies auth; no fallback in agent processes; allowed calls logged for agent principals |
| MCP gate trusts `CAO_TERMINAL_ID`, not the bearer (reproduced) | Bearer's row is the principal; mismatched id refused; terminal routes bind path id to bearer |
| Causality overstated: two of seven issues need identity | Problem restated as attribution plus two gaps; the rest named as fixed or orthogonal |
| `authorize()` is not one chokepoint (115 scope checks, unaudited ephemeral policy, `OPERATOR_ROUTE` used once) | Chokepoint claim withdrawn; scope checks documented as function-level; `OPERATOR_ROUTE` dropped |
| Lifecycle unspecified | Nine-case contract, each a test before PR A merges |
| Migration is a cutover; branch is 74 files, +9,613 lines | Migration section; no flip, no retirement; cost stated |
| Audit log is a debugging artifact | Bounded: rotation, request id, outcome, fix hint, write failures counted |

## How we would land it

Three PRs, each independently useful, each leaving main working with the flag off.

- **PR A, identity plumbing and bearer-bound caller.** Core modules, `credential_digest` column, mint, inject, revoke, resolve. MCP gate reads the bearer's row and refuses a mismatched id. No fallback when a terminal id is set. `delegate_tools` populated on both construction paths (`security/tool_gate.py:108-125` omits it today). Allowed calls logged for agent principals, meaning principals of kind `terminal` or `run`; operator and anonymous calls stay unlogged, which is why attribution holds only for callers that present a token. Closes #965 and the #990 class.
- **PR B, run ownership.** Owner and frozen ancestors stamped at run creation; cancel, resume and replay call the check; on owner death a recorded ancestor or the operator may act and the audit line says who did. Closes the `workflow_cancel` gap.
- **PR C, ops server gate and install lint.** Ops tools refuse agent principals; `install_profile` refuses under enforce or warns otherwise when a profile pairs the ops server with a restricted allowlist.

## Lifecycle contract

Each row is a test that must pass before PR A merges.

| Case | Expected outcome |
|---|---|
| Mint fails | `create_terminal` raises before any backend call; no pane, no row |
| Injection fails (backend drops the env) | Agent has an id and no token; `agent_credential()` refuses in-process with a named error; no request leaves |
| Close with calls in flight | Digest cleared first. A request that has already resolved its bearer to a row completes; a request that has not yet resolved is 401. Resolution is one read, so there is no window in which a resolved request is later refused. Both modes |
| Session teardown | Every terminal in the session is 401 after teardown even when row removal is deferred; same revoke path as single delete |
| Restart with live terminals | Tokens keep resolving; effective mode logged at startup; a mode change is an audit line |
| Pane gone, row remains | The recovery sweep clears the digest when it marks the terminal crashed; relaunch mints fresh |
| Run outlives its owner | Owner frozen; recorded ancestors and the operator may act; under enforce nobody else can |
| Intermediate ancestor deleted | Ancestry is stamped on the row at creation, not recomputed through live rows as today (`security/principal.py:147`) |
| Profile edited while terminals live | Effective allowlist snapshotted onto the row at launch; edits affect new terminals only; the audit line carries the allowlist the decision saw. To narrow a live terminal the operator closes it and relaunches; a live edit never revokes, and the docs say so |

The profile-edit choice rejects eager revocation (kills live work) and versioned tokens (key management for one property). Snapshot-at-launch is what `create_terminal` already does for an explicit `allowed_tools`; the change is that a profile-resolved `None` is resolved once and recorded.

## Migration

- **Live terminals** launched before PR A have an id and no token, and a token cannot be injected into a running pane. The server logs their ids at startup with the remedy; the agent-side error says only that its credential is missing. Release notes say relaunch.
- **Legacy runs** have no owner. Owner null means operator-only for cancel, resume and replay. Under default-off that is everyone, as today.
- **Profiles.** Tool reach does not change. Only PR C's lint touches profiles, and only ones pairing the ops server with a restricted allowlist. Its message names the fix.
- **Provider token delivery.** Providers forward `CAO_TERMINAL_ID` by inheritance, by name (codex, `providers/codex.py:1661`), or by a literal env map written into a generated config file (copilot, cursor, claude_code, grok, antigravity). The token is never written to a file. A provider that can only deliver a literal map does not get the token; its agents fail closed with the named error, and it is listed as unsupported for enforce until it forwards by name. PR A ships the per-provider table.
- **The shared bearer.** Nothing changes.

## Audit log as a bounded artifact

Today `logs/authz.jsonl` is append-only with no rotation, whole-file reads, and write failures swallowed at debug (`security/audit.py:66-70`). The revision adds rotation by size or age with a small keep count, a request id and outcome on every line, allowed calls for agent principals, the allowlist the decision saw, a `reason` that carries the fix ("add `@cao-mcp-server` to allowedTools") and not only the list that failed, and write failures counted and surfaced on a health endpoint. Warn mode cannot prove "nothing legitimate is refused", because unexercised paths and anonymous callers produce no lines. We will not make that claim.

## Cost

The demo branch is 74 files, +9,613 and -205 lines. PR A is roughly 3,800 lines, about 40 percent of the branch, two-thirds of it tests. PR B is about 1,300 and PR C about 1,400. Around 3,100 lines are dropped: the tool-reach rewrite, its census, and the demo script and transcript. The v1 line "one new column, three new modules" described the modules, not the change.

The review fixes added 42 files, +4,136 and -532 lines on top, most of it tests. They also exposed a debt the v1 text did not know about: 154 test sites across 60 files set `CAO_TERMINAL_ID` with no token and relied on the silent fallback to the operator token. They now run behind a named autouse fixture, `legacy_operator_token_fallback`, that restores the old behaviour for tests whose subject is not the credential. Converting them to seed a real row and digest is part of PR A's migration work, not a footnote. Warn mode still permits an id substitution by design, now recorded as `terminal:impersonation` where it used to be silent; enforce mode refuses it.

## Evidence bar for any later enforcement proposal

The reviewers said what would change their minds. It is the acceptance bar for turning `CAO_PRINCIPAL_ENFORCE` on by default or retiring the shared bearer.

1. Comparative traces of representative runaway and prompt-injected agents with and without the change, including credential stripping and shell retries. Not a scripted demo of refusals.
2. An upgrade and lifecycle test matrix across existing profiles, scripts, live terminals, legacy runs and restart, under both modes.
3. A measurement that identity-dependent failures dominate incidents or maintenance after the coverage and propagation fixes land. One concrete incident would count.
4. A bypass-detection test: the three bypass paths tried, with the audit log showing the forgery as a forgery rather than blaming the victim.
5. Either a multi-user roadmap this model is compatible with, or an explicit decision that single-user CAO wants it anyway.

## What we would like the team to decide

1. Is attribution on every call worth PR A on its own, with no enforcement claim?
2. Is "enforce implies auth" the right answer to the anonymous-operator hole, or should enforce mode wait for isolation?
3. Are PR B and PR C the right two object-level gates, and do they wait for PR A?
4. Who reviews the demo branch once the defects in the plan's checklist are fixed? (The branch is not shown until they are; a second adversarial pass on this text found the fixes described but not yet present.)
