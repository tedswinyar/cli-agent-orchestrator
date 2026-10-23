# Changes from v1 (2026-10-23)

Tags are the finding numbers in the review synthesis (kept with the author): F1 voluntary enforcement, F2 gate trusts the env var, F3 overstated causality, F4 not one chokepoint, F5 lifecycle, F6 migration, F7 audit.

## Claims removed

- "A guardrail against runaway and prompt-injected agents." Without isolation the policy is bypassed by what it restrains. [F1]
- The Pod Security Admission analogy and the anchors built on it. PSA sits on a kernel boundary CAO lacks. [F1]
- "Seven open issues are that one gap in different clothes." Two need identity; #948, #972, #829 and #990 have non-principal fixes; #896 does not belong. [F3]
- "`authorize()` is the one policy decision point." 115 scope checks decide function-level access in parallel and never audit. [F4]
- "Not a change for operators." Live terminals, ops-server profiles and provider token delivery all change. [F6]
- The default flip and "retire the shared bearer for agents." Neither has a defined meaning or a compatibility path. [F1, F6]
- The warn-mode log as "evidence that nothing legitimate is refused." Unexercised paths and anonymous callers produce no lines. [F7]
- "One new column, three new modules." The branch is 74 files, +9,613 lines. [F6]

## Claims narrowed

- Problem: from seven issues to attribution plus two object-level gaps. [F3]
- Landing: from five PRs plus a flip to three PRs, no flip. Tool reach (WS3) dropped; #972's gate stays. [F3, F4]
- Caller identity: "the bearer's row is the principal; a mismatched claimed id is a refusal", because the demo did this in name only. [F2]
- `authorize()`: object-level actions only; scope checks are the documented function-level layer; `OPERATOR_ROUTE` dropped. [F4]
- Cost: stated per PR with the dropped fraction. [F6]

## New commitments

- Enforce implies auth: `CAO_PRINCIPAL_ENFORCE=1` refused without `CAO_AUTH_LOCAL_TOKEN` or an IdP; unauthenticated is 401 under enforce. [F1]
- Agent processes never fall back to the operator token when `CAO_TERMINAL_ID` is set. [F1]
- Allowed calls logged for agent principals. [F1, F7]
- Nine-case lifecycle contract, each a test before PR A merges; chosen answers for owner death, deleted ancestor (frozen on the row) and profile edit (snapshot at launch). [F5]
- Six demo-branch defect fixes before anyone runs it, DONE on the branch (dd89c297), plus a seventh the demo run found: the ops MCP server presented the operator token. [F2, F5, F7]
- Migration section: live terminals, legacy runs, profiles, per-provider delivery with "never written to a file", shared bearer untouched. [F6]
- Bounded audit log: rotation, request id, outcome, fix hint, write failures counted. [F7]
- Evidence bar for any later enforcement proposal, from the reviewers' "what would change my mind". [all]
- One adversarial pass per PR before it opens upstream. [process]

## Sentences in ARCHITECTURE-ASSESSMENT.md to correct later

The assessment is unchanged. The reviews rejected the causality in these sentences.

- "The missing piece that addresses the first and largest class is a per-terminal principal issued by the server at launch, verified at one chokepoint, from which ceiling, ownership, reach and audit all derive." Ceiling (#948) and reach (#972) derive from the row today. [F3, F4]
- #671 row: "policy enforced per registration inside one server, because the host layer has no principal to decide on". #972 covers all 34 tools with no principal. [F3]
- #948 / #965 row: "no principal to bind the ceiling to". #948 bound it to the creator's row. [F3]
- #896 row: "capability decisions scattered per call site". Sender identity does not establish delivery safety; remove the row. [F3]
- "#671 becomes `authorize(p, "tool:call", tool)` evaluated at the host layer from `p.allowed_tools`, for every server". Dropped with WS3. [F4]
- "it makes it a guardrail with a name on every action, which is what you need against prompt-injected or runaway agents". Attribution, not a guardrail. [F1]
- "Pod Security Admission has exactly this status in Kubernetes and nobody argues for removing it." Withdrawn. [F1]
- "Each step is a PR of the size this week's PRs have been." The demo is 9,613 lines. [F6]
- "(5) retire the shared bearer for agents." Not in this proposal. [F6]
