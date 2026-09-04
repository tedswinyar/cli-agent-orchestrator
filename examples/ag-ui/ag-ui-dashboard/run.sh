#!/usr/bin/env bash
#
# Live AG-UI dashboard demo.
#
# Starts cao-server with the AG-UI surface enabled, waits for health, and
# leaves it running so you can tail the SSE stream or run ./showcase.sh
# against the *live* server. Ctrl-C tears everything down.
#
# The generative-UI path (emit_ui -> /agui/v1/stream) is pure HTTP and needs
# no agents and no tmux — that is the live path showcase.sh exercises.
#
# Optionally (CAO_AGUI_DEMO_FLEET=1) it also launches a mock_cli fleet so the
# dashboard shows live launch/handoff/completion cards too. That path needs
# tmux + the credentials-free mock_cli fixture binary and degrades gracefully
# when tmux is absent.
#
# Usage:
#   ./examples/ag-ui/ag-ui-dashboard/run.sh
#   CAO_AGUI_DEMO_FLEET=1 ./examples/ag-ui/ag-ui-dashboard/run.sh    # + mock_cli fleet
#   CAO_AGUI_RUN_SHOWCASE=1 ./examples/ag-ui/ag-ui-dashboard/run.sh  # auto-run showcase.sh once healthy

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export CAO_AGUI_ENABLED="${CAO_AGUI_ENABLED:-1}"
# Exported so the spawned cao-server binds the same port the URLs below use.
export CAO_API_PORT="${CAO_API_PORT:-9889}"
BASE="http://localhost:${CAO_API_PORT}"
DEMO_FLEET="${CAO_AGUI_DEMO_FLEET:-0}"
RUN_SHOWCASE="${CAO_AGUI_RUN_SHOWCASE:-0}"
FLEET_SESSION="agui-demo-$$"
SERVER_PID=""
SERVER_LOG="$(mktemp -t agui-demo-server.XXXXXX.log)"

cleanup() {
    local code=$?
    if [ "${DEMO_FLEET}" = "1" ]; then
        cao shutdown --session "cao-${FLEET_SESSION}" >/dev/null 2>&1 || true
    fi
    [ -n "${SERVER_PID}" ] && kill "${SERVER_PID}" >/dev/null 2>&1 || true
    rm -f "${SERVER_LOG}"
    exit "${code}"
}
# Completion guard. On macOS bash 3.2 — the only bash here, and what
# `#!/usr/bin/env bash` resolves to — a `set -u` abort in a script that has an EXIT
# trap delivers status 0 to the trap, so this demo could fail to launch and still
# report success. Only a ZERO status has to prove it was deliberate; nonzero exits
# (including Ctrl-C's 130) are failures either way and pass through untouched.
#
# INT/TERM keep their own trap so signal behaviour is unchanged; only EXIT is
# rerouted through the guard, which still runs cleanup.
COMPLETED=0
finish() { COMPLETED=1; exit "${1:-0}"; }
__guard_on_exit() {
  local s=$?
  # In a SUBSHELL on purpose: most of these cleanup functions end with
  # `exit "${code}"` where code=$? is captured at their entry, which here would be
  # 0 and would exit 0 straight past the check below. That `exit` inside cleanup is
  # also precisely what made the original `trap cleanup EXIT` swallow the aborted
  # status. Running it in a subshell keeps its side effects and leaves the exit
  # status to this handler. INT/TERM still call cleanup directly, unchanged.
  ( cleanup ) || true
  if [ "$s" = "0" ] && [ "$COMPLETED" != "1" ]; then
    echo "demo: exited 0 before finishing — treating as FAILURE." >&2
    exit 70
  fi
  exit "$s"
}
trap __guard_on_exit EXIT
trap cleanup INT TERM

# Prefer the repo venv's cao-server; fall back to whatever is on PATH
# (uv run / an activated venv).
CAO_SERVER_BIN="cao-server"
if [ -x "${REPO_ROOT}/.venv/bin/cao-server" ]; then
    CAO_SERVER_BIN="${REPO_ROOT}/.venv/bin/cao-server"
fi

# Optional mock_cli fleet (demo-only; needs tmux + the fixture binary on PATH).
if [ "${DEMO_FLEET}" = "1" ]; then
    if command -v tmux >/dev/null 2>&1; then
        export PATH="${REPO_ROOT}/test/providers/fixtures/bin:${PATH}"
        echo "[agui-demo] mock_cli fleet enabled (fixture binary on PATH)" >&2
    else
        echo "[agui-demo] tmux not found — skipping the mock_cli fleet (emit_ui showcase still works)" >&2
        DEMO_FLEET=0
    fi
fi

echo "[agui-demo] starting cao-server (CAO_AGUI_ENABLED=${CAO_AGUI_ENABLED}) on ${BASE}" >&2
"${CAO_SERVER_BIN}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

# Wait for the server to become healthy.
for _ in $(seq 1 40); do
    if curl -fsS "${BASE}/health" >/dev/null 2>&1; then break; fi
    sleep 0.5
done
if ! curl -fsS "${BASE}/health" >/dev/null 2>&1; then
    echo "[agui-demo] server did not become healthy; log follows:" >&2
    cat "${SERVER_LOG}" >&2 || true
    exit 1
fi
echo "[agui-demo] server healthy." >&2

if [ "${DEMO_FLEET}" = "1" ]; then
    cao install "${REPO_ROOT}/examples/ag-ui/ag-ui-dashboard/fleet_worker.md" >/dev/null 2>&1 || true
    cao launch --agents fleet_worker --provider mock_cli --async --yolo \
        --session-name "${FLEET_SESSION}" \
        "Greet the operator, then emit a status card." >/dev/null 2>&1 ||
        echo "[agui-demo] fleet launch failed (continuing; the emit_ui showcase is independent)" >&2
fi

if [ "${RUN_SHOWCASE}" = "1" ]; then
    echo "[agui-demo] running showcase.sh against the live server" >&2
    CAO_AGUI_BASE="${BASE}" "${REPO_ROOT}/examples/ag-ui/ag-ui-dashboard/showcase.sh"
fi

cat >&2 <<EOF

[agui-demo] AG-UI stream is LIVE:
  • SSE stream:  GET  ${BASE}/agui/v1/stream
  • emit_ui:     POST ${BASE}/agui/v1/emit_ui

Drive it (separate terminal):
  ./examples/ag-ui/ag-ui-dashboard/showcase.sh

Tail the raw AG-UI frames (separate terminal):
  curl -N ${BASE}/agui/v1/stream

Press Ctrl-C to stop the server.
EOF

wait "${SERVER_PID}"

finish 0
