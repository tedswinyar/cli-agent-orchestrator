"""A dialog the terminal's status did not report: #896 case 2 (herdr) and #405 (tmux).

The pre-send pane check reads the pane once before typing orchestrated input
and asks the provider whether a user-answer dialog is on screen
(``BaseProvider.shows_user_answer_dialog``). It runs on every backend. The file
keeps the name it had when the check was herdr-only.

herdr (#896 case 2). On the herdr backends CAO does not read the screen to decide status: the
provider returns herdr's own agent state. herdr has reported ``idle`` and
``done`` with a Claude Code dialog open (herdrdev/herdr#4573, #5741), so the
#973 guard, which tests the status, saw a ready terminal and the inbox message
was typed into the dialog: the paste was swallowed and the trailing Enter
selected the highlighted option.

tmux (#405, the race). Status is the monitor's cached verdict, computed as
terminal output is processed. A dialog that opened after the last verdict, or
whose frame is not processed yet, reads as ready (or PROCESSING, which eager
delivery sends on), and the message was typed into it. The ``TestTmux*``
classes at the end cover that backend.

Frames. ``claude_code_896_herdr_*`` in test/providers/fixtures are what CAO
itself read in a live run (Claude Code 2.1.330, herdr 0.9.5): the output of
``herdr pane read <pane> --source recent --lines 50 --format text`` with the
dialog open, scrubbed of a user name and an organisation banner at unchanged
line lengths. They cover every AskUserQuestion page seen there, in a named and
an unnamed session, plan approval, and ready panes. The two permission prompts
and their ready pane are the ``tmux capture-pane`` fixtures of 2.1.310.

That run found two pages the first version of this check did not recognise, and
typed a message into one of them: the footer of a multi-question page without
previews, and the "Review your answers" page, which has no footer at all.
``TestLiveMisses`` pins both.
"""

from __future__ import annotations

import threading
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, Iterator, List, Optional
from unittest.mock import MagicMock, call, patch

import pytest

from cli_agent_orchestrator.backends.herdr_backend import HerdrBackend
from cli_agent_orchestrator.models.inbox import InboxMessage, MessageStatus, OrchestrationType
from cli_agent_orchestrator.models.terminal import (
    TerminalInputBlockedError,
    TerminalInputBlockedReason,
    TerminalStatus,
)
from cli_agent_orchestrator.providers.base import BaseProvider
from cli_agent_orchestrator.providers.claude_code import ClaudeCodeProvider
from cli_agent_orchestrator.providers.codex import CodexProvider
from cli_agent_orchestrator.services import terminal_service as ts
from cli_agent_orchestrator.services.inbox_service import InboxService

FIXTURES = Path(__file__).parent.parent / "providers" / "fixtures"
MESSAGE = "MSG1: refactor module A so the retry policy lives in one place"


@pytest.fixture(autouse=True)
def _no_pane_check_hold_crosses_a_test():
    """The hold episodes are module state in terminal_service: start and end clean."""
    with ts._pane_check_holding_lock:
        ts._pane_check_holding.clear()
    yield
    with ts._pane_check_holding_lock:
        ts._pane_check_holding.clear()


def _fixture(name: str) -> str:
    return (FIXTURES / f"{name}.txt").read_text(encoding="utf-8")


def _herdr(shape: str) -> str:
    return _fixture(f"claude_code_896_herdr_{shape}")


# Every dialog page captured through herdr. "named_session" frames have the
# session-name rule under the dialog, which moves the footer off the last row.
HERDR_DIALOG_SHAPES = [
    "single_question",
    "preview",
    "two_question_page1",
    "two_question_page2",
    "review_page",
    "named_session_single",
    "named_session_focus_type_something",
    "named_session_focus_chat",
    "named_session_typed_in_other",
    "named_session_preview",
    "named_session_two_question_preview_page1",
    "named_session_two_question_preview_page2",
    "review_page_named_session",
    "plan_approval",
]
HERDR_READY_SHAPES = ["idle", "finished_turn", "named_session_idle"]

DIALOG_PANES = {
    "bash_permission_prompt": _fixture("claude_code_310_bash_permission_prompt"),
    "write_permission_prompt": _fixture("claude_code_310_write_permission_prompt"),
    **{f"herdr_{shape}": _herdr(shape) for shape in HERDR_DIALOG_SHAPES},
}
ASK_USER_QUESTION = "herdr_single_question"
PLAN_APPROVAL = "herdr_plan_approval"
# The two pages the live run showed the first version of the check missing.
TWO_QUESTION_FOOTER = "herdr_two_question_page1"
REVIEW_PAGE_NAMED = "herdr_review_page_named_session"

# test_claude_code_unit.py::TestClaudeCodeDialogDetection::
# test_agent_prose_with_nav_text_in_footer_false_waiting (strict xfail there).
PROSE_IN_FOOTER_WINDOW = (
    "⏺ The dialog shows:\n"
    "Enter to select · ↑/↓ to navigate · Esc to cancel\n"
    "────────────────────────\n"
    "❯ "
)

# What an agent that had just described the dialogs would leave in its reply.
# The last three blocks are the wording #896's live run added to the detection.
_DIALOG_PROSE = [
    "● The dialog shows:",
    "  Enter to select · ↑/↓ to navigate · Esc to cancel",
    "  Would you like to proceed?",
    "  Esc to cancel · Tab to amend",
    "  Enter to select · Tab/Arrow keys to navigate · Esc to cancel",
    "  Review your answers",
    "   ● Pick a color:",
    "     → Red",
    "  ❯ 1. Submit answers",
    "    2. Cancel",
]


def _prose_above_idle_prompt(fixture: str, prose: List[str], rows_above_prompt: int) -> str:
    """``prose`` spliced into a real ready pane, ``rows_above_prompt`` rows above
    the top rail of its input box."""
    rows = fixture.rstrip("\n").split("\n")
    top_rail = max(i for i, row in enumerate(rows) if row.startswith("────")) - 2
    assert rows[top_rail].startswith("────") and rows[top_rail + 1].startswith("❯")
    at = top_rail - rows_above_prompt
    return "\n".join(rows[:at] + prose + rows[at:])


READY_PANES = {
    "startup_idle": _fixture("claude_code_865_startup_idle"),
    "idle_after_permission": _fixture("claude_code_310_permission_idle_after"),
    "turn_ended": _fixture("claude_code_865_turn_ended"),
    **{f"herdr_{shape}": _herdr(shape) for shape in HERDR_READY_SHAPES},
    # Far up the transcript, and then as the newest output, directly above the
    # input box, where all of it is inside every bottom region the detection reads.
    "dialog_wording_in_transcript": _prose_above_idle_prompt(
        _herdr("finished_turn"), _DIALOG_PROSE, 16
    ),
    "dialog_wording_directly_above_prompt": _prose_above_idle_prompt(
        _herdr("finished_turn"), _DIALOG_PROSE, 0
    ),
    "dialog_wording_directly_above_prompt_named_session": _prose_above_idle_prompt(
        _herdr("named_session_idle"), _DIALOG_PROSE, 0
    ),
}


def _claude() -> ClaudeCodeProvider:
    return ClaudeCodeProvider("term-1", "cao-session", "developer-abcd")


def _backend(pane: Any, *, native: Optional[TerminalStatus], event_inbox: bool = True) -> MagicMock:
    """A backend double. ``event_inbox=True`` with a native status is herdr's shape."""
    backend = MagicMock()
    backend.supports_event_inbox.return_value = event_inbox
    backend.event_inbox_confirms_submit.return_value = False
    backend.get_native_status.return_value = native
    if isinstance(pane, BaseException):
        backend.get_history.side_effect = pane
    else:
        backend.get_history.return_value = pane
    return backend


def _screen_reads(backend: MagicMock) -> List[Any]:
    """The backstop's reads: the only caller here that asks for the visible screen."""
    return [c for c in backend.get_history.call_args_list if c.kwargs.get("visible_only")]


@contextmanager
def _terminal(
    provider: Any, backend: MagicMock, status: Optional[TerminalStatus] = None
) -> Iterator[MagicMock]:
    """Patch ``dispatch_input``'s collaborators around one provider and one backend.

    With ``status`` None the monitor answers the way StatusMonitor.get_status
    does on an event-inbox backend: by asking the provider, which returns the
    backend's native state without looking at the pane. That is the path the bug
    lives on, so the tests go through it and not through a canned status.
    """
    monitor = MagicMock()
    monitor.output_generation.return_value = 7
    if status is None:
        monitor.get_status.side_effect = lambda _tid: provider.get_status("")
    else:
        monitor.get_status.return_value = status
    with ExitStack() as stack:
        stack.enter_context(patch("cli_agent_orchestrator.backends.registry._backend", backend))
        stack.enter_context(patch.object(ts, "status_monitor", monitor))
        stack.enter_context(
            patch.object(
                ts,
                "get_terminal_metadata",
                return_value={
                    "tmux_session": "cao-session",
                    "tmux_window": "developer-abcd",
                    "provider": "claude_code",
                },
            )
        )
        stack.enter_context(
            patch.object(ts.provider_manager, "get_provider", return_value=provider)
        )
        stack.enter_context(patch.object(ts, "inject_memory_context", side_effect=lambda m, *a: m))
        stack.enter_context(patch.object(ts, "update_last_active"))
        yield monitor


def _assert_refused(backend: MagicMock, **dispatch: Any) -> None:
    with pytest.raises(TerminalInputBlockedError, match="waiting for a user answer") as exc:
        ts.dispatch_input("term-1", MESSAGE, **dispatch)
    assert exc.value.reason is TerminalInputBlockedReason.WAITING_USER_ANSWER
    backend.send_keys.assert_not_called()
    backend.send_special_key.assert_not_called()


class TestProviderDialogCheck:
    """``shows_user_answer_dialog``: the provider's own detection, on a pane read."""

    def test_default_is_cannot_tell(self):
        assert BaseProvider.shows_user_answer_dialog(MagicMock(), DIALOG_PANES[PLAN_APPROVAL]) is (
            False
        )

    @pytest.mark.parametrize("name", sorted(DIALOG_PANES))
    def test_claude_code_sees_each_dialog(self, name):
        assert _claude().shows_user_answer_dialog(DIALOG_PANES[name]) is True

    @pytest.mark.parametrize("name", sorted(READY_PANES))
    def test_claude_code_does_not_see_a_dialog_on_a_ready_pane(self, name):
        assert _claude().shows_user_answer_dialog(READY_PANES[name]) is False

    @pytest.mark.parametrize("pane", ["", "\n\n   \n"])
    def test_blank_pane_is_not_a_dialog(self, pane):
        assert _claude().shows_user_answer_dialog(pane) is False

    def test_plan_approval_is_seen_only_by_the_buffer_path_detection(self):
        """Why the method reuses get_status's detection, not get_status_from_screen (#405)."""
        provider = _claude()
        rows = DIALOG_PANES[PLAN_APPROVAL].split("\n")
        assert provider.get_status_from_screen(rows) != TerminalStatus.WAITING_USER_ANSWER
        assert provider.shows_user_answer_dialog(DIALOG_PANES[PLAN_APPROVAL]) is True

    @pytest.mark.parametrize("name", sorted(DIALOG_PANES))
    def test_agrees_with_get_status_on_the_real_dialog_captures(self, name):
        """One definition: the method and the tmux buffer path cannot disagree."""
        backend = _backend("", native=None, event_inbox=False)
        with patch("cli_agent_orchestrator.backends.registry._backend", backend):
            assert _claude().get_status(DIALOG_PANES[name]) == TerminalStatus.WAITING_USER_ANSWER

    @pytest.mark.parametrize("name", sorted(READY_PANES))
    def test_agrees_with_get_status_on_the_ready_panes(self, name):
        backend = _backend("", native=None, event_inbox=False)
        with patch("cli_agent_orchestrator.backends.registry._backend", backend):
            assert _claude().get_status(READY_PANES[name]) != TerminalStatus.WAITING_USER_ANSWER

    def test_startup_trust_dialog_is_excluded_as_in_get_status(self):
        """Parity with the status guard: ``initialize`` answers this one itself."""
        pane = _fixture("claude_code_1277_resume_trust_dialog")
        assert _claude().shows_user_answer_dialog(pane) is False

    @pytest.mark.xfail(
        reason="Inherited from get_status (#405 residual, strict xfail in "
        "test_claude_code_unit.py): prose quoting the footer inside the last 6 "
        "rows reads as a dialog. Here that holds a message; it does not lose one.",
        strict=True,
    )
    def test_prose_quoting_the_footer_in_the_last_six_rows(self):
        assert _claude().shows_user_answer_dialog(PROSE_IN_FOOTER_WINDOW) is False


def _last_reply_above_idle_prompt(reply: List[str]) -> str:
    """A real ready pane whose newest output, directly above the input box, is ``reply``."""
    return _prose_above_idle_prompt(_herdr("finished_turn"), reply, 0)


class TestLiveMisses:
    """The two pages the live run on Claude Code 2.1.330 showed the check missing.

    Each pair of tests is the regression and its false-positive bound. The
    regressions fail on 0edfce1d, where the pane check exists but does not know
    these pages.
    """

    def test_review_page_in_a_named_session_is_refused_and_nothing_is_typed(self):
        """THE LIVE MISS. herdr said ``idle`` on this exact frame; CAO typed the
        message into it and the Enter submitted the answers."""
        provider = _claude()
        backend = _backend(DIALOG_PANES[REVIEW_PAGE_NAMED], native=TerminalStatus.IDLE)
        with _terminal(provider, backend) as monitor:
            assert monitor.get_status("term-1") == TerminalStatus.IDLE
            _assert_refused(backend, orchestration_type=OrchestrationType.SEND_MESSAGE)
        assert len(_screen_reads(backend)) == 1

    def test_two_question_footer_is_refused_and_nothing_is_typed(self):
        """``Enter to select · Tab/Arrow keys to navigate · Esc to cancel``."""
        provider = _claude()
        backend = _backend(DIALOG_PANES[TWO_QUESTION_FOOTER], native=TerminalStatus.IDLE)
        with _terminal(provider, backend) as monitor:
            assert monitor.get_status("term-1") == TerminalStatus.IDLE
            _assert_refused(backend, orchestration_type=OrchestrationType.SEND_MESSAGE)
        assert len(_screen_reads(backend)) == 1

    def test_review_page_layout_the_region_has_to_cover(self):
        """Why the review page is counted in non-blank rows, pinned on the capture.

        Named session: 8 blank rows and the session-name rule sit under the
        choices, so the heading is 18 screen rows from the bottom, outside both
        the 6-row footer window and the 15-row plan-approval region.
        """
        rows = DIALOG_PANES[REVIEW_PAGE_NAMED].rstrip().split("\n")
        from_bottom = {row.strip(): len(rows) - i for i, row in enumerate(rows)}
        assert from_bottom["Review your answers"] == 18
        assert from_bottom["❯ 1. Submit answers"] == 11
        assert from_bottom["2. Cancel"] == 10
        assert "add-readme-file" in rows[-1]
        non_blank = [row for row in rows if row.strip()]
        assert [row.strip() for row in non_blank[-8:-1]] == [
            "Review your answers",
            "● Which layout is better?",
            "→ Sidebar",
            "● Which theme is better?",
            "→ Light",
            "❯ 1. Submit answers",
            "2. Cancel",
        ]

    def test_review_page_with_the_cursor_on_cancel(self):
        """Down-arrow moves the cursor; the page is as live as before."""
        pane = DIALOG_PANES[REVIEW_PAGE_NAMED]
        moved = pane.replace("❯ 1. Submit answers", "  1. Submit answers").replace(
            "  2. Cancel", "❯ 2. Cancel"
        )
        assert moved != pane
        assert _claude().shows_user_answer_dialog(moved) is True

    @pytest.mark.parametrize(
        "reply",
        [
            # The phrases, as an agent mentions them.
            ["● Use Tab/Arrow keys to navigate, then Review your answers and Submit answers."],
            ["● Review your answers", "  1. Submit answers", "  2. Cancel"],
            # A list with the two labels but no heading.
            ["● Pick one:", "  ❯ 1. Submit answers", "    2. Cancel"],
            # The heading and the labels, not as the two numbered choices.
            ["● Review your answers", "  - Submit answers", "  - Cancel"],
            # The whole page quoted, cursor and all: the input box is under it.
            [
                "● The last page reads:",
                "  Review your answers",
                "   ● Pick a color:",
                "     → Red",
                "  ❯ 1. Submit answers",
                "    2. Cancel",
            ],
        ],
        ids=["phrases", "no-cursor", "no-heading", "not-numbered", "quoted-page"],
    )
    def test_new_wording_as_the_last_reply_above_an_idle_prompt_is_delivered(self, reply):
        pane = _last_reply_above_idle_prompt(reply)
        assert _claude().shows_user_answer_dialog(pane) is False
        backend = _backend(pane, native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.send_keys.assert_called_once()

    def test_a_user_turn_that_says_review_your_answers_is_not_the_heading(self):
        pane = _last_reply_above_idle_prompt(
            ["❯ Review your answers", "", "● ❯ 1. Submit answers", "    2. Cancel"]
        )
        assert _claude().shows_user_answer_dialog(pane) is False

    @pytest.mark.xfail(
        reason="Same class as the '↑/↓ to navigate' residual (#405): a reply whose "
        "LAST row quotes the whole multi-question footer puts it inside the 6-row "
        "footer window of an idle prompt, and a footer is recognised by its text. "
        "The pairing 'Enter to select · <keys> to navigate' on one line is required, "
        "so a mention of the keys alone does not do this. Cost: the message is "
        "held until the screen moves on; it is not lost.",
        strict=True,
    )
    def test_whole_two_question_footer_quoted_on_the_last_row_of_a_reply(self):
        pane = _last_reply_above_idle_prompt(
            [
                "● The footer reads:",
                "  Enter to select · Tab/Arrow keys to navigate · Esc to cancel",
            ]
        )
        assert _claude().shows_user_answer_dialog(pane) is False

    @pytest.mark.xfail(
        reason="The review page has no footer, so it is recognised by structure, and "
        "a verbatim quote of the page (heading, the two numbered choices, the "
        "cursor) with NOTHING under it is that structure. An idle Claude Code "
        "always draws its input box under the reply, which is the case "
        "test_new_wording_as_the_last_reply_above_an_idle_prompt_is_delivered[quoted-page] "
        "shows is delivered; this frame needs the quote to be the last thing on "
        "screen. Cost: the message is held until the screen moves on; it is not lost.",
        strict=True,
    )
    def test_review_page_quoted_verbatim_with_nothing_under_it(self):
        rows = _herdr("finished_turn").rstrip("\n").split("\n")[:24]
        pane = "\n".join(
            rows
            + [
                "",
                "● The last page reads:",
                "  Review your answers",
                "   ● Pick a color:",
                "     → Red",
                "  ❯ 1. Submit answers",
                "    2. Cancel",
            ]
        )
        assert _claude().shows_user_answer_dialog(pane) is False


class TestDispatchRefusesIntoUnreportedDialog:
    """``dispatch_input`` on a native-status backend that reports a ready pane."""

    @pytest.mark.parametrize("name", sorted(DIALOG_PANES))
    def test_inbox_delivery_is_refused_when_herdr_reports_idle(self, name):
        """THE REGRESSION (#896 case 2). Fails on main: the message is typed."""
        provider = _claude()
        backend = _backend(DIALOG_PANES[name], native=TerminalStatus.IDLE)
        with _terminal(provider, backend) as monitor:
            assert monitor.get_status("term-1") == TerminalStatus.IDLE
            _assert_refused(backend, orchestration_type=OrchestrationType.SEND_MESSAGE)
        assert len(_screen_reads(backend)) == 1

    def test_inbox_delivery_is_refused_when_herdr_reports_done(self):
        """The issue's log: ``done`` is PROCESSING for the flush wait, and still delivered."""
        provider = _claude()
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.COMPLETED)
        with _terminal(provider, backend) as monitor:
            provider.mark_input_received()  # an earlier turn: "done" is now post-dispatch
            assert monitor.get_status("term-1") == TerminalStatus.PROCESSING
            _assert_refused(backend, orchestration_type=OrchestrationType.SEND_MESSAGE)

    @pytest.mark.parametrize("orchestration_type", list(OrchestrationType), ids=lambda t: t.value)
    def test_every_orchestration_type_is_refused(self, orchestration_type):
        backend = _backend(DIALOG_PANES["bash_permission_prompt"], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend):
            _assert_refused(backend, orchestration_type=orchestration_type)

    def test_refusal_does_not_spend_the_memory_block(self):
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend):
            _assert_refused(backend, orchestration_type=OrchestrationType.SEND_MESSAGE)
            ts.inject_memory_context.assert_not_called()  # type: ignore[attr-defined]

    @pytest.mark.parametrize("name", sorted(READY_PANES))
    def test_ready_pane_is_delivered_after_exactly_one_screen_read(self, name):
        backend = _backend(READY_PANES[name], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.send_keys.assert_called_once()
        assert _screen_reads(backend) == [
            call("cao-session", "developer-abcd", strip_escapes=True, visible_only=True)
        ]

    def test_operator_input_reaches_the_dialog(self):
        """No orchestration type: a human, or answer_user_prompt. Must not be read or held."""
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend):
            ts.dispatch_input("term-1", "1")
        backend.send_keys.assert_called_once()
        assert _screen_reads(backend) == []

    def test_provider_that_does_not_block_at_dialogs_is_never_read(self):
        provider = MagicMock()
        provider.blocks_orchestrated_input_while_waiting_user_answer = False
        provider.shows_user_answer_dialog.return_value = True
        provider.paste_enter_count = 1
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _terminal(provider, backend, status=TerminalStatus.IDLE):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.send_keys.assert_called_once()
        backend.get_history.assert_not_called()

    def test_blocking_provider_that_inherits_the_method_is_never_read(self):
        """codex blocks at dialogs but inherits the default, which answers False
        for every pane: reading one for it would buy nothing."""
        assert CodexProvider.shows_user_answer_dialog is BaseProvider.shows_user_answer_dialog
        provider = CodexProvider("term-1", "cao-session", "developer-abcd")
        assert provider.blocks_orchestrated_input_while_waiting_user_answer is True
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _terminal(provider, backend, status=TerminalStatus.IDLE):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.send_keys.assert_called_once()
        assert _screen_reads(backend) == []

    def test_blocking_provider_whose_method_cannot_tell_is_unaffected(self):
        """A stand-in is asked, and the default's "cannot tell" sends."""
        provider = MagicMock()
        provider.blocks_orchestrated_input_while_waiting_user_answer = True
        provider.shows_user_answer_dialog.side_effect = lambda text: (
            BaseProvider.shows_user_answer_dialog(provider, text)
        )
        provider.paste_enter_count = 1
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _terminal(provider, backend, status=TerminalStatus.IDLE):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.send_keys.assert_called_once()

    @pytest.mark.parametrize(
        "pane",
        [RuntimeError("herdr pane read: socket closed"), "", "   \n\n", None],
        ids=["raises", "empty", "blank", "not-text"],
    )
    def test_failed_pane_read_fails_open_and_warns(self, pane, caplog):
        """A backstop must not turn a herdr CLI hiccup into an inbox that never drains."""
        backend = _backend(pane, native=TerminalStatus.IDLE)
        provider = MagicMock()
        provider.blocks_orchestrated_input_while_waiting_user_answer = True
        provider.paste_enter_count = 1
        with _terminal(provider, backend, status=TerminalStatus.IDLE), caplog.at_level("WARNING"):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.send_keys.assert_called_once()
        provider.shows_user_answer_dialog.assert_not_called()
        assert "Could not read the pane of term-1" in caplog.text

    def test_provider_check_raising_fails_open(self, caplog):
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        provider = MagicMock()
        provider.blocks_orchestrated_input_while_waiting_user_answer = True
        provider.shows_user_answer_dialog.side_effect = ValueError("bad frame")
        provider.paste_enter_count = 1
        with _terminal(provider, backend, status=TerminalStatus.IDLE), caplog.at_level("WARNING"):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.send_keys.assert_called_once()
        assert "Could not read the pane of term-1" in caplog.text

    def test_status_guard_refuses_without_a_pane_read(self):
        """Case 1 is unchanged: a status that already says so costs no read."""
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend, status=TerminalStatus.WAITING_USER_ANSWER):
            _assert_refused(backend, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.get_history.assert_not_called()


PANE_CHECK_LOG = "Pre-send pane check held input to term-1"


class TestRefusalsCanBeToldApart:
    """Same exception type and reason from both guards; the wording says which.

    The live run could not tell a hold by the pane check from a hold by the
    status guard: both logged the same sentence.
    """

    @pytest.mark.parametrize("name", [ASK_USER_QUESTION, REVIEW_PAGE_NAMED])
    def test_pane_check_refusal_names_the_reported_status_and_the_check(self, name, caplog):
        backend = _backend(DIALOG_PANES[name], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend), caplog.at_level("INFO"):
            with pytest.raises(TerminalInputBlockedError) as exc:
                ts.dispatch_input(
                    "term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE
                )
        assert exc.value.reason is TerminalInputBlockedReason.WAITING_USER_ANSWER
        message = str(exc.value)
        assert message.startswith("Terminal term-1 is waiting for a user answer: ")
        assert "its reported status was idle, but a dialog is open on screen" in message
        assert "(pre-send pane check)" in message
        assert "Use answer_user_prompt" in message
        held = [r for r in caplog.records if PANE_CHECK_LOG in r.getMessage()]
        assert [r.levelname for r in held] == ["INFO"]

    def test_status_guard_refusal_keeps_its_wording_and_does_not_log_the_check(self, caplog):
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with (
            _terminal(_claude(), backend, status=TerminalStatus.WAITING_USER_ANSWER),
            caplog.at_level("INFO"),
        ):
            with pytest.raises(TerminalInputBlockedError) as exc:
                ts.dispatch_input(
                    "term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE
                )
        assert exc.value.reason is TerminalInputBlockedReason.WAITING_USER_ANSWER
        assert str(exc.value).startswith(
            "Terminal term-1 is waiting for a user answer. Use answer_user_prompt"
        )
        assert "pane check" not in str(exc.value)
        assert PANE_CHECK_LOG not in caplog.text

    def test_ready_pane_does_not_log_the_check(self, caplog):
        backend = _backend(READY_PANES["herdr_idle"], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend), caplog.at_level("INFO"):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
        assert PANE_CHECK_LOG not in caplog.text

    def test_pane_content_is_not_logged_or_put_in_the_error(self, caplog):
        pane = DIALOG_PANES[REVIEW_PAGE_NAMED]
        backend = _backend(pane, native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend), caplog.at_level("DEBUG"):
            with pytest.raises(TerminalInputBlockedError) as exc:
                ts.dispatch_input(
                    "term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE
                )
        for on_screen in ("Submit answers", "Which layout is better?", "add-readme-file"):
            assert on_screen in pane
            assert on_screen not in caplog.text
            assert on_screen not in str(exc.value)


class TestReadOnRealHerdrBackend:
    """What the backstop asks herdr for, through the real backend's ``get_history``."""

    def test_one_bounded_plain_text_pane_read(self):
        # As test/backends/test_herdr_backend.py builds it: the socket "exists".
        with patch(
            "cli_agent_orchestrator.backends.herdr_backend.os.path.exists", return_value=True
        ):
            backend = HerdrBackend(send_delay_ms=0)
        result = MagicMock(returncode=0, stdout=DIALOG_PANES["bash_permission_prompt"], stderr="")
        with (
            patch.object(backend, "_resolve_pane_id_from_window", return_value="p_1"),
            patch.object(backend, "_run_herdr", return_value=result) as run,
            patch.object(ts, "get_backend", return_value=backend),
            patch.object(
                ts,
                "get_terminal_metadata",
                return_value={"tmux_session": "cao-session", "tmux_window": "developer-abcd"},
            ),
        ):
            assert backend.supports_event_inbox() is True
            assert (
                ts._pre_send_pane_check_holds("term-1", _claude(), OrchestrationType.SEND_MESSAGE)
                is True
            )
        assert run.call_args_list == [
            call(
                ["pane", "read", "p_1", "--source", "recent", "--lines", "50", "--format", "text"],
                check=False,
            )
        ]


def _inbox_message() -> InboxMessage:
    from datetime import datetime

    return InboxMessage(
        id=1,
        sender_id="sender-1",
        receiver_id="term-1",
        message=MESSAGE,
        status=MessageStatus.PENDING,
        created_at=datetime.now(),
    )


class TestInboxHoldsThenDelivers:
    """Through InboxService: the refused message stays PENDING and is delivered later."""

    def test_message_is_held_while_the_dialog_is_open_and_delivered_once_it_is_gone(self):
        provider = _claude()
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with (
            _terminal(provider, backend) as monitor,
            patch(
                "cli_agent_orchestrator.services.inbox_service.get_pending_messages",
                return_value=[_inbox_message()],
            ),
            patch("cli_agent_orchestrator.services.inbox_service.update_message_status") as update,
            patch("cli_agent_orchestrator.services.inbox_service.status_monitor", monitor),
            patch(
                "cli_agent_orchestrator.services.inbox_service.get_backend", return_value=backend
            ),
        ):
            service = InboxService()

            service.deliver_pending("term-1")

            backend.send_keys.assert_not_called()
            assert update.call_args_list == [
                call(1, MessageStatus.DELIVERED),
                call(1, MessageStatus.PENDING),
            ]

            # The human answers; the pane is an ordinary idle prompt again.
            update.reset_mock()
            backend.get_history.return_value = READY_PANES["idle_after_permission"]

            service.deliver_pending("term-1")

            backend.send_keys.assert_called_once()
            assert MESSAGE in backend.send_keys.call_args.args[2]
            assert update.call_args_list == [call(1, MessageStatus.DELIVERED)]


class TestBareEnterRecovery:
    """The one submit that never reaches ``dispatch_input`` gets the same pane check.

    It sends an Enter and nothing else, which is exactly what answers a dialog.
    """

    def _recover(
        self,
        pane: Any,
        *,
        event_inbox: bool,
        orchestration_type: Any,
        status: TerminalStatus = TerminalStatus.IDLE,
    ) -> List[str]:
        provider = _claude()
        backend = _backend(
            pane, native=TerminalStatus.IDLE if event_inbox else None, event_inbox=event_inbox
        )
        enters: List[str] = []
        with (
            _terminal(provider, backend, status=status),
            patch.object(ts, "_capture_current_composer_region", return_value=MESSAGE),
            patch.object(ts, "send_special_key", side_effect=lambda _tid, key: enters.append(key)),
        ):
            ts.redeliver_dropped_message_with_boundary(
                "term-1",
                MESSAGE,
                1,
                provider,
                full_resend_requires_composer_evidence=True,
                orchestration_type=orchestration_type,
            )
        return enters

    def test_no_enter_into_a_dialog_herdr_did_not_report(self):
        """Fails on main: the Enter is sent."""
        assert (
            self._recover(
                DIALOG_PANES["bash_permission_prompt"],
                event_inbox=True,
                orchestration_type=OrchestrationType.SEND_MESSAGE,
            )
            == []
        )

    @pytest.mark.parametrize("name", [TWO_QUESTION_FOOTER, REVIEW_PAGE_NAMED])
    def test_no_enter_into_the_pages_the_live_run_found_missed(self, name):
        """On the review page that Enter is "Submit answers"."""
        assert (
            self._recover(
                DIALOG_PANES[name],
                event_inbox=True,
                orchestration_type=OrchestrationType.SEND_MESSAGE,
            )
            == []
        )

    def test_skip_log_says_which_guard_held_the_enter(self, caplog):
        with caplog.at_level("INFO"):
            self._recover(
                DIALOG_PANES[REVIEW_PAGE_NAMED],
                event_inbox=True,
                orchestration_type=OrchestrationType.SEND_MESSAGE,
            )
        assert PANE_CHECK_LOG in caplog.text
        assert "the pre-send pane check found a dialog on screen" in caplog.text
        caplog.clear()
        with caplog.at_level("INFO"):
            self._recover(
                DIALOG_PANES[REVIEW_PAGE_NAMED],
                event_inbox=True,
                orchestration_type=OrchestrationType.SEND_MESSAGE,
                status=TerminalStatus.WAITING_USER_ANSWER,
            )
        assert "skipping the bare-Enter re-submit" in caplog.text
        assert "pane check" not in caplog.text

    def test_enter_is_still_resent_on_a_ready_pane(self):
        assert self._recover(
            READY_PANES["idle_after_permission"],
            event_inbox=True,
            orchestration_type=OrchestrationType.SEND_MESSAGE,
        ) == ["Enter"]

    def test_enter_is_still_resent_for_untyped_input(self):
        assert self._recover(
            DIALOG_PANES["bash_permission_prompt"], event_inbox=True, orchestration_type=None
        ) == ["Enter"]


HELD = "Pre-send pane check held input to "
RELEASED = "Pre-send pane check released "
FAILED_TO_SEND = "Failed to send input to terminal "
CANNOT_TAKE_INPUT = "cannot take input yet; leaving 1 message(s) pending for retry"
UNREADABLE = "Could not read the pane of "
# The three lines one refused inbox delivery writes, with the level each has on
# the first hold of an episode.
HOLD_LINES = {HELD: "INFO", FAILED_TO_SEND: "ERROR", CANNOT_TAKE_INPUT: "WARNING"}


def _levels(caplog: Any, text: str) -> List[str]:
    """The level of every captured record whose message contains ``text``, in order."""
    return [r.levelname for r in caplog.records if text in r.getMessage()]


def _refused(terminal_id: str = "term-1") -> TerminalInputBlockedError:
    """One inbox-type dispatch that must be refused; the exception it raised."""
    with pytest.raises(TerminalInputBlockedError) as exc:
        ts.dispatch_input(terminal_id, MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
    assert exc.value.reason is TerminalInputBlockedReason.WAITING_USER_ANSWER
    return exc.value


def _make_screen_unreadable(backend: MagicMock, unreadable: Any) -> None:
    """Fail the pane check's read (the visible screen) and no other pane read."""

    def read(*_args: Any, **kwargs: Any) -> Any:
        if not kwargs.get("visible_only"):
            return ""
        if isinstance(unreadable, BaseException):
            raise unreadable
        return unreadable

    backend.get_history.side_effect = read


@contextmanager
def _inbox(
    backend: MagicMock,
    status: Optional[TerminalStatus] = None,
    provider: Optional[ClaudeCodeProvider] = None,
) -> Iterator[Any]:
    """An InboxService with one pending message for term-1, on ``backend``.

    ``status`` is the monitor's canned answer, the cached status of the tmux
    path; None derives it from the provider as on herdr (see ``_terminal``).
    Yields ``(service, update)``; ``update`` is the patched message-status write.
    """
    with ExitStack() as stack:
        monitor = stack.enter_context(_terminal(provider or _claude(), backend, status))
        module = "cli_agent_orchestrator.services.inbox_service"
        stack.enter_context(
            patch(f"{module}.get_pending_messages", return_value=[_inbox_message()])
        )
        update = stack.enter_context(patch(f"{module}.update_message_status"))
        stack.enter_context(patch(f"{module}.status_monitor", monitor))
        stack.enter_context(patch(f"{module}.get_backend", return_value=backend))
        yield InboxService(), update


class TestHoldEpisodeLogging:
    """One open dialog is one hold episode, however often delivery is retried.

    The live run retried a held message on every herdr event, up to once every
    3 seconds, and each refusal wrote an INFO, an ERROR and a WARNING. A dialog
    can stay open overnight. The start of an episode keeps those levels, the
    retries inside it log at DEBUG, and the end is one INFO line. Nothing but
    the levels differs between the first refusal and the ones after it.
    """

    def test_first_hold_logs_all_three_lines_at_their_levels(self, caplog):
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _inbox(backend) as (service, update), caplog.at_level("DEBUG"):
            service.deliver_pending("term-1")
        for line, level in HOLD_LINES.items():
            assert _levels(caplog, line) == [level], line
        assert _levels(caplog, RELEASED) == []
        assert update.call_args_list[-1] == call(1, MessageStatus.PENDING)

    def test_repeat_holds_log_at_debug_and_are_still_refused_and_left_pending(self, caplog):
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _inbox(backend) as (service, update), caplog.at_level("DEBUG"):
            service.deliver_pending("term-1")
            first = list(update.call_args_list)
            assert first[-1] == call(1, MessageStatus.PENDING)
            caplog.clear()
            for _ in range(2):
                update.reset_mock()
                service.deliver_pending("term-1")
                # Refused and requeued exactly as the first time.
                assert update.call_args_list == first
        backend.send_keys.assert_not_called()
        backend.send_special_key.assert_not_called()
        assert len(_screen_reads(backend)) == 3
        for line in HOLD_LINES:
            assert _levels(caplog, line) == ["DEBUG", "DEBUG"], line
        assert not [
            r
            for r in caplog.records
            if r.levelname != "DEBUG" and any(line in r.getMessage() for line in HOLD_LINES)
        ]

    def test_repeat_refusal_differs_from_the_first_only_in_its_flag(self):
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend):
            first, second, third = _refused(), _refused(), _refused()
        assert [e.repeat_of_logged_hold for e in (first, second, third)] == [False, True, True]
        assert str(first) == str(second) == str(third)
        assert type(first) is type(second) is TerminalInputBlockedError
        backend.send_keys.assert_not_called()

    def test_flag_defaults_to_false_and_is_keyword_only(self):
        assert TerminalInputBlockedError("x").repeat_of_logged_hold is False
        reason = TerminalInputBlockedReason.WAITING_USER_ANSWER
        assert TerminalInputBlockedError("x", reason).repeat_of_logged_hold is False
        with pytest.raises(TypeError):
            TerminalInputBlockedError("x", reason, True)  # type: ignore[misc]

    def test_status_guard_refusal_is_never_a_repeat_and_stays_at_error(self, caplog):
        """Only the pane check has episodes: the status guard logs as it always did."""
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with (
            _terminal(_claude(), backend, status=TerminalStatus.WAITING_USER_ANSWER),
            caplog.at_level("DEBUG"),
        ):
            assert [_refused().repeat_of_logged_hold for _ in range(3)] == [False] * 3
        assert _levels(caplog, FAILED_TO_SEND) == ["ERROR"] * 3
        assert ts._pane_check_holding == set()

    def test_other_failures_stay_at_error_inside_an_episode(self, caplog):
        """Only a flagged refusal is demoted, not whatever fails while a hold is on."""
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend), caplog.at_level("DEBUG"):
            _refused()
            caplog.clear()
            with patch.object(ts, "get_terminal_metadata", return_value=None):
                with pytest.raises(Exception, match="term-1"):
                    ts.dispatch_input(
                        "term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE
                    )
        assert _levels(caplog, FAILED_TO_SEND) == ["ERROR"]

    def test_release_is_logged_once_and_a_new_dialog_is_a_new_episode(self, caplog):
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _inbox(backend) as (service, update), caplog.at_level("DEBUG"):
            service.deliver_pending("term-1")
            service.deliver_pending("term-1")
            assert _levels(caplog, RELEASED) == []

            # The human answers; the pane is an ordinary idle prompt again.
            caplog.clear()
            update.reset_mock()
            backend.get_history.return_value = READY_PANES["idle_after_permission"]
            service.deliver_pending("term-1")

            backend.send_keys.assert_called_once()
            assert MESSAGE in backend.send_keys.call_args.args[2]
            assert update.call_args_list == [call(1, MessageStatus.DELIVERED)]
            released = [r.getMessage() for r in caplog.records if RELEASED in r.getMessage()]
            assert released == ["Pre-send pane check released term-1: no dialog on screen any more"]
            assert _levels(caplog, RELEASED) == ["INFO"]
            for line in HOLD_LINES:
                assert _levels(caplog, line) == [], line

            # Still ready: the release is not said again.
            caplog.clear()
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
            assert _levels(caplog, RELEASED) == []

        # A second dialog later on is a new episode, logged in full. A fresh
        # provider, as the first one is now mid-turn and the inbox would wait.
        backend.get_history.return_value = DIALOG_PANES[PLAN_APPROVAL]
        with _inbox(backend) as (service, update), caplog.at_level("DEBUG"):
            caplog.clear()
            service.deliver_pending("term-1")
            for line, level in HOLD_LINES.items():
                assert _levels(caplog, line) == [level], line
            caplog.clear()
            service.deliver_pending("term-1")
            for line in HOLD_LINES:
                assert _levels(caplog, line) == ["DEBUG"], line
            assert update.call_args_list[-1] == call(1, MessageStatus.PENDING)

    @pytest.mark.parametrize(
        "unreadable",
        [RuntimeError("herdr pane read: socket closed"), "", None],
        ids=["raises", "empty", "not-text"],
    )
    def test_failed_pane_read_neither_ends_nor_restarts_an_episode(self, unreadable, caplog):
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend), caplog.at_level("DEBUG"):
            assert _refused().repeat_of_logged_hold is False
            caplog.clear()

            # The read fails: delivery goes ahead on the backend's status, as it
            # always did, and the episode is left exactly as it was.
            _make_screen_unreadable(backend, unreadable)
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
            backend.send_keys.assert_called_once()
            assert _levels(caplog, UNREADABLE) == ["WARNING"]
            assert _levels(caplog, RELEASED) == []
            assert _levels(caplog, HELD) == []
            assert ts._pane_check_holding == {"term-1"}

            # The dialog is readable again: the same episode, so a repeat.
            caplog.clear()
            backend.get_history.side_effect = None
            backend.get_history.return_value = DIALOG_PANES[ASK_USER_QUESTION]
            assert _refused().repeat_of_logged_hold is True
            assert _levels(caplog, HELD) == ["DEBUG"]
            assert _levels(caplog, FAILED_TO_SEND) == ["DEBUG"]

    def test_failed_pane_read_does_not_start_an_episode(self, caplog):
        backend = _backend("", native=TerminalStatus.IDLE)
        _make_screen_unreadable(backend, RuntimeError("socket closed"))
        with _terminal(_claude(), backend), caplog.at_level("DEBUG"):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
            assert ts._pane_check_holding == set()
            backend.get_history.side_effect = None
            backend.get_history.return_value = DIALOG_PANES[ASK_USER_QUESTION]
            assert _refused().repeat_of_logged_hold is False
        assert _levels(caplog, HELD) == ["INFO"]

    def test_input_the_check_does_not_apply_to_leaves_the_episode_alone(self, caplog):
        """The operator typing the answer is not a pane read that found no dialog."""
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend), caplog.at_level("DEBUG"):
            _refused()
            ts.dispatch_input("term-1", "1")
            assert ts._pane_check_holding == {"term-1"}
            assert _levels(caplog, RELEASED) == []
            assert _refused().repeat_of_logged_hold is True

    def test_two_terminals_hold_independently(self, caplog):
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend), caplog.at_level("DEBUG"):
            assert _refused("term-1").repeat_of_logged_hold is False
            assert _refused("term-1").repeat_of_logged_hold is True
            # term-2's first hold is its own episode, whatever term-1 is doing.
            assert _refused("term-2").repeat_of_logged_hold is False
            assert _refused("term-2").repeat_of_logged_hold is True
            assert _levels(caplog, HELD + "term-1") == ["INFO", "DEBUG"]
            assert _levels(caplog, HELD + "term-2") == ["INFO", "DEBUG"]
            assert _levels(caplog, FAILED_TO_SEND + "term-1") == ["ERROR", "DEBUG"]
            assert _levels(caplog, FAILED_TO_SEND + "term-2") == ["ERROR", "DEBUG"]

            # term-1's dialog goes away; term-2 is still held.
            backend.get_history.return_value = READY_PANES["herdr_idle"]
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
            assert _levels(caplog, RELEASED + "term-1") == ["INFO"]
            assert _levels(caplog, RELEASED + "term-2") == []
            assert ts._pane_check_holding == {"term-2"}
            backend.get_history.return_value = DIALOG_PANES[ASK_USER_QUESTION]
            assert _refused("term-2").repeat_of_logged_hold is True
            assert _refused("term-1").repeat_of_logged_hold is False

    def test_concurrent_checks_of_one_terminal_log_one_hold(self, caplog):
        """Delivery runs on worker threads: one of them starts the episode."""
        workers = 8
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        provider = _claude()
        start = threading.Barrier(workers)
        results: List[Any] = []

        def check() -> None:
            start.wait(timeout=10)
            results.append(
                ts._pre_send_pane_check("term-1", provider, OrchestrationType.SEND_MESSAGE)
            )

        with _terminal(provider, backend), caplog.at_level("DEBUG"):
            threads = [threading.Thread(target=check) for _ in range(workers)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)
        assert len(results) == workers
        assert all(result.held for result in results)
        assert sorted(result.repeat for result in results) == [False] + [True] * (workers - 1)
        assert sorted(_levels(caplog, HELD)) == ["DEBUG"] * (workers - 1) + ["INFO"]

    def test_bare_enter_skip_warning_is_not_demoted_inside_an_episode(self, caplog):
        """It is written at most once per recovery attempt of a message that was
        typed, not once per retry of a pending one, so it keeps its level."""
        provider = _claude()
        backend = _backend(DIALOG_PANES[REVIEW_PAGE_NAMED], native=TerminalStatus.IDLE)
        enters: List[str] = []
        with (
            _terminal(provider, backend, status=TerminalStatus.IDLE),
            patch.object(ts, "_capture_current_composer_region", return_value=MESSAGE),
            patch.object(ts, "send_special_key", side_effect=lambda _tid, key: enters.append(key)),
            caplog.at_level("DEBUG"),
        ):
            _refused()
            for attempt in (1, 2):
                ts.redeliver_dropped_message_with_boundary(
                    "term-1",
                    MESSAGE,
                    attempt,
                    provider,
                    full_resend_requires_composer_evidence=True,
                    orchestration_type=OrchestrationType.SEND_MESSAGE,
                )
        assert enters == []
        assert _levels(caplog, "skipping the bare-Enter re-submit") == ["WARNING", "WARNING"]
        # The check's own line follows the episode: the dispatch above started it.
        assert _levels(caplog, HELD) == ["INFO", "DEBUG", "DEBUG"]

    def test_teardown_forgets_the_terminal(self, monkeypatch):
        backend = _backend(DIALOG_PANES[ASK_USER_QUESTION], native=TerminalStatus.IDLE)
        with _terminal(_claude(), backend):
            _refused("term-1")
            _refused("term-2")
            monkeypatch.setattr(ts, "get_herdr_inbox_service", lambda: None)
            monkeypatch.setattr(ts.fifo_manager, "stop_reader", lambda terminal_id: True)
            monkeypatch.setattr(ts.provider_manager, "cleanup_provider", lambda terminal_id: True)
            monkeypatch.setattr(ts.ephemeral_service, "release", lambda *a, **k: None)
            ts.dismantle_terminal_runtime(
                "term-1", {"tmux_session": "cao-session", "tmux_window": "developer-abcd"}
            )
        assert ts._pane_check_holding == {"term-2"}


# --- tmux (#405, the race) ---------------------------------------------------

# The dialog frames #405's regression is pinned on: three AskUserQuestion and
# plan-approval pages, and the two permission prompts captured from tmux.
TMUX_RACE_DIALOGS = [
    "herdr_single_question",
    "herdr_plan_approval",
    "herdr_review_page",
    "bash_permission_prompt",
    "write_permission_prompt",
]
TMUX_READY_PANES = ["startup_idle", "turn_ended", "idle_after_permission", "herdr_idle"]
SCREEN_READ = call("cao-session", "developer-abcd", strip_escapes=True, visible_only=True)


def _tmux(pane: Any) -> MagicMock:
    """A tmux-shaped backend double: no event inbox and no native status."""
    return _backend(pane, native=None, event_inbox=False)


@contextmanager
def _tmux_inbox(
    backend: MagicMock, cached: TerminalStatus, *, eager: bool = False
) -> Iterator[Any]:
    """``_inbox`` on tmux with the cached status ``cached``.

    The submit confirmation is off: it waits on real output after a delivery,
    and what is under test ends at the paste. ``eager`` turns eager delivery on
    for an initialized provider, the only kind it sends to mid-turn.
    """
    module = "cli_agent_orchestrator.services.inbox_service"
    provider = _claude()
    provider._initialized = eager
    with ExitStack() as stack:
        stack.enter_context(patch(f"{module}.INBOX_SUBMIT_CONFIRMATION", False))
        stack.enter_context(patch(f"{module}.EAGER_INBOX_DELIVERY", eager))
        yield stack.enter_context(_inbox(backend, cached, provider))


class TestTmuxCachedStatusRace:
    """THE REGRESSION (#405). The cached status is ready, the screen shows a dialog."""

    @pytest.mark.parametrize("cached", [TerminalStatus.IDLE, TerminalStatus.COMPLETED])
    @pytest.mark.parametrize("name", TMUX_RACE_DIALOGS)
    def test_inbox_message_is_held_then_delivered_once_the_dialog_is_gone(self, name, cached):
        """Fails without the tmux pane check: the message is typed into the dialog."""
        backend = _tmux(DIALOG_PANES[name])
        with _tmux_inbox(backend, cached) as (service, update):
            service.deliver_pending("term-1")

            backend.send_keys.assert_not_called()
            backend.send_special_key.assert_not_called()
            assert update.call_args_list == [
                call(1, MessageStatus.DELIVERED),
                call(1, MessageStatus.PENDING),
            ]
            assert _screen_reads(backend) == [SCREEN_READ]

            # The human answers; the pane is an ordinary idle prompt again.
            update.reset_mock()
            backend.get_history.return_value = READY_PANES["idle_after_permission"]
            service.deliver_pending("term-1")

            backend.send_keys.assert_called_once()
            assert MESSAGE in backend.send_keys.call_args.args[2]
            assert update.call_args_list == [call(1, MessageStatus.DELIVERED)]
            assert _screen_reads(backend) == [SCREEN_READ, SCREEN_READ]

    @pytest.mark.parametrize("name", TMUX_RACE_DIALOGS)
    def test_eager_delivery_is_held_while_the_cached_status_says_processing(self, name):
        """Eager delivery sends on PROCESSING, which is what a cached status
        still says when the dialog opened after it was computed."""
        backend = _tmux(DIALOG_PANES[name])
        with _tmux_inbox(backend, TerminalStatus.PROCESSING, eager=True) as (service, update):
            service.deliver_pending("term-1")

            backend.send_keys.assert_not_called()
            assert update.call_args_list == [
                call(1, MessageStatus.DELIVERED),
                call(1, MessageStatus.PENDING),
            ]

            update.reset_mock()
            backend.get_history.return_value = READY_PANES["turn_ended"]
            service.deliver_pending("term-1")

            backend.send_keys.assert_called_once()
            assert MESSAGE in backend.send_keys.call_args.args[2]
            assert update.call_args_list == [call(1, MessageStatus.DELIVERED)]

    @pytest.mark.parametrize("orchestration_type", list(OrchestrationType), ids=lambda t: t.value)
    def test_every_orchestration_type_is_refused(self, orchestration_type):
        backend = _tmux(DIALOG_PANES["herdr_plan_approval"])
        with _terminal(_claude(), backend, status=TerminalStatus.IDLE):
            _assert_refused(backend, orchestration_type=orchestration_type)
            ts.inject_memory_context.assert_not_called()  # type: ignore[attr-defined]

    def test_refusal_names_the_cached_status_and_the_check(self):
        backend = _tmux(DIALOG_PANES[ASK_USER_QUESTION])
        with _terminal(_claude(), backend, status=TerminalStatus.COMPLETED):
            message = str(_refused())
        assert message.startswith("Terminal term-1 is waiting for a user answer: ")
        assert "its reported status was completed, but a dialog is open on screen" in message
        assert "(pre-send pane check)" in message
        assert "native" not in message


class TestTmuxCaptureCount:
    """One capture per orchestrated dispatch that can use the answer, none otherwise."""

    @pytest.mark.parametrize("name", TMUX_READY_PANES)
    def test_ready_pane_is_delivered_after_exactly_one_capture(self, name):
        backend = _tmux(READY_PANES[name])
        with _terminal(_claude(), backend, status=TerminalStatus.IDLE):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.send_keys.assert_called_once()
        assert _screen_reads(backend) == [SCREEN_READ]

    def test_the_answer_is_not_kept_between_dispatches(self):
        """A kept answer would be as stale as the cached status: read every time."""
        backend = _tmux(READY_PANES["turn_ended"])
        with _terminal(_claude(), backend, status=TerminalStatus.IDLE):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
            backend.get_history.return_value = DIALOG_PANES[ASK_USER_QUESTION]
            _refused()
        backend.send_keys.assert_called_once()
        assert _screen_reads(backend) == [SCREEN_READ, SCREEN_READ]

    def test_operator_input_is_not_captured_and_reaches_the_dialog(self):
        backend = _tmux(DIALOG_PANES[ASK_USER_QUESTION])
        with _terminal(_claude(), backend, status=TerminalStatus.IDLE):
            ts.dispatch_input("term-1", "1")
        backend.send_keys.assert_called_once()
        assert _screen_reads(backend) == []

    def test_provider_that_does_not_block_at_dialogs_is_not_captured(self):
        provider = MagicMock()
        provider.blocks_orchestrated_input_while_waiting_user_answer = False
        provider.shows_user_answer_dialog.return_value = True
        provider.paste_enter_count = 1
        backend = _tmux(DIALOG_PANES[ASK_USER_QUESTION])
        with _terminal(provider, backend, status=TerminalStatus.IDLE):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.send_keys.assert_called_once()
        backend.get_history.assert_not_called()

    def test_blocking_provider_that_inherits_the_method_is_not_captured(self):
        provider = CodexProvider("term-1", "cao-session", "developer-abcd")
        backend = _tmux(DIALOG_PANES[ASK_USER_QUESTION])
        with _terminal(provider, backend, status=TerminalStatus.IDLE):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.send_keys.assert_called_once()
        assert _screen_reads(backend) == []

    def test_status_guard_refuses_without_a_capture(self):
        backend = _tmux(DIALOG_PANES[ASK_USER_QUESTION])
        with _terminal(_claude(), backend, status=TerminalStatus.WAITING_USER_ANSWER):
            _assert_refused(backend, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.get_history.assert_not_called()


class TestTmuxFailOpen:
    """A capture that fails does not hold delivery, and a missing pane is not a dialog."""

    @pytest.mark.parametrize(
        "pane",
        [RuntimeError("tmux capture-pane: server exited"), "", "   \n\n", None, MagicMock()],
        ids=["raises", "empty", "blank", "none", "not-text"],
    )
    def test_failed_capture_is_delivered_and_warns(self, pane, caplog):
        backend = _tmux("")
        _make_screen_unreadable(backend, pane)
        with (
            _terminal(_claude(), backend, status=TerminalStatus.IDLE),
            caplog.at_level("WARNING"),
        ):
            ts.dispatch_input("term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE)
        backend.send_keys.assert_called_once()
        assert _levels(caplog, UNREADABLE + "term-1") == ["WARNING"]
        assert "sending on its status alone" in caplog.text
        assert ts._pane_check_holding == set()

    def test_missing_pane_fails_as_it_did_and_is_not_called_a_dialog(self, caplog):
        """tmux's get_history raises ValueError for a session or window that is
        gone. The check lets that pass, and the dispatch then fails on its own
        next pane read exactly as it did before the check ran on tmux."""
        gone = ValueError("Session 'cao-session' not found")
        backend = _tmux(gone)
        with (
            _terminal(_claude(), backend, status=TerminalStatus.IDLE),
            caplog.at_level("DEBUG"),
        ):
            with pytest.raises(ts.TerminalRowMissingError, match="not found") as exc:
                ts.dispatch_input(
                    "term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE
                )
        assert not isinstance(exc.value, TerminalInputBlockedError)
        assert exc.value.__cause__ is gone
        backend.send_keys.assert_not_called()
        assert _levels(caplog, HELD) == []
        assert _levels(caplog, UNREADABLE + "term-1") == ["WARNING"]
        assert ts._pane_check_holding == set()


class TestTmuxBareEnterRecovery:
    """An Enter is exactly what answers a dialog: the same check, on tmux too."""

    def _recover(self, pane: Any, orchestration_type: Any, status: TerminalStatus) -> Any:
        provider = _claude()
        backend = _tmux(pane)
        enters: List[str] = []
        with (
            _terminal(provider, backend, status=status),
            patch.object(ts, "_capture_current_composer_region", return_value=MESSAGE),
            patch.object(ts, "send_special_key", side_effect=lambda _tid, key: enters.append(key)),
        ):
            ts.redeliver_dropped_message_with_boundary(
                "term-1",
                MESSAGE,
                1,
                provider,
                full_resend_requires_composer_evidence=True,
                orchestration_type=orchestration_type,
            )
        return enters, backend

    @pytest.mark.parametrize("name", TMUX_RACE_DIALOGS)
    def test_no_enter_into_a_dialog_the_cached_status_missed(self, name, caplog):
        """Fails without the tmux pane check: the Enter is sent."""
        with caplog.at_level("INFO"):
            enters, backend = self._recover(
                DIALOG_PANES[name], OrchestrationType.SEND_MESSAGE, TerminalStatus.IDLE
            )
        assert enters == []
        assert _screen_reads(backend) == [SCREEN_READ]
        assert "the pre-send pane check found a dialog on screen" in caplog.text

    def test_enter_is_resent_on_a_ready_pane_after_one_capture(self):
        enters, backend = self._recover(
            READY_PANES["turn_ended"], OrchestrationType.SEND_MESSAGE, TerminalStatus.IDLE
        )
        assert enters == ["Enter"]
        assert _screen_reads(backend) == [SCREEN_READ]

    def test_enter_is_resent_for_untyped_input_without_a_capture(self):
        enters, backend = self._recover(
            DIALOG_PANES["bash_permission_prompt"], None, TerminalStatus.IDLE
        )
        assert enters == ["Enter"]
        assert _screen_reads(backend) == []

    def test_status_guard_holds_the_enter_without_a_capture(self):
        enters, backend = self._recover(
            DIALOG_PANES["bash_permission_prompt"],
            OrchestrationType.SEND_MESSAGE,
            TerminalStatus.WAITING_USER_ANSWER,
        )
        assert enters == []
        assert _screen_reads(backend) == []


class TestTmuxHoldEpisodeLogging:
    """The reconcile sweep retries a held message every 30 seconds on tmux: the
    same episode logging as on herdr."""

    def test_first_hold_in_full_then_debug_then_one_release_line(self, caplog):
        backend = _tmux(DIALOG_PANES[ASK_USER_QUESTION])
        with _tmux_inbox(backend, TerminalStatus.IDLE) as (service, update):
            with caplog.at_level("DEBUG"):
                service.deliver_pending("term-1")
                for line, level in HOLD_LINES.items():
                    assert _levels(caplog, line) == [level], line

                caplog.clear()
                for _ in range(2):
                    service.deliver_pending("term-1")
                for line in HOLD_LINES:
                    assert _levels(caplog, line) == ["DEBUG", "DEBUG"], line
                assert _levels(caplog, RELEASED) == []
                assert update.call_args_list[-1] == call(1, MessageStatus.PENDING)
                backend.send_keys.assert_not_called()

                caplog.clear()
                backend.get_history.return_value = READY_PANES["idle_after_permission"]
                service.deliver_pending("term-1")
                backend.send_keys.assert_called_once()
                assert [r.getMessage() for r in caplog.records if RELEASED in r.getMessage()] == [
                    "Pre-send pane check released term-1: no dialog on screen any more"
                ]
                assert _levels(caplog, RELEASED) == ["INFO"]
                for line in HOLD_LINES:
                    assert _levels(caplog, line) == [], line

                # Still ready: the release is not said again.
                caplog.clear()
                ts.dispatch_input(
                    "term-1", MESSAGE, orchestration_type=OrchestrationType.SEND_MESSAGE
                )
                assert _levels(caplog, RELEASED) == []
        assert ts._pane_check_holding == set()


class TestReadOnRealTmuxBackend:
    """What the check asks tmux for, through the real backend and client."""

    def test_one_plain_text_capture_of_the_viewport(self):
        from cli_agent_orchestrator.backends.tmux_backend import TmuxBackend
        from cli_agent_orchestrator.clients.tmux import TmuxClient

        frame = DIALOG_PANES["bash_permission_prompt"]
        pane = MagicMock()
        # libtmux hands capture-pane back as rows, with trailing blank rows dropped.
        pane.cmd.return_value = MagicMock(stdout=frame.rstrip("\n").split("\n"))
        window = MagicMock()
        window.panes = [pane]
        session = MagicMock()
        session.windows.get.return_value = window
        with patch("cli_agent_orchestrator.clients.tmux.libtmux") as libtmux:
            libtmux.Server.return_value.sessions.get.return_value = session
            backend = TmuxBackend(client=TmuxClient())
        with (
            patch.object(ts, "get_backend", return_value=backend),
            patch.object(
                ts,
                "get_terminal_metadata",
                return_value={"tmux_session": "cao-session", "tmux_window": "developer-abcd"},
            ),
        ):
            assert backend.supports_event_inbox() is False
            assert (
                ts._pre_send_pane_check_holds("term-1", _claude(), OrchestrationType.SEND_MESSAGE)
                is True
            )
        # The rendered viewport only (-S 0), as text: no -e escapes, no -J rejoin.
        assert pane.cmd.call_args_list == [call("capture-pane", "-p", "-S", "0")]

    def test_a_window_that_is_gone_is_not_a_hold(self, caplog):
        from cli_agent_orchestrator.backends.tmux_backend import TmuxBackend
        from cli_agent_orchestrator.clients.tmux import TmuxClient

        with patch("cli_agent_orchestrator.clients.tmux.libtmux") as libtmux:
            libtmux.Server.return_value.sessions.get.return_value = None
            backend = TmuxBackend(client=TmuxClient())
        with (
            patch.object(ts, "get_backend", return_value=backend),
            patch.object(
                ts,
                "get_terminal_metadata",
                return_value={"tmux_session": "cao-session", "tmux_window": "developer-abcd"},
            ),
            caplog.at_level("WARNING"),
        ):
            assert (
                ts._pre_send_pane_check_holds("term-1", _claude(), OrchestrationType.SEND_MESSAGE)
                is False
            )
        assert _levels(caplog, UNREADABLE + "term-1") == ["WARNING"]
