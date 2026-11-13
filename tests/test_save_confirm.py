"""save_config Y/N confirmation handling (issue #4).

The LGS328PC save prompt text is not live-confirmed; these tests pin the
fail-closed behaviour for the shapes we answer and the ones we do not.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from netmiko_mcp_linksys.connection import (
    SAVE_CONFIRM_ANSWER,
    SAVE_CONFIRM_RE,
    run_save,
    send_paged,
)
from netmiko_mcp_linksys.connection import (
    ConnectionError as SwitchConnectionError,
)

CONFIRM = (SAVE_CONFIRM_RE, SAVE_CONFIRM_ANSWER)


class ScriptedChannel:
    """Each write releases the next scripted list of chunks."""

    RETURN = "\n"
    base_prompt = "LGS328PC"

    def __init__(self, replies: list[list[str]]) -> None:
        self._replies = replies
        self._queue: list[str] = []
        self.writes: list[str] = []
        self.disconnect = MagicMock()

    def clear_buffer(self) -> None:
        pass

    def write_channel(self, data: str) -> None:
        self.writes.append(data)
        if self._replies:
            self._queue.extend(self._replies.pop(0))

    def read_channel(self) -> str:
        return self._queue.pop(0) if self._queue else ""


@pytest.mark.parametrize(
    "line",
    [
        "Overwrite file [startup-config] ?(y/n) ",
        "Do you want to save the configuration? [Y/N]:",
        "Continue (yes/no)?",
        "Save configuration [y/n]",
        "Are you sure (Y/N) ? ",
    ],
)
def test_confirm_regex_matches(line: str) -> None:
    assert SAVE_CONFIRM_RE.search(line)


@pytest.mark.parametrize(
    "line",
    [
        "LGS328PC#",
        "Description: y/n toggle",
        "(y/n) answered earlier, continuing",
        "Are you sure? ",
        "Proceed [confirm]",
    ],
)
def test_confirm_regex_ignores(line: str) -> None:
    assert not SAVE_CONFIRM_RE.search(line)


def test_save_answers_one_confirmation() -> None:
    chan = ScriptedChannel(
        [
            ["save\r\n", "Overwrite file [startup-config] ?(y/n) "],
            ["y\r\n", "Copy succeeded\r\n", "LGS328PC#"],
        ]
    )
    out = send_paged(chan, "save", timeout=2, poll_interval=0, confirm=CONFIRM)
    assert chan.writes == ["save\n", "y\n"]
    assert "Copy succeeded" in out


def test_save_confirmation_split_across_chunks() -> None:
    chan = ScriptedChannel(
        [
            ["save\r\n", "Overwrite file [startup-", "config] ?(y", "/n) "],
            ["y\r\nCopy succeeded\r\nLGS328PC#"],
        ]
    )
    out = send_paged(chan, "save", timeout=2, poll_interval=0, confirm=CONFIRM)
    assert chan.writes == ["save\n", "y\n"]
    assert out.endswith("Copy succeeded")


def test_save_without_confirmation_sends_only_save() -> None:
    chan = ScriptedChannel([["save\r\n", "Copy succeeded\r\nLGS328PC#"]])
    out = send_paged(chan, "save", timeout=2, poll_interval=0, confirm=CONFIRM)
    assert chan.writes == ["save\n"]
    assert out == "Copy succeeded"


def test_second_confirmation_is_not_answered() -> None:
    chan = ScriptedChannel(
        [
            ["save\r\n", "Overwrite file [startup-config] ?(y/n) "],
            ["y\r\n", "Really overwrite? (y/n) "],
        ]
    )
    with pytest.raises(SwitchConnectionError, match="second confirmation prompt"):
        send_paged(chan, "save", timeout=2, poll_interval=0, confirm=CONFIRM)
    assert chan.writes == ["save\n", "y\n"]


def test_show_never_answers_confirmation() -> None:
    """Without confirm= (show, read-backs) a Y/N prompt is never answered."""
    chan = ScriptedChannel([["show x\r\n", "Proceed? (y/n) "]])
    with pytest.raises(SwitchConnectionError, match="No prompt after 'show x'"):
        send_paged(chan, "show x", timeout=0.05, poll_interval=0.01)
    assert chan.writes == ["show x\n"]


def _run_save_with(chan: ScriptedChannel, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    monkeypatch.setenv("SWITCH_READ_TIMEOUT", "1")
    with patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=chan):
        return run_save()


def test_run_save_end_to_end_with_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    chan = ScriptedChannel(
        [
            ["save\r\n", "Overwrite file [startup-config] ?(y/n) "],
            ["y\r\n", "Copy succeeded\r\nLGS328PC#"],
        ]
    )
    out = _run_save_with(chan, monkeypatch)
    assert chan.writes == ["save\n", "y\n"]
    assert "Copy succeeded" in out
    chan.disconnect.assert_called_once()


def test_run_save_unknown_prompt_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    password = os.environ["SWITCH_PASSWORD"]
    chan = ScriptedChannel([["save\r\n", f"Overwrite {password}? "]])
    with pytest.raises(SwitchConnectionError) as excinfo:
        _run_save_with(chan, monkeypatch)
    message = str(excinfo.value)
    assert message.startswith("save did not complete: No prompt after 'save'")
    assert "Whether startup-config was written is unknown" in message
    assert "Overwrite ***?" in message
    assert password not in message
    assert chan.writes == ["save\n"]
    chan.disconnect.assert_called_once()


def test_run_save_error_after_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    chan = ScriptedChannel(
        [
            ["save\r\n", "Overwrite file [startup-config] ?(y/n) "],
            ["y\r\n", "% Error: flash write failed\r\nLGS328PC#"],
        ]
    )
    with pytest.raises(SwitchConnectionError, match="save failed"):
        _run_save_with(chan, monkeypatch)


def test_save_config_tool_reports_unknown_state(monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys.server import save_config

    chan = ScriptedChannel([["save\r\n", "Are you sure? "]])
    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    monkeypatch.setenv("SWITCH_READ_TIMEOUT", "1")
    with patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=chan):
        result = save_config()
    assert result.startswith("Error: save did not complete")
    assert "unknown" in result


def test_run_save_unexpected_error_reports_unknown_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = os.environ["SWITCH_PASSWORD"]
    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    conn = MagicMock()
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn),
        patch(
            "netmiko_mcp_linksys.connection.send_paged",
            side_effect=OSError(f"socket closed {password}"),
        ),
        pytest.raises(SwitchConnectionError) as excinfo,
    ):
        run_save()
    message = str(excinfo.value)
    assert message.startswith("save did not complete: socket closed ***")
    assert "unknown" in message
    assert password not in message
    conn.disconnect.assert_called_once()
