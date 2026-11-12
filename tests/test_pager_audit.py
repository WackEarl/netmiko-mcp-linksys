"""Pager handling, read timeout, session log, and non-fatal audit (0.1.1)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from netmiko_mcp_linksys.audit import check_audit_path, write_audit
from netmiko_mcp_linksys.connection import (
    PAGER_RE,
    clean_output,
    connect_params,
    disable_paging_best_effort,
    read_timeout,
    run_show,
    send_paged,
)
from netmiko_mcp_linksys.connection import (
    ConnectionError as SwitchConnectionError,
)
from netmiko_mcp_linksys.validation import ValidationError


class FakeChannel:
    """Scripted channel: each write of a space releases the next page."""

    RETURN = "\n"
    base_prompt = "LGS328PC"

    def __init__(self, pages: list[list[str]]) -> None:
        self._pages = pages
        self._queue: list[str] = []
        self.writes: list[str] = []

    def clear_buffer(self) -> None:
        pass

    def write_channel(self, data: str) -> None:
        self.writes.append(data)
        if self._pages:
            self._queue.extend(self._pages.pop(0))

    def read_channel(self) -> str:
        return self._queue.pop(0) if self._queue else ""


def _lines(start: int, stop: int) -> str:
    return "".join(f"Gi0/{n}   up   1000M\r\n" for n in range(start, stop))


def test_pager_more_split_across_chunks() -> None:
    chan = FakeChannel(
        [
            ["show interfaces status\r\n", _lines(1, 10), "--Mo", "re--"],
            ["\r        \r", _lines(10, 20), "\x1b[7m--More--\x1b[m"],
            ["\b" * 8 + " " * 8 + "\b" * 8, _lines(20, 29), "\r\nLGS32", "8PC# "],
        ]
    )
    out = send_paged(chan, "show interfaces status", timeout=2, poll_interval=0)
    assert chan.writes == ["show interfaces status\n", " ", " "]
    lines = out.splitlines()
    assert lines[0] == "Gi0/1   up   1000M"
    assert lines[-1] == "Gi0/28   up   1000M"
    assert len(lines) == 28
    assert "More" not in out
    assert "LGS328PC#" not in out
    assert "\x1b" not in out and "\b" not in out and "\r" not in out


@pytest.mark.parametrize(
    "prompt",
    ["--More--", "-- More --", "--More-- (45%)", "More: <space>,  Quit: q or CTRL+Z, One line: <return>",
     "<--- More --->", "Press any key to continue (Q to quit)"],
)
def test_pager_variants_detected(prompt: str) -> None:
    assert PAGER_RE.search(prompt)
    chan = FakeChannel([["show vlan\r\n", "a\r\n", prompt], ["b\r\nLGS328PC#"]])
    assert send_paged(chan, "show vlan", timeout=2, poll_interval=0) == "a\nb"


def test_pager_ignores_plain_more_text() -> None:
    assert not PAGER_RE.search("Description: more cameras")


def test_short_output_no_pager() -> None:
    chan = FakeChannel([["show clock\r\n12:00:00 2026-11-12\r\nLGS328PC#"]])
    assert send_paged(chan, "show clock", timeout=2, poll_interval=0) == "12:00:00 2026-11-12"
    assert chan.writes == ["show clock\n"]


def test_pager_unknown_prompt_times_out_with_context() -> None:
    chan = FakeChannel([["show interfaces\r\n", "x\r\n", "[space to go on]"]])
    with pytest.raises(SwitchConnectionError, match=r"No prompt after 'show interfaces'.*space to go on"):
        send_paged(chan, "show interfaces", timeout=0.05, poll_interval=0.01)


def test_clean_output_keeps_error_text() -> None:
    import re

    raw = "show version\r\n% Invalid input detected at '^' marker.\r\nLGS328PC#"
    out = clean_output(raw, "show version", re.compile(r"^\s*LGS328PC[^\r\n#>]*[#>]\s*$"))
    assert out == "% Invalid input detected at '^' marker."


def test_paging_off_is_best_effort() -> None:
    conn = MagicMock()
    conn.send_config_set.return_value = "% Invalid input detected"
    disable_paging_best_effort(conn)  # must not raise
    conn.send_config_set.side_effect = RuntimeError("boom")
    disable_paging_best_effort(conn)  # must not raise
    assert conn.send_config_set.call_args.args[0] == ["set cli pagination off"]


def test_paging_off_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    conn = MagicMock()
    disable_paging_best_effort(conn)
    conn.send_config_set.assert_not_called()


def test_run_show_end_to_end_with_pager(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    chan = FakeChannel(
        [["show power inline\r\n", _lines(1, 5), "--More--"], [_lines(5, 9), "LGS328PC#"]]
    )
    chan.disconnect = MagicMock()  # type: ignore[attr-defined]
    with patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=chan):
        out = run_show("show power inline")
    assert len(out.splitlines()) == 8
    chan.disconnect.assert_called_once()  # type: ignore[attr-defined]


def test_read_timeout_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SWITCH_READ_TIMEOUT", raising=False)
    assert read_timeout() == 60.0
    monkeypatch.setenv("SWITCH_READ_TIMEOUT", "120")
    assert read_timeout() == 120.0
    assert connect_params()["read_timeout_override"] == 120.0
    for bad in ("abc", "0", "9999"):
        monkeypatch.setenv("SWITCH_READ_TIMEOUT", bad)
        with pytest.raises(ValidationError, match="SWITCH_READ_TIMEOUT"):
            read_timeout()


def test_session_log_param(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = tmp_path / "sub" / "session.log"
    monkeypatch.setenv("SWITCH_SESSION_LOG", str(log))
    params = connect_params()
    assert params["session_log"] == str(log)
    assert params["session_log_file_mode"] == "append"
    assert params["session_log_record_writes"] is False
    assert (log.stat().st_mode & 0o777) == 0o600


def test_session_log_unwritable_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setenv("SWITCH_SESSION_LOG", str(blocker / "session.log"))
    params = connect_params()
    assert "session_log" not in params
    assert "session log disabled" in capsys.readouterr().err


def test_session_log_masks_password(tmp_path: Path) -> None:
    """netmiko's SessionLog no_log filter hides the password (used via connect_params)."""
    from netmiko.session_log import SessionLog

    password = os.environ["SWITCH_PASSWORD"]
    log = tmp_path / "s.log"
    slog = SessionLog(file_name=str(log), no_log={"password": password})
    slog.open()
    slog.write(f"login ok {password}\n")
    slog.close()
    assert password not in log.read_text()


def _readonly_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_AUDIT_LOG", "/data/netmiko/switch-audit.log")

    def boom(*_args: object, **_kwargs: object) -> None:
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr("netmiko_mcp_linksys.audit.prepare_private_file", boom)


def test_audit_failure_is_non_fatal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _readonly_audit(monkeypatch)
    warning = write_audit(tool="show", params={}, allowed=True, result="ok")
    assert warning is not None and "Read-only file system" in warning
    assert "Read-only file system" in capsys.readouterr().err


def test_tool_result_carries_audit_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys.server import port_set_admin_state, save_config

    _readonly_audit(monkeypatch)
    with patch("netmiko_mcp_linksys.server.run_save", return_value="saved"):
        result = save_config()
    assert result.startswith("saved")
    assert "audit_warning:" in result
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24")
    rejected = port_set_admin_state("0/24", False)
    assert rejected.startswith("Rejected:")
    assert "audit_warning:" in rejected


def test_audit_ok_has_no_warning(audit_log: Path) -> None:
    from netmiko_mcp_linksys.server import save_config

    with patch("netmiko_mcp_linksys.server.run_save", return_value="saved"):
        assert save_config() == "saved"
    assert json.loads(audit_log.read_text().splitlines()[-1])["tool"] == "save_config"


def test_startup_check_writable(audit_log: Path) -> None:
    assert check_audit_path() is None
    assert audit_log.exists()
    assert (audit_log.stat().st_mode & 0o777) == 0o600


def test_startup_check_readonly_warns_not_aborts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from netmiko_mcp_linksys.server import startup_checks

    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setenv("SWITCH_AUDIT_LOG", str(blocker / "audit.log"))
    warnings = startup_checks()
    assert any("SWITCH_AUDIT_LOG" in w and "not writable" in w for w in warnings)
    assert "not writable" in capsys.readouterr().err


def test_startup_check_unset_warns(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SWITCH_AUDIT_LOG", raising=False)
    assert check_audit_path() is None
    assert "not audited" in capsys.readouterr().err


def test_whitelist_has_system_information_not_version(commands_file: Path) -> None:
    data = yaml.safe_load(commands_file.read_text())
    assert "show system information" in data["allowed_commands"]
    assert "show version" not in data["allowed_commands"]


def test_show_system_information_allowed_show_version_not(
    reset_command_file: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netmiko_mcp_linksys.server import show

    monkeypatch.setattr("netmiko_mcp_linksys.server.run_show", lambda cmd: f"OK:{cmd}")
    assert show("show system information") == "OK:show system information"
    assert show("show version").startswith("Command rejected:")
