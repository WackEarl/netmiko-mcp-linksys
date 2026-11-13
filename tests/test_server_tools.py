from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from netmiko_mcp_linksys.audit import write_audit
from netmiko_mcp_linksys.server import (
    poe_set,
    port_overview,
    port_set_admin_state,
    port_set_description,
    save_config,
    show,
)


def test_port_set_admin_state_rejects_protected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24")
    with patch("netmiko_mcp_linksys.server.run_config_and_readback") as run:
        result = port_set_admin_state("0/24", False)
    run.assert_not_called()
    assert result.startswith("Rejected:")
    assert "protected port" in result


def test_poe_set_rejects_protected_and_non_poe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/8")
    with patch("netmiko_mcp_linksys.server.run_config_and_readback") as run:
        protected = poe_set("0/8", False)
        uplink = poe_set("0/28", False)
    run.assert_not_called()
    assert "protected port" in protected
    assert "PoE is only supported" in uplink


def test_port_set_admin_state_calls_builder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24")
    with patch(
        "netmiko_mcp_linksys.server.run_config_and_readback", return_value="done"
    ) as run:
        result = port_set_admin_state("0/2", False)
    assert result == "done"
    commands, readback = run.call_args.args
    assert commands == ["interface gigabitethernet 0/2", "shutdown"]
    assert "gigabitethernet 0/2" in readback


def test_description_rejects_special_chars() -> None:
    with patch("netmiko_mcp_linksys.server.run_config_and_readback") as run:
        result = port_set_description("0/1", "bad|text")
    run.assert_not_called()
    assert result.startswith("Rejected:")


def test_description_none_clears() -> None:
    with patch(
        "netmiko_mcp_linksys.server.run_config_and_readback", return_value="cleared"
    ) as run:
        result = port_set_description("0/1", None)
    assert result.startswith("cleared")
    assert "could not verify (port row not found)" in result
    commands, readback = run.call_args.args
    assert commands == ["interface gigabitethernet 0/1", "no description"]
    assert readback == "show interfaces description"


def test_save_config_tool() -> None:
    with patch("netmiko_mcp_linksys.server.run_save", return_value="saved"):
        assert save_config() == "saved"


def test_show_missing_command_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NETMIKO_MCP_COMMAND_FILE", raising=False)
    result = show("show system information")
    assert "NETMIKO_MCP_COMMAND_FILE" in result


def test_audit_log_written(audit_log, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24")
    port_set_admin_state("0/24", False)
    lines = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert lines[-1]["tool"] == "port_set_admin_state"
    assert lines[-1]["allowed"] is False
    assert lines[-1]["params"] == {"port": "0/24", "enabled": False}
    assert "dummy-password-not-real" not in audit_log.read_text(encoding="utf-8")
    assert (audit_log.stat().st_mode & 0o777) == 0o600


def test_tools_registered() -> None:
    from netmiko_mcp_linksys.server import mcp

    names = {tool.name for tool in mcp._tool_manager.list_tools()}
    assert names == {
        "show",
        "port_overview",
        "port_set_admin_state",
        "poe_set",
        "port_set_description",
        "save_config",
        "snmp_view_create",
        "snmp_write_view_create",
        "snmp_community_create",
        "snmp_community_remove",
        "snmp_user_remove",
    }


def test_disable_fails_closed_when_protected_ports_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SWITCH_PROTECTED_PORTS", raising=False)
    with patch("netmiko_mcp_linksys.server.run_config_and_readback") as run:
        admin = port_set_admin_state("0/1", False)
        poe = poe_set("0/1", False)
    run.assert_not_called()
    assert admin.startswith("Rejected:")
    assert "fail-closed" in admin
    assert poe.startswith("Rejected:")
    assert "fail-closed" in poe


def test_enable_allowed_when_protected_ports_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SWITCH_PROTECTED_PORTS", raising=False)
    with patch(
        "netmiko_mcp_linksys.server.run_config_and_readback", return_value="on"
    ) as run:
        result = port_set_admin_state("0/1", True)
    assert result == "on"
    run.assert_called_once()


def test_port_overview_is_read_only(reset_command_file: None, monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys.server import PORT_OVERVIEW_COMMANDS

    seen: list[list[str]] = []

    def fake_sequence(commands: list[str]) -> list[tuple[str, str | None, str | None]]:
        seen.append(list(commands))
        return [(command, f"OUT:{command}", None) for command in commands]

    with (
        patch("netmiko_mcp_linksys.server.run_show", create=True) as run_show,
        patch(
            "netmiko_mcp_linksys.server.run_show_sequence", side_effect=fake_sequence
        ) as run_seq,
        patch("netmiko_mcp_linksys.server.run_config_and_readback") as run_cfg,
        patch("netmiko_mcp_linksys.server.run_save") as run_save,
        patch("netmiko_mcp_linksys.server.run_config_set", create=True) as run_set,
    ):
        result = port_overview()
    assert seen == [list(PORT_OVERVIEW_COMMANDS)]
    run_seq.assert_called_once()
    run_show.assert_not_called()
    run_cfg.assert_not_called()
    run_save.assert_not_called()
    run_set.assert_not_called()
    for command in PORT_OVERVIEW_COMMANDS:
        assert command in result
        assert f"OUT:{command}" in result
    assert not result.startswith("Error:")


def test_port_overview_opens_one_session(
    reset_command_file: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for #5: one SSH session for all four show commands."""
    from netmiko_mcp_linksys.server import PORT_OVERVIEW_COMMANDS

    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    conn = MagicMock()
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn) as ch,
        patch(
            "netmiko_mcp_linksys.connection.send_paged",
            side_effect=lambda _conn, command: f"OUT:{command}",
        ) as paged,
    ):
        result = port_overview()
    ch.assert_called_once()
    conn.disconnect.assert_called_once()
    conn.send_config_set.assert_not_called()
    assert [c.args for c in paged.call_args_list] == [
        (conn, command) for command in PORT_OVERVIEW_COMMANDS
    ]
    sections = [f"=== {command} ===\nOUT:{command}" for command in PORT_OVERVIEW_COMMANDS]
    assert result == "\n\n".join(sections)


def test_port_overview_stops_after_failed_command(
    reset_command_file: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from netmiko_mcp_linksys.connection import SEQUENCE_SKIPPED
    from netmiko_mcp_linksys.connection import ConnectionError as SwitchConnectionError
    from netmiko_mcp_linksys.server import PORT_OVERVIEW_COMMANDS

    password = os.environ["SWITCH_PASSWORD"]
    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    conn = MagicMock()
    first, second, third, fourth = PORT_OVERVIEW_COMMANDS
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn) as ch,
        patch(
            "netmiko_mcp_linksys.connection.send_paged",
            side_effect=[
                "INFO",
                SwitchConnectionError(f"No prompt after {second!r} ({password})"),
            ],
        ) as paged,
    ):
        result = port_overview()
    ch.assert_called_once()
    assert paged.call_count == 2
    assert result.startswith(f"=== {first} ===\nINFO")
    assert "=== errors ===" in result
    assert f"{second}: No prompt after" in result
    assert f"{third}: {SEQUENCE_SKIPPED}" in result
    assert f"{fourth}: {SEQUENCE_SKIPPED}" in result
    assert password not in result


def test_port_overview_unexpected_error_is_redacted(
    reset_command_file: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from netmiko_mcp_linksys.server import PORT_OVERVIEW_COMMANDS

    password = os.environ["SWITCH_PASSWORD"]
    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    conn = MagicMock()
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn),
        patch(
            "netmiko_mcp_linksys.connection.send_paged",
            side_effect=OSError(f"socket closed {password}"),
        ) as paged,
    ):
        result = port_overview()
    paged.assert_called_once()
    assert result.startswith("Error: ")
    assert f"{PORT_OVERVIEW_COMMANDS[0]}: socket closed ***" in result
    assert password not in result


def test_port_overview_connect_failure_single_attempt(
    reset_command_file: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from netmiko_mcp_linksys.server import PORT_OVERVIEW_COMMANDS

    password = os.environ["SWITCH_PASSWORD"]
    with patch(
        "netmiko_mcp_linksys.connection.ConnectHandler",
        side_effect=RuntimeError(f"auth failed for {password}"),
    ) as ch:
        result = port_overview()
    ch.assert_called_once()
    assert result.startswith("Error: ")
    for command in PORT_OVERVIEW_COMMANDS:
        assert f"{command}: auth failed for ***" in result
    assert password not in result


def test_port_overview_requires_command_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NETMIKO_MCP_COMMAND_FILE", raising=False)
    with patch("netmiko_mcp_linksys.server.run_show_sequence") as run:
        result = port_overview()
    run.assert_not_called()
    assert "NETMIKO_MCP_COMMAND_FILE" in result


def test_audit_log_redacts_password_in_params_and_result(
    audit_log, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    password = os.environ["SWITCH_PASSWORD"]
    write_audit(
        tool="show",
        params={"command": f"leaked {password}"},
        allowed=False,
        result=f"auth failed for {password}",
    )
    body = audit_log.read_text(encoding="utf-8")
    assert password not in body
    assert "***" in body
    record = json.loads(body.splitlines()[-1])
    assert record["params"]["command"] == "leaked ***"
    assert record["result"] == "auth failed for ***"
    assert (audit_log.stat().st_mode & 0o777) == 0o600
