from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from netmiko_mcp_linksys.connection import (
    READBACK_INTERFACE,
    READBACK_POE,
    build_admin_state_commands,
    build_description_commands,
    build_poe_commands,
    connect_params,
    run_config_and_readback,
    run_save,
    run_show,
)
from netmiko_mcp_linksys.validation import ValidationError


def test_admin_state_sequences() -> None:
    assert build_admin_state_commands("0/3", True) == [
        "interface gigabitethernet 0/3",
        "no shutdown",
    ]
    assert build_admin_state_commands("0/3", False) == [
        "interface gigabitethernet 0/3",
        "shutdown",
    ]


def test_poe_sequences() -> None:
    assert build_poe_commands("0/5", True) == [
        "interface gigabitethernet 0/5",
        "power inline enable",
    ]
    assert build_poe_commands("0/5", False) == [
        "interface gigabitethernet 0/5",
        "power inline disable",
    ]


def test_description_sequences() -> None:
    assert build_description_commands("0/2", "nas uplink") == [
        "interface gigabitethernet 0/2",
        'description "nas uplink"',
    ]
    assert build_description_commands("0/2", None) == [
        "interface gigabitethernet 0/2",
        "no description",
    ]


def test_connect_params_from_env() -> None:
    params = connect_params()
    assert params["device_type"] == "cisco_s300"
    assert params["host"] == "192.0.2.10"
    assert params["username"] == "dummy-user"
    assert params["password"] == "dummy-password-not-real"
    assert params["use_keys"] is False
    assert params["allow_agent"] is False
    assert params["ssh_strict"] is True
    assert params["system_host_keys"] is False
    assert params["alt_host_keys"] is True
    assert params["alt_key_file"].endswith("examples/known_hosts")
    assert params["conn_timeout"] == 15
    assert params["auth_timeout"] == 20
    assert params["fast_cli"] is False
    assert params["read_timeout_override"] == 60.0
    assert "session_log" not in params


def test_connect_params_missing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SWITCH_HOST", raising=False)
    with pytest.raises(ValidationError, match="SWITCH_HOST"):
        connect_params()


def test_run_show_uses_pager_loop() -> None:
    conn = MagicMock()
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn) as ch,
        patch("netmiko_mcp_linksys.connection.send_paged", return_value="INFO") as paged,
    ):
        assert run_show("show system information") == "INFO"
    ch.assert_called_once()
    paged.assert_called_once_with(conn, "show system information")
    conn.send_command.assert_not_called()
    conn.disconnect.assert_called_once()


def test_run_config_and_readback() -> None:
    conn = MagicMock()
    conn.send_config_set.return_value = "ok"
    commands = build_admin_state_commands("0/1", False)
    readback = READBACK_INTERFACE.format(port="0/1")
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn),
        patch("netmiko_mcp_linksys.connection.send_paged", return_value="STATE") as paged,
    ):
        result = run_config_and_readback(commands, readback)
    # call 0: best-effort paging-off, call 1: the interface sequence
    assert conn.send_config_set.call_args_list[0].args[0] == ["set cli pagination off"]
    assert conn.send_config_set.call_args_list[1].args[0] == commands
    assert conn.send_config_set.call_args_list[1].kwargs["cmd_verify"] is True
    assert conn.send_config_set.call_args_list[1].kwargs["exit_config_mode"] is True
    paged.assert_called_once_with(conn, readback)
    conn.disconnect.assert_called_once()
    assert "STATE" in result
    assert readback in result


def test_run_config_rejects_device_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    conn = MagicMock()
    conn.send_config_set.return_value = "% Invalid input detected"
    with patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn):
        from netmiko_mcp_linksys.connection import (
            ConnectionError as SwitchConnectionError,
        )

        with pytest.raises(SwitchConnectionError, match="rejected"):
            run_config_and_readback(build_poe_commands("0/1", True), READBACK_POE.format(port="0/1"))
    conn.write_channel.assert_not_called()


def test_run_save_sends_only_save(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    conn = MagicMock()
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn),
        patch("netmiko_mcp_linksys.connection.send_paged", return_value="success") as paged,
    ):
        assert run_save() == "success"
    paged.assert_called_once_with(conn, "save")
    conn.send_config_set.assert_not_called()


def test_password_redacted_from_connection_error() -> None:
    from netmiko_mcp_linksys.connection import ConnectionError as SwitchConnectionError

    with patch(
        "netmiko_mcp_linksys.connection.ConnectHandler",
        side_effect=RuntimeError("auth failed for dummy-password-not-real"),
    ):
        with pytest.raises(SwitchConnectionError, match=r"\*\*\*") as excinfo:
            run_show("show system information")
    assert "dummy-password-not-real" not in str(excinfo.value)
