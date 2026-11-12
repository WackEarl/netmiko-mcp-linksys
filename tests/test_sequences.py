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
        "description nas uplink",
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


def test_connect_params_missing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SWITCH_HOST", raising=False)
    with pytest.raises(ValidationError, match="SWITCH_HOST"):
        connect_params()


def test_run_show_uses_send_command_without_textfsm() -> None:
    conn = MagicMock()
    conn.send_command.return_value = "VERSION"
    with patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn) as ch:
        assert run_show("show version") == "VERSION"
    ch.assert_called_once()
    conn.send_command.assert_called_once_with("show version", use_textfsm=False)
    conn.disconnect.assert_called_once()


def test_run_config_and_readback() -> None:
    conn = MagicMock()
    conn.send_config_set.return_value = "ok"
    conn.send_command.return_value = "STATE"
    commands = build_admin_state_commands("0/1", False)
    readback = READBACK_INTERFACE.format(port="0/1")
    with patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn):
        result = run_config_and_readback(commands, readback)
    conn.send_config_set.assert_called_once_with(
        commands, exit_config_mode=True, cmd_verify=True
    )
    conn.send_command.assert_called_once_with(readback, use_textfsm=False)
    conn.disconnect.assert_called_once()
    assert "STATE" in result
    assert readback in result


def test_run_config_rejects_device_error() -> None:
    conn = MagicMock()
    conn.send_config_set.return_value = "% Invalid input detected"
    with patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn):
        from netmiko_mcp_linksys.connection import ConnectionError as SwitchConnectionError

        with pytest.raises(SwitchConnectionError, match="rejected"):
            run_config_and_readback(build_poe_commands("0/1", True), READBACK_POE.format(port="0/1"))
    conn.send_command.assert_not_called()


def test_run_save_sends_only_save() -> None:
    conn = MagicMock()
    conn.send_command.return_value = "success"
    with patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn):
        assert run_save() == "success"
    conn.send_command.assert_called_once_with("save", use_textfsm=False)
    conn.send_config_set.assert_not_called()


def test_password_redacted_from_connection_error() -> None:
    from netmiko_mcp_linksys.connection import ConnectionError as SwitchConnectionError

    with patch(
        "netmiko_mcp_linksys.connection.ConnectHandler",
        side_effect=RuntimeError("auth failed for dummy-password-not-real"),
    ):
        with pytest.raises(SwitchConnectionError, match=r"\*\*\*") as excinfo:
            run_show("show version")
    assert "dummy-password-not-real" not in str(excinfo.value)
