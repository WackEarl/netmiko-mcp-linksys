from __future__ import annotations

import pytest

from netmiko_mcp_linksys.server import prepare_runtime, show
from netmiko_mcp_linksys.validation import (
    ValidationError,
    parse_protected_ports,
    reject_if_protected,
    reject_unsafe_show_command,
    validate_description,
    validate_port,
)


@pytest.mark.parametrize(
    "port",
    ["0/1", "0/9", "0/10", "0/24", "0/28"],
)
def test_valid_ports(port: str) -> None:
    assert validate_port(port) == port


@pytest.mark.parametrize(
    "port",
    ["0/0", "0/29", "0/01", "1/1", "gi0/1", "0/24.5", "0/", "", "0/1 ", " 0/1"],
)
def test_invalid_ports(port: str) -> None:
    with pytest.raises(ValidationError, match="Invalid port"):
        validate_port(port)


@pytest.mark.parametrize("port", ["0/1", "0/24"])
def test_valid_poe_ports(port: str) -> None:
    assert validate_port(port, poe=True) == port


@pytest.mark.parametrize("port", ["0/25", "0/26", "0/27", "0/28"])
def test_poe_rejected_on_uplink_range(port: str) -> None:
    with pytest.raises(ValidationError, match="PoE is only supported"):
        validate_port(port, poe=True)


def test_protected_ports_block_disable_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24, 0/25")
    assert parse_protected_ports() == {"0/24", "0/25"}
    reject_if_protected("0/24", disabling=False, action="poe_set(enabled=False)")
    with pytest.raises(ValidationError, match="protected port 0/24"):
        reject_if_protected("0/24", disabling=True, action="poe_set(enabled=False)")
    reject_if_protected("0/1", disabling=True, action="poe_set(enabled=False)")


@pytest.mark.parametrize("text", ["Uplink", "nas 1", "port_A-01", "x" * 32])
def test_valid_descriptions(text: str) -> None:
    assert validate_description(text) == text


@pytest.mark.parametrize(
    "text",
    ["", "x" * 33, 'bad"quote', "bad'quote", "why?", "pipe|me", "line\nbreak", "ümlaut"],
)
def test_invalid_descriptions(text: str) -> None:
    with pytest.raises(ValidationError, match="Invalid description"):
        validate_description(text)


@pytest.mark.parametrize(
    "command",
    [
        "show version",
        "show system information",
        "show vlan",
        "show power inline gigabitethernet 0/1",
        "show interfaces",
        "show interfaces gigabitethernet 0/1",
    ],
)
def test_show_allow_list(command: str, reset_command_file: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("netmiko_mcp_linksys.server.run_show", lambda cmd: f"OK:{cmd}")
    result = show(command)
    assert result.startswith("OK:")


@pytest.mark.parametrize(
    "command",
    [
        "show running-config",
        "show startup-config",
        "show snmp",
        "show interface cable-diag",
        "configure terminal",
        "save",
        "write memory",
        "reload",
        "interface gigabitethernet 0/1",
        "shutdown",
        "sh ver",
        "show not-a-real-command",
    ],
)
def test_show_deny_or_no_allow(command: str, reset_command_file: None) -> None:
    result = show(command)
    assert result.startswith("Command rejected:")


def test_protected_ports_fail_closed_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SWITCH_PROTECTED_PORTS", raising=False)
    with pytest.raises(ValidationError, match="not set"):
        parse_protected_ports()
    with pytest.raises(ValidationError, match="fail-closed"):
        reject_if_protected("0/1", disabling=True, action="port_set_admin_state(enabled=False)")
    # Enabling is still allowed when the list is unset.
    reject_if_protected("0/1", disabling=False, action="port_set_admin_state(enabled=False)")


def test_protected_ports_fail_closed_when_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "  ,  ")
    with pytest.raises(ValidationError, match="empty"):
        parse_protected_ports()
    with pytest.raises(ValidationError, match="fail-closed"):
        reject_if_protected("0/2", disabling=True, action="poe_set(enabled=False)")


def test_protected_ports_fail_closed_on_invalid_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24,gi0/25")
    with pytest.raises(ValidationError, match="invalid port"):
        parse_protected_ports()
    with pytest.raises(ValidationError, match="fail-closed"):
        reject_if_protected("0/1", disabling=True, action="poe_set(enabled=False)")


@pytest.mark.parametrize(
    "command",
    [
        "show version | include Software",
        "show version; shutdown",
        "show version\nreload",
        "show version\rshutdown",
    ],
)
def test_show_rejects_pipe_semicolon_newlines(
    command: str, reset_command_file: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import MagicMock

    run = MagicMock(return_value="SHOULD_NOT_RUN")
    monkeypatch.setattr("netmiko_mcp_linksys.server.run_show", run)
    result = show(command)
    assert result.startswith("Command rejected:")
    run.assert_not_called()


def test_reject_unsafe_show_command_direct() -> None:
    with pytest.raises(ValidationError, match=r"'\|', ';', and newlines"):
        reject_unsafe_show_command("show version | include x")
    with pytest.raises(ValidationError, match="not allowed"):
        reject_unsafe_show_command("show version; shutdown")
    with pytest.raises(ValidationError, match="not allowed"):
        reject_unsafe_show_command("show version\nreload")
    assert reject_unsafe_show_command("show version") == "show version"
