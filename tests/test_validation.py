from __future__ import annotations

import pytest

from netmiko_mcp_linksys.server import show
from netmiko_mcp_linksys.validation import (
    ValidationError,
    config_output_is_error,
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


@pytest.mark.parametrize("text", ["Uplink", "nas 1", "port_A-01", "Error LED", "Invalid Port", "x" * 32])
def test_valid_descriptions(text: str) -> None:
    assert validate_description(text) == text


@pytest.mark.parametrize(
    "text",
    ["", "x" * 33, 'bad"quote', "bad'quote", "why?", "pipe|me", "line\nbreak", "ümlaut", "%", "100%", "pre%post"],
)
def test_invalid_descriptions(text: str) -> None:
    with pytest.raises(ValidationError, match="Invalid description"):
        validate_description(text)


@pytest.mark.parametrize(
    "command",
    [
        "show system information",
        "show clock",
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
        "show system information | include Software",
        "show system information; shutdown",
        "show system information\nreload",
        "show system information\rshutdown",
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
        reject_unsafe_show_command("show system information | include x")
    with pytest.raises(ValidationError, match="not allowed"):
        reject_unsafe_show_command("show system information; shutdown")
    with pytest.raises(ValidationError, match="not allowed"):
        reject_unsafe_show_command("show system information\nreload")
    assert reject_unsafe_show_command("show system information") == "show system information"


def _description_commands(description: str) -> list[str]:
    return [
        "interface gigabitethernet 0/7",
        f'description "{description}"',
    ]


def _config_echo(description: str) -> str:
    return (
        "configure terminal\r\n"
        "LGS328PC(config)# interface gigabitethernet 0/7\r\n"
        f'LGS328PC(config-if)# description "{description}"\r\n'
        "LGS328PC(config-if)# end\r\n"
        "LGS328PC#"
    )


@pytest.mark.parametrize("description", ["Error LED", "Invalid Port"])
def test_config_output_ignores_error_words_in_echoed_description(description: str) -> None:
    commands = _description_commands(description)
    assert config_output_is_error(_config_echo(description), commands) is False
    # Echoed command, with and without a leading prompt prefix.
    assert config_output_is_error(f'description "{description}"', commands) is False
    assert (
        config_output_is_error(
            f'LGS328PC(config-if)# description "{description}"',
            commands,
        )
        is False
    )


def test_config_output_detects_iss_percent_error() -> None:
    raw = (
        "interface gigabitethernet 0/7\r\n"
        'description "foo bar"\r\n'
        "                 ^\r\n"
        "% Invalid input detected at '^' marker.\r\n"
        "LGS328PC(config-if)#"
    )
    assert config_output_is_error(raw) is True
    assert config_output_is_error("% Invalid input detected") is True
    assert config_output_is_error("  % Invalid input detected at '^' marker.  ") is True


def test_config_output_percent_on_same_line_as_prompt() -> None:
    assert config_output_is_error("LGS328PC(config-if)#% Invalid input") is True
    assert config_output_is_error("LGS328PC(config-if)# % Invalid input detected") is True


def test_config_output_percent_error_still_wins_with_error_description() -> None:
    mixed = (
        _config_echo("Error LED")
        + "\r\n% Invalid input detected at '^' marker.\r\n"
        + "LGS328PC#"
    )
    assert config_output_is_error(mixed, _description_commands("Error LED")) is True


def test_config_output_flags_bare_error_or_invalid_words() -> None:
    assert config_output_is_error("Error: port is protected") is True
    assert config_output_is_error("Error") is True
    assert config_output_is_error("Invalid input") is True
    assert config_output_is_error("LGS328PC# Error: port is protected") is True
    assert config_output_is_error("") is False
    assert config_output_is_error("LGS328PC#") is False
    assert config_output_is_error("LGS328PC(config-if)#") is False


def test_config_output_detects_ansi_prefixed_percent_error() -> None:
    assert config_output_is_error("\x1b[31m% Invalid input detected at '^' marker.") is True
    assert config_output_is_error("\x1b[31m% Invalid input detected\x1b[0m") is True
    # Terminated OSC (BEL) is stripped; the following '%' error still counts.
    assert config_output_is_error("\x1b]0;title\x07% Invalid input detected") is True


def test_validate_description_rejects_percent() -> None:
    for text in ("%", "100%", "pre%post", "%LED"):
        with pytest.raises(ValidationError, match="Invalid description"):
            validate_description(text)
