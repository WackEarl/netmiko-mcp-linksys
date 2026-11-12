from __future__ import annotations

import json
from unittest.mock import patch

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
    assert result == "cleared"
    commands, _ = run.call_args.args
    assert commands == ["interface gigabitethernet 0/1", "no description"]


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

    seen: list[str] = []

    def fake_show(command: str) -> str:
        seen.append(command)
        return f"OUT:{command}"

    with (
        patch("netmiko_mcp_linksys.server.run_show", side_effect=fake_show) as run_show,
        patch("netmiko_mcp_linksys.server.run_config_and_readback") as run_cfg,
        patch("netmiko_mcp_linksys.server.run_save") as run_save,
        patch("netmiko_mcp_linksys.server.run_config_set", create=True) as run_set,
    ):
        result = port_overview()
    assert seen == list(PORT_OVERVIEW_COMMANDS)
    run_show.assert_called()
    run_cfg.assert_not_called()
    run_save.assert_not_called()
    run_set.assert_not_called()
    for command in PORT_OVERVIEW_COMMANDS:
        assert command in result
        assert f"OUT:{command}" in result
    assert not result.startswith("Error:")


def test_port_overview_requires_command_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NETMIKO_MCP_COMMAND_FILE", raising=False)
    with patch("netmiko_mcp_linksys.server.run_show") as run:
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
