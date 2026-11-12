"""stdio MCP server entrypoint. Connections are opened only when a tool runs."""

from __future__ import annotations

import os
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from netmiko_mcp.security import (
    build_abbreviation_filter,
    load_commands,
    validate_command,
)

from netmiko_mcp_linksys.audit import write_audit
from netmiko_mcp_linksys.connection import (
    READBACK_INTERFACE,
    READBACK_POE,
    ConnectionError as SwitchConnectionError,
    build_admin_state_commands,
    build_description_commands,
    build_poe_commands,
    run_config_and_readback,
    run_save,
    run_show,
)
from netmiko_mcp_linksys.validation import (
    ValidationError,
    redact_secrets,
    reject_if_protected,
    reject_unsafe_show_command,
    validate_description,
    validate_port,
)

try:
    _PKG_VERSION = version("netmiko-mcp-linksys")
except PackageNotFoundError:  # pragma: no cover
    from netmiko_mcp_linksys import __version__ as _PKG_VERSION

mcp = MCPServer(
    name="netmiko-mcp-linksys",
    instructions=(
        "MCP server for a single Linksys LGS-series switch, based on "
        "netmiko and netmiko-mcp. Use show for allow-listed read commands. "
        "Configuration tools build fixed CLI sequences; they do not accept "
        "free-form config. There are no VLAN, reboot, or reset tools. "
        "Changes are not saved until save_config is called."
    ),
    version=_PKG_VERSION,
)

PORT_OVERVIEW_COMMANDS = (
    "show system information",
    "show vlan",
    "show power inline",
    "show interfaces",
)


def prepare_runtime() -> None:
    """Point netmiko-mcp's command-file singleton at NETMIKO_MCP_COMMAND_FILE."""
    command_file = (os.environ.get("NETMIKO_MCP_COMMAND_FILE") or "").strip()
    if not command_file:
        return
    from netmiko_mcp.config import settings

    settings.command_file = str(Path(command_file).expanduser())
    load_commands.cache_clear()
    build_abbreviation_filter.cache_clear()


def _fail(tool: str, params: dict[str, Any], message: str, *, allowed: bool) -> str:
    text = redact_secrets(message)
    write_audit(tool=tool, params=params, allowed=allowed, result=text)
    return text


def _ok(tool: str, params: dict[str, Any], result: str) -> str:
    write_audit(tool=tool, params=params, allowed=True, result="ok")
    return result


@mcp.tool()
def show(command: str) -> str:
    """Run an allow-listed show command on the switch (no TextFSM parsing)."""
    params = {"command": command}
    command_file = (os.environ.get("NETMIKO_MCP_COMMAND_FILE") or "").strip()
    if not command_file or not Path(command_file).expanduser().is_file():
        return _fail(
            "show",
            params,
            "Error: NETMIKO_MCP_COMMAND_FILE is not set or the file does not exist.",
            allowed=False,
        )
    prepare_runtime()
    try:
        reject_unsafe_show_command(command)
    except ValidationError as exc:
        return _fail("show", params, str(exc), allowed=False)
    verdict = validate_command(command)
    if not verdict.allowed:
        return _fail(
            "show",
            params,
            f"Command rejected: {verdict.reason}",
            allowed=False,
        )
    try:
        output = run_show(verdict.normalized_command)
    except (ValidationError, SwitchConnectionError) as exc:
        return _fail("show", params, f"Error: {exc}", allowed=True)
    return _ok("show", params, output)


@mcp.tool()
def port_overview() -> str:
    """Read a bundle of allow-listed status commands in one session each.

    Read-only: runs only the hardcoded show commands through the same
    netmiko-mcp command filter as the show tool. Never sends config.
    """
    params: dict[str, Any] = {}
    command_file = (os.environ.get("NETMIKO_MCP_COMMAND_FILE") or "").strip()
    if not command_file or not Path(command_file).expanduser().is_file():
        return _fail(
            "port_overview",
            params,
            "Error: NETMIKO_MCP_COMMAND_FILE is not set or the file does not exist.",
            allowed=False,
        )
    prepare_runtime()
    sections: list[str] = []
    errors: list[str] = []
    for command in PORT_OVERVIEW_COMMANDS:
        verdict = validate_command(command)
        if not verdict.allowed:
            errors.append(f"{command}: Command rejected: {verdict.reason}")
            continue
        try:
            output = run_show(verdict.normalized_command)
        except (ValidationError, SwitchConnectionError) as exc:
            errors.append(f"{command}: {redact_secrets(str(exc))}")
            continue
        sections.append(f"=== {command} ===\n{output}")
    if errors and not sections:
        return _fail(
            "port_overview",
            params,
            "Error: " + " | ".join(errors),
            allowed=True,
        )
    body = "\n\n".join(sections)
    if errors:
        body += "\n\n=== errors ===\n" + "\n".join(errors)
    return _ok("port_overview", params, body)


@mcp.tool()
def port_set_admin_state(port: str, enabled: bool) -> str:
    """Enable or disable a switch port (no shutdown / shutdown). Does not save."""
    params = {"port": port, "enabled": enabled}
    try:
        validate_port(port)
        reject_if_protected(
            port,
            disabling=not enabled,
            action="port_set_admin_state(enabled=False)",
        )
        commands = build_admin_state_commands(port, enabled)
        output = run_config_and_readback(commands, READBACK_INTERFACE.format(port=port))
    except ValidationError as exc:
        return _fail("port_set_admin_state", params, f"Rejected: {exc}", allowed=False)
    except SwitchConnectionError as exc:
        return _fail("port_set_admin_state", params, f"Error: {exc}", allowed=True)
    return _ok("port_set_admin_state", params, output)


@mcp.tool()
def poe_set(port: str, enabled: bool) -> str:
    """Enable or disable PoE on a copper port (0/1..0/24). Does not save."""
    params = {"port": port, "enabled": enabled}
    try:
        validate_port(port, poe=True)
        reject_if_protected(port, disabling=not enabled, action="poe_set(enabled=False)")
        commands = build_poe_commands(port, enabled)
        output = run_config_and_readback(commands, READBACK_POE.format(port=port))
    except ValidationError as exc:
        return _fail("poe_set", params, f"Rejected: {exc}", allowed=False)
    except SwitchConnectionError as exc:
        return _fail("poe_set", params, f"Error: {exc}", allowed=True)
    return _ok("poe_set", params, output)


@mcp.tool()
def port_set_description(port: str, text: str | None = None) -> str:
    """Set an interface description, or clear it when text is omitted. Does not save."""
    params = {"port": port, "text": text}
    try:
        validate_port(port)
        if text is not None:
            validate_description(text)
        commands = build_description_commands(port, text)
        output = run_config_and_readback(commands, READBACK_INTERFACE.format(port=port))
    except ValidationError as exc:
        return _fail("port_set_description", params, f"Rejected: {exc}", allowed=False)
    except SwitchConnectionError as exc:
        return _fail("port_set_description", params, f"Error: {exc}", allowed=True)
    return _ok("port_set_description", params, output)


@mcp.tool()
def save_config() -> str:
    """Copy running-config to startup-config by sending the privileged exec command 'save'."""
    params: dict[str, Any] = {}
    try:
        output = run_save()
    except (ValidationError, SwitchConnectionError) as exc:
        return _fail("save_config", params, f"Error: {exc}", allowed=True)
    return _ok("save_config", params, output)


def main() -> None:
    """Start the stdio MCP server. Does not open an SSH session."""
    prepare_runtime()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
