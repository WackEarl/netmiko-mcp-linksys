# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-12

### Added

- Initial stdio MCP wrapper `netmiko-mcp-linksys` for Linksys LGS-series
  switches, based on netmiko 4.8.0 and netmiko-mcp 0.3.0 (command filter reused),
  with paramiko 4.0.0 and mcp 2.3.0.
- Tools: `show`, `port_overview` (read-only), `port_set_admin_state`,
  `poe_set`, `port_set_description`, and `save_config`. No VLAN, reboot, or
  reset tools.
- Hard parameter validation for ports (`0/1`–`0/28`), PoE range (`0/1`–`0/24`),
  interface descriptions (`^[A-Za-z0-9 ._-]{1,32}$`), and protected ports,
  applied before any SSH connection is opened.
- Protected ports fail closed: if `SWITCH_PROTECTED_PORTS` is unset, empty, or
  invalid, disable and PoE-off are refused on every port.
- Command whitelist/deny list for `show` via `netmiko_mcp.security.validate_command`
  and `NETMIKO_MCP_COMMAND_FILE`. The wrapper also rejects `|`, `;`, and
  newlines (deny wins).
- JSON-lines audit log (`SWITCH_AUDIT_LOG`) with mode 0600; passwords are
  redacted from parameters and results.
- One SSH session per tool call, serialized by a process-wide lock. No
  connection at process start. No automatic save.
- Host-key pinning through `SWITCH_KNOWN_HOSTS` (`ssh_strict=True`,
  `use_keys=False`, `allow_agent=False`, system host keys disabled).
