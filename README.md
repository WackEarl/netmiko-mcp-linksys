# netmiko-mcp-linksys

stdio MCP server for a single Linksys LGS-series switch (developed against the
LGS328PC CLI).

This project is based on [netmiko](https://github.com/ktbyers/netmiko) and
[netmiko-mcp](https://github.com/ktbyers/netmiko_mcp). The `show` tool reuses
netmiko-mcp's command filter (`netmiko_mcp.security.validate_command`) and the
same allow/deny list format (`commands.yml`). Configuration tools send only
fixed command sequences built by this wrapper; the model never supplies
free-form config.

**This is 0.1.0.** Validation and sequence building are covered by offline
tests. A live SSH test against a switch has not been run yet. See
[Untested assumptions](#untested-assumptions).

## Install and run

The intended way to run this server is the packaged entrypoint, pinned to a
tag:

```bash
uvx --from git+https://github.com/WackEarl/netmiko-mcp-linksys@v0.1.0 netmiko-mcp-linksys
```

From a local checkout:

```bash
uvx --from /path/to/netmiko-mcp-linksys netmiko-mcp-linksys
```

The process speaks MCP over stdio. It does **not** open an SSH session at
startup; a connection is made only when a tool is called.

`paramiko==4.0.0` is intentional. The target switch speaks `ssh-rsa` with
SHA-1; paramiko 5.x rejects that host-key algorithm.

A compatibility shim, `lgs_mcp.py`, exists only for the older hub invocation
`python /config/netmiko/lgs_mcp.py`. That file is not a standalone
implementation: it imports `netmiko_mcp_linksys`. Prefer the `uvx --from ...
netmiko-mcp-linksys` entry above. If you must keep the old command, add
`--with git+https://github.com/WackEarl/netmiko-mcp-linksys@v0.1.0` so the
package is installed in that environment.

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `SWITCH_HOST` | yes (at tool call) | Switch IP or hostname. |
| `SWITCH_USER` | yes (at tool call) | SSH username. |
| `SWITCH_PASSWORD` | yes (at tool call) | SSH password. Never logged or returned. |
| `SWITCH_DEVICE_TYPE` | no | netmiko device type. Default: `cisco_s300`. |
| `SWITCH_KNOWN_HOSTS` | yes (at tool call) | Path to an OpenSSH `known_hosts` file with the switch host key. System host keys are not used. |
| `SWITCH_PROTECTED_PORTS` | yes before any disable / PoE-off | Comma-separated ports (e.g. `0/24,0/25`) that may not be shut down or have PoE disabled. If this variable is unset, empty, or contains an invalid port, disable and PoE-off fail closed (every port is refused). Enabling a port is still allowed. |
| `NETMIKO_MCP_COMMAND_FILE` | yes for `show` and `port_overview` | Path to a `commands.yml` allow/deny list. See `examples/commands.yml`. Restart the server after edits (`lru_cache`). |
| `SWITCH_AUDIT_LOG` | no | If set, append one JSON line per tool call. The file is created with mode `0600`. Passwords are redacted from parameters and results. |

Python 3.12 or newer is required.

## mcp-hub entry snippet

Secrets stay in hub template variables. `save_config` is gated by the hub
`unlock` feature (0.12+); `maxMinutes: 0` means every call needs a fresh
approval. Fill `SWITCH_PROTECTED_PORTS` after the first read test — until it
is set to a valid list, disable and PoE-off are refused.

```json
{
  "switch": {
    "command": "uvx",
    "args": [
      "--python", "3.12",
      "--from", "git+https://github.com/WackEarl/netmiko-mcp-linksys@v0.1.0",
      "netmiko-mcp-linksys"
    ],
    "env": {
      "SWITCH_HOST": "192.0.2.10",
      "SWITCH_USER": "${SWITCH_USER}",
      "SWITCH_PASSWORD": "${SWITCH_PASSWORD}",
      "SWITCH_DEVICE_TYPE": "cisco_s300",
      "SWITCH_KNOWN_HOSTS": "/config/netmiko/known_hosts",
      "SWITCH_PROTECTED_PORTS": "<uplink and management ports, e.g. 0/24>",
      "NETMIKO_MCP_COMMAND_FILE": "/config/netmiko/commands.yml",
      "SWITCH_AUDIT_LOG": "/data/netmiko/audit.log",
      "UV_CACHE_DIR": "/data/uv-cache",
      "UV_PYTHON_INSTALL_DIR": "/data/uv-python",
      "UV_TOOL_DIR": "/data/uv-tools",
      "PATH": "/usr/local/bin:/usr/bin:/bin",
      "HOME": "/home/node"
    },
    "unlock": { "tools": ["save_config"], "maxMinutes": 0 }
  }
}
```

Copy `examples/commands.yml` to `NETMIKO_MCP_COMMAND_FILE`. Create
`SWITCH_KNOWN_HOSTS` yourself from a verified host key; do not use
`examples/known_hosts` as-is (it is a placeholder, not a real key).

## Tools

| Tool | Effect | Saved? |
| --- | --- | --- |
| `show(command)` | Allow-listed show command via `netmiko_mcp.security.validate_command`, then `send_command`. Pipe, semicolon, and newlines are rejected. Deny wins. | n/a |
| `port_overview()` | Read-only bundle of `show system information`, `show vlan`, `show power inline`, and `show interfaces`, each passed through the same command filter. | n/a |
| `port_set_admin_state(port, enabled)` | `interface gigabitethernet 0/N` then `no shutdown` / `shutdown`. | no |
| `poe_set(port, enabled)` | `interface gigabitethernet 0/N` then `power inline enable` / `power inline disable`. PoE ports: `0/1`–`0/24`. | no |
| `port_set_description(port, text?)` | `description <text>` or `no description` when `text` is omitted. | no |
| `save_config()` | Privileged exec `save` only. Gate this in the hub with `unlock`. | yes |

There are no VLAN, reboot, or reset tools.

Port format: `0/1` … `0/28` (no leading zeros). PoE: `0/1` … `0/24`.
Descriptions: 1–32 characters from `[A-Za-z0-9 ._-]`.

## Security model

- **Default deny** for `show`. Only commands listed in `allowed_commands` run;
  `denied_commands` always wins. The allow list does not expand abbreviations
  (`sh ver` is not `show version`). See the netmiko-mcp 0.3.0 validator docs.
  The wrapper also rejects `|`, `;`, and newlines before that filter runs
  (`allow_pipe` is not honoured).
- **No free-form config.** Interface commands are built only by this package.
- **No VLAN, reboot, or reset tools.**
- **Protected ports, fail-closed.** `SWITCH_PROTECTED_PORTS` blocks
  `port_set_admin_state(enabled=False)` and `poe_set(enabled=False)` on those
  ports. Enabling is still allowed. If the variable is unset, empty, or
  contains an invalid port identifier, every disable / PoE-off is refused.
- **Host-key pinning.** `ssh_strict=True`, `system_host_keys=False`,
  `use_keys=False`, `allow_agent=False`, key file from `SWITCH_KNOWN_HOSTS`.
- **No connection at startup.** Missing or dummy environment is enough for
  `initialize` and `tools/list`.
- **One session per tool call**, serialized with a process-wide lock.
- **No automatic save.** Running-config changes die on reboot until
  `save_config`. In the hub, `save_config` must be gated by `unlock`.
- **Audit log** records time, tool, parameters, allow/deny, and a short
  result. Passwords are redacted from parameters, results, and error text.
- **paramiko 4.0.0** for `ssh-rsa`/SHA-1 host keys. Do not bump to 5.x
  without a live SSH check.

## Untested assumptions

These need a live test on the real switch before relying on the config tools:

- netmiko `cisco_s300` prompt handling, paging, and `fast_cli=False` against
  this firmware.
- Whether the login user is already in privileged exec, or an enable secret
  is required (`SWITCH_ENABLE` is not implemented).
- `send_config_set(..., exit_config_mode=True, cmd_verify=True)` and the
  `configure terminal` / `end` dance the cisco_s300 driver uses.
- Read-back commands `show interfaces gigabitethernet 0/N` and
  `show power inline gigabitethernet 0/N` (syntax and useful fields).
- Device error text actually contains `%`, `Invalid`, or `Error` (the
  rejection heuristic).
- `save` as a single privileged exec command, and its output.
- 28 ports and PoE on `0/1`–`0/24` (true for LGS328PC; other LGS models differ).
- paramiko 4.0.0 still negotiates `ssh-rsa`/SHA-1 with this switch.
- Timing, SSH banners, and the first-login prompt.
- Hub `unlock` behaviour for `save_config`.

## Development

```bash
uv sync --extra dev
uv run --extra dev pytest
```

Pinned runtime dependencies: `netmiko==4.8.0`, `paramiko==4.0.0`,
`netmiko-mcp==0.3.0`, `mcp==2.3.0`.
