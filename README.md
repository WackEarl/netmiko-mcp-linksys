# netmiko-mcp-linksys

stdio MCP server for a single Linksys LGS-series switch (developed against the
LGS328PC CLI).

This project is based on [netmiko](https://github.com/ktbyers/netmiko) and
[netmiko-mcp](https://github.com/ktbyers/netmiko_mcp). The `show` tool reuses
netmiko-mcp's command filter (`netmiko_mcp.security.validate_command`) and the
same allow/deny list format (`commands.yml`). Configuration tools send only
fixed command sequences built by this wrapper; the model never supplies
free-form config.

**This is 0.1.3.** It includes the fixes from the live tests on an
LGS328PC with firmware 1.01.02.02 (SSH with `ssh-rsa` via paramiko 4.0.0;
login lands directly in privilege 15 with prompt `LGS328PC#`; no banner or
second login prompt). See [Live-test status](#live-test-status).

## Install and run

The intended way to run this server is the packaged entrypoint, pinned to a
tag:

```bash
uvx --from git+https://github.com/WackEarl/netmiko-mcp-linksys@v0.1.3 netmiko-mcp-linksys
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
`--with git+https://github.com/WackEarl/netmiko-mcp-linksys@v0.1.3` so the
package is installed in that environment.

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `SWITCH_HOST` | yes (at tool call) | Switch IP or hostname. |
| `SWITCH_USER` | yes (at tool call) | SSH username. |
| `SWITCH_PASSWORD` | yes (at tool call) | SSH password. Never logged or returned. |
| `SWITCH_SNMP_COMMUNITY` | yes before `snmp_community_create` / `snmp_community_remove` | SNMPv2c community string for the new, non-default community. Never a tool argument, never logged or returned (shown as `[REDACTED]`). Must not be `public` or `private`; 8–64 characters from `[A-Za-z0-9._-]`. |
| `SWITCH_DEVICE_TYPE` | no | netmiko device type. Default: `cisco_s300`. |
| `SWITCH_KNOWN_HOSTS` | yes (at tool call) | Path to an OpenSSH `known_hosts` file with the switch host key. System host keys are not used. |
| `SWITCH_PROTECTED_PORTS` | yes before any disable / PoE-off | Comma-separated ports (e.g. `0/24,0/25`) that may not be shut down or have PoE disabled. If this variable is unset, empty, or contains an invalid port, disable and PoE-off fail closed (every port is refused). Enabling a port is still allowed. |
| `NETMIKO_MCP_COMMAND_FILE` | yes for `show` and `port_overview` | Path to a `commands.yml` allow/deny list. See `examples/commands.yml`. Restart the server after edits (`lru_cache`). |
| `SWITCH_AUDIT_LOG` | no (recommended) | If set, append one JSON line per tool call. The file is created with mode `0600`. Passwords are redacted from parameters and results. There is no default path; unset means no audit (warned at startup). An unwritable path does not break tools: a warning goes to stderr and the result gets an `audit_warning:` line. |
| `SWITCH_READ_TIMEOUT` | no | Seconds without new output before a command is given up. Also passed to netmiko as `read_timeout_override`. Default `60`, range `1`–`600`. |
| `SWITCH_PAGING_OFF` | no | `1` (default) sends `configure terminal` / `set cli pagination off` / `end` at session start, best effort. `0` skips it; the pager loop handles paging either way. |
| `SWITCH_SESSION_LOG` | no | Debug only. If set, netmiko appends a session log there (mode `0600`). netmiko masks the password (`no_log`) and only channel reads are recorded. The log does contain full show output (MAC/ARP tables, descriptions); unset it after debugging. An unwritable path disables the log with a warning. |

Python 3.12 or newer is required.

## mcp-hub entry snippet

Secrets stay in hub template variables. Write tools that can persist or
widen device access (`save_config` and the SNMP tools) are gated by the
hub `unlock` feature (0.12+); `maxMinutes: 0` means every call needs a
fresh approval. Fill `SWITCH_PROTECTED_PORTS` after the first read test —
until it is set to a valid list, disable and PoE-off are refused.

```json
{
  "switch": {
    "command": "uvx",
    "args": [
      "--python", "3.12",
      "--from", "git+https://github.com/WackEarl/netmiko-mcp-linksys@v0.1.3",
      "netmiko-mcp-linksys"
    ],
    "env": {
      "SWITCH_HOST": "192.0.2.10",
      "SWITCH_USER": "${SWITCH_USER}",
      "SWITCH_PASSWORD": "${SWITCH_PASSWORD}",
      "SWITCH_SNMP_COMMUNITY": "${SWITCH_SNMP_COMMUNITY}",
      "SWITCH_DEVICE_TYPE": "cisco_s300",
      "SWITCH_KNOWN_HOSTS": "/config/netmiko/known_hosts",
      "SWITCH_PROTECTED_PORTS": "<uplink and management ports, e.g. 0/24>",
      "NETMIKO_MCP_COMMAND_FILE": "/config/netmiko/commands.yml",
      "SWITCH_AUDIT_LOG": "/data/netmiko/switch-audit.log",
      "SWITCH_READ_TIMEOUT": "60",
      "UV_CACHE_DIR": "/data/uv-cache",
      "UV_PYTHON_INSTALL_DIR": "/data/uv-python",
      "UV_TOOL_DIR": "/data/uv-tools",
      "PATH": "/usr/local/bin:/usr/bin:/bin",
      "HOME": "/home/node"
    },
    "unlock": {
      "tools": [
        "save_config",
        "snmp_view_create",
        "snmp_community_create",
        "snmp_community_remove",
        "snmp_user_remove"
      ],
      "maxMinutes": 0
    }
  }
}
```

Paths under `/config` are read-only inside the hub container; put the audit
log (and an optional `SWITCH_SESSION_LOG`) under `/data`.

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
| `port_set_description(port, text?)` | `description "<text>"` (always quoted, the LGS CLI takes only one word unquoted) or `no description` when `text` is omitted. The result ends with an informational read-back of `show interfaces description` for that port (verified, quoted, empty, probably truncated, or could not verify). | no |
| `save_config()` | Privileged exec `save` only. Gate this in the hub with `unlock`. | yes |
| `snmp_view_create(view_name, subtree)` | Add one **included** subtree from a fixed OID allowlist to a view. Gate with hub `unlock`. **Not live-confirmed.** | no |
| `snmp_community_create(view_name, access)` | Create a v2c community from `SWITCH_SNMP_COMMUNITY` (`ro` or `rw`) bound to an existing restricted view. The secret is never a tool argument. Gate with hub `unlock`. **Not live-confirmed.** | no |
| `snmp_community_remove(name)` | Remove `public` or `private` only, and only after the configured community is verified present with a restricted view. Never removes the configured community. Gate with hub `unlock`. **Not live-confirmed.** | no |
| `snmp_user_remove(name)` | Remove `noAuthUser` only. Gate with hub `unlock`. **Not live-confirmed.** | no |

There are no VLAN, reboot, or reset tools.

Port format: `0/1` … `0/28` (no leading zeros). PoE: `0/1` … `0/24`.
Descriptions: 1–32 characters from `[A-Za-z0-9 ._-]`, with no leading or
trailing spaces. Quotes are not allowed in the input, so the wrapper's
own quoting cannot be broken out of.

## Security model

- **Default deny** for `show`. Only commands listed in `allowed_commands` run;
  `denied_commands` always wins. The allow list does not expand abbreviations
  (`sh sys info` is not `show system information`). See the netmiko-mcp 0.3.0 validator docs.
  The wrapper also rejects `|`, `;`, and newlines before that filter runs
  (`allow_pipe` is not honoured).
- **No free-form config.** Interface commands are built only by this package.
  The only other config sequence is the fixed best-effort
  `set cli pagination off` at session start (see [Paging](#paging)).
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
  `save_config`. In the hub, `save_config` and the SNMP write tools
  must be gated by `unlock`.
- **Audit log** records time, tool, parameters, allow/deny, and a short
  result. Passwords are redacted from parameters, results, and error text
  (`***`). The SNMP community (`SWITCH_SNMP_COMMUNITY`) is redacted as
  `[REDACTED]`, including `show snmp community` listings.
  Audit failures never abort a tool; they are reported on stderr and as an
  `audit_warning:` line in the result.
- **paramiko 4.0.0** for `ssh-rsa`/SHA-1 host keys. Do not bump to 5.x
  without a live SSH check.

## Paging

The LGS CLI (ISS-based firmware) pages long output. netmiko's `cisco_s300`
driver sends `terminal datadump`, which this firmware does not honour, and
`set cli pagination off` is rejected in privileged exec. This package
therefore:

1. Tries `set cli pagination off` in Global Configuration mode
   (`configure terminal` … `end`) at the start of each session, best effort.
   A rejection only logs one warning. The setting is a CLI display option; it
   would only persist if `save_config` is run afterwards. Set
   `SWITCH_PAGING_OFF=0` to skip it.
2. Runs every exec command (`show`, read-backs, `save`) through its own read
   loop: when the last visible line is a pager prompt (`--More--`,
   `-- More --`, `--More-- (NN%)`, `More: <space>, Quit: q …`,
   `<--- More --->`, `Press any key to continue`) it sends one space, and it
   finishes on the real prompt (`<hostname>#`). Pager text, backspaces, ANSI
   sequences, orphaned ESC bytes, other control characters, the command echo,
   and the trailing prompt are stripped. Blank lines directly before or after
   a page break (the pager's erase sequence, which netmiko turns into
   newlines, and trailing blanks at the end of a page) are dropped; blank
   lines elsewhere in the output are kept.
3. Gives up after `SWITCH_READ_TIMEOUT` seconds without new output. The error
   contains the last visible line, so an unknown pager prompt can be added.

## SNMP tools (not live-confirmed)

These tools exist so Home Assistant can use a **non-default SNMPv2c
community** that is read-write (or read-only) but restricted to IF-MIB,
and so the default `public` / `private` communities and the default v3
user `noAuthUser` can be removed afterwards. They send only fixed
command sequences; there is no generic SNMP configure tool.

**Do not run the write tools against the live switch until Redy has
verified the CLI syntax on the LGS328PC (firmware 1.01.02.02).** The
command templates live in `src/netmiko_mcp_linksys/snmp_cli.py` and
cite their source. The primary source is the official Linksys LGSXXX
CLI User Manual, chapter 19
([MAN_LGSXXX_LNKPG-00878_Rev_A00.pdf](https://downloads.linksys.com/support/assets/others/MAN_LGSXXX_LNKPG-00878_Rev_A00.pdf)):

```
snmp view <ViewName> <OIDTree> included
snmp group <GroupName> user <UserName> security-model v2c
snmp access <GroupName> v2c read <View> write <View|none> notify none
snmp community name <CommunityName> security <SecurityName>
no snmp community name <CommunityName>
no snmp user <UserName>
show snmp community
show snmp viewtree
show snmp group
show snmp group access
show snmp user
```

This is **not** Cisco IOS (`snmp-server community X view V rw`). Generic
Aricent ISS documentation (Super Micro SNMP Configuration Guide, Cisco
Skylight/Flex SNMP commands) often uses `snmp community index <Index>
name <Name> security <Security>` and a `volatile|nonvolatile` storage
flag. The tools use the Linksys form **without** `index` and without
that flag. If the device rejects a command, stop and confirm the ISS
variant live; do not guess.

The community string is **only** read from `SWITCH_SNMP_COMMUNITY`. It is
never a tool argument, is not reused as the group or security name
(those are derived as `<view>_grp` / `<view>_sec`), and is replaced with
`[REDACTED]` in tool output, audit entries, exceptions, and (after the
session closes) the netmiko session log. `show snmp community` output is
redacted even when it is run through the `show` tool. Validation
failures never echo the secret.

Suggested order, each call unlock-gated:

1. `snmp_view_create("<view>", "interfaces")` — OID `1.3.6.1.2.1.2`
2. `snmp_view_create("<view>", "ifmib")` — OID `1.3.6.1.2.1.31`
3. Optionally `snmp_view_create("<view>", "power-ethernet")` — OID
   `1.3.6.1.2.1.105` (see PoE trade-off below)
4. `snmp_community_create("<view>", "rw")` (or `"ro"`)
5. `snmp_community_remove("public")` then `snmp_community_remove("private")`
   — refused unless the configured community is present and mapped to a
   view whose included subtrees are only on that allowlist (not `iso` /
   the whole tree)
6. `snmp_user_remove("noAuthUser")`
7. `save_config` when you are ready to persist

### PoE trade-off

Home Assistant can set `ifAdminStatus` (`1.3.6.1.2.1.2.2.1.7`) and
`ifAlias` (`1.3.6.1.2.1.31.1.1.1.18`) and can read bandwidth counters
from IF-MIB / ifMIB alone. Standard PoE objects (`pethPsePortAdminEnable`,
detection status, power budget) live in POWER-ETHERNET-MIB
`1.3.6.1.2.1.105`, which is **not** inside IF-MIB. Adding that subtree
is required if HA should read or toggle PoE over SNMP; leaving it out
keeps PoE out of reach even if the community is RW. Whether the
LGS328PC implements `1.3.6.1.2.1.105` (or only a vendor MIB) is
unconfirmed. A RW community that includes it can turn PoE off via SNMP.

### SNMP and protected ports

`SWITCH_PROTECTED_PORTS` is enforced only by the CLI tools
(`port_set_admin_state`, `poe_set`). An RW community that can write
`ifAdminStatus` (and, if included, PoE OIDs) can still change those
ports over SNMP. There is no source-IP / `transporttag` restriction in
these tools. Treat the community as a secret, restrict UDP/161 at the
firewall, and prefer `ro` if HA only needs to read counters.

### Live-test checklist (Redy)

- Exact syntax: does `snmp community name … security …` work, or is the
  ISS `index` form required? Is `notify none` / `write none` accepted?
- Storage type of new view / group / community (volatile vs
  nonvolatile) and whether `save_config` actually persists them.
- Whether `enable snmpagent` is required first.
- Exact `show snmp community`, `show snmp viewtree`, `show snmp group`,
  `show snmp group access`, and `show snmp user` layouts (the parsers
  assume ISS `Key: value` blocks separated by `-----`).
- Exact spelling of the default communities and of `noAuthUser`.
- `show snmp view` as an alias of `show snmp viewtree` (unconfirmed;
  the manual only documents `viewtree`).
- SET of `ifAdminStatus` / `ifAlias` with the new view; walk of
  `1.3.6.1.2.1.105` if PoE is needed.
- Confirm leftover `public` / `private` / `noAuthUser` are gone, and
  that the session log and tool output never contain the community.

## Live-test status

Confirmed on LGS328PC, firmware 1.01.02.02 (0.1.0 and 0.1.1 live tests):

- paramiko 4.0.0 negotiates `ssh-rsa`/SHA-1; strict host-key check works.
- Login lands directly in privilege 15 (`LGS328PC#`); no enable needed, no
  banner, no second login prompt.
- `show version` does not exist; use `show system information`.
- Read-back `show power inline gigabitethernet 0/N` works.
- Read-back `show interfaces gigabitethernet 0/N` works; output starts with
  e.g. `Gi0/24 up, line protocol is up (connected)`.
- The pager loop completes long outputs (`show interfaces status`,
  `show power inline`, `show interfaces gigabitethernet 0/24`), tested with
  `SWITCH_PAGING_OFF=0`.
- Error heuristic: after ANSI/control stripping, a line is a failure if it
  contains `%` anywhere (including a same-line prompt such as
  `LGS328PC(config-if)#% Invalid input`), or if — after removing a leading
  prompt (`hostname`, optional `(config…)`, then `#` or `>`) — the remainder
  is not empty, is not one of the commands just sent (compared after
  dropping double quotes and collapsing whitespace), and contains the word
  `Error` or `Invalid` (case-insensitive). Echoed commands such as
  `description "Error LED"` or the unquoted echo `description Error LED`
  are skipped. Invalid commands on this firmware
  return `% Invalid input detected` (confirmed live).
- `description <two words>` unquoted is rejected (`% Invalid input detected`
  at the second word); fixed in 0.1.2 by quoting.

Still to confirm with 0.1.2:

- Quoted `description "<text>"` is accepted and shown without quotes in
  `show interfaces description`. The exact table layout of that command
  is assumed (Cisco/ISS-style fixed-width `Description` column, `Gi0/N`
  rows) and should be confirmed live.
- Page breaks without leftover ESC bytes or blank lines.
- Whether `set cli pagination off` in config mode is accepted.
- The other interface tools (`shutdown`, `power inline …`) and the output of
  `save`.
- Hub `unlock` behaviour for `save_config`.

## Development

```bash
uv sync --extra dev
uv run --extra dev pytest
```

Pinned runtime dependencies: `netmiko==4.8.0`, `paramiko==4.0.0`,
`netmiko-mcp==0.3.0`, `mcp==2.3.0`.
