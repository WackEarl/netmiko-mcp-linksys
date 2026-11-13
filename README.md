# netmiko-mcp-linksys

stdio MCP server for a single Linksys LGS-series switch (developed against the
LGS328PC CLI).

This project is based on [netmiko](https://github.com/ktbyers/netmiko) and
[netmiko-mcp](https://github.com/ktbyers/netmiko_mcp). The `show` tool reuses
netmiko-mcp's command filter (`netmiko_mcp.security.validate_command`) and the
same allow/deny list format (`commands.yml`). Configuration tools send only
fixed command sequences built by this wrapper; the model never supplies
free-form config.

**This is 0.2.0.** It adds narrow, unlock-gated SNMP tools (a
column-only write view, a tool-level lock on the protected ports, and
`SWITCH_SNMP_WRITE_ENABLED` off by default) and includes the fixes from
the live tests on an
LGS328PC with firmware 1.01.02.02 (SSH with `ssh-rsa` via paramiko 4.0.0;
login lands directly in privilege 15 with prompt `LGS328PC#`; no banner or
second login prompt). See [Live-test status](#live-test-status).

## Install and run

The intended way to run this server is the packaged entrypoint, pinned to a
tag:

```bash
uvx --from git+https://github.com/WackEarl/netmiko-mcp-linksys@v0.2.0 netmiko-mcp-linksys
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
`--with git+https://github.com/WackEarl/netmiko-mcp-linksys@v0.2.0` so the
package is installed in that environment.

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `SWITCH_HOST` | yes (at tool call) | Switch IP or hostname. |
| `SWITCH_USER` | yes (at tool call) | SSH username. |
| `SWITCH_PASSWORD` | yes (at tool call) | SSH password. Never logged or returned. |
| `SWITCH_SNMP_COMMUNITY` | yes before `snmp_community_create` / `snmp_community_remove` | SNMPv2c community string for the new, non-default community. Never a tool argument, never logged or returned (shown as `[REDACTED]`). Must not be `public` or `private`; 8–32 characters from `[A-Za-z0-9_]` (no dots or dashes). An invalid value is not used for redaction. |
| `SWITCH_SNMP_WRITE_ENABLED` | yes (`1`) before any SNMP write tool | Hard gate, **off by default**. SNMP write tools refuse unless this is exactly `1`. Leave it unset until the remaining unconfirmed CLI (community create/remove) has been verified live. |
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
fresh approval. Keep `SWITCH_SNMP_WRITE_ENABLED` unset (the tools refuse)
until the community-create syntax has been confirmed live; only then set it to `1` in the
hub env (shown below as the value to use after that confirmation). Fill `SWITCH_PROTECTED_PORTS` after the first read test —
until it is set to a valid list, disable and PoE-off are refused.

```json
{
  "switch": {
    "command": "uvx",
    "args": [
      "--python", "3.12",
      "--from", "git+https://github.com/WackEarl/netmiko-mcp-linksys@v0.2.0",
      "netmiko-mcp-linksys"
    ],
    "env": {
      "SWITCH_HOST": "192.0.2.10",
      "SWITCH_USER": "${SWITCH_USER}",
      "SWITCH_PASSWORD": "${SWITCH_PASSWORD}",
      "SWITCH_SNMP_COMMUNITY": "${SWITCH_SNMP_COMMUNITY}",
      "SWITCH_SNMP_WRITE_ENABLED": "1",
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
        "snmp_write_view_create",
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
| `port_overview()` | Read-only bundle of `show system information`, `show vlan`, `show power inline`, and `show interfaces`, each passed through the same command filter, run in one SSH session. If one command fails, the remaining ones are not sent and are listed as not run. | n/a |
| `port_set_admin_state(port, enabled)` | `interface gigabitethernet 0/N` then `no shutdown` / `shutdown`. | no |
| `poe_set(port, enabled)` | `interface gigabitethernet 0/N` then `power inline enable` / `power inline disable`. PoE ports: `0/1`–`0/24`. | no |
| `port_set_description(port, text?)` | `description "<text>"` (always quoted, the LGS CLI takes only one word unquoted) or `no description` when `text` is omitted. The result ends with an informational read-back of `show interfaces description` for that port (verified, quoted, empty, probably truncated, or could not verify). | no |
| `save_config()` | Privileged exec `save` only. Gate this in the hub with `unlock`. | yes |
| `snmp_view_create(view_name, subtree)` | Add one **included** subtree from a fixed OID allowlist (`interfaces`, `ifmib`, `power-ethernet`) to a **read** view. Refused for a view that is used as a write view or holds a writable column or an excluded entry. Gate with hub `unlock` and `SWITCH_SNMP_WRITE_ENABLED=1`. **Not live-confirmed.** | no |
| `snmp_write_view_create(view_name, subtree)` | Add one writable column to a **write** view: `ifAdminStatus` (`1.3.6.1.2.1.2.2.1.7`), `ifAlias` (`1.3.6.1.2.1.31.1.1.1.18`) or `pethPsePortAdminEnable` (`1.3.6.1.2.1.105.1.1.1.3`, PoE on/off). One `snmp view <view> <column> included` line, sent with a `%` error check and verified in `show snmp viewtree`; on failure it is removed again (see below). Whole MIB subtrees are never allowed. **No per-port exclusions:** the column is writable for every port, protected ports included. Gate with hub `unlock` and `SWITCH_SNMP_WRITE_ENABLED=1`. **Create and viewtree read-back live-confirmed; rollback (`no snmp view`) is not.** | no |
| `snmp_community_create(view_name, access, write_view=None)` | Create a v2c community from `SWITCH_SNMP_COMMUNITY` bound to an existing restricted read view (`view_name`). `ro`: write view `none`. `rw`: requires a separate `write_view` that passes the write-view check (only writable columns). The secret is never a tool argument. Gate with hub `unlock` and `SWITCH_SNMP_WRITE_ENABLED=1`. **Not live-confirmed.** | no |
| `snmp_community_remove(name)` | Remove `public` or `private` only, and only after the configured community is verified present with a restricted view. Never removes the configured community. Gate with hub `unlock` and `SWITCH_SNMP_WRITE_ENABLED=1`. **Not live-confirmed.** | no |
| `snmp_user_remove(name)` | Remove `noAuthUser` only. Gate with hub `unlock` and `SWITCH_SNMP_WRITE_ENABLED=1`. **Not live-confirmed.** | no |

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

## SNMP tools

These tools exist so Home Assistant can use a **non-default SNMPv2c
community** that is read-write (or read-only) but restricted to IF-MIB,
and so the default `public` / `private` communities and the default v3
user `noAuthUser` can be removed afterwards. They send only fixed
command sequences; there is no generic SNMP configure tool.

Creating a column in a write view (`snmp view <view> <column>
included`) and reading it back from `show snmp viewtree` were confirmed
in the 0.2.0 live check. **Community create/remove syntax and the SNMP
read/write path through an external client are not live-confirmed.**
`SWITCH_SNMP_WRITE_ENABLED` should stay unset (or anything other than
`1`) until then; the tools fail closed. The
command templates live in `src/netmiko_mcp_linksys/snmp_cli.py` and
cite their source. The primary source is the official Linksys LGSXXX
CLI User Manual, chapter 19
([MAN_LGSXXX_LNKPG-00878_Rev_A00.pdf](https://downloads.linksys.com/support/assets/others/MAN_LGSXXX_LNKPG-00878_Rev_A00.pdf)):

```
snmp view <ViewName> <OIDTree> included
snmp view <ViewName> <OIDTree> excluded
snmp group <GroupName> user <UserName> security-model v2c
snmp access <GroupName> v2c read <ReadView> write <WriteView|none> notify none
snmp community name <CommunityName> security <SecurityName>
no snmp community name <CommunityName>
no snmp user <UserName>
show snmp community
show snmp viewtree
show snmp group
show snmp group access
show snmp user
```

View names are compared exactly (case-sensitive). A view name that
differs from an existing view only in letter case (for example `wv` and
`WV`) is refused, because it is not confirmed whether the switch treats
view names case-sensitively.

This is **not** Cisco IOS (`snmp-server community X view V rw`). Generic
Aricent ISS documentation (Super Micro SNMP Configuration Guide, Cisco
Skylight/Flex SNMP commands) often uses `snmp community index <Index>
name <Name> security <Security>` and a `volatile|nonvolatile` storage
flag. The tools use the Linksys form **without** `index` and without
that flag. If the device rejects a command, stop and confirm the ISS
variant live; do not guess.

The community string is **only** read from `SWITCH_SNMP_COMMUNITY` (8–32
characters from `[A-Za-z0-9_]`, not `public`/`private`). It is never a
tool argument and is not reused as the group or security name (those are
derived as `<view>_grp` / `<view>_sec`). It is replaced with `[REDACTED]`
in tool output, audit entries, and exceptions, including `re.escape`/`repr`
forms and a wrapped `snmp community name … security` span. An invalid env
value is not used for redaction (and is warned at startup). SNMP write
tools disable the netmiko session log for that session so a community
echo cannot sit in the log in the clear. The `show` tool also disables
the session log for `show snmp community`, `show snmp viewtree`, and
`show snmp user`. `show snmp community` output is redacted even when it
is run through the `show` tool; session-log Community Name fields are
masked by label even when the name is not the configured secret.
Validation failures never echo the secret.

Suggested order, each call unlock-gated:

1. `snmp_view_create("<view>", "interfaces")` — OID `1.3.6.1.2.1.2`
2. `snmp_view_create("<view>", "ifmib")` — OID `1.3.6.1.2.1.31`
3. `snmp_view_create("<view>", "power-ethernet")` — OID
   `1.3.6.1.2.1.105`, so HA can read PoE state and budget
4. For `rw` only:
   `snmp_write_view_create("<view>_w", "ifAdminStatus")`,
   `snmp_write_view_create("<view>_w", "ifAlias")` and, for PoE
   switching, `snmp_write_view_create("<view>_w", "pethPsePortAdminEnable")`
5. `snmp_community_create("<view>", "rw", "<view>_w")` (or
   `snmp_community_create("<view>", "ro")`)
6. `snmp_community_remove("public")` then `snmp_community_remove("private")`
   — refused unless the configured community is present and mapped to a
   read view whose included subtrees are only on that allowlist (not
   `iso` / the whole tree) and, if it has write access, to a separate
   write view that passes the write-view check below
7. `snmp_user_remove("noAuthUser")`
8. `save_config` when you are ready to persist

### Read/write view split

A RW community never writes through its read view. `snmp access` names a
separate write view (manual p. 103: `read <ReadView | none> write
<WriteView | none>`), so the read view holds whole MIB subtrees (IF-MIB,
ifMIB, POWER-ETHERNET-MIB) while the write view holds only the writable
columns. A write view passes the check (before
binding, after `snmp_write_view_create`, after `snmp_community_create`,
and before `snmp_community_remove`) only if, in `show snmp viewtree`:

- every entry of the view has an explicit `included` / `excluded` type,
  an OID in a known format and an exact mask (see below);
- it includes at least one subtree, and its included subtrees are only
  the columns `1.3.6.1.2.1.2.2.1.7` (ifAdminStatus),
  `1.3.6.1.2.1.31.1.1.1.18` (ifAlias) and `1.3.6.1.2.1.105.1.1.1.3`
  (pethPsePortAdminEnable), never a whole MIB such as `1.3.6.1.2.1.2` or
  `1.3.6.1.2.1.105` and never an instance;
- it is not the same view as the read view.

Excluded entries (for example from an older build) only narrow a view and
are accepted, but none are required or sent.

`snmp_write_view_create` sends one line, `snmp view <view> <column>
included`, with netmiko `error_pattern="%"` (ISS error lines start with
`%`), then reads `show snmp viewtree` back and runs the check above. If
the column was already there, nothing is sent. On any error after
sending, the column added by this call is removed again (`no snmp view
<view> <column>`) and `show snmp viewtree` must match the state before
the call exactly; otherwise the result says `ROLLBACK NOT VERIFIED` and
the view must not be bound to a community. A column that existed before
the call is never removed. The rollback is the only place that sends
`no snmp view`.

OIDs from `show snmp viewtree` go through one normalization
(`oid_arcs`): whitespace, one leading dot, a leading `iso` (= `1`, only
when followed by `3`) and trailing dots are accepted, so `.1.3.6.1…`,
`iso.3.6.1…` and `1.3.6.1…` are the same OID; `iso.1.3.6.1…`, a bare
`iso` and other variants are refused instead of reinterpreted. Prefixes are compared by whole arcs, so
`1.3.6.1.2.1.105` is not below `1.3.6.1.2.1.10`. Any other format makes
the check refuse (fail-closed), in the read-view precheck as well.

Masks follow RFC 3415: bit *n* belongs to sub-identifier *n*, a missing
or short mask is extended with ones, and bits beyond the OID length do
not matter. A mask is exact when every bit that covers an arc of the OID
is 1. Accepted spellings: empty / `none` / `-`, dotted bits (`1`,
`1.1.1`) and hex octets (`ff`, `ff:e0`, `0xffe0`). The 0.2.0 live check
showed that after adding a column, the switch prints a mask with one `1`
per arc (`Subtree Mask : 1.1.1.1.1.1.1.1.1.1.1` for
`1.3.6.1.2.1.105.1.1.1.3`) and `Storage Type : Non-volatile` immediately.
The earlier read-only check printed `Subtree Mask : 1` for OID `1`. A
hex mask such as `ff:e0` for an 11-arc column is also accepted, while a
mask with a 0 inside the OID (a wildcard, such as `ff:c0` for an 11-arc
OID) is refused.

The viewtree parser reads the layout from Redy's read-only check:

```
View Name    : iso
Subtree OID  : 1
Subtree Mask : 1
View Type    : Included
```

(no leading dot, no `iso.`, with a mask; the views on the switch are
`iso` and `restricted`). Blocks are split on `-----` lines and before
every `View Name` line, so blank-line separated blocks work too.

After a create, the access entry must name exactly the requested read and
write views. A failed check before sending refuses; after sending it is
reported as "Configuration was sent, verification failed". Read views
are also refused if any of their entries has an unrecognised mask.

### PoE over SNMP

Home Assistant reads bandwidth counters from IF-MIB / ifMIB and PoE
state (detection status, power budget) from POWER-ETHERNET-MIB
`1.3.6.1.2.1.105`, which is **not** inside IF-MIB, through the read view.
It switches ports with `ifAdminStatus` (`1.3.6.1.2.1.2.2.1.7`), sets
descriptions with `ifAlias` (`1.3.6.1.2.1.31.1.1.1.18`), and turns PoE
on or off with `pethPsePortAdminEnable` (`1.3.6.1.2.1.105.1.1.1.3`)
through the write view (decision in Vikunja task 48). Only that PoE
column is writable, never the whole PoE MIB.

pethPsePortTable is indexed by
`pethPsePortGroupIndex.pethPsePortIndex`, which need not equal the port
number or the ifIndex. Whether the LGS328PC implements
`1.3.6.1.2.1.105` (or only a vendor MIB) is unconfirmed; if it does not,
the fallback is PoE read-only (no `pethPsePortAdminEnable` in the write
view).

> **Note on 0/15:** 0/15 feeds a LINOVISION EoC converter that powers the
> Zigbee router at the far end over PoE. Do **not** turn PoE (or the
> port) off on 0/15, or the Zigbee router goes down. Roland decided
> against an extra technical lock (task 48, comment 69): 0/15 is not in
> `SWITCH_PROTECTED_PORTS`, so SNMP and the CLI tools do not block it.
> In Home Assistant its PoE and port switches should be disabled.

### SNMP and protected ports

**The protected ports are only protected at tool level.**
`SWITCH_PROTECTED_PORTS` (production: `0/10`, which powers the Unraid
server through a PoE splitter, and `0/24`, the uplink) is enforced by
the tools of this server: `port_set_admin_state(..., False)` and
`poe_set(..., False)` refuse those ports, and refuse every port if the
variable is unset, empty or invalid (fail-closed). This server has no
tool that writes SNMP values itself.

There is **no** protection at SNMP level (Roland's decision of
2026-11-13; earlier builds excluded the protected ports in the write
view, which needed live ifIndex / PoE index mappings). The write view
makes `ifAdminStatus`, `ifAlias` and `pethPsePortAdminEnable` writable
for **every** port. Anyone who has the write community can switch off
0/10 or 0/24 (or cut their PoE) with a direct SNMP SET, past these tools;
the switch then needs local access to recover. Therefore:

- keep the write community secret and use it only where it is needed
  (Home Assistant); give everything else a read-only community;
- keep the write view to the columns that are really used (leave out
  `pethPsePortAdminEnable` if PoE switching is not needed);
- restrict UDP/161 at the firewall to the hosts that need it (Redy
  handles the ACL as a separate work package); these tools set no
  source-IP / `transporttag` restriction;
- disable the HA switches for 0/10, 0/24 and 0/15.

### Live-test checklist (Redy)

Confirmed in the 0.2.0 live check (see [Live-test status](#live-test-status)):

- Refused config lines print an error starting with `%` (`% Invalid
  input detected at '^' marker`).
- `show snmp view` is an alias of `show snmp viewtree`.
- After `snmp_write_view_create`, `show snmp viewtree` prints the column
  OID as given (no leading dot), a mask of one `1` per arc
  (`1.1.1.1.1.1.1.1.1.1.1` for `1.3.6.1.2.1.105.1.1.1.3`), `View Type :
  Included`, and `Storage Type : Non-volatile` immediately, without
  `save_config`. The column is accepted without a mask in the create
  command.

Still unconfirmed:

- Exact syntax: does `snmp community name … security …` work, or is the
  ISS `index` form required? (The switch lists communities under a
  Community Index, so the `index` form may be needed.) Is `notify none`
  / `write none` accepted?
- Storage type of a new group / community and whether `save_config`
  actually persists them (new views are already Non-volatile).
- Whether `enable snmpagent` is required first.
- Exact `show snmp community`, `show snmp group`, `show snmp group
  access`, and `show snmp user` layouts (the parsers assume ISS
  `Key: value` blocks separated by `-----`; `show snmp viewtree` is
  confirmed, see above).
- Exact spelling of the default communities and of `noAuthUser`.
- SET of `ifAlias` with the new view.
- That `no snmp view <view> <oid>` removes exactly that entry (used
  for rollback; not triggered in the 0.2.0 check).
- That a GET/WALK of `1.3.6.1.2.1.105` works with the community and a
  SET of `pethPsePortAdminEnable` and `ifAdminStatus` works on a free
  port (e.g. 0/18) through an external SNMP client. If PoE SET fails,
  fall back to PoE read-only. Do **not** SET 0/10 or 0/24: nothing at
  SNMP level stops it.
- Confirm leftover `public` / `private` / `noAuthUser` are gone, and
  that the session log and tool output never contain the community.
- Terminal width: `cisco_s300` `session_preparation` already sends
  `terminal width 511`. Confirm that is in effect (no extra width
  command is sent by these tools) and that `snmp community` lines do
  not wrap mid-secret in a way that a later live check would miss.

## Live-test status

Confirmed on LGS328PC, firmware 1.01.02.02, in the 0.2.0 live check
(Redy, commit 177dc84, 2026-11-13):

- Device error lines start with `%` (example: `% Invalid input
  detected at '^' marker`).
- `snmp view <view> <column> included` (no mask) is accepted for a
  write-view column such as `1.3.6.1.2.1.105.1.1.1.3` or
  `1.3.6.1.2.1.2.2.1.7`.
- `show snmp viewtree` prints `Subtree OID  : 1.3.6.1.2.1.105.1.1.1.3`
  / `Subtree Mask : 1.1.1.1.1.1.1.1.1.1.1` (one `1` per arc),
  `View Type : Included`, `Storage Type : Non-volatile` immediately
  (no `save_config`), `Row Status : Active`. `show snmp view` is an
  alias of `viewtree`.
- `port_set_admin_state` and `poe_set` (CLI, not SNMP) worked on a
  free port (0/18) and were reversed.

Not verified in that check:

- The SNMP read/write path through an external client (GET/WALK of
  `1.3.6.1.2.1.105`, SET of `pethPsePortAdminEnable` / `ifAdminStatus`
  / `ifAlias`).
- Community create/remove syntax (the switch lists communities under a
  Community Index, so the ISS form with `index` may be required).
- `no snmp view <view> <oid>` removing exactly one entry.

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
