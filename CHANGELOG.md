# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Narrow, unlock-gated SNMP tools to create an allow-listed IF-MIB view,
  bind a non-default v2c community from `SWITCH_SNMP_COMMUNITY` (never a
  tool argument; redacted as `[REDACTED]`), remove only `public`/`private`
  after the new community is verified with a restricted view, and remove
  only `noAuthUser`. POWER-ETHERNET-MIB (`1.3.6.1.2.1.105`) is an optional
  allow-listed subtree for PoE. Command templates live in `snmp_cli.py`
  and follow the Linksys LGSXXX CLI manual; they are **not live-confirmed**
  ([#7](https://github.com/WackEarl/netmiko-mcp-linksys/issues/7)).
  SNMP write tools require `SWITCH_SNMP_WRITE_ENABLED=1` (off by default),
  disable the session log for the call, and redact community echoes
  (including wrapped lines and `re.escape`/`repr` variants). The community
  charset is `[A-Za-z0-9_]`, length 8–32.
- `snmp_write_view_create(view_name, subtree)` builds a separate write
  view: only IF-MIB `1.3.6.1.2.1.2` / `1.3.6.1.2.1.31`, never
  POWER-ETHERNET-MIB, and always `snmp view <view>
  1.3.6.1.2.1.2.2.1.7.<ifIndex> excluded` (ifAdminStatus) for each
  protected port, sent before the included subtree.
- `SWITCH_SNMP_PROTECTED_IFINDEXES` (`port=ifIndex,…`): explicit ifIndex
  values for exactly the ports in `SWITCH_PROTECTED_PORTS`. The ifIndex
  is never derived from the port number; without a valid mapping every
  write-view and RW operation refuses (fail-closed).

### Changed

- `snmp_community_create(view_name, access, write_view=None)`: `rw` now
  requires a separate `write_view` (`snmp access … read <ReadView> write
  <WriteView> notify none`); the same view for read and write is refused,
  and `ro` refuses a `write_view`. The write view is checked strictly
  before sending, and after sending the access entry must name exactly
  the requested views.
- The `show snmp viewtree` read-back now verifies write views strictly
  (explicit included/excluded type, all-ones or empty mask, only
  write-allowed subtrees, every ifAdminStatus exclusion present, no
  PoE) in `snmp_community_create` and `snmp_community_remove`. Read and
  write views with an unrecognised (possibly wildcard) mask are refused.
- `snmp_view_create` refuses `power-ethernet` for a view that is used as a
  write view or carries ifAdminStatus exclusions, and now runs in a
  single session with the "Configuration was sent, verification failed"
  wrapper for post-send read-back errors.

- SNMP community rejection paths return only a generic message (no device
  text). ANSI and prompt redraws are stripped only inside
  `snmp community name` … `security` command spans; other output stays
  byte-identical except for secret replacements. Read-back
  failures after a config send are always reported as "Configuration was
  sent, verification failed". The `show` tool disables the session log for
  `show snmp community` / `viewtree` / `user`, and session-log Community
  Name fields are masked by label. The extra terminal-width helper was
  removed; `cisco_s300` already sends `terminal width 511` in
  `session_preparation`.

## [0.1.3] - 2026-11-13

Fixes from Cody's architecture review and the remaining nits from the
0.1.2 live retest, tracked in [#2](https://github.com/WackEarl/netmiko-mcp-linksys/issues/2)
and [#3](https://github.com/WackEarl/netmiko-mcp-linksys/issues/3).

### Fixed

- `config_output_is_error` classifies device output after ANSI/control
  stripping (same helper as the output cleanup, including the
  terminated-OSC rule). A line is a failure if it contains `%` anywhere
  (including a same-line prompt such as
  `LGS328PC(config-if)#% Invalid input`), or if after removing a leading
  prompt the remainder is not empty, is not one of the commands just
  sent, and contains the word `Error` or `Invalid` (case-insensitive).
  Echoed descriptions such as `description "Error LED"` are therefore
  not reported as rejected, including an unquoted echo
  (`description Error LED`); a separate line like
  `Error: port is protected` is
  ([#3](https://github.com/WackEarl/netmiko-mcp-linksys/issues/3)).
- `port_set_description` now reads back via `show interfaces description`
  and parses the row for the port (the previous
  `show interfaces gigabitethernet 0/N` read-back does not show
  descriptions on the LGS). Port rows `Gi0/7`, `gi7`, `gi1/0/7`, and
  `GigabitEthernet0/7` are recognised (and `0/1` does not match `0/10`).
  With a `Description`/`Name` header, the note compares the column
  (whitespace collapsed). A strict prefix is reported as probably
  truncated only if it is at least 8 characters, or if a known column
  width (next header column, or the Description bar on a separator
  line) equals the parsed length; a stale short prefix such as `Rep`
  is a mismatch. Without a recognised header, a row that
  ends with the expected text is verified; otherwise the note says
  `could not verify (unknown table layout)` and includes the raw row.
  A missing row is `could not verify (port row not found)` plus a short
  preview, never a mismatch. Leading or trailing spaces in the
  description are rejected
  ([#2](https://github.com/WackEarl/netmiko-mcp-linksys/issues/2)).
- Blank lines immediately before a page break (as well as after it) are
  dropped, so the two leftover blank lines seen at page breaks in the
  v0.1.2 live retest are removed ([#2](https://github.com/WackEarl/netmiko-mcp-linksys/issues/2)).
- `examples/commands.yml` lists `show interfaces description` (already
  covered by `show interfaces *`).

### Changed

- README: install pins now point to `@v0.1.3`.

## [0.1.2] - 2026-11-12

Fixes from the 0.1.1 live retest on the LGS328PC (firmware 1.01.02.02),
tracked in [#1](https://github.com/WackEarl/netmiko-mcp-linksys/issues/1).

### Fixed

- `port_set_description` now sends the text quoted (`description "Repeater EG"`).
  Unquoted, the LGS CLI rejected multi-word descriptions with
  `% Invalid input detected` at the second word. Quoting is always applied;
  input validation still forbids quotes (#1).
- Page breaks no longer leave an ESC byte and blank lines in the output (for
  example between `Gi0/20` and `Gi0/21`). Stray ESC bytes, wider ANSI/VT100
  sequences (CSI, OSC, charset, two-byte ESC), and other control characters
  are stripped; blank lines directly after a page break are dropped, other
  blank lines are kept (#1).

- Descriptions consisting only of spaces are rejected.

### Known limitations

- If netmiko splits an escape sequence across two reads, the orphaned ESC can
  still take a following character with it (e.g. `ESC D…`, `ESC [G…`). An OSC
  sequence is only stripped when terminated (BEL or ST), so an orphaned
  `ESC ]` no longer eats the rest of the line.

### Added

- `port_set_description` appends an informational read-back check: whether
  the description shows up in `show interfaces gigabitethernet 0/N` without
  quotes, with quotes (stored literally), or not at all.

### Changed

- README: read-back `show interfaces gigabitethernet 0/N` and the pager loop
  are confirmed live; install pins now point to `@v0.1.2`.

## [0.1.1] - 2026-11-12

Fixes from the first live test on an LGS328PC (firmware 1.01.02.02).

### Fixed

- Long `show` outputs (`show interfaces`, `show interfaces status`,
  `show power inline`, `show spanning-tree`, `show mac-address-table`, and the
  `show interfaces gigabitethernet 0/N` read-back) no longer fail with
  `Pattern not detected`. Exec commands now run through a pager-aware read
  loop that answers `--More--`-style prompts with a space, waits for the real
  prompt, and strips pager text, backspaces, and ANSI sequences. Read-backs
  and `save` use the same loop.
- An unwritable audit log (for example `OSError: [Errno 30] Read-only file
  system`) no longer aborts the tool. The failure is written to stderr and
  appended to the tool result as an `audit_warning:` line.

### Added

- Best-effort paging-off at session start: `configure terminal`,
  `set cli pagination off`, `end`. On this ISS-based CLI the command only
  exists in Global Configuration mode; if it is rejected, the pager loop still
  handles paging. Disable with `SWITCH_PAGING_OFF=0`.
- `SWITCH_READ_TIMEOUT` (default 60 s, 1–600): idle timeout of the read loop
  and netmiko `read_timeout_override`.
- `SWITCH_SESSION_LOG`: optional netmiko session log (append, mode 0600,
  password masked by netmiko's `no_log`, writes not recorded). An unwritable
  path disables the log with a warning.
- Startup check: warns on stderr when `SWITCH_AUDIT_LOG` is unset or not
  writable, when `SWITCH_READ_TIMEOUT` is invalid, or when `SWITCH_SESSION_LOG`
  is not writable. Startup never aborts and never contacts the switch.

### Changed

- `examples/commands.yml`: removed `show version` (invalid on this firmware);
  use `show system information`.
- README example audit path is now `/data/netmiko/switch-audit.log`.

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
