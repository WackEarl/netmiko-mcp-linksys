# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-13

### Added

- Narrow, unlock-gated SNMP tools to create an allow-listed IF-MIB view,
  bind a non-default v2c community from `SWITCH_SNMP_COMMUNITY` (never a
  tool argument; redacted as `[REDACTED]`), remove only `public`/`private`
  after the new community is verified with a restricted view, and remove
  only `noAuthUser`. POWER-ETHERNET-MIB (`1.3.6.1.2.1.105`) is an
  allow-listed read-view subtree so HA can read PoE. Command templates live in `snmp_cli.py`
  and follow the Linksys LGSXXX CLI manual
  ([#7](https://github.com/WackEarl/netmiko-mcp-linksys/issues/7)).
  The write-view create syntax and the viewtree read-back were
  live-confirmed on 2026-11-13; community create/remove syntax and the
  SNMP read/write path through an external client are not.
  SNMP write tools require `SWITCH_SNMP_WRITE_ENABLED=1` (off by default),
  disable the session log for the call, and redact community echoes
  (including wrapped lines and `re.escape`/`repr` variants). The community
  charset is `[A-Za-z0-9_]`, length 8–32.
- `snmp_write_view_create(view_name, subtree)` builds a separate write
  view from the writable columns only: `ifAdminStatus`
  (`1.3.6.1.2.1.2.2.1.7`), `ifAlias` (`1.3.6.1.2.1.31.1.1.1.18`) and
  `pethPsePortAdminEnable` (`1.3.6.1.2.1.105.1.1.1.3`) for PoE on/off
  from Home Assistant (Vikunja task 48). Whole MIB subtrees are refused.
  It sends one `snmp view <view> <column> included` line with
  `error_pattern="%"`, verifies it in `show snmp viewtree`, and on any
  failure removes the column again and checks that the viewtree equals
  the state before (else `ROLLBACK NOT VERIFIED`). There are no per-port
  exclusions: the protected ports (`SWITCH_PROTECTED_PORTS`, production
  0/10 and 0/24) are refused by the tools only, not at SNMP level
  (Roland, 2026-11-13). Anyone with the write community can switch them
  directly over SNMP; the README says so. 0/15 (EoC converter feeding the
  Zigbee router) is documented as "do not turn PoE off", not locked.
- The `show snmp viewtree` parser reads the layout from Redy's read-only
  check (`Subtree OID  : 1` / `Subtree Mask : 1` / `View Type    :
  Included`) and starts a new entry at every `View Name` line, so blank
  line separated blocks work too. Masks are read per RFC 3415: a full
  mask such as `1`, `1.1.1` or `ff:e0` (11-arc column) is exact, a mask
  with a 0 inside the OID length is a wildcard and refused. The 0.2.0
  live check printed a column mask as `1.1.1…` (one `1` per arc) with
  Storage Type Non-volatile.

### Changed

- `snmp_community_create(view_name, access, write_view=None)`: `rw` now
  requires a separate `write_view` (`snmp access … read <ReadView> write
  <WriteView> notify none`); the same view for read and write is refused,
  and `ro` refuses a `write_view`. The write view is checked strictly
  before sending, and after sending the access entry must name exactly
  the requested views.
- The `show snmp viewtree` read-back now verifies write views strictly
  (explicit included/excluded type, exact mask, only write-allowed
  columns) in `snmp_community_create` and `snmp_community_remove`. Read and
  write views with an unrecognised (possibly wildcard) mask are refused.
- `snmp_view_create` refuses any subtree for a view that is used as a
  write view or holds a writable column or an excluded entry (whole MIBs would
  widen the column-only write view), and now runs in a
  single session with the "Configuration was sent, verification failed"
  wrapper for post-send read-back errors.
- README: install pins now point to `@v0.2.0`.

### Live test

Redy's 0.2.0 live check on an LGS328PC (firmware 1.01.02.02, commit
177dc84, 2026-11-13):

- Device error lines start with `%` (example: `% Invalid input detected
  at '^' marker`).
- A column OID without a mask is accepted (`snmp view <view> <column>
  included`).
- `show snmp viewtree` (and its alias `show snmp view`) prints a column
  entry as `Subtree OID  : 1.3.6.1.2.1.105.1.1.1.3` / `Subtree Mask :
  1.1.1.1.1.1.1.1.1.1.1` (one `1` per arc), `View Type : Included`,
  `Storage Type : Non-volatile` immediately, without `save_config`.
- `port_set_admin_state` and `poe_set` (CLI) worked on a free port
  (0/18) and were reversed.

Not live-verified in that check:

- The SNMP read/write path through an external client (GET/WALK/SET).
- Community create/remove syntax (the switch lists communities under a
  Community Index, so the ISS form with `index` may be required; the
  Linksys form without `index` remains unconfirmed).
- `no snmp view <view> <oid>` to remove a single entry (the rollback
  path was not triggered).

### Security

- Removed again before release (Roland, 2026-11-13): the view-level
  exclusions of the protected ports, `SWITCH_SNMP_PROTECTED_IFINDEXES`,
  `SWITCH_SNMP_PROTECTED_POE_INDEXES` and the two-stage
  exclusion/include apply with its staged rollback. They needed live
  ifIndex and PoE index mappings that the tools cannot read. What stays:
  the tool-level port lock, `error_pattern="%"`, read-back verification
  with rollback of the added column, the central OID normalization and
  `SWITCH_SNMP_WRITE_ENABLED` off by default.
- `oid_arcs` accepts a leading `iso` only as `iso.3…`; `iso.1.3.6…`, a
  bare `iso` and other variants are refused (fail-closed) instead of
  being read as `1.1.3.6…`.
- One central OID normalization (`oid_arcs`/`canonical_oid`/`oid_within`)
  for all view checks, prechecks and read-backs: leading dot, `iso`,
  trailing dots and whitespace are accepted, prefixes are compared by
  whole arcs, and unknown formats or partial (wildcard) masks are refused,
  also in the read-view precheck. Before, other OID spellings could hide
  a write view from `snmp_view_create`, so the whole POWER-ETHERNET-MIB
  could be added to it (Cody). The read-view precheck now refuses any
  view with excluded entries or writable columns.
- SNMP view names are compared exactly (case-sensitive) in all view
  checks (`view_is_restricted`, `view_is_write_safe`, the read-back
  checks, and the PoE/write-view prechecks). A view name that differs
  from an existing view only in letter case is refused (fail-closed),
  because it is not live-confirmed whether ISS treats view names
  case-sensitively (found by Cody). `snmp_view_create` now reads `show snmp viewtree` before
  sending and refuses if it cannot be parsed.

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
