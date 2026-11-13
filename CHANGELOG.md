# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
