"""stdio MCP server entrypoint. Connections are opened only when a tool runs."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from netmiko_mcp.security import (
    build_abbreviation_filter,
    load_commands,
    validate_command,
)

from netmiko_mcp_linksys.audit import check_audit_path, write_audit
from netmiko_mcp_linksys.connection import (
    READBACK_DESCRIPTION,
    READBACK_INTERFACE,
    READBACK_POE,
    _send_config,
    build_admin_state_commands,
    build_description_commands,
    build_poe_commands,
    read_timeout,
    redact_show_output,
    run_config_and_readback,
    run_config_and_readbacks,
    run_in_session,
    run_save,
    run_show,
    send_paged,
    session_log_path,
)
from netmiko_mcp_linksys.connection import (
    ConnectionError as SwitchConnectionError,
)
from netmiko_mcp_linksys.snmp_cli import (
    CLI_SOURCE,
    READBACK_SNMP_ACCESS,
    READBACK_SNMP_COMMUNITY,
    READBACK_SNMP_GROUP,
    READBACK_SNMP_USER,
    READBACK_SNMP_VIEW,
    assert_configured_community_ready,
    build_community_create_commands,
    build_community_remove_commands,
    build_user_remove_commands,
    build_view_create_commands,
    format_sent_commands,
    normalize_subtree,
    parse_snmp_community,
    parse_snmp_viewtree,
    resolve_removable_community_name,
    user_present,
    view_is_restricted,
)
from netmiko_mcp_linksys.validation import (
    ValidationError,
    redact_secrets,
    reject_if_protected,
    reject_unsafe_show_command,
    require_snmp_write_enabled,
    validate_community_remove_name,
    validate_description,
    validate_port,
    validate_snmp_access,
    validate_snmp_community_secret,
    validate_snmp_name,
    validate_user_remove_name,
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
        "SNMP write tools (snmp_view_create, snmp_community_create, "
        "snmp_community_remove, snmp_user_remove) are narrow and must be "
        "gated by hub unlock, like save_config. The community secret comes "
        "only from SWITCH_SNMP_COMMUNITY and is redacted as [REDACTED]. "
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


def _with_audit_warning(text: str, warning: str | None) -> str:
    if not warning:
        return text
    return f"{text}\n\naudit_warning: {warning}"


def _fail(tool: str, params: dict[str, Any], message: str, *, allowed: bool) -> str:
    text = redact_secrets(message)
    warning = write_audit(tool=tool, params=params, allowed=allowed, result=text)
    return _with_audit_warning(text, warning)


def _ok(tool: str, params: dict[str, Any], result: str) -> str:
    warning = write_audit(tool=tool, params=params, allowed=True, result="ok")
    return _with_audit_warning(result, warning)


def startup_checks() -> list[str]:
    """Check local paths and settings at start. Warn on stderr, never abort,
    never contact the switch."""
    warnings: list[str] = []
    audit_warning = check_audit_path()
    if audit_warning:
        warnings.append(audit_warning)
    try:
        read_timeout()
    except ValidationError as exc:
        warnings.append(str(exc))
        print(f"netmiko-mcp-linksys: warning: {exc}", file=sys.stderr, flush=True)
    session_log_path()
    if "SWITCH_SNMP_COMMUNITY" in os.environ:
        try:
            validate_snmp_community_secret()
        except ValidationError as exc:
            # Invalid values are not used for redaction; never echo them.
            warnings.append(str(exc))
            print(
                f"netmiko-mcp-linksys: warning: {exc}",
                file=sys.stderr,
                flush=True,
            )
    write_flag = (os.environ.get("SWITCH_SNMP_WRITE_ENABLED") or "").strip()
    if write_flag != "1":
        message = (
            "SNMP write tools are disabled (SWITCH_SNMP_WRITE_ENABLED "
            "is not 1) until the CLI syntax is live-confirmed."
        )
        warnings.append(message)
        print(f"netmiko-mcp-linksys: warning: {message}", file=sys.stderr, flush=True)
    return warnings


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


def _collapse_ws(text: str) -> str:
    return " ".join(text.split())


_MIN_TRUNCATION_PREFIX = 8
_PREVIEW_LINES = 4

# Port 0/7 also appears as gi7, gi1/0/7, Gi0/7, or GigabitEthernet0/7.
# Longer patterns come first; a following alnum char rejects gi0/1 vs gi0/10.
_PORT_TOKEN_PATTERNS = (
    r"gigabitethernet\s*{port}",
    r"gigabitethernet\s*\d+/\d+/{number}",
    r"gigabitethernet\s*{number}",
    r"gi\s*{port}",
    r"gi\s*\d+/\d+/{number}",
    r"gi\s*{number}",
)


def _port_token_end(line: str, port: str) -> int | None:
    """If line starts with a recognised name for port, return the end index."""
    stripped = line.lstrip()
    pad = len(line) - len(stripped)
    lower = stripped.lower()
    number = port.split("/")[-1]
    values = {"port": re.escape(port), "number": re.escape(number)}
    for pattern in _PORT_TOKEN_PATTERNS:
        match = re.match(pattern.format(**values), lower)
        if match is None:
            continue
        end = match.end()
        # Reject a following alnum (gi0/1 vs gi0/10) or '/' (gi1 vs gi1/0/7).
        if end == len(stripped) or not (
            stripped[end].isalnum() or stripped[end] == "/"
        ):
            return pad + end
    return None


def _is_interface_row(line: str) -> bool:
    return bool(
        re.match(
            r"(?i)^\s*(?:gi|gigabitethernet)\s*\d+(?:/\d+){0,2}(?:\s|$|[^0-9a-z])",
            line,
        )
    )


def _ends_with_text(row: str, text: str) -> bool:
    haystack = _collapse_ws(row)
    needle = _collapse_ws(text)
    if not needle:
        return False
    return haystack == needle or haystack.endswith(" " + needle)


def _is_truncated(
    parsed: str, expected: str, *, column_width: int | None
) -> bool:
    parsed_n = _collapse_ws(parsed)
    expected_n = _collapse_ws(expected)
    if not parsed_n or parsed_n == expected_n or not expected_n.startswith(parsed_n):
        return False
    if len(parsed_n) >= _MIN_TRUNCATION_PREFIX:
        return True
    return column_width is not None and len(parsed) == column_width


def _is_separator(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and bool(re.fullmatch(r"[\s\-=]+", line)) and any(
        char in stripped for char in "-="
    )


def _column_width_from_header(header: str, label_start: int, label_end: int) -> int | None:
    next_token = re.search(r"\S", header[label_end:])
    if next_token is None:
        return None
    width = (label_end + next_token.start()) - label_start
    return width if width > 0 else None


def _column_width_from_separator(line: str, header_col: int) -> int | None:
    # A distinct dash/equals bar starting at the header column, not a
    # single rule drawn across the whole table.
    if header_col >= len(line) or line[header_col] not in "-=":
        return None
    if header_col > 0 and line[header_col - 1] in "-=":
        return None
    end = header_col
    while end < len(line) and line[end] in "-=":
        end += 1
    width = end - header_col
    return width if width > 0 else None


def _output_preview(body: str) -> str:
    lines = [line.rstrip() for line in body.splitlines() if line.strip()]
    return "\n".join(lines[:_PREVIEW_LINES]) or "(empty)"


@dataclass(frozen=True)
class DescriptionRow:
    raw: str
    header_col: int | None
    parsed: str | None
    column_width: int | None


def find_description_row(
    output: str, port: str
) -> tuple[DescriptionRow | None, str]:
    """Locate the port row in a show interfaces description table.

    The second item is a short preview of the table body, for notes when
    the row cannot be found.
    """
    # run_config_and_readback wraps the table in a "--- <command> ---" line.
    # Do not treat a separator bar that merely contains " ---" as that wrapper.
    match = re.search(r"^--- .+ ---\n", output, re.MULTILINE)
    body = output[match.end() :] if match else output
    preview = _output_preview(body)
    header_col: int | None = None
    column_width: int | None = None
    for line in body.splitlines():
        raw = line.rstrip("\r")
        if not raw.strip():
            continue
        if not _is_interface_row(raw):
            if header_col is None:
                match = re.search(r"\bDescription\b", raw, re.IGNORECASE) or re.search(
                    r"\bName\b", raw, re.IGNORECASE
                )
                if match:
                    header_col = match.start()
                    column_width = _column_width_from_header(
                        raw, match.start(), match.end()
                    )
                    continue
            elif _is_separator(raw):
                sep_width = _column_width_from_separator(raw, header_col)
                if sep_width is not None:
                    column_width = sep_width
                continue
        if _port_token_end(raw, port) is None:
            continue
        if header_col is not None:
            field = raw[header_col:] if len(raw) > header_col else ""
            return (
                DescriptionRow(
                    raw=raw.rstrip(),
                    header_col=header_col,
                    parsed=field.strip(),
                    column_width=column_width,
                ),
                preview,
            )
        return (
            DescriptionRow(
                raw=raw.rstrip(),
                header_col=None,
                parsed=None,
                column_width=None,
            ),
            preview,
        )
    return None, preview


def parse_interface_description(output: str, port: str) -> str | None:
    """Return the header-column description for port, or None.

    ``None`` means the row was not found or the table header was not
    recognised (no Description/Name column). An empty string means the
    row was present with no description.
    """
    row, _ = find_description_row(output, port)
    if row is None or row.header_col is None:
        return None
    return row.parsed


def description_readback_note(readback: str, port: str, text: str | None) -> str:
    """Compare the parsed description for port with the requested text.

    The command is sent quoted; the switch should store and show the text
    without quotes. A quoted match means the quotes were stored literally.
    Comparisons collapse whitespace. Without a recognised header, a row
    that ends with the expected text is treated as verified; otherwise
    the note says the layout could not be verified. Truncation is
    accepted only for a strict prefix of at least 8 characters, or when
    a known column width (next header column or separator dash length)
    equals the parsed length. A missing row is never reported as a
    mismatch.
    """
    row, preview = find_description_row(readback, port)
    if row is None:
        return (
            "Read-back check: could not verify (port row not found). "
            f"Output starts with:\n{preview}"
        )
    if text is None:
        if row.header_col is None:
            end = _port_token_end(row.raw, port)
            remainder = _collapse_ws(row.raw[end:] if end is not None else row.raw)
            if not remainder:
                return "Read-back check: description is empty."
            return (
                "Read-back check: could not verify (unknown table layout): "
                f"{row.raw!r}"
            )
        if not row.parsed:
            return "Read-back check: description is empty."
        return f"Read-back check: description is still {row.parsed!r}."

    if row.header_col is None:
        if _ends_with_text(row.raw, f'"{text}"'):
            return (
                "Read-back check: description appears WITH quotes; the switch "
                "stored the quotes literally."
            )
        if _ends_with_text(row.raw, text):
            return "Read-back check: description found in read-back (without quotes)."
        return (
            "Read-back check: could not verify (unknown table layout): "
            f"{row.raw!r}"
        )

    parsed = row.parsed or ""
    parsed_n = _collapse_ws(parsed)
    if parsed_n == _collapse_ws(f'"{text}"'):
        return (
            "Read-back check: description appears WITH quotes; the switch "
            "stored the quotes literally."
        )
    if parsed_n == _collapse_ws(text):
        return "Read-back check: description found in read-back (without quotes)."
    if _is_truncated(parsed, text, column_width=row.column_width):
        return (
            "Read-back check: probably truncated by the switch table, ok "
            f"({parsed!r})."
        )
    if not parsed_n:
        return "Read-back check: description is empty in the read-back output."
    return f"Read-back check: description is {parsed!r}, expected {text!r}."


@mcp.tool()
def port_set_description(port: str, text: str | None = None) -> str:
    """Set an interface description, or clear it when text is omitted. Does not save."""
    params = {"port": port, "text": text}
    try:
        validate_port(port)
        if text is not None:
            validate_description(text)
        commands = build_description_commands(port, text)
        output = run_config_and_readback(commands, READBACK_DESCRIPTION)
        output = f"{output}\n\n{description_readback_note(output, port, text)}"
    except ValidationError as exc:
        return _fail("port_set_description", params, f"Rejected: {exc}", allowed=False)
    except SwitchConnectionError as exc:
        return _fail("port_set_description", params, f"Error: {exc}", allowed=True)
    return _ok("port_set_description", params, output)



def _snmp_exec(conn: Any, command: str) -> str:
    """Exec a show command; return raw device text. Caller must redact before returning."""
    return send_paged(conn, command)


def _snmp_syntax_note() -> str:
    return (
        "CLI syntax source: " + CLI_SOURCE + " "
        "These commands are not live-confirmed; have Redy verify them "
        "before relying on the result."
    )


def _snmp_fail(tool: str, params: dict[str, Any], exc: BaseException, *, allowed: bool) -> str:
    prefix = "Rejected: " if isinstance(exc, ValidationError) and not allowed else "Error: "
    # ValidationError is already written without the secret; still redact.
    return _fail(tool, params, prefix + str(exc), allowed=allowed)


def _verification_failed(exc: BaseException) -> SwitchConnectionError:
    return SwitchConnectionError(
        "Configuration was sent, verification failed: " + redact_secrets(str(exc))
    )


@mcp.tool()
def snmp_view_create(view_name: str, subtree: str) -> str:
    """Add one allow-listed included subtree to an SNMP view. Does not save.

    Gate this in the hub with unlock. subtree must be an OID or alias from
    the fixed allowlist (interfaces / ifmib / power-ethernet). The CLI
    syntax is not live-confirmed; see the README.
    """
    params = {"view_name": view_name, "subtree": subtree}
    try:
        require_snmp_write_enabled()
        view_name = validate_snmp_name(view_name, what="view name")
        oid = normalize_subtree(subtree)
        commands = build_view_create_commands(view_name, oid)
        output = run_config_and_readbacks(
            commands,
            [READBACK_SNMP_VIEW],
            enable_session_log=False,
            wide_terminal=True,
        )
        views = parse_snmp_viewtree(output)
        present = any(
            item.name.lower() == view_name.lower() and item.oid == oid
            for item in views
        )
        if present:
            note = (
                f"Read-back check: view {view_name} includes {oid}."
            )
        else:
            note = (
                f"Read-back check: could not verify that view {view_name} "
                f"includes {oid}. Confirm show snmp viewtree live; the "
                "parser assumes ISS key: value blocks."
            )
        body = (
            format_sent_commands(commands)
            + "\n\n"
            + output
            + "\n\n"
            + note
            + "\n"
            + _snmp_syntax_note()
        )
    except ValidationError as exc:
        return _snmp_fail("snmp_view_create", params, exc, allowed=False)
    except SwitchConnectionError as exc:
        return _snmp_fail("snmp_view_create", params, exc, allowed=True)
    return _ok("snmp_view_create", params, body)


def _precheck_view_for_community(conn: Any, view_name: str) -> None:
    views_text = _snmp_exec(conn, READBACK_SNMP_VIEW)
    views = parse_snmp_viewtree(views_text)
    if not views:
        raise ValidationError(
            "Could not parse show snmp viewtree (unknown table layout, or "
            "the view list is empty). Refusing to create a community until "
            "the view can be verified. Confirm the output format live."
        )
    names = {item.name.lower() for item in views}
    if view_name.lower() not in names:
        raise ValidationError(
            f"View {view_name!r} was not found in show snmp viewtree. "
            "Create it with snmp_view_create first."
        )
    ok, note = view_is_restricted(views, view_name)
    if not ok:
        raise ValidationError(
            note + ". Refusing to bind a community to a view that is not "
            "restricted to the OID allowlist."
        )


@mcp.tool()
def snmp_community_create(view_name: str, access: str) -> str:
    """Create a v2c community from SWITCH_SNMP_COMMUNITY, bound to a view.

    access is 'ro' or 'rw'. The secret is never a tool argument and is
    redacted as [REDACTED] in all output. Does not save. Gate with hub unlock.
    The CLI syntax is not live-confirmed; see the README.
    """
    params = {"view_name": view_name, "access": access}
    try:
        require_snmp_write_enabled()
        view_name = validate_snmp_name(view_name, what="view name")
        access = validate_snmp_access(access)
        community = validate_snmp_community_secret()
        commands = build_community_create_commands(view_name, access, community)

        def _run(conn: Any) -> str:
            _precheck_view_for_community(conn, view_name)
            _send_config(conn, commands)
            try:
                community_out = _snmp_exec(conn, READBACK_SNMP_COMMUNITY)
                group_out = _snmp_exec(conn, READBACK_SNMP_GROUP)
                access_out = _snmp_exec(conn, READBACK_SNMP_ACCESS)
                view_out = _snmp_exec(conn, READBACK_SNMP_VIEW)
                status = assert_configured_community_ready(
                    community_output=community_out,
                    group_output=group_out,
                    access_output=access_out,
                    view_output=view_out,
                    community=community,
                )
                return (
                    format_sent_commands(commands)
                    + "\n\nConfiguration sent.\n"
                    + f"--- {READBACK_SNMP_COMMUNITY} ---\n"
                    + redact_show_output(READBACK_SNMP_COMMUNITY, community_out)
                    + "\n"
                    + f"--- {READBACK_SNMP_GROUP} ---\n"
                    + redact_show_output(READBACK_SNMP_GROUP, group_out)
                    + "\n"
                    + f"--- {READBACK_SNMP_ACCESS} ---\n"
                    + redact_show_output(READBACK_SNMP_ACCESS, access_out)
                    + "\n"
                    + f"--- {READBACK_SNMP_VIEW} ---\n"
                    + redact_show_output(READBACK_SNMP_VIEW, view_out)
                    + "\n\n"
                    + "Read-back check: "
                    + status
                    + "\n"
                    + _snmp_syntax_note()
                )
            except (ValidationError, SwitchConnectionError) as exc:
                raise _verification_failed(exc) from None

        body = run_in_session(
            _run, enable_session_log=False, wide_terminal=True
        )
    except ValidationError as exc:
        return _snmp_fail("snmp_community_create", params, exc, allowed=False)
    except SwitchConnectionError as exc:
        return _snmp_fail("snmp_community_create", params, exc, allowed=True)
    return _ok("snmp_community_create", params, redact_secrets(body))


@mcp.tool()
def snmp_community_remove(name: str) -> str:
    """Remove an allow-listed default community (public or private).

    Refuses unless the configured SWITCH_SNMP_COMMUNITY community is
    present and mapped to a restricted allow-listed view. Never removes
    the configured community itself. Does not save. Gate with hub unlock.
    """
    params = {"name": name}
    try:
        require_snmp_write_enabled()
        community = validate_snmp_community_secret()
        requested = validate_community_remove_name(name, community)

        def _run(conn: Any) -> str:
            community_out = _snmp_exec(conn, READBACK_SNMP_COMMUNITY)
            group_out = _snmp_exec(conn, READBACK_SNMP_GROUP)
            access_out = _snmp_exec(conn, READBACK_SNMP_ACCESS)
            view_out = _snmp_exec(conn, READBACK_SNMP_VIEW)
            status = assert_configured_community_ready(
                community_output=community_out,
                group_output=group_out,
                access_output=access_out,
                view_output=view_out,
                community=community,
            )
            entries = parse_snmp_community(community_out)
            exact = resolve_removable_community_name(requested, entries, community)
            commands = build_community_remove_commands(exact)
            _send_config(conn, commands)
            try:
                after = _snmp_exec(conn, READBACK_SNMP_COMMUNITY)
                still = any(
                    (item.name.lower() == exact.lower())
                    or (item.index.lower() == exact.lower())
                    for item in parse_snmp_community(after)
                )
                if still:
                    note = (
                        f"Read-back check: {exact} is still present in "
                        "show snmp community after the no-command."
                    )
                else:
                    note = (
                        f"Read-back check: {exact} is no longer present in "
                        "show snmp community. "
                        + status
                    )
                return (
                    format_sent_commands(commands)
                    + "\n\n"
                    + status
                    + "\n\nConfiguration sent.\n"
                    + f"--- {READBACK_SNMP_COMMUNITY} ---\n"
                    + redact_show_output(READBACK_SNMP_COMMUNITY, after)
                    + "\n\n"
                    + note
                    + "\n"
                    + _snmp_syntax_note()
                )
            except (ValidationError, SwitchConnectionError) as exc:
                raise _verification_failed(exc) from None

        body = run_in_session(
            _run, enable_session_log=False, wide_terminal=True
        )
    except ValidationError as exc:
        return _snmp_fail("snmp_community_remove", params, exc, allowed=False)
    except SwitchConnectionError as exc:
        return _snmp_fail("snmp_community_remove", params, exc, allowed=True)
    return _ok("snmp_community_remove", params, redact_secrets(body))


@mcp.tool()
def snmp_user_remove(name: str) -> str:
    """Remove an allow-listed SNMP user (noAuthUser). Does not save.

    Gate this in the hub with unlock. The CLI syntax is not live-confirmed.
    """
    params = {"name": name}
    try:
        require_snmp_write_enabled()
        name = validate_user_remove_name(name)
        commands = build_user_remove_commands(name)

        def _run(conn: Any) -> str:
            before = _snmp_exec(conn, READBACK_SNMP_USER)
            if not user_present(before, name):
                return (
                    f"SNMP user {name} was not present in show snmp user; "
                    "no configuration was sent.\n"
                    f"--- {READBACK_SNMP_USER} ---\n"
                    + redact_show_output(READBACK_SNMP_USER, before)
                    + "\n"
                    + _snmp_syntax_note()
                )
            _send_config(conn, commands)
            try:
                after = _snmp_exec(conn, READBACK_SNMP_USER)
                if user_present(after, name):
                    note = (
                        f"Read-back check: {name} is still present in show snmp user."
                    )
                else:
                    note = (
                        f"Read-back check: {name} is no longer present in show snmp user."
                    )
                return (
                    format_sent_commands(commands)
                    + "\n\nConfiguration sent.\n"
                    + f"--- {READBACK_SNMP_USER} ---\n"
                    + redact_show_output(READBACK_SNMP_USER, after)
                    + "\n\n"
                    + note
                    + "\n"
                    + _snmp_syntax_note()
                )
            except (ValidationError, SwitchConnectionError) as exc:
                raise _verification_failed(exc) from None

        body = run_in_session(
            _run, enable_session_log=False, wide_terminal=True
        )
    except ValidationError as exc:
        return _snmp_fail("snmp_user_remove", params, exc, allowed=False)
    except SwitchConnectionError as exc:
        return _snmp_fail("snmp_user_remove", params, exc, allowed=True)
    return _ok("snmp_user_remove", params, redact_secrets(body))


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
    startup_checks()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
