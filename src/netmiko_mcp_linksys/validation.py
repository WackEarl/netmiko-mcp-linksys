"""Hard parameter checks applied before any switch connection is opened."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence

from netmiko_mcp_linksys.output import strip_controls

PORT_RE = re.compile(r"^0/([1-9]|1[0-9]|2[0-8])$")
POE_PORT_RE = re.compile(r"^0/([1-9]|1[0-9]|2[0-4])$")
DESCRIPTION_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,32}$")
UNSAFE_SHOW_CHARS_RE = re.compile(r"[|;\r\n]")

MAX_PORT = 28
MAX_POE_PORT = 24

_MISSING_PROTECTED = (
    "SWITCH_PROTECTED_PORTS is not set. Refusing to disable any port "
    "(fail-closed). Set it to a comma-separated list such as 0/24,0/25."
)
_EMPTY_PROTECTED = (
    "SWITCH_PROTECTED_PORTS is empty. Refusing to disable any port "
    "(fail-closed). Set it to a comma-separated list such as 0/24,0/25."
)


class ValidationError(ValueError):
    """User-facing validation failure. Safe to return as a tool result."""


def redact_secrets(text: str) -> str:
    """Strip the switch password from any text that might be shown or logged."""
    password = os.environ.get("SWITCH_PASSWORD") or ""
    if password and password in text:
        text = text.replace(password, "***")
    return text


def parse_protected_ports(raw: str | None = None) -> set[str]:
    """Return the configured protected ports, or raise (fail-closed).

    An unset, empty, or invalid SWITCH_PROTECTED_PORTS value is a
    configuration error, not "no ports are protected".
    """
    if raw is None:
        if "SWITCH_PROTECTED_PORTS" not in os.environ:
            raise ValidationError(_MISSING_PROTECTED)
        raw = os.environ["SWITCH_PROTECTED_PORTS"]
    ports = {part.strip() for part in raw.split(",") if part.strip()}
    if not ports:
        raise ValidationError(_EMPTY_PROTECTED)
    invalid = sorted(port for port in ports if not PORT_RE.fullmatch(port))
    if invalid:
        raise ValidationError(
            "SWITCH_PROTECTED_PORTS contains invalid port(s): "
            + ", ".join(invalid)
            + ". Refusing to disable any port (fail-closed)."
        )
    return ports


def validate_port(port: str, *, poe: bool = False) -> str:
    if not isinstance(port, str) or not PORT_RE.fullmatch(port):
        raise ValidationError(
            f"Invalid port {port!r}. Expected 0/1..0/{MAX_PORT} (no leading zeros)."
        )
    if poe and not POE_PORT_RE.fullmatch(port):
        raise ValidationError(
            f"PoE is only supported on 0/1..0/{MAX_POE_PORT}, not {port}."
        )
    return port


def validate_description(text: str) -> str:
    if not isinstance(text, str) or not DESCRIPTION_RE.fullmatch(text):
        raise ValidationError(
            "Invalid description. Use 1..32 characters from [A-Za-z0-9 ._-]; "
            "no quotes, '?', '|', or control characters."
        )
    if text != text.strip():
        raise ValidationError(
            "Invalid description. Leading or trailing spaces are not allowed."
        )
    return text


def reject_unsafe_show_command(command: str) -> str:
    """Reject '|', ';', and newlines before the netmiko-mcp filter runs."""
    if not isinstance(command, str) or UNSAFE_SHOW_CHARS_RE.search(command):
        raise ValidationError(
            "Command rejected: '|', ';', and newlines are not allowed."
        )
    return command


def reject_if_protected(port: str, *, disabling: bool, action: str) -> None:
    """Reject shutdown / PoE-off on ports listed in SWITCH_PROTECTED_PORTS.

    When disabling is True, an unset, empty, or invalid protected-port list
    also rejects the action (fail-closed). Enabling a port is still allowed.
    """
    if not disabling:
        return
    protected = parse_protected_ports()
    if port in protected:
        raise ValidationError(
            f"Refusing {action} on protected port {port}. "
            "Protected ports come from SWITCH_PROTECTED_PORTS."
        )


# Hostname, optional (config…) mode, then # or >. Used to drop a leading
# prompt so echoed commands and prompt-only lines can be skipped.
_PROMPT_PREFIX_RE = re.compile(r"^[\w.\-]+(?:\([^)\r\n]*\))?[#>]\s*")
_ERROR_WORD_RE = re.compile(r"\b(?:Error|Invalid)\b", re.IGNORECASE)


def _line_without_prompt(line: str) -> str:
    match = _PROMPT_PREFIX_RE.match(line)
    if match is None:
        return line
    return line[match.end() :].strip()


def _normalize_echo(text: str) -> str:
    """Drop double quotes, collapse whitespace, and strip for echo compares."""
    return " ".join(text.replace('"', "").split())


def config_output_is_error(output: str, *, commands: Sequence[str]) -> bool:
    """Classify switch config/save output as a device rejection.

    Each line is first run through strip_controls (same helper as the
    output cleanup, including the terminated-OSC rule). After that:

    * If the line contains '%' anywhere, it is an error. That includes a
      prompt and an error on the same line, e.g.
      ``LGS328PC(config-if)#% Invalid input``. Sent commands cannot
      contain '%' (descriptions allow only [A-Za-z0-9 ._-]).
    * A leading prompt (hostname, optional ``(config…)``, then ``#`` or
      ``>``) is removed. An empty remainder (prompt-only) is skipped.
    * If the remainder matches one of the commands just sent — after
      dropping double quotes, collapsing whitespace, and stripping —
      the line is an echo and is skipped. An unquoted echo such as
      ``description Error LED`` therefore matches the sent
      ``description "Error LED"``.
    * Otherwise the words ``Error`` and ``Invalid`` (case-insensitive)
      are treated as a failure, so a line such as
      ``Error: port is protected`` is caught.
    """
    if not output:
        return False
    sent = {
        _normalize_echo(command)
        for command in commands
        if _normalize_echo(command)
    }
    for line in output.splitlines():
        stripped = strip_controls(line).strip()
        if not stripped:
            continue
        if "%" in stripped:
            return True
        remainder = _line_without_prompt(stripped)
        if not remainder or _normalize_echo(remainder) in sent:
            continue
        if _ERROR_WORD_RE.search(remainder):
            return True
    return False
