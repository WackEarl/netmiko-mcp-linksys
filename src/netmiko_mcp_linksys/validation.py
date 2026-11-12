"""Hard parameter checks applied before any switch connection is opened."""

from __future__ import annotations

import os
import re

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


def config_output_is_error(output: str) -> bool:
    """Heuristic: treat %, Invalid, or Error in device output as failure."""
    if not output:
        return False
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("%") or "Invalid" in stripped or "Error" in stripped:
            return True
    return False
