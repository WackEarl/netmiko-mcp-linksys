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


REDACTED_COMMUNITY = "[REDACTED]"

# View / group / security identifiers. Capped at 28 so derived names
# "{view}_grp" / "{view}_sec" stay within the CLI's 32-character limit.
SNMP_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,27}$")
SNMP_COMMUNITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_]{7,31}$")
SNMP_COMMUNITY_MIN = 8
SNMP_COMMUNITY_MAX = 32
DEFAULT_SNMP_COMMUNITIES = frozenset({"public", "private"})
SNMP_REMOVE_COMMUNITY_ALLOWLIST = frozenset({"public", "private"})
SNMP_REMOVE_USER_ALLOWLIST = frozenset({"noAuthUser"})
SNMP_RESERVED_NAMES = frozenset(
    {
        "iso",
        "restricted",
        "default",
        "defaultsuper",
        "initial",
        "public",
        "private",
        "noauthuser",
        "templatemd5",
        "templatesha",
        "netman",
        "none",
        "all",
        "snmp",
    }
)


# "snmp community name <secret> security" may wrap mid-secret (ISS
# terminals are often ~80-144 columns). The community token is only
# [A-Za-z0-9_] plus wrap whitespace, so this cannot eat later table
# labels such as "Security Name". The keyword "security" is matched
# case-sensitively (CLI spelling).
_COMMUNITY_CMD_SPAN_RE = re.compile(
    r"snmp[ \t]+community[ \t]+name(?:\s|\\[nrt])+"
    r"[A-Za-z0-9_\r\n\\]+"
    r"(?:\s|\\[nrt])+security\b"
)


def valid_community_for_redaction() -> str | None:
    """Return SWITCH_SNMP_COMMUNITY only when it passes validation.

    A short or malformed value must not be used for replacement; it
    would mangle unrelated output (for example ``1`` inside ``Gi0/1``).
    """
    if "SWITCH_SNMP_COMMUNITY" not in os.environ:
        return None
    raw = os.environ["SWITCH_SNMP_COMMUNITY"]
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return validate_snmp_community_secret(raw)
    except ValidationError:
        return None


def redact_community_command_spans(text: str) -> str:
    """Replace a (possibly wrapped) community-config command with a redacted span."""
    return _COMMUNITY_CMD_SPAN_RE.sub(
        "snmp community name " + REDACTED_COMMUNITY + " security",
        text,
    )


def _secret_variants(secret: str) -> list[str]:
    """Exact, case-preserving, re.escape, and repr/escape forms, longest first."""
    escaped = re.escape(secret)
    variants = {
        secret,
        escaped,
        escaped.replace("\\", "\\\\"),
        repr(secret),
        repr(escaped),
        repr(secret)[1:-1],
        repr(escaped)[1:-1],
    }
    return sorted((item for item in variants if item), key=len, reverse=True)


def _replace_secret_and_variants(text: str, secret: str, token: str) -> str:
    # Case-insensitive for the raw secret so a different device spelling
    # cannot leak. Escaped/repr forms are replaced exactly.
    text = re.sub(re.escape(secret), token, text, flags=re.IGNORECASE)
    for variant in _secret_variants(secret):
        if variant and variant in text and variant.lower() != secret.lower():
            text = text.replace(variant, token)
    return text


def redact_secrets(text: str) -> str:
    """Strip the switch password and SNMP community from shown or logged text.

    The community becomes ``[REDACTED]``; the SSH password stays ``***``
    (existing behaviour). Community config-line spans are redacted even
    when the secret is wrapped across line breaks. The env community is
    only substituted when it is a valid secret (see
    valid_community_for_redaction).
    """
    text = redact_community_command_spans(text)
    community = valid_community_for_redaction()
    if community:
        text = _replace_secret_and_variants(text, community, REDACTED_COMMUNITY)
    password = os.environ.get("SWITCH_PASSWORD") or ""
    if password and password in text:
        text = text.replace(password, "***")
    return text


def require_snmp_write_enabled() -> None:
    """Fail closed unless SWITCH_SNMP_WRITE_ENABLED=1 (live syntax unconfirmed)."""
    raw = (os.environ.get("SWITCH_SNMP_WRITE_ENABLED") or "").strip()
    if raw != "1":
        raise ValidationError(
            "SNMP write tools are disabled until the CLI syntax is "
            "live-confirmed. Set SWITCH_SNMP_WRITE_ENABLED=1 to enable "
            "them (off by default)."
        )


def validate_snmp_name(name: str, *, what: str = "name") -> str:
    """Strict identifier for view / group / security names (not secrets)."""
    if not isinstance(name, str) or not SNMP_NAME_RE.fullmatch(name):
        raise ValidationError(
            f"Invalid SNMP {what} {name!r}. Use 1..28 characters matching "
            "[A-Za-z][A-Za-z0-9_-]* (no dots, spaces, or quotes)."
        )
    if name.lower() in SNMP_RESERVED_NAMES:
        raise ValidationError(
            f"SNMP {what} {name!r} is reserved and cannot be used."
        )
    return name


def validate_snmp_access(access: str) -> str:
    if not isinstance(access, str) or access.lower() not in {"ro", "rw"}:
        raise ValidationError("access must be 'ro' or 'rw'.")
    return access.lower()


def validate_snmp_community_secret(raw: str | None = None) -> str:
    """Validate SWITCH_SNMP_COMMUNITY. Never echo the value in errors."""
    if raw is None:
        if "SWITCH_SNMP_COMMUNITY" not in os.environ:
            raise ValidationError(
                "SWITCH_SNMP_COMMUNITY is not set. Set it to a non-default "
                "community string (8..32 characters from [A-Za-z0-9_]). "
                "The value is never accepted as a tool argument."
            )
        raw = os.environ["SWITCH_SNMP_COMMUNITY"]
    if not isinstance(raw, str) or not raw:
        raise ValidationError(
            "SWITCH_SNMP_COMMUNITY is empty. Set it to a non-default "
            "community string (8..32 characters from [A-Za-z0-9_]). "
            "The value is not shown."
        )
    # Default names first, even when they are shorter than the minimum,
    # so the error is specific and still does not echo the value.
    if raw.lower() in DEFAULT_SNMP_COMMUNITIES:
        raise ValidationError(
            "SWITCH_SNMP_COMMUNITY must not be a default community "
            "(public or private)."
        )
    if raw != raw.strip() or not SNMP_COMMUNITY_RE.fullmatch(raw):
        raise ValidationError(
            "SWITCH_SNMP_COMMUNITY is invalid. Use "
            f"{SNMP_COMMUNITY_MIN}..{SNMP_COMMUNITY_MAX} characters from "
            "[A-Za-z0-9_], starting with alphanumeric, with no spaces, "
            "dots, dashes, or quotes. The value is not shown."
        )
    return raw


def validate_community_remove_name(name: str, configured: str) -> str:
    """Allow only public/private. Never allow the configured community."""
    if not isinstance(name, str) or not name:
        raise ValidationError(
            "Community name must be one of the removal allowlist: "
            + ", ".join(sorted(SNMP_REMOVE_COMMUNITY_ALLOWLIST))
            + "."
        )
    if name == configured or name.lower() == configured.lower():
        raise ValidationError(
            "Refusing to remove the configured SWITCH_SNMP_COMMUNITY community."
        )
    for allowed in SNMP_REMOVE_COMMUNITY_ALLOWLIST:
        if name == allowed or name.lower() == allowed.lower():
            return allowed
    raise ValidationError(
        f"Community {name!r} is not on the removal allowlist "
        f"({', '.join(sorted(SNMP_REMOVE_COMMUNITY_ALLOWLIST))})."
    )


def validate_user_remove_name(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise ValidationError(
            "User name must be one of the removal allowlist: "
            + ", ".join(sorted(SNMP_REMOVE_USER_ALLOWLIST))
            + "."
        )
    for allowed in SNMP_REMOVE_USER_ALLOWLIST:
        if name == allowed or name.lower() == allowed.lower():
            return allowed
    raise ValidationError(
        f"SNMP user {name!r} is not on the removal allowlist "
        f"({', '.join(sorted(SNMP_REMOVE_USER_ALLOWLIST))})."
    )


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
