"""SSH session handling, pager handling, and CLI sequence builders.

No connection is opened at import or process start. Each tool call opens one
session, holds a process-wide lock for the duration, and disconnects after.
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from netmiko import ConnectHandler

from netmiko_mcp_linksys.output import strip_controls as _strip_controls
from netmiko_mcp_linksys.snmp_cli import redact_community_listing
from netmiko_mcp_linksys.validation import (
    ValidationError,
    config_output_is_error,
    redact_secrets,
)

_LOCK = threading.Lock()

READBACK_INTERFACE = "show interfaces gigabitethernet {port}"
READBACK_POE = "show power inline gigabitethernet {port}"
READBACK_DESCRIPTION = "show interfaces description"

DEFAULT_READ_TIMEOUT = 60.0
MAX_READ_TIMEOUT = 600.0

# Best-effort paging-off for the Aricent/ISS-based LGS CLI. On ISS-family
# firmware this is a Global Configuration command (it is rejected in
# privileged exec, which is what the 0.1.0 live test hit). The result is not
# trusted: the pager loop below handles paging either way.
PAGING_OFF_CONFIG = ("set cli pagination off",)

# Pager prompts seen on ISS / Cisco-SMB style CLIs, e.g. "--More--",
# "-- More --", "--More-- (45%)", "More: <space>,  Quit: q ...",
# "<--- More --->", "Press any key to continue (Q to quit)".
PAGER_RE = re.compile(
    r"(?:"
    r"-{2,}\s*\(?\s*more\s*\)?\s*-{2,}(?:\s*\(\d{1,3}%\))?"
    r"|<-+\s*more\s*-+>"
    r"|more:\s*<space>(?:[^\r\n]*?<return>)?"
    r"|press any key to continue(?:\s*\([^()\r\n]{0,40}\))?"
    r")",
    re.IGNORECASE,
)
# Marks where a pager prompt was cut; blank lines right after it are erase
# leftovers (netmiko turns the pager's "\r    \r" into newlines).
PAGE_BREAK = "\ue000"
MAX_PAGES = 2000

_warned: set[str] = set()


class ConnectionError(RuntimeError):
    """Switch connection or CLI execution failed. Message is already redacted."""


def warn(message: str, *, once_key: str | None = None) -> None:
    """Write a redacted warning to stderr (stdout is the MCP channel)."""
    if once_key is not None:
        if once_key in _warned:
            return
        _warned.add(once_key)
    print(f"netmiko-mcp-linksys: warning: {redact_secrets(message)}", file=sys.stderr, flush=True)


def read_timeout() -> float:
    raw = (os.environ.get("SWITCH_READ_TIMEOUT") or "").strip()
    if not raw:
        return DEFAULT_READ_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        raise ValidationError(
            f"SWITCH_READ_TIMEOUT must be a number of seconds, got {raw!r}."
        ) from None
    if not 1 <= value <= MAX_READ_TIMEOUT:
        raise ValidationError(
            f"SWITCH_READ_TIMEOUT must be between 1 and {int(MAX_READ_TIMEOUT)} seconds."
        )
    return value


def paging_off_enabled() -> bool:
    raw = (os.environ.get("SWITCH_PAGING_OFF") or "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def prepare_private_file(path_str: str) -> Path:
    """Create (if needed) an append-only file with mode 0600, or raise OSError."""
    path = Path(path_str).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    created = not path.exists()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        if created:
            os.chmod(path, 0o600)
    finally:
        os.close(fd)
    return path


def session_log_path() -> str | None:
    """Return a writable SWITCH_SESSION_LOG path, or None (never raises)."""
    raw = (os.environ.get("SWITCH_SESSION_LOG") or "").strip()
    if not raw:
        return None
    try:
        return str(prepare_private_file(raw))
    except OSError as exc:
        warn(
            f"SWITCH_SESSION_LOG {raw} is not writable ({exc}); session log disabled.",
            once_key=f"session-log:{raw}",
        )
        return None


def _commands_include_snmp_community(commands: list[str]) -> bool:
    return any(re.search(r"(?i)\bsnmp\s+community\b", command) for command in commands)


def _set_terminal_width_best_effort(conn: Any) -> None:
    """Widen the CLI if the driver supports it, so a community line is less likely to wrap."""
    setter = getattr(conn, "set_terminal_width", None)
    if not callable(setter):
        return
    try:
        setter(511)
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
        warn(
            f"could not set terminal width ({exc}); continuing.",
            once_key="term-width",
        )


def redact_show_output(command: str, text: str) -> str:
    """Redact secrets in exec output. Community listings are fully masked."""
    if re.search(r"(?i)\bshow\s+snmp\s+community\b", command.strip()):
        return redact_community_listing(text)
    return redact_secrets(text)


def redact_session_log_file() -> None:
    """Rewrite SWITCH_SESSION_LOG so a community echo cannot remain in clear text.

    Called after the netmiko session is disconnected. Failures are
    warnings only; they never raise.
    """
    raw = (os.environ.get("SWITCH_SESSION_LOG") or "").strip()
    if not raw:
        return
    path = Path(raw).expanduser()
    if not path.is_file():
        return
    try:
        original = path.read_text(encoding="utf-8", errors="replace")
        # Do not use listing fail-closed here: a session log is not a
        # show snmp community table and must not be replaced wholesale.
        redacted = redact_secrets(original)
        if redacted == original:
            return
        path.write_text(redacted, encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError as exc:
        warn(
            f"SWITCH_SESSION_LOG could not be redacted ({exc}).",
            once_key=f"session-log-redact:{raw}",
        )


def connect_params(*, enable_session_log: bool = True) -> dict[str, Any]:
    host = (os.environ.get("SWITCH_HOST") or "").strip()
    username = (os.environ.get("SWITCH_USER") or "").strip()
    password = os.environ.get("SWITCH_PASSWORD") or ""
    device_type = (os.environ.get("SWITCH_DEVICE_TYPE") or "cisco_s300").strip() or "cisco_s300"
    known_hosts = (os.environ.get("SWITCH_KNOWN_HOSTS") or "").strip()

    missing = [
        name
        for name, value in (
            ("SWITCH_HOST", host),
            ("SWITCH_USER", username),
            ("SWITCH_PASSWORD", password),
            ("SWITCH_KNOWN_HOSTS", known_hosts),
        )
        if not value
    ]
    if missing:
        raise ValidationError(
            "Missing required environment variable(s): " + ", ".join(missing)
        )
    if not Path(known_hosts).expanduser().is_file():
        raise ValidationError(
            f"SWITCH_KNOWN_HOSTS file does not exist: {known_hosts}"
        )

    params: dict[str, Any] = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "use_keys": False,
        "allow_agent": False,
        "ssh_strict": True,
        "system_host_keys": False,
        "alt_host_keys": True,
        "alt_key_file": str(Path(known_hosts).expanduser()),
        "conn_timeout": 15,
        "auth_timeout": 20,
        "fast_cli": False,
        "read_timeout_override": read_timeout(),
    }
    log_path = session_log_path() if enable_session_log else None
    if log_path is not None:
        # netmiko masks the password/secret in the session log (no_log), and
        # only channel reads are recorded (record_writes stays False).
        params["session_log"] = log_path
        params["session_log_file_mode"] = "append"
        params["session_log_record_writes"] = False
    return params


def disable_paging_best_effort(conn: Any) -> None:
    """Try the ISS paging-off command; never fail the tool call because of it."""
    if not paging_off_enabled():
        return
    try:
        output = conn.send_config_set(
            list(PAGING_OFF_CONFIG),
            exit_config_mode=True,
            cmd_verify=False,
            read_timeout=read_timeout(),
        )
    except Exception as exc:
        warn(f"paging-off sequence failed ({exc}); relying on pager handling.", once_key="paging")
        return
    if config_output_is_error(str(output), commands=list(PAGING_OFF_CONFIG)):
        warn(
            "switch rejected 'set cli pagination off'; relying on pager handling.",
            once_key="paging",
        )


@contextmanager
def session(
    *,
    enable_session_log: bool = True,
    wide_terminal: bool = False,
) -> Iterator[Any]:
    """Yield a connected ConnectHandler, exclusive to one caller at a time.

    SNMP write tools pass enable_session_log=False so a community echo
    cannot sit in the session log in the clear until disconnect.
    """
    params = connect_params(enable_session_log=enable_session_log)
    with _LOCK:
        conn = None
        try:
            conn = ConnectHandler(**params)
            disable_paging_best_effort(conn)
            if wide_terminal:
                _set_terminal_width_best_effort(conn)
            yield conn
        except ValidationError:
            raise
        except ConnectionError:
            raise
        except Exception as exc:
            raise ConnectionError(redact_secrets(str(exc))) from None
        finally:
            if conn is not None:
                try:
                    conn.disconnect()
                except Exception:
                    pass
            redact_session_log_file()


def _prompt_regex(conn: Any) -> re.Pattern[str]:
    base = getattr(conn, "base_prompt", None)
    if isinstance(base, str) and base.strip():
        return re.compile(r"^\s*" + re.escape(base.strip()) + r"[^\r\n#>]*[#>]\s*$")
    return re.compile(r"^\s*[\w.\-]+[^\r\n#>]*[#>]\s*$")


def _visible_tail(raw: str) -> str:
    """Last unterminated line as the terminal would show it."""
    text = _strip_controls(raw).replace(PAGE_BREAK, "")
    line = text.rsplit("\n", 1)[-1]
    if "\r" in line:
        segments = [seg for seg in line.split("\r") if seg.strip()]
        line = segments[-1] if segments else ""
    return line


def clean_output(raw: str, command: str, prompt_re: re.Pattern[str]) -> str:
    """Strip ANSI, control characters, pager prompts and their erase leftovers,
    the command echo, and the prompt.

    Blank lines directly before or after a page break are dropped
    (pager erase leftovers, including trailing blanks at the end of a
    page); blank lines elsewhere in the device output are kept.
    """
    text = _strip_controls(raw)
    text = PAGER_RE.sub("", text)
    text = text.replace("\r\n", "\n")
    lines: list[str] = []
    after_break = False
    for line in text.split("\n"):
        if PAGE_BREAK in line:
            line = line.replace(PAGE_BREAK, "")
            after_break = True
            while lines and not lines[-1].strip():
                lines.pop()
        if "\r" in line:
            segments = [seg for seg in line.split("\r") if seg.strip()]
            line = segments[-1] if segments else ""
        line = line.rstrip()
        if after_break:
            if not line.strip():
                continue
            after_break = False
        lines.append(line)
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and command.strip() and command.strip() in lines[0]:
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if lines and prompt_re.search(lines[-1]):
        lines.pop()
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def send_paged(
    conn: Any,
    command: str,
    *,
    timeout: float | None = None,
    poll_interval: float = 0.1,
) -> str:
    """Send one exec command and read until the prompt, paging through pagers.

    Each time the last visible line matches PAGER_RE a single space is sent.
    Finishes when the last visible line is the device prompt. ``timeout`` is
    an idle timeout: the seconds allowed without any new output.
    """
    limit = read_timeout() if timeout is None else timeout
    prompt_re = _prompt_regex(conn)
    try:
        conn.clear_buffer()
    except Exception:
        pass
    conn.write_channel(command + getattr(conn, "RETURN", "\n"))
    buffer = ""
    scan_from = 0
    pages = 0
    deadline = time.monotonic() + limit
    while True:
        chunk = conn.read_channel()
        if chunk:
            buffer += chunk
            deadline = time.monotonic() + limit
            tail = _visible_tail(buffer[scan_from:])
            if PAGER_RE.search(tail):
                pages += 1
                if pages > MAX_PAGES:
                    raise ConnectionError(f"Gave up after {MAX_PAGES} pager pages for {command!r}.")
                # Drop the pager line itself; PAGER_RE in clean_output is only
                # a fallback for prompts that are echoed elsewhere.
                cut = buffer.rfind("\n", scan_from)
                buffer = buffer[: cut + 1] if cut >= 0 else buffer[:scan_from]
                buffer += PAGE_BREAK
                conn.write_channel(" ")
                scan_from = len(buffer)
                continue
            if "\n" in buffer and prompt_re.search(tail):
                return clean_output(buffer, command, prompt_re)
        elif time.monotonic() > deadline:
            last = _visible_tail(buffer)[-80:]
            raise ConnectionError(
                f"No prompt after {command!r} ({limit:g}s without new output, "
                f"pages: {pages}, last line: {redact_secrets(last)!r})."
            )
        else:
            time.sleep(poll_interval)


def build_admin_state_commands(port: str, enabled: bool) -> list[str]:
    return [
        f"interface gigabitethernet {port}",
        "no shutdown" if enabled else "shutdown",
    ]


def build_poe_commands(port: str, enabled: bool) -> list[str]:
    return [
        f"interface gigabitethernet {port}",
        "power inline enable" if enabled else "power inline disable",
    ]


def build_description_commands(port: str, text: str | None) -> list[str]:
    """Always quote the text: the LGS CLI takes only one word unquoted.

    validate_description() forbids quotes in the text, so quoting is safe.
    """
    if text is None:
        inner = "no description"
    else:
        inner = f'description "{text}"'
    return [
        f"interface gigabitethernet {port}",
        inner,
    ]


def send_paged_redacted(conn: Any, command: str) -> str:
    """send_paged, then redact secrets (and community listings)."""
    return redact_show_output(command, send_paged(conn, command))


def run_show(command: str) -> str:
    with session() as conn:
        return send_paged_redacted(conn, command)


def run_shows(commands: list[str]) -> dict[str, str]:
    """Run several exec commands in one session; values are already redacted."""
    with session() as conn:
        return {command: send_paged_redacted(conn, command) for command in commands}


def _send_config(conn: Any, commands: list[str]) -> str:
    try:
        output = conn.send_config_set(
            commands,
            exit_config_mode=True,
            cmd_verify=True,
            read_timeout=read_timeout(),
        )
    except Exception as exc:
        if _commands_include_snmp_community(commands):
            # Never return or log str(exc): netmiko cmd_verify timeouts
            # embed repr(re.escape(command)), which bypasses exact redaction.
            raise ConnectionError(
                "Device rejected the configuration sequence "
                f"({type(exc).__name__}). The exception text is omitted "
                "because the sequence may include a community string."
            ) from None
        raise ConnectionError(redact_secrets(str(exc))) from None
    text = output if isinstance(output, str) else str(output)
    if config_output_is_error(text, commands=commands):
        raise ConnectionError(
            "Device rejected the configuration sequence:\n" + redact_secrets(text)
        )
    return redact_secrets(text)


def run_config_set(commands: list[str]) -> str:
    with session() as conn:
        return _send_config(conn, commands)


def run_config_and_readback(commands: list[str], readback: str) -> str:
    """Apply a config set, then read the resulting state in the same session."""
    with session() as conn:
        _send_config(conn, commands)
        try:
            state_text = send_paged(conn, readback)
        except Exception as exc:
            raise ConnectionError(
                "Configuration was sent, but read-back failed: "
                + redact_secrets(str(exc))
            ) from None
        return (
            "Configuration sent.\n"
            f"--- {readback} ---\n"
            f"{redact_show_output(readback, state_text)}"
        )


def run_config_and_readbacks(
    commands: list[str],
    readbacks: list[str],
    *,
    enable_session_log: bool = True,
    wide_terminal: bool = False,
) -> str:
    """Apply a config set, then run one or more exec read-backs in the same session."""
    with session(
        enable_session_log=enable_session_log, wide_terminal=wide_terminal
    ) as conn:
        _send_config(conn, commands)
        sections: list[str] = ["Configuration sent."]
        for readback in readbacks:
            try:
                state_text = send_paged_redacted(conn, readback)
            except ConnectionError as exc:
                raise ConnectionError(
                    "Configuration was sent, but read-back failed: "
                    + redact_secrets(str(exc))
                ) from None
            sections.append(f"--- {readback} ---\n{state_text}")
        return "\n".join(sections)


def run_in_session(
    callback: Any,
    *,
    enable_session_log: bool = True,
    wide_terminal: bool = False,
) -> Any:
    """Run ``callback(conn)`` inside a locked session. Output must be redacted by the caller if needed."""
    with session(
        enable_session_log=enable_session_log, wide_terminal=wide_terminal
    ) as conn:
        return callback(conn)


def run_save() -> str:
    with session() as conn:
        try:
            text = send_paged(conn, "save")
        except ConnectionError:
            raise
        except Exception as exc:
            raise ConnectionError(redact_secrets(str(exc))) from None
    if config_output_is_error(text, commands=["save"]):
        raise ConnectionError("save failed:\n" + redact_secrets(text))
    return redact_secrets(text)
