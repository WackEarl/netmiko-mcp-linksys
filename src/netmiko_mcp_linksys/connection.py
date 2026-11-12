"""SSH session handling and CLI sequence builders.

No connection is opened at import or process start. Each tool call opens one
session, holds a process-wide lock for the duration, and disconnects after.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from netmiko import ConnectHandler

from netmiko_mcp_linksys.validation import (
    ValidationError,
    config_output_is_error,
    redact_secrets,
)

_LOCK = threading.Lock()

READBACK_INTERFACE = "show interfaces gigabitethernet {port}"
READBACK_POE = "show power inline gigabitethernet {port}"


class ConnectionError(RuntimeError):
    """Switch connection or CLI execution failed. Message is already redacted."""


def connect_params() -> dict[str, Any]:
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

    return {
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
    }


@contextmanager
def session() -> Iterator[Any]:
    """Yield a connected ConnectHandler, exclusive to one caller at a time."""
    params = connect_params()
    with _LOCK:
        conn = None
        try:
            conn = ConnectHandler(**params)
            yield conn
        except ValidationError:
            raise
        except Exception as exc:
            raise ConnectionError(redact_secrets(str(exc))) from None
        finally:
            if conn is not None:
                try:
                    conn.disconnect()
                except Exception:
                    pass


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
    if text is None:
        inner = "no description"
    else:
        inner = f"description {text}"
    return [
        f"interface gigabitethernet {port}",
        inner,
    ]


def run_show(command: str) -> str:
    with session() as conn:
        try:
            output = conn.send_command(command, use_textfsm=False)
        except Exception as exc:
            raise ConnectionError(redact_secrets(str(exc))) from None
    return output if isinstance(output, str) else str(output)


def run_config_set(commands: list[str]) -> str:
    with session() as conn:
        try:
            output = conn.send_config_set(
                commands,
                exit_config_mode=True,
                cmd_verify=True,
            )
        except Exception as exc:
            raise ConnectionError(redact_secrets(str(exc))) from None
        if config_output_is_error(str(output)):
            raise ConnectionError(
                "Device rejected the configuration sequence:\n"
                + redact_secrets(str(output))
            )
        return output if isinstance(output, str) else str(output)


def run_config_and_readback(commands: list[str], readback: str) -> str:
    """Apply a config set, then read the resulting state in the same session."""
    with session() as conn:
        try:
            config_output = conn.send_config_set(
                commands,
                exit_config_mode=True,
                cmd_verify=True,
            )
        except Exception as exc:
            raise ConnectionError(redact_secrets(str(exc))) from None
        config_text = config_output if isinstance(config_output, str) else str(config_output)
        if config_output_is_error(config_text):
            raise ConnectionError(
                "Device rejected the configuration sequence:\n"
                + redact_secrets(config_text)
            )
        try:
            state = conn.send_command(readback, use_textfsm=False)
        except Exception as exc:
            raise ConnectionError(
                "Configuration was sent, but read-back failed: "
                + redact_secrets(str(exc))
            ) from None
        state_text = state if isinstance(state, str) else str(state)
        return (
            "Configuration sent.\n"
            f"--- {readback} ---\n"
            f"{state_text}"
        )


def run_save() -> str:
    with session() as conn:
        try:
            output = conn.send_command("save", use_textfsm=False)
        except Exception as exc:
            raise ConnectionError(redact_secrets(str(exc))) from None
    text = output if isinstance(output, str) else str(output)
    if config_output_is_error(text):
        raise ConnectionError("save failed:\n" + redact_secrets(text))
    return text
