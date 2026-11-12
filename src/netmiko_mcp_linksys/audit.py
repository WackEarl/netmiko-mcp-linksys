"""JSON-lines audit log. Never records passwords. Never breaks a tool call."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any

from netmiko_mcp_linksys.connection import prepare_private_file, warn
from netmiko_mcp_linksys.validation import redact_secrets


def _redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {str(key): _redact_obj(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_obj(item) for item in value]
    return value


def audit_path() -> str:
    return (os.environ.get("SWITCH_AUDIT_LOG") or "").strip()


def write_audit(
    *,
    tool: str,
    params: dict[str, Any],
    allowed: bool,
    result: str,
) -> str | None:
    """Append one audit line. Return a warning string on failure, else None.

    Failures (read-only file system, permissions, full disk, ...) are written
    to stderr and returned so the caller can surface them; they never raise.
    """
    path_str = audit_path()
    if not path_str:
        return None

    try:
        record = {
            "time": datetime.now(UTC).isoformat(),
            "tool": tool,
            "params": _redact_obj(params),
            "allowed": allowed,
            "result": redact_secrets(result),
        }
        line = redact_secrets(json.dumps(record, ensure_ascii=True, separators=(",", ":")))
        path = prepare_private_file(path_str)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except Exception as exc:
        message = redact_secrets(f"audit log {path_str} not written: {exc}")
        warn(message)
        return message
    return None


def check_audit_path() -> str | None:
    """Startup check: verify SWITCH_AUDIT_LOG is writable. Warn, never abort."""
    path_str = audit_path()
    if not path_str:
        warn("SWITCH_AUDIT_LOG is not set; tool calls are not audited.")
        return None
    try:
        path = prepare_private_file(path_str)
        if not os.access(path, os.W_OK):
            raise PermissionError(f"{path} is not writable")
    except Exception as exc:
        message = redact_secrets(
            f"SWITCH_AUDIT_LOG {path_str} is not writable ({exc}). Tools keep "
            "working, but audit entries will be missing and results will carry "
            "an audit_warning line."
        )
        warn(message)
        return message
    return None


__all__ = ["check_audit_path", "write_audit"]
