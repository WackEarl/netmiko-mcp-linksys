"""JSON-lines audit log. Never records passwords."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netmiko_mcp_linksys.validation import redact_secrets


def _redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {str(key): _redact_obj(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_obj(item) for item in value]
    return value


def write_audit(
    *,
    tool: str,
    params: dict[str, Any],
    allowed: bool,
    result: str,
) -> None:
    path_str = (os.environ.get("SWITCH_AUDIT_LOG") or "").strip()
    if not path_str:
        return

    path = Path(path_str).expanduser()
    record = {
        "time": datetime.now(UTC).isoformat(),
        "tool": tool,
        "params": _redact_obj(params),
        "allowed": allowed,
        "result": redact_secrets(result),
    }
    line = redact_secrets(json.dumps(record, ensure_ascii=True, separators=(",", ":")))
    path.parent.mkdir(parents=True, exist_ok=True)
    created = not path.exists()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        if created:
            os.chmod(path, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            fd = -1
            handle.write(line + "\n")
    finally:
        if fd >= 0:
            os.close(fd)
