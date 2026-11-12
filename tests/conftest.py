"""Set env before netmiko-mcp settings and the package are imported."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
COMMANDS = EXAMPLES / "commands.yml"

os.environ.setdefault("NETMIKO_MCP_COMMAND_FILE", str(COMMANDS))
os.environ.setdefault("SWITCH_HOST", "192.0.2.10")
os.environ.setdefault("SWITCH_USER", "dummy-user")
os.environ.setdefault("SWITCH_PASSWORD", "dummy-password-not-real")
os.environ.setdefault("SWITCH_DEVICE_TYPE", "cisco_s300")
os.environ.setdefault("SWITCH_KNOWN_HOSTS", str(EXAMPLES / "known_hosts"))
os.environ.setdefault("SWITCH_PROTECTED_PORTS", "0/24,0/25")


@pytest.fixture
def commands_file() -> Path:
    return COMMANDS


@pytest.fixture
def reset_command_file(monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys.server import prepare_runtime

    monkeypatch.setenv("NETMIKO_MCP_COMMAND_FILE", str(COMMANDS))
    prepare_runtime()


@pytest.fixture
def audit_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "audit.log"
    monkeypatch.setenv("SWITCH_AUDIT_LOG", str(path))
    return path
