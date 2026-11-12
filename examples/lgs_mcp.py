#!/usr/bin/env python3
"""Thin shim kept for the old `python /config/netmiko/lgs_mcp.py` hub entry.

The intended installation path is the packaged entrypoint:

    uvx --from git+https://github.com/WackEarl/netmiko-mcp-linksys@v0.1.2 netmiko-mcp-linksys

This file is not a standalone implementation. The `netmiko-mcp-linksys`
package must be installed in the same environment. For the older
`uv run --no-project --with ... python /config/netmiko/lgs_mcp.py` form, add:

    --with git+https://github.com/WackEarl/netmiko-mcp-linksys@v0.1.2
"""

from __future__ import annotations

import sys
from pathlib import Path

_CANDIDATES = (
    Path("/workspace/netmiko-mcp-linksys/src"),
    Path(__file__).resolve().parent.parent.parent / "netmiko-mcp-linksys" / "src",
    Path(__file__).resolve().parent / "src",
)
for _src in _CANDIDATES:
    if _src.is_dir() and str(_src) not in sys.path:
        sys.path.insert(0, str(_src))
        break

from netmiko_mcp_linksys.server import main

if __name__ == "__main__":
    main()
