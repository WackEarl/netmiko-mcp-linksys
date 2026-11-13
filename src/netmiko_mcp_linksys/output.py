"""ANSI / control-character stripping for switch CLI output."""

from __future__ import annotations

import re

# CSI (ESC [ params intermediates final), OSC (ESC ] ... BEL/ST), charset
# selection (ESC ( B), and the common two-byte ESC 7/8/=/>/D/E/H/M/c.
# Any ESC left after this is dropped on its own (netmiko strips per read,
# which can orphan an ESC).
# An OSC sequence is only stripped when terminated (BEL or ST); an
# unterminated ESC ] is not treated as an OSC, so only the ESC byte is
# dropped and the rest of the line is kept.
ANSI_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b\][^\x07\x1b\n]*(?:\x07|\x1b\\)"
    r"|\x1b[()#%][A-Za-z0-9]"
    r"|\x1b[78=>DEHMc\\]"
)
# C0 controls other than \t, \n, \r, \b (handled separately), plus DEL.
CONTROL_RE = re.compile(r"[\x00-\x07\x0b\x0c\x0e-\x1f\x7f]")


def _apply_backspaces(text: str) -> str:
    if "\b" not in text:
        return text
    out: list[str] = []
    for char in text:
        if char == "\b":
            if out and out[-1] != "\n":
                out.pop()
        else:
            out.append(char)
    return "".join(out)


def strip_controls(raw: str) -> str:
    """Remove ANSI/VT100 sequences, orphaned ESC bytes, backspaces, and other
    control characters (keeps \t, \n, \r and the PAGE_BREAK marker)."""
    text = ANSI_RE.sub("", raw).replace("\x1b", "")
    text = _apply_backspaces(text)
    return CONTROL_RE.sub("", text)
