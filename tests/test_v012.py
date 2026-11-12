"""0.1.2: quoted descriptions and page-break cleanup (issue #1)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from netmiko_mcp_linksys.connection import (
    build_description_commands,
    clean_output,
    send_paged,
)
from netmiko_mcp_linksys.server import description_readback_note, port_set_description
from tests.test_pager_audit import FakeChannel

READBACK_HEAD = "Gi0/24 up, line protocol is up (connected)"


def test_description_with_space_is_quoted() -> None:
    assert build_description_commands("0/7", "Repeater EG") == [
        "interface gigabitethernet 0/7",
        'description "Repeater EG"',
    ]


def test_single_word_description_is_quoted_too() -> None:
    assert build_description_commands("0/7", "NAS")[1] == 'description "NAS"'


def test_clear_description_is_unquoted() -> None:
    assert build_description_commands("0/7", None)[1] == "no description"


@pytest.mark.parametrize("text", ['Repeater "EG"', "Repeater 'EG'", 'a"b'])
def test_quotes_in_input_still_rejected(text: str) -> None:
    with patch("netmiko_mcp_linksys.server.run_config_and_readback") as run:
        result = port_set_description("0/7", text)
    run.assert_not_called()
    assert result.startswith("Rejected:")


def test_port_set_description_sends_quoted_and_checks_readback() -> None:
    readback = (
        "Configuration sent.\n--- show interfaces gigabitethernet 0/7 ---\n"
        f"{READBACK_HEAD}\nDescription: Repeater EG\n"
    )
    with patch(
        "netmiko_mcp_linksys.server.run_config_and_readback", return_value=readback
    ) as run:
        result = port_set_description("0/7", "Repeater EG")
    commands, _ = run.call_args.args
    assert commands[1] == 'description "Repeater EG"'
    assert result.startswith("Configuration sent.")
    assert "description found in read-back (without quotes)" in result


def test_readback_note_variants() -> None:
    assert "WITH quotes" in description_readback_note('Description: "Repeater EG"', "Repeater EG")
    assert "without quotes" in description_readback_note("Description: Repeater EG", "Repeater EG")
    assert "not visible" in description_readback_note(READBACK_HEAD, "Repeater EG")
    # header line is ignored
    header = "Configuration sent.\n--- show interfaces gigabitethernet 0/7 ---\n" + READBACK_HEAD
    assert "not visible" in description_readback_note(header, "interfaces")
    # no substring false positives
    assert "not visible" in description_readback_note("Description: Repeater EG2", "Repeater EG")


def _rows(start: int, stop: int) -> str:
    # netmiko already normalised \r\n -> \n and stray \r -> \n in read_channel
    return "".join(f"Gi0/{n}   connected   1   a-full   a-1000M\n" for n in range(start, stop))


@pytest.mark.parametrize(
    "erase",
    [
        "\n        \n",                 # "\r        \r" after netmiko's \r -> \n
        "\x1b\n        \n\n",           # orphaned ESC (rest stripped by netmiko)
        "\x1b[K\n\x1b[1D\x1b[8D",       # erase-line / cursor-left variants
        "\x1b[2K\x1bE\n",               # erase line + ESC E (next line)
        "\x1b",                         # lone ESC directly before the next row
        "\x08" * 8 + " " * 8 + "\x08" * 8,  # backspace erase
        "\x1b[0;7m\x1b[m\x07\n",        # attributes + BEL
    ],
)
def test_page_break_leftovers_are_removed(erase: str) -> None:
    chan = FakeChannel(
        [
            ["show interfaces status\n", _rows(1, 21), "\x1b[7m--More--", "\x1b[m"],
            [erase, _rows(21, 29), "\nLGS328PC#"],
        ]
    )
    out = send_paged(chan, "show interfaces status", timeout=2, poll_interval=0)
    lines = out.splitlines()
    assert len(lines) == 28, lines
    assert lines[19].startswith("Gi0/20 ")
    assert lines[20].startswith("Gi0/21 ")
    assert "\x1b" not in out and "\x08" not in out and "\x07" not in out
    assert "More" not in out and "\ue000" not in out


def test_split_escape_across_chunks_after_pager() -> None:
    chan = FakeChannel(
        [
            ["show power inline\n", _rows(1, 5), "--More--"],
            ["\x1b", "[K\n", _rows(5, 9), "LGS328PC#"],
        ]
    )
    out = send_paged(chan, "show power inline", timeout=2, poll_interval=0)
    assert out.splitlines()[4].startswith("Gi0/5 ")
    assert "[K" not in out and "\x1b" not in out


def test_legit_blank_lines_are_kept() -> None:
    chan = FakeChannel(
        [
            ["show power inline\n", "Power budget: 250W\n", "\n", "Port  Status\n", "--More--"],
            ["\n        \n", "Gi0/1 on\n", "\n", "Total: 1\n", "LGS328PC#"],
        ]
    )
    out = send_paged(chan, "show power inline", timeout=2, poll_interval=0)
    assert out == "Power budget: 250W\n\nPort  Status\nGi0/1 on\n\nTotal: 1"


def test_clean_output_without_page_break_keeps_blank_lines() -> None:
    import re

    prompt = re.compile(r"^\s*LGS328PC[^\r\n#>]*[#>]\s*$")
    assert clean_output("show x\na\n\nb\nLGS328PC#", "show x", prompt) == "a\n\nb"


def test_unterminated_osc_does_not_eat_line():
    import re as _re

    from netmiko_mcp_linksys.connection import clean_output
    out = clean_output("\x1b]0 real line\nLGS328PC#", "", _re.compile(r"^LGS328PC#\s*$"))
    assert "real line" in out


def test_terminated_osc_is_stripped():
    import re as _re

    from netmiko_mcp_linksys.connection import clean_output
    out = clean_output("\x1b]0;title\x07Gi0/1 up\nLGS328PC#", "", _re.compile(r"^LGS328PC#\s*$"))
    assert "Gi0/1 up" in out and "title" not in out


def test_whitespace_only_description_rejected():
    import pytest as _pytest

    from netmiko_mcp_linksys.validation import ValidationError, validate_description
    with _pytest.raises(ValidationError):
        validate_description("   ")
