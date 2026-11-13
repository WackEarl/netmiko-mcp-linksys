"""Quoted descriptions, description read-back, and page-break cleanup (#1, #2)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from netmiko_mcp_linksys.connection import (
    PAGE_BREAK,
    READBACK_DESCRIPTION,
    build_description_commands,
    clean_output,
    send_paged,
)
from netmiko_mcp_linksys.server import (
    description_readback_note,
    parse_interface_description,
    port_set_description,
)
from tests.test_pager_audit import FakeChannel


# Assumed Cisco/ISS-style show interfaces description table. The v0.1.2 live
# retest confirmed that this command shows e.g. "Repeater EG" without quotes,
# but no full table was captured. Rows are fixed-width; Description starts
# at the same column as the header word. Confirm on the next live test.
def _desc_row(port: str, status: str, proto: str, desc: str) -> str:
    return f"Gi{port}".ljust(31) + status.ljust(15) + proto.ljust(9) + desc


ASSUMED_DESCRIPTION_HEADER = (
    "Interface".ljust(31) + "Status".ljust(15) + "Protocol".ljust(9) + "Description"
)
ASSUMED_INTERFACES_DESCRIPTION = "\n".join(
    [
        ASSUMED_DESCRIPTION_HEADER,
        _desc_row("0/1", "up", "up", ""),
        _desc_row("0/7", "up", "up", "Repeater EG"),
        _desc_row("0/17", "down", "down", "Invalid Port"),
        _desc_row("0/24", "up", "up", "nas uplink"),
    ]
)


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


def test_port_set_description_reads_back_interfaces_description() -> None:
    readback = (
        "Configuration sent.\n--- show interfaces description ---\n"
        + ASSUMED_INTERFACES_DESCRIPTION
        + "\n"
    )
    with patch(
        "netmiko_mcp_linksys.server.run_config_and_readback", return_value=readback
    ) as run:
        result = port_set_description("0/7", "Repeater EG")
    commands, command = run.call_args.args
    assert commands[1] == 'description "Repeater EG"'
    assert command == READBACK_DESCRIPTION == "show interfaces description"
    assert result.startswith("Configuration sent.")
    assert "description found in read-back (without quotes)" in result


def test_parse_interface_description_from_assumed_table() -> None:
    table = ASSUMED_INTERFACES_DESCRIPTION
    assert parse_interface_description(table, "0/7") == "Repeater EG"
    assert parse_interface_description(table, "0/1") == ""
    assert parse_interface_description(table, "0/17") == "Invalid Port"
    assert parse_interface_description(table, "0/2") is None
    # Gi0/1 must not match the Gi0/17 row.
    assert parse_interface_description(table, "0/1") != "Invalid Port"


def test_parse_interface_description_ignores_other_ports_and_header() -> None:
    wrapped = (
        "Configuration sent.\n--- show interfaces description ---\n"
        + ASSUMED_INTERFACES_DESCRIPTION
    )
    assert parse_interface_description(wrapped, "0/7") == "Repeater EG"
    # A substring on another port is not this port's description.
    assert parse_interface_description(wrapped, "0/24") == "nas uplink"


def test_readback_note_variants() -> None:
    table = ASSUMED_INTERFACES_DESCRIPTION
    assert "without quotes" in description_readback_note(table, "0/7", "Repeater EG")
    quoted = table.replace("Repeater EG", '"Repeater EG"')
    assert "WITH quotes" in description_readback_note(quoted, "0/7", "Repeater EG")
    missing = description_readback_note(table, "0/2", "Repeater EG")
    assert "could not verify (port row not found)" in missing
    assert "Interface" in missing
    assert "expected" not in missing
    assert "expected" in description_readback_note(table, "0/7", "nas uplink")
    assert "is empty" in description_readback_note(table, "0/1", "Repeater EG")
    assert "description is empty." in description_readback_note(table, "0/1", None)
    assert "still" in description_readback_note(table, "0/7", None)


@pytest.mark.parametrize(
    "row",
    [
        "Gi0/7  Up  Up  Repeater EG",
        "gi7  Up  Up  Repeater EG",
        "gi1/0/7  Up  Up  Repeater EG",
        "GigabitEthernet0/7  Up  Up  Repeater EG",
    ],
)
def test_readback_without_header_ends_with_description(row: str) -> None:
    note = description_readback_note(row, "0/7", "Repeater EG")
    assert "without quotes" in note
    assert "could not verify" not in note
    assert "expected" not in note


def test_readback_without_header_unknown_layout_includes_raw_row() -> None:
    row = "Gi0/7  Up  Up  something else"
    note = description_readback_note(row, "0/7", "Repeater EG")
    assert "could not verify (unknown table layout)" in note
    assert "Gi0/7  Up  Up  something else" in note
    assert "expected" not in note


def test_readback_without_header_collapses_whitespace() -> None:
    row = "Gi0/7   Up   Up   Repeater    EG"
    assert "without quotes" in description_readback_note(row, "0/7", "Repeater EG")


def test_readback_truncated_description_is_ok() -> None:
    table = "\n".join(
        [
            ASSUMED_DESCRIPTION_HEADER,
            _desc_row("0/7", "up", "up", "Repeater EG Wohnzimme"),
        ]
    )
    note = description_readback_note(table, "0/7", "Repeater EG Wohnzimmer")
    assert "probably truncated by the switch table, ok" in note
    assert "Repeater EG Wohnzimme" in note
    assert "expected" not in note


def test_readback_short_prefix_ok_when_it_fills_column_width() -> None:
    # No trailing padding: the parsed field runs to the end of the line.
    header = ASSUMED_DESCRIPTION_HEADER
    col = header.find("Description")
    row = ("Gi0/7".ljust(col) + "Repeat")
    table = header + "\n" + row
    note = description_readback_note(table, "0/7", "Repeater EG")
    assert "probably truncated by the switch table, ok" in note


def test_short_port_form_does_not_match_three_level_row() -> None:
    # gi1/0/7 is port 0/7, not a short gi1 (port 0/1).
    row = "gi1/0/7  Up  Up  Repeater EG"
    assert "without quotes" in description_readback_note(row, "0/7", "Repeater EG")
    note = description_readback_note(row, "0/1", "Repeater EG")
    assert "could not verify (port row not found)" in note
    assert "expected" not in note


def test_readback_port_row_not_found_includes_preview_not_mismatch() -> None:
    table = "Header junk\nGi0/10  Up  Up  Repeater EG\n"
    note = description_readback_note(table, "0/1", "Repeater EG")
    assert "could not verify (port row not found)" in note
    assert "Gi0/10" in note
    assert "expected" not in note


def test_readback_header_collapses_whitespace_in_comparison() -> None:
    table = "\n".join(
        [
            ASSUMED_DESCRIPTION_HEADER,
            _desc_row("0/7", "up", "up", "Repeater  EG"),
        ]
    )
    assert "without quotes" in description_readback_note(table, "0/7", "Repeater EG")


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


def test_blank_lines_immediately_before_page_break_are_removed() -> None:
    # Live leftover of #2: two blank lines at the end of a page, before --More--.
    chan = FakeChannel(
        [
            ["show interfaces status\n", _rows(1, 21), "\n\n", "--More--"],
            [_rows(21, 29), "\nLGS328PC#"],
        ]
    )
    out = send_paged(chan, "show interfaces status", timeout=2, poll_interval=0)
    lines = out.splitlines()
    assert len(lines) == 28, lines
    assert lines[19].startswith("Gi0/20 ")
    assert lines[20].startswith("Gi0/21 ")
    assert "\n\n" not in out


def test_clean_output_drops_blanks_on_both_sides_of_page_break() -> None:
    import re

    prompt = re.compile(r"^\s*LGS328PC[^\r\n#>]*[#>]\s*$")
    raw = "show x\nGi0/20\n\n\n" + PAGE_BREAK + "\n\nGi0/21\n\nLGS328PC#"
    assert clean_output(raw, "show x", prompt) == "Gi0/20\nGi0/21"
