from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from netmiko_mcp_linksys.connection import (
    ConnectionError,
    redact_session_log_file,
    redact_show_output,
)
from netmiko_mcp_linksys.snmp_cli import (
    READBACK_SNMP_ACCESS,
    READBACK_SNMP_COMMUNITY,
    READBACK_SNMP_GROUP,
    READBACK_SNMP_USER,
    READBACK_SNMP_VIEW,
    assert_configured_community_ready,
    build_community_create_commands,
    build_community_remove_commands,
    build_user_remove_commands,
    build_view_create_commands,
    build_write_view_commands,
    case_variant_view_names,
    format_sent_commands,
    group_name_for_view,
    mask_is_exact,
    normalize_subtree,
    normalize_write_subtree,
    parse_snmp_access,
    parse_snmp_community,
    parse_snmp_group,
    parse_snmp_user,
    parse_snmp_viewtree,
    protected_admin_status_oids,
    redact_community_listing,
    resolve_removable_community_name,
    security_name_for_view,
    user_present,
    view_is_restricted,
    view_is_write_safe,
)
from netmiko_mcp_linksys.validation import (
    ValidationError,
    parse_protected_ifindexes,
    redact_secrets,
    validate_community_remove_name,
    validate_snmp_access,
    validate_snmp_community_secret,
    validate_snmp_name,
    validate_user_remove_name,
)

# Dummy test secret only. Never a real community.
SECRET = "HaIfMibComm9x"


COMMUNITY_SHOW = """
Community Index: public
Community Name: public
Security Name: none
Context Name:
Storage Type: volatile
Row Status: active
------------------------------
Community Index: ifmib
Community Name: HaIfMibComm9x
Security Name: ifmib_sec
Context Name:
Storage Type: nonVolatile
Row Status: active
------------------------------
Community Index: private
Community Name: private
Security Name: none
Storage Type: volatile
Row Status: active
"""

VIEW_SHOW_RESTRICTED = """
View Name: iso
Subtree OID: 1
Subtree Mask:
View Type: included
Storage Type: nonVolatile
Row Status: active
------------------------------
View Name: ifmib
Subtree OID: 1.3.6.1.2.1.2
Subtree Mask:
View Type: included
Storage Type: nonVolatile
Row Status: active
------------------------------
View Name: ifmib
Subtree OID: 1.3.6.1.2.1.31
Subtree Mask:
View Type: included
Storage Type: nonVolatile
Row Status: active
------------------------------
View Name: ifmib_w
Subtree OID: 1.3.6.1.2.1.2.2.1.7
Subtree Mask:
View Type: included
Storage Type: nonVolatile
Row Status: active
------------------------------
View Name: ifmib_w
Subtree OID: 1.3.6.1.2.1.2.2.1.7.124
Subtree Mask:
View Type: excluded
Storage Type: nonVolatile
Row Status: active
------------------------------
View Name: ifmib_w
Subtree OID: 1.3.6.1.2.1.2.2.1.7.125
Subtree Mask:
View Type: excluded
Storage Type: nonVolatile
Row Status: active
"""

VIEW_SHOW_WITH_POE = VIEW_SHOW_RESTRICTED + """
------------------------------
View Name: ifmib
Subtree OID: 1.3.6.1.2.1.105
Subtree Mask:
View Type: included
Storage Type: nonVolatile
Row Status: active
"""

GROUP_SHOW = """
Group Name: ifmib_grp
User Name: ifmib_sec
Security Model: v2c
Storage Type: nonVolatile
Row Status: active
------------------------------
Group Name: iso
User Name: none
Security Model: v1
Row Status: active
"""

ACCESS_SHOW_RW = """
Group Name: ifmib_grp
Security Model: v2c
Read View: ifmib
Write View: ifmib_w
Notify View: none
Storage Type: nonVolatile
Row Status: active
"""

ACCESS_SHOW_ISO_WRITE = """
Group Name: ifmib_grp
Security Model: v2c
Read View: ifmib
Write View: iso
Notify View: none
"""

USER_SHOW = """
Engine ID               : 80.00.08.1c.04.46.53
User                    : noAuthUser
Authentication Protocol : None
Privacy Protocol        : None
Storage Type            : Nonvolatile
Row Status              : Active
------------------------------
Engine ID               : 80.00.08.1c.04.46.53
User                    : templateMD5
Authentication Protocol : MD5
Privacy Protocol        : None
"""


@pytest.fixture(autouse=True)
def enable_snmp_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_SNMP_WRITE_ENABLED", "1")


# Dummy ifIndex values for the conftest SWITCH_PROTECTED_PORTS (0/24,0/25).
# Deliberately not the port numbers: the real mapping is verified live.
IFINDEX_ENV = "0/24=124,0/25=125"
EXCLUDED_OIDS = ["1.3.6.1.2.1.2.2.1.7.124", "1.3.6.1.2.1.2.2.1.7.125"]


@pytest.fixture(autouse=True)
def protected_ifindexes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_SNMP_PROTECTED_IFINDEXES", IFINDEX_ENV)


@pytest.fixture
def community_env(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", SECRET)
    return SECRET


def test_validate_snmp_name_accepts_and_rejects() -> None:
    assert validate_snmp_name("ifmib", what="view name") == "ifmib"
    assert validate_snmp_name("Ha_View-1", what="view name") == "Ha_View-1"
    with pytest.raises(ValidationError, match="Invalid SNMP view name"):
        validate_snmp_name("1bad", what="view name")
    with pytest.raises(ValidationError, match="Invalid SNMP view name"):
        validate_snmp_name("has.dot", what="view name")
    with pytest.raises(ValidationError, match="Invalid SNMP view name"):
        validate_snmp_name("name with space", what="view name")
    with pytest.raises(ValidationError, match="reserved"):
        validate_snmp_name("iso", what="view name")
    with pytest.raises(ValidationError, match="reserved"):
        validate_snmp_name("DefaultSuper", what="view name")
    # 29 characters would overflow {name}_grp (32-char CLI limit is 28+4).
    with pytest.raises(ValidationError, match="Invalid SNMP view name"):
        validate_snmp_name("a" + "b" * 28, what="view name")


def test_validate_snmp_access() -> None:
    assert validate_snmp_access("RO") == "ro"
    assert validate_snmp_access("rw") == "rw"
    with pytest.raises(ValidationError, match="ro"):
        validate_snmp_access("admin")


def test_community_secret_validation_never_echoes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SWITCH_SNMP_COMMUNITY", raising=False)
    with pytest.raises(ValidationError, match="not set") as missing:
        validate_snmp_community_secret()
    assert "SWITCH_SNMP_COMMUNITY is not set" in str(missing.value)

    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", "public")
    with pytest.raises(ValidationError, match="must not be a default") as pub:
        validate_snmp_community_secret()
    assert "public or private" in str(pub.value)

    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", "PRIVATE")
    with pytest.raises(ValidationError, match="must not be a default"):
        validate_snmp_community_secret()

    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", "short")
    with pytest.raises(ValidationError, match="invalid") as short:
        validate_snmp_community_secret()
    assert "short" not in str(short.value)

    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", "has space!!")
    with pytest.raises(ValidationError, match="invalid") as bad:
        validate_snmp_community_secret()
    assert "has space" not in str(bad.value)
    assert "The value is not shown" in str(bad.value)

    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", "Ha.If-Mib.Comm9")
    with pytest.raises(ValidationError, match="invalid") as dotted:
        validate_snmp_community_secret()
    assert "Ha.If" not in str(dotted.value)

    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", "A" * 33)
    with pytest.raises(ValidationError, match="invalid"):
        validate_snmp_community_secret()

    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", "Abcdefg1")
    assert validate_snmp_community_secret() == "Abcdefg1"
    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", "A" * 32)
    assert validate_snmp_community_secret() == "A" * 32

    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", SECRET)
    assert validate_snmp_community_secret() == SECRET


def test_remove_name_allowlist_and_configured_guard(community_env: str) -> None:
    assert validate_community_remove_name("PUBLIC", SECRET) == "public"
    assert validate_community_remove_name("private", SECRET) == "private"
    with pytest.raises(ValidationError, match="not on the removal allowlist"):
        validate_community_remove_name("guest", SECRET)
    with pytest.raises(ValidationError, match="configured SWITCH_SNMP_COMMUNITY"):
        validate_community_remove_name(SECRET, SECRET)
    with pytest.raises(ValidationError, match="configured SWITCH_SNMP_COMMUNITY"):
        validate_community_remove_name(SECRET.lower(), SECRET)
    # Error must not contain the secret.
    with pytest.raises(ValidationError) as exc:
        validate_community_remove_name(SECRET, SECRET)
    assert SECRET not in str(exc.value)


def test_user_remove_allowlist() -> None:
    assert validate_user_remove_name("noAuthUser") == "noAuthUser"
    assert validate_user_remove_name("noauthuser") == "noAuthUser"
    with pytest.raises(ValidationError, match="not on the removal allowlist"):
        validate_user_remove_name("admin")
    with pytest.raises(ValidationError, match="not on the removal allowlist"):
        validate_user_remove_name("templateMD5")


def test_normalize_subtree_allowlist() -> None:
    assert normalize_subtree("interfaces") == "1.3.6.1.2.1.2"
    assert normalize_subtree("ifmib") == "1.3.6.1.2.1.31"
    assert normalize_subtree("1.3.6.1.2.1.105") == "1.3.6.1.2.1.105"
    assert normalize_subtree("power-ethernet") == "1.3.6.1.2.1.105"
    with pytest.raises(ValidationError, match="allowlist"):
        normalize_subtree("1.3.6.1.2.1.1")
    with pytest.raises(ValidationError, match="allowlist"):
        normalize_subtree("1.3.6.1.2.1.2.2.1.7")
    with pytest.raises(ValidationError, match="allowlist"):
        normalize_subtree("1")


def test_command_builders_and_redacted_listing(community_env: str) -> None:
    view_cmds = build_view_create_commands("ifmib", "1.3.6.1.2.1.2")
    assert view_cmds == ["snmp view ifmib 1.3.6.1.2.1.2 included"]
    cmds = build_community_create_commands("ifmib", "rw", SECRET, "ifmib_w")
    assert cmds[0] == "snmp group ifmib_grp user ifmib_sec security-model v2c"
    assert cmds[1] == "snmp access ifmib_grp v2c read ifmib write ifmib_w notify none"
    assert cmds[2] == f"snmp community name {SECRET} security ifmib_sec"
    # Security name is derived, not the secret.
    assert security_name_for_view("ifmib") == "ifmib_sec"
    assert group_name_for_view("ifmib") == "ifmib_grp"
    assert SECRET not in cmds[0]
    assert SECRET not in cmds[1]
    listing = format_sent_commands(cmds)
    assert SECRET not in listing
    assert "[REDACTED]" in listing
    assert "snmp community name [REDACTED] security ifmib_sec" in listing
    ro = build_community_create_commands("ifmib", "ro", SECRET)
    assert "write none" in ro[1]
    assert build_community_remove_commands("public") == ["no snmp community name public"]
    assert build_user_remove_commands("noAuthUser") == ["no snmp user noAuthUser"]


def test_redact_secrets_uses_redacted_token(community_env: str) -> None:
    text = f"community {SECRET} and password dummy-password-not-real"
    out = redact_secrets(text)
    assert SECRET not in out
    assert "dummy-password-not-real" not in out
    assert "[REDACTED]" in out
    assert "***" in out


def test_redact_community_listing_hides_all_names(community_env: str) -> None:
    out = redact_community_listing(COMMUNITY_SHOW)
    assert SECRET not in out
    assert "Community Name: [REDACTED]" in out
    assert "Community Name: public" not in out
    assert "Community Name: private" not in out
    # Security name is not the secret and may remain.
    assert "ifmib_sec" in out


def test_redact_show_output_for_community_command(community_env: str) -> None:
    out = redact_show_output("show snmp community", COMMUNITY_SHOW)
    assert SECRET not in out
    assert "[REDACTED]" in out
    # Other shows still redact the env value.
    other = redact_show_output("show snmp group", f"User Name: {SECRET}")
    assert SECRET not in other
    assert "[REDACTED]" in other


def test_redact_in_exception_message(community_env: str) -> None:
    err = ConnectionError(
        redact_secrets(f"Device rejected:\nsnmp community name {SECRET} security ifmib_sec")
    )
    assert SECRET not in str(err)
    assert "[REDACTED]" in str(err)


def test_audit_redacts_community(audit_log, community_env: str) -> None:
    from netmiko_mcp_linksys.audit import write_audit

    write_audit(
        tool="snmp_community_create",
        params={"note": f"leaked {SECRET}"},
        allowed=True,
        result=f"echo {SECRET}",
    )
    body = audit_log.read_text(encoding="utf-8")
    assert SECRET not in body
    assert "[REDACTED]" in body
    record = json.loads(body.splitlines()[-1])
    assert record["params"]["note"] == "leaked [REDACTED]"
    assert record["result"] == "echo [REDACTED]"


def test_session_log_redaction_does_not_clobber_unrelated_index(
    tmp_path, community_env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "session.log"
    path.write_text(
        "Port Index: 1\nGi0/1 up, line protocol is up\n"
        f"snmp community name {SECRET} security ifmib_sec\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SWITCH_SESSION_LOG", str(path))
    redact_session_log_file()
    body = path.read_text(encoding="utf-8")
    assert SECRET not in body
    assert "Port Index: 1" in body
    assert "Gi0/1" in body
    assert "[REDACTED]" in body


def test_session_log_is_redacted_after_write(
    tmp_path, community_env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "session.log"
    path.write_text(
        f"LGS328PC(config)# snmp community name {SECRET} security ifmib_sec\n"
        "Community Name: public\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SWITCH_SESSION_LOG", str(path))
    redact_session_log_file()
    body = path.read_text(encoding="utf-8")
    assert SECRET not in body
    assert "[REDACTED]" in body
    assert (path.stat().st_mode & 0o777) == 0o600


def test_parsers_read_iss_blocks() -> None:
    communities = parse_snmp_community(COMMUNITY_SHOW)
    assert [item.name for item in communities] == ["public", SECRET, "private"]
    assert communities[1].security_name == "ifmib_sec"
    views = parse_snmp_viewtree(VIEW_SHOW_RESTRICTED)
    assert [(item.name, item.oid) for item in views if item.name == "ifmib"] == [
        ("ifmib", "1.3.6.1.2.1.2"),
        ("ifmib", "1.3.6.1.2.1.31"),
    ]
    groups = parse_snmp_group(GROUP_SHOW)
    assert groups[0].group == "ifmib_grp"
    assert groups[0].user == "ifmib_sec"
    access = parse_snmp_access(ACCESS_SHOW_RW)
    assert access[0].read_view == "ifmib"
    assert access[0].write_view == "ifmib_w"
    users = parse_snmp_user(USER_SHOW)
    assert user_present(USER_SHOW, "noAuthUser")
    assert not user_present(USER_SHOW, "admin")
    assert {item.name for item in users} == {"noAuthUser", "templateMD5"}


def test_view_is_restricted() -> None:
    views = parse_snmp_viewtree(VIEW_SHOW_RESTRICTED)
    ok, note = view_is_restricted(views, "ifmib")
    assert ok
    assert "1.3.6.1.2.1.2" in note
    ok, note = view_is_restricted(views, "iso")
    assert not ok
    assert "broad subtree" in note
    ok, note = view_is_restricted(parse_snmp_viewtree(VIEW_SHOW_WITH_POE), "ifmib")
    assert ok
    assert "1.3.6.1.2.1.105" in note


def test_configured_community_ready_success(community_env: str) -> None:
    status = assert_configured_community_ready(
        community_output=COMMUNITY_SHOW,
        group_output=GROUP_SHOW,
        access_output=ACCESS_SHOW_RW,
        view_output=VIEW_SHOW_RESTRICTED,
        community=SECRET,
    )
    assert SECRET not in status
    assert "ifmib_grp" in status
    assert "allow-listed" in status


def test_refuse_remove_when_community_missing(community_env: str) -> None:
    only_defaults = """
Community Index: public
Community Name: public
Security Name: none
------------------------------
"""
    with pytest.raises(ValidationError, match="not present") as exc:
        assert_configured_community_ready(
            community_output=only_defaults,
            group_output=GROUP_SHOW,
            access_output=ACCESS_SHOW_RW,
            view_output=VIEW_SHOW_RESTRICTED,
            community=SECRET,
        )
    assert SECRET not in str(exc.value)


def test_refuse_remove_when_write_view_is_iso(community_env: str) -> None:
    with pytest.raises(ValidationError, match="not allowed in a write view") as exc:
        assert_configured_community_ready(
            community_output=COMMUNITY_SHOW,
            group_output=GROUP_SHOW,
            access_output=ACCESS_SHOW_ISO_WRITE,
            view_output=VIEW_SHOW_RESTRICTED,
            community=SECRET,
        )
    assert SECRET not in str(exc.value)


def test_refuse_when_community_listing_unparseable(community_env: str) -> None:
    with pytest.raises(ValidationError, match="Could not parse"):
        assert_configured_community_ready(
            community_output="garbage without keys",
            group_output=GROUP_SHOW,
            access_output=ACCESS_SHOW_RW,
            view_output=VIEW_SHOW_RESTRICTED,
            community=SECRET,
        )


def test_resolve_removable_uses_device_spelling(community_env: str) -> None:
    listing = """
Community Index: PUBLIC
Community Name: PUBLIC
Security Name: none
------------------------------
Community Index: ifmib
Community Name: HaIfMibComm9x
Security Name: ifmib_sec
"""
    entries = parse_snmp_community(listing)
    assert resolve_removable_community_name("public", entries, SECRET) == "PUBLIC"
    with pytest.raises(ValidationError, match="configured"):
        resolve_removable_community_name(SECRET, entries, SECRET)


def _fake_snmp_session(
    shows: dict[str, str] | Any, sent_log: list[list[str]]
) -> Any:
    """run_in_session stand-in: canned show output, records config sets."""

    def exec_cmd(_conn: Any, command: str) -> str:
        return shows(command) if callable(shows) else shows[command]

    def send(_conn: Any, commands: list[str]) -> str:
        sent_log.append(list(commands))
        return "ok"

    def fake_session(callback: Any, **_kwargs: Any) -> str:
        with (
            patch("netmiko_mcp_linksys.server._snmp_exec", side_effect=exec_cmd),
            patch("netmiko_mcp_linksys.server._send_config", side_effect=send),
        ):
            return callback(object())

    return fake_session


def test_snmp_view_create_tool() -> None:
    from netmiko_mcp_linksys.server import snmp_view_create

    sent: list[list[str]] = []
    session = _fake_snmp_session(
        {READBACK_SNMP_ACCESS: ACCESS_SHOW_RW, READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED},
        sent,
    )
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        result = snmp_view_create("ifmib", "interfaces")
    assert sent == [["snmp view ifmib 1.3.6.1.2.1.2 included"]]
    assert "--- show snmp viewtree ---" in result
    assert "Read-back check: view ifmib includes 1.3.6.1.2.1.2" in result
    assert "Not live-confirmed" in result or "not live-confirmed" in result.lower()


def test_snmp_view_create_rejects_bad_oid() -> None:
    from netmiko_mcp_linksys.server import snmp_view_create

    with patch("netmiko_mcp_linksys.server.run_in_session") as run:
        result = snmp_view_create("ifmib", "1.3.6.1.2.1.1")
    run.assert_not_called()
    assert result.startswith("Rejected:")
    assert "allowlist" in result


def test_snmp_community_create_and_redaction(community_env: str) -> None:
    from netmiko_mcp_linksys.server import snmp_community_create

    shows = {
        READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED,
        READBACK_SNMP_COMMUNITY: COMMUNITY_SHOW,
        READBACK_SNMP_GROUP: GROUP_SHOW,
        READBACK_SNMP_ACCESS: ACCESS_SHOW_RW,
    }

    def fake_session(callback: Any, **_kwargs: Any) -> str:
        class Conn:
            pass

        with (
            patch(
                "netmiko_mcp_linksys.server._snmp_exec",
                side_effect=lambda conn, command: shows[command],
            ),
            patch("netmiko_mcp_linksys.server._send_config", return_value="ok") as sent,
        ):
            result = callback(Conn())
            sent.assert_called_once()
            sent_cmds = sent.call_args.args[1]
            assert sent_cmds[-1] == f"snmp community name {SECRET} security ifmib_sec"
        return result

    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=fake_session):
        result = snmp_community_create("ifmib", "rw", "ifmib_w")
    assert SECRET not in result
    assert "[REDACTED]" in result
    assert "snmp community name [REDACTED] security ifmib_sec" in result
    assert "Read-back check:" in result
    assert "ifmib_grp" in result


def test_snmp_community_create_requires_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys.server import snmp_community_create

    monkeypatch.delenv("SWITCH_SNMP_COMMUNITY", raising=False)
    with patch("netmiko_mcp_linksys.server.run_in_session") as run:
        result = snmp_community_create("ifmib", "rw")
    run.assert_not_called()
    assert result.startswith("Rejected:")
    assert "SWITCH_SNMP_COMMUNITY is not set" in result


def test_snmp_community_create_refuses_missing_view(community_env: str) -> None:
    from netmiko_mcp_linksys.server import snmp_community_create

    def fake_session(callback: Any, **_kwargs: Any) -> str:
        with (
            patch(
                "netmiko_mcp_linksys.server._snmp_exec",
                return_value=VIEW_SHOW_RESTRICTED,
            ),
            patch("netmiko_mcp_linksys.server._send_config") as sent,
        ):
            try:
                return callback(object())
            finally:
                sent.assert_not_called()

    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=fake_session):
        result = snmp_community_create("missingview", "ro")
    assert result.startswith("Rejected:")
    assert "was not found" in result


def test_snmp_community_remove_happy_path(community_env: str) -> None:
    from netmiko_mcp_linksys.server import snmp_community_remove

    after = """
Community Index: ifmib
Community Name: HaIfMibComm9x
Security Name: ifmib_sec
------------------------------
Community Index: private
Community Name: private
Security Name: none
"""
    calls: list[str] = []

    def exec_cmd(_conn: Any, command: str) -> str:
        calls.append(command)
        if command == READBACK_SNMP_COMMUNITY:
            return after if calls.count(command) > 1 else COMMUNITY_SHOW
        if command == READBACK_SNMP_GROUP:
            return GROUP_SHOW
        if command == READBACK_SNMP_ACCESS:
            return ACCESS_SHOW_RW
        if command == READBACK_SNMP_VIEW:
            return VIEW_SHOW_RESTRICTED
        raise AssertionError(command)

    def fake_session(callback: Any, **_kwargs: Any) -> str:
        with (
            patch("netmiko_mcp_linksys.server._snmp_exec", side_effect=exec_cmd),
            patch("netmiko_mcp_linksys.server._send_config", return_value="ok") as sent,
        ):
            result = callback(object())
            sent.assert_called_once()
            assert sent.call_args.args[1] == ["no snmp community name public"]
        return result

    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=fake_session):
        result = snmp_community_remove("public")
    assert SECRET not in result
    assert "no longer present" in result
    assert "no snmp community name public" in result


def test_snmp_community_remove_refuses_without_configured(
    community_env: str,
) -> None:
    from netmiko_mcp_linksys.server import snmp_community_remove

    only_defaults = """
Community Index: public
Community Name: public
Security Name: none
"""

    def fake_session(callback: Any, **_kwargs: Any) -> str:
        def exec_cmd(_conn: Any, command: str) -> str:
            if command == READBACK_SNMP_COMMUNITY:
                return only_defaults
            if command == READBACK_SNMP_GROUP:
                return GROUP_SHOW
            if command == READBACK_SNMP_ACCESS:
                return ACCESS_SHOW_RW
            if command == READBACK_SNMP_VIEW:
                return VIEW_SHOW_RESTRICTED
            raise AssertionError(command)

        with (
            patch("netmiko_mcp_linksys.server._snmp_exec", side_effect=exec_cmd),
            patch("netmiko_mcp_linksys.server._send_config") as sent,
        ):
            try:
                return callback(object())
            finally:
                sent.assert_not_called()

    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=fake_session):
        result = snmp_community_remove("public")
    assert result.startswith("Rejected:")
    assert "not present" in result
    assert SECRET not in result


def test_snmp_community_remove_refuses_configured_name(community_env: str) -> None:
    from netmiko_mcp_linksys.server import snmp_community_remove

    with patch("netmiko_mcp_linksys.server.run_in_session") as run:
        result = snmp_community_remove(SECRET)
    run.assert_not_called()
    assert result.startswith("Rejected:")
    assert "configured SWITCH_SNMP_COMMUNITY" in result
    assert SECRET not in result


def test_snmp_user_remove_and_already_absent() -> None:
    from netmiko_mcp_linksys.server import snmp_user_remove

    def fake_session_present(callback: Any, **_kwargs: Any) -> str:
        after = USER_SHOW.replace("noAuthUser", "goneUser")

        def exec_cmd(_conn: Any, command: str) -> str:
            assert command == READBACK_SNMP_USER
            return after if exec_cmd.calls else USER_SHOW  # type: ignore[attr-defined]

        exec_cmd.calls = 0  # type: ignore[attr-defined]

        def counted(_conn: Any, command: str) -> str:
            text = USER_SHOW if exec_cmd.calls == 0 else after
            exec_cmd.calls += 1  # type: ignore[attr-defined]
            return text

        with (
            patch("netmiko_mcp_linksys.server._snmp_exec", side_effect=counted),
            patch("netmiko_mcp_linksys.server._send_config", return_value="ok") as sent,
        ):
            result = callback(object())
            sent.assert_called_once()
            assert sent.call_args.args[1] == ["no snmp user noAuthUser"]
        return result

    with patch(
        "netmiko_mcp_linksys.server.run_in_session", side_effect=fake_session_present
    ):
        result = snmp_user_remove("noAuthUser")
    assert "no longer present" in result
    assert "no snmp user noAuthUser" in result

    def fake_session_absent(callback: Any, **_kwargs: Any) -> str:
        with (
            patch(
                "netmiko_mcp_linksys.server._snmp_exec",
                return_value="User                    : templateMD5\n",
            ),
            patch("netmiko_mcp_linksys.server._send_config") as sent,
        ):
            result = callback(object())
            sent.assert_not_called()
        return result

    with patch(
        "netmiko_mcp_linksys.server.run_in_session", side_effect=fake_session_absent
    ):
        result = snmp_user_remove("noAuthUser")
    assert "was not present" in result
    assert "no configuration was sent" in result


def test_show_snmp_community_is_allowed_and_redacted(
    reset_command_file: None,
    community_env: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netmiko_mcp_linksys.server import show

    monkeypatch.setattr(
        "netmiko_mcp_linksys.server.run_show",
        lambda cmd: redact_show_output(cmd, COMMUNITY_SHOW),
    )
    result = show("show snmp community")
    assert SECRET not in result
    assert "[REDACTED]" in result
    assert not result.startswith("Command rejected:")


def test_show_snmp_bare_still_denied(reset_command_file: None) -> None:
    from netmiko_mcp_linksys.server import show

    result = show("show snmp")
    assert result.startswith("Command rejected:")


# ---------------------------------------------------------------------------
# Regression tests from Cody's security probes (probe.py, probe2.py, p3.py, p5.py,
# re1.py, re2.py)
# ---------------------------------------------------------------------------


def _secret_in(text: str, secret: str) -> bool:
    """True if the secret or a common escaped/repr form appears in text."""
    if secret in text or secret.lower() in text.lower():
        return True
    escaped = __import__("re").escape(secret)
    if escaped in text or escaped.replace("\\", "\\\\") in text:
        return True
    if repr(secret) in text or repr(escaped) in text:
        return True
    # Recover by stripping backslashes, as in probe2.py.
    stripped = text.replace("\\", "")
    return secret in stripped


class _FakeConn:
    def __init__(self, cfg: Any = None) -> None:
        self.cfg = cfg
        self.width: int | None = None

    def send_config_set(self, cmds: list[str], **_kwargs: Any) -> str:
        if callable(self.cfg):
            return self.cfg(cmds)
        return self.cfg or ""

    def disconnect(self) -> None:
        return None

    def set_terminal_width(self, width: int) -> None:
        self.width = width


def _run_snmp_tool(
    tool: str,
    fake: _FakeConn,
    shows: dict[str, Any],
    *args: Any,
) -> str:
    from netmiko_mcp_linksys import connection, server

    def fake_paged(_conn: Any, command: str, *_a: Any, **_k: Any) -> str:
        value = shows.get(command, "")
        if isinstance(value, Exception):
            raise value
        return value

    with (
        patch.object(connection, "connect_params", lambda **_k: {}),
        patch.object(connection, "ConnectHandler", lambda **_k: fake),
        patch.object(connection, "disable_paging_best_effort", lambda _c: None),
        patch.object(connection, "send_paged", fake_paged),
        patch.object(server, "send_paged", fake_paged),
    ):
        return getattr(server, tool)(*args)


def test_cody_cmd_verify_timeout_does_not_leak(community_env: str, audit_log) -> None:
    """Finding 1: netmiko cmd_verify ReadTimeout must not return or audit str(exc)."""
    from netmiko.exceptions import ReadTimeout

    def cfg_timeout(cmds: list[str]) -> str:
        pat = __import__("re").escape(cmds[-1].strip())
        raise ReadTimeout(f"\n\nPattern not detected: {pat!r} in output.\n")

    result = _run_snmp_tool(
        "snmp_community_create",
        _FakeConn(cfg_timeout),
        {READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED},
        "ifmib",
        "ro",
    )
    assert SECRET not in result
    assert not _secret_in(result, SECRET)
    assert "ReadTimeout" in result
    assert "exception text is omitted" in result
    assert not result.startswith("Rejected:")
    audit = audit_log.read_text(encoding="utf-8")
    assert not _secret_in(audit, SECRET)
    record = json.loads(audit.splitlines()[-1])
    assert record["allowed"] is True
    assert not _secret_in(record["result"], SECRET)


def test_cody_wrapped_echo_does_not_leak(monkeypatch: pytest.MonkeyPatch, audit_log) -> None:
    """Finding 2: a line wrap mid-secret must not leak either half."""
    secret = "HaIfMibComm9xLongSecret42"
    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", secret)

    def cfg_wrap(cmds: list[str]) -> str:
        line = cmds[-1]
        cut = len("snmp community name ") + 12
        return (
            f"sw(config)# {line[:cut]}\r\n{line[cut:]}\r\n"
            "% Invalid input detected\r\nsw(config)#"
        )

    result = _run_snmp_tool(
        "snmp_community_create",
        _FakeConn(cfg_wrap),
        {READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED},
        "ifmib",
        "ro",
    )
    assert not _secret_in(result, secret)
    assert secret[:12] not in result
    assert secret[12:] not in result
    assert "device output is omitted" in result
    assert "Invalid input" not in result
    assert not _secret_in(audit_log.read_text(encoding="utf-8"), secret)


def test_cody_wrapped_echo_at_column_60(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "A" * 20 + "Bcdefgh1234"
    assert 8 <= len(secret) <= 32
    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", secret)

    def cfg_wrap(cmds: list[str]) -> str:
        line = cmds[-1]
        wrapped = line[:60] + "\r\n" + line[60:]
        return f"sw(config)# {wrapped}\r\n% Invalid input detected\r\nsw(config)#"

    result = _run_snmp_tool(
        "snmp_community_create",
        _FakeConn(cfg_wrap),
        {READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED},
        "ifmib",
        "ro",
    )
    assert not _secret_in(result, secret)
    frag = secret[60 - len("snmp community name ") :] if 60 > len("snmp community name ") else secret
    assert frag not in result or frag == ""
    assert "device output is omitted" in result
    assert "Invalid input" not in result


def test_cody_short_invalid_env_does_not_mangle_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 9: a short or invalid env community must not be used for redaction."""
    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", "a")
    assert redact_secrets("Gi0/1 admin state up") == "Gi0/1 admin state up"
    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", "1")
    assert redact_secrets("Gi0/1 1.3.6.1.2.1.31") == "Gi0/1 1.3.6.1.2.1.31"
    from netmiko_mcp_linksys.server import startup_checks

    warnings = startup_checks()
    assert any("invalid" in item or "not used" in item or "SWITCH_SNMP_COMMUNITY" in item for item in warnings)
    assert all("is not shown" in item or "1" not in item or "invalid" in item.lower() or "disabled" in item.lower() or "not 1" in item or "empty" in item.lower() or "SWITCH" in item for item in warnings)
    joined = "\n".join(warnings)
    # The warning must not echo the bad secret as a standalone assigned value.
    assert "SWITCH_SNMP_COMMUNITY=1" not in joined
    assert "'1'" not in joined


def test_cody_unparseable_readback_after_send_is_not_rejected(
    community_env: str, audit_log
) -> None:
    """Finding 5: config sent + unparseable read-back is verification failed, allowed=True."""
    sent: list[str] = []
    shows = {
        READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED,
        READBACK_SNMP_COMMUNITY: "Idx  Name  Sec\n1  HaIfMibComm9x  ifmib_sec\n",
        READBACK_SNMP_GROUP: GROUP_SHOW,
        READBACK_SNMP_ACCESS: ACCESS_SHOW_RW,
    }

    def cfg(cmds: list[str]) -> str:
        sent.extend(cmds)
        return "ok"

    result = _run_snmp_tool(
        "snmp_community_create",
        _FakeConn(cfg),
        shows,
        "ifmib",
        "ro",
    )
    assert sent, "configuration should have been sent"
    assert result.startswith("Error: Configuration was sent, verification failed")
    assert "Rejected:" not in result
    assert not _secret_in(result, SECRET)
    record = json.loads(audit_log.read_text(encoding="utf-8").splitlines()[-1])
    assert record["allowed"] is True
    assert "Configuration was sent, verification failed" in record["result"]
    assert not _secret_in(record["result"], SECRET)


def test_cody_unparseable_listing_redacts_whole_body(community_env: str) -> None:
    """Finding 6: unknown layout must not show foreign communities."""
    table = (
        "Index  Community Name     Security Name\n"
        "1      public            none\n"
        "2      OldSecretComm77    old_sec\n"
        "3      HaIfMibComm9x      ifmib_sec\n"
    )
    redacted = redact_show_output("show snmp community", table)
    assert SECRET not in redacted
    assert "OldSecretComm77" not in redacted
    assert "public" not in redacted
    assert "unparseable show snmp community output" in redacted


def test_cody_verification_is_exact_but_device_spelling_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 11: verification is exact; redaction still covers the device spelling."""
    from netmiko_mcp_linksys.snmp_cli import find_community_entry, parse_snmp_community

    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", "haifmibcomm9X")
    entry = find_community_entry(parse_snmp_community(COMMUNITY_SHOW), "haifmibcomm9X")
    assert entry is None
    with pytest.raises(ValidationError, match="not present"):
        assert_configured_community_ready(
            community_output=COMMUNITY_SHOW,
            group_output=GROUP_SHOW,
            access_output=ACCESS_SHOW_RW,
            view_output=VIEW_SHOW_RESTRICTED,
            community="haifmibcomm9X",
        )
    redacted = redact_secrets("Community Name: HaIfMibComm9x")
    assert "HaIfMibComm9x" not in redacted
    assert "haifmibcomm9X" not in redacted
    assert "[REDACTED]" in redacted


def test_cody_index_as_name_is_not_globally_replaced(community_env: str) -> None:
    """Finding 10: do not globally replace a community index that equals a name."""
    listing = (
        "Community Index: 1\n"
        "Security Name: v1_sec\n"
        "Storage Type: nonVolatile\n"
        "Row Status: active (since 10:01)\n"
    )
    redacted = redact_community_listing(listing)
    assert "Community Index: 1" in redacted
    assert "v1_sec" in redacted
    assert "10:01" in redacted
    assert "[REDACTED]" not in redacted or "Community Index: [REDACTED]" not in redacted


def test_cody_write_view_unknown_label_aborts(community_env: str) -> None:
    """Finding 3: only an explicit 'none' write view is read-only."""
    acc = ACCESS_SHOW_ISO_WRITE.replace("Write View:", "Write View Name:")
    # The parser will not see Write View, so write_view is empty -> abort.
    with pytest.raises(ValidationError, match="no write view"):
        assert_configured_community_ready(
            community_output=COMMUNITY_SHOW,
            group_output=GROUP_SHOW,
            access_output=acc,
            view_output=VIEW_SHOW_RESTRICTED,
            community=SECRET,
        )


def test_cody_v3_model_is_not_accepted_as_v2c_fallback(community_env: str) -> None:
    """Finding 4: v2c fallback applies only when the model field is empty."""
    grp = GROUP_SHOW.replace("Security Model: v2c", "Security Model: v3")
    acc = ACCESS_SHOW_RW.replace("Security Model: v2c", "Security Model: v3 priv")
    with pytest.raises(ValidationError, match="not mapped to an SNMP group|no v2c access"):
        assert_configured_community_ready(
            community_output=COMMUNITY_SHOW,
            group_output=grp,
            access_output=acc,
            view_output=VIEW_SHOW_RESTRICTED,
            community=SECRET,
        )


def test_cody_empty_model_fallback_still_allowed(community_env: str) -> None:
    grp = GROUP_SHOW.replace("Security Model: v2c\n", "")
    acc = ACCESS_SHOW_RW.replace("Security Model: v2c\n", "")
    status = assert_configured_community_ready(
        community_output=COMMUNITY_SHOW,
        group_output=grp,
        access_output=acc,
        view_output=VIEW_SHOW_RESTRICTED,
        community=SECRET,
    )
    assert "ifmib_grp" in status


def test_cody_snmp_tools_disable_session_log(
    community_env: str, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 7: SNMP write tools must not open a session log."""
    from netmiko_mcp_linksys import connection, server

    log = tmp_path / "session.log"
    monkeypatch.setenv("SWITCH_SESSION_LOG", str(log))
    captured: dict[str, Any] = {}

    def fake_handler(**params: Any) -> _FakeConn:
        captured.update(params)
        return _FakeConn("ok")

    def fake_paged(_conn: Any, command: str, *_a: Any, **_k: Any) -> str:
        mapping = {
            READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED,
            READBACK_SNMP_COMMUNITY: COMMUNITY_SHOW,
            READBACK_SNMP_GROUP: GROUP_SHOW,
            READBACK_SNMP_ACCESS: ACCESS_SHOW_RW,
        }
        return mapping.get(command, "")

    with (
        patch.object(connection, "ConnectHandler", fake_handler),
        patch.object(connection, "disable_paging_best_effort", lambda _c: None),
        patch.object(connection, "send_paged", fake_paged),
        patch.object(server, "send_paged", fake_paged),
    ):
        server.snmp_community_create("ifmib", "rw", "ifmib_w")
        assert captured, "the tool must reach the connection layer"
        assert "session_log" not in captured
        captured.clear()
        server.snmp_write_view_create("ifmib_w", "ifAdminStatus")
        server.snmp_view_create("ifmib", "power-ethernet")
    assert captured, "the tool must reach the connection layer"
    assert "session_log" not in captured
    assert not log.exists() or log.read_text(encoding="utf-8") == ""


def test_cody_session_log_redact_handles_wrapped_echo(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "HaIfMibComm9xLongSecret42"
    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", secret)
    path = tmp_path / "s.log"
    path.write_text(
        "LGS(config)# snmp community name HaIfMibComm9\r\n"
        "xLongSecret42 security v_sec\r\n"
        f"LGS(config)# snmp community name {secret} security v_sec\r\n",
        encoding="utf-8",
    )
    path.chmod(0o644)
    monkeypatch.setenv("SWITCH_SESSION_LOG", str(path))
    redact_session_log_file()
    body = path.read_text(encoding="utf-8")
    assert not _secret_in(body, secret)
    assert secret[:12] not in body
    assert secret[12:] not in body
    assert (path.stat().st_mode & 0o777) == 0o600


def test_cody_write_tools_require_enable_flag(
    community_env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 8: SWITCH_SNMP_WRITE_ENABLED=1 is required and off by default."""
    from netmiko_mcp_linksys.server import (
        snmp_community_create,
        snmp_community_remove,
        snmp_user_remove,
        snmp_view_create,
        snmp_write_view_create,
    )

    monkeypatch.delenv("SWITCH_SNMP_WRITE_ENABLED", raising=False)
    with patch("netmiko_mcp_linksys.server.run_in_session") as run:
        view = snmp_view_create("ifmib", "interfaces")
        write_view = snmp_write_view_create("ifmib_w", "ifAdminStatus")
        create = snmp_community_create("ifmib", "rw", "ifmib_w")
        remove = snmp_community_remove("public")
        user = snmp_user_remove("noAuthUser")
    run.assert_not_called()
    for result in (view, write_view, create, remove, user):
        assert result.startswith("Rejected:")
        assert "SWITCH_SNMP_WRITE_ENABLED" in result
        assert SECRET not in result


def test_cody_readback_exception_after_send_is_verification_failed(
    community_env: str, audit_log
) -> None:
    def cfg(_cmds: list[str]) -> str:
        return "ok"

    def later(_conn: Any, command: str, *_a: Any, **_k: Any) -> str:
        if command == READBACK_SNMP_VIEW and later.calls == 0:
            later.calls += 1
            return VIEW_SHOW_RESTRICTED
        raise ConnectionError(f"timeout after sending {SECRET}")

    later.calls = 0  # type: ignore[attr-defined]

    from netmiko_mcp_linksys import connection, server

    with (
        patch.object(connection, "connect_params", lambda **_k: {}),
        patch.object(connection, "ConnectHandler", lambda **_k: _FakeConn(cfg)),
        patch.object(connection, "disable_paging_best_effort", lambda _c: None),
        patch.object(connection, "send_paged", later),
        patch.object(server, "send_paged", later),
    ):
        result = server.snmp_community_create("ifmib", "ro")
    assert result.startswith("Error: Configuration was sent, verification failed")
    assert not _secret_in(result, SECRET)
    record = json.loads(audit_log.read_text(encoding="utf-8").splitlines()[-1])
    assert record["allowed"] is True
    assert not _secret_in(record["result"], SECRET)




def test_cody_wrapped_echo_with_prompt_redraw_omits_device_text(
    monkeypatch: pytest.MonkeyPatch, audit_log
) -> None:
    """Retest A: a mid-wrap prompt redraw must not leak, and device text is omitted."""
    secret = "HaIfMibComm9xLong_42"
    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", secret)
    cut = len("snmp community name ") + 8

    def cfg_wrap(cmds: list[str]) -> str:
        line = cmds[-1]
        return (
            f"LGS(config)# {line[:cut]}\r\n"
            f"LGS(config)# {line[cut:]}\r\n"
            "% Invalid input detected\r\nLGS(config)#"
        )

    result = _run_snmp_tool(
        "snmp_community_create",
        _FakeConn(cfg_wrap),
        {READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED},
        "ifmib",
        "ro",
    )
    assert not _secret_in(result, secret)
    assert secret[:8] not in result
    assert secret[8:] not in result
    assert "device output is omitted" in result
    assert "Invalid input" not in result
    assert "LGS(config)" not in result
    assert not _secret_in(audit_log.read_text(encoding="utf-8"), secret)


def test_cody_wrapped_echo_with_ansi_erase_omits_device_text(
    monkeypatch: pytest.MonkeyPatch, audit_log
) -> None:
    """Retest A: ANSI erase mid-wrap must not leak, and device text is omitted."""
    secret = "HaIfMibComm9xLong_42"
    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", secret)
    cut = len("snmp community name ") + 8

    def cfg_wrap(cmds: list[str]) -> str:
        line = cmds[-1]
        return (
            f"LGS(config)# {line[:cut]}\r\n"
            f"\x1b[K{line[cut:]}\r\n"
            "% Invalid input detected\r\nLGS(config)#"
        )

    result = _run_snmp_tool(
        "snmp_community_create",
        _FakeConn(cfg_wrap),
        {READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED},
        "ifmib",
        "ro",
    )
    assert not _secret_in(result, secret)
    assert secret[:8] not in result
    assert secret[8:] not in result
    assert "device output is omitted" in result
    assert "Invalid input" not in result
    assert not _secret_in(audit_log.read_text(encoding="utf-8"), secret)


def test_cody_wrapped_echo_with_dollar_scroll_omits_device_text(
    monkeypatch: pytest.MonkeyPatch, audit_log
) -> None:
    """Retest A: a '$' scroll leftover mid-wrap must not leak, and device text is omitted."""
    secret = "HaIfMibComm9xLong_42"
    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", secret)
    cut = len("snmp community name ") + 8

    def cfg_wrap(cmds: list[str]) -> str:
        line = cmds[-1]
        return (
            f"LGS(config)# {line[:cut]}\r\n"
            f"${line[cut:]}\r\n"
            "% Invalid input detected\r\nLGS(config)#"
        )

    result = _run_snmp_tool(
        "snmp_community_create",
        _FakeConn(cfg_wrap),
        {READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED},
        "ifmib",
        "ro",
    )
    assert not _secret_in(result, secret)
    assert secret[:8] not in result
    assert secret[8:] not in result
    assert "device output is omitted" in result
    assert "Invalid input" not in result
    assert not _secret_in(audit_log.read_text(encoding="utf-8"), secret)


def test_cody_redact_secrets_strips_ansi_and_prompt_redraws(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retest A: elsewhere, ANSI and prompt redraws are stripped before redaction."""
    from netmiko_mcp_linksys.validation import redact_secrets

    secret = "HaIfMibComm9xLong_42"
    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", secret)
    cut = 12
    with_prompt = (
        f"snmp community name {secret[:cut]}\r\n"
        f"LGS(config)# {secret[cut:]} security ifmib_sec\n"
    )
    with_ansi = (
        f"snmp community name {secret[:cut]}\r\n"
        f"\x1b[K{secret[cut:]} security ifmib_sec\n"
    )
    for raw in (with_prompt, with_ansi):
        redacted = redact_secrets(raw)
        assert not _secret_in(redacted, secret)
        assert secret[:cut] not in redacted
        assert secret[cut:] not in redacted
        assert "[REDACTED]" in redacted
        assert "\x1b" not in redacted
        assert "LGS(config)" not in redacted


def test_cody_readback_readtimeout_after_send_is_verification_failed(
    community_env: str, audit_log
) -> None:
    """Retest B: a raw ReadTimeout after send is verification-failed, allowed=True."""
    from netmiko.exceptions import ReadTimeout

    def cfg(_cmds: list[str]) -> str:
        return "ok"

    def later(_conn: Any, command: str, *_a: Any, **_k: Any) -> str:
        if command == READBACK_SNMP_VIEW and later.calls == 0:
            later.calls += 1
            return VIEW_SHOW_RESTRICTED
        raise ReadTimeout(f"timed out reading after {SECRET}")

    later.calls = 0  # type: ignore[attr-defined]

    from netmiko_mcp_linksys import connection, server

    with (
        patch.object(connection, "connect_params", lambda **_k: {}),
        patch.object(connection, "ConnectHandler", lambda **_k: _FakeConn(cfg)),
        patch.object(connection, "disable_paging_best_effort", lambda _c: None),
        patch.object(connection, "send_paged", later),
        patch.object(server, "send_paged", later),
    ):
        result = server.snmp_community_create("ifmib", "ro")
    assert result.startswith("Error: Configuration was sent, verification failed")
    assert not _secret_in(result, SECRET)
    record = json.loads(audit_log.read_text(encoding="utf-8").splitlines()[-1])
    assert record["allowed"] is True
    assert not _secret_in(record["result"], SECRET)


def test_cody_show_tool_disables_session_log_for_snmp_shows(
    community_env: str, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Retest C: show snmp community/viewtree/user must not open a session log."""
    from netmiko_mcp_linksys import connection, server

    log = tmp_path / "session.log"
    monkeypatch.setenv("SWITCH_SESSION_LOG", str(log))
    captured: dict[str, Any] = {}

    def fake_handler(**params: Any) -> _FakeConn:
        captured.clear()
        captured.update(params)
        return _FakeConn("ok")

    def fake_paged(_conn: Any, command: str, *_a: Any, **_k: Any) -> str:
        mapping = {
            "show snmp community": COMMUNITY_SHOW,
            "show snmp viewtree": VIEW_SHOW_RESTRICTED,
            "show snmp user": USER_SHOW,
            "show system information": "INFO",
        }
        return mapping.get(command, "")

    with (
        patch.object(connection, "ConnectHandler", fake_handler),
        patch.object(connection, "disable_paging_best_effort", lambda _c: None),
        patch.object(connection, "send_paged", fake_paged),
        patch.object(server, "send_paged", fake_paged),
    ):
        for command in (
            "show snmp community",
            "show snmp viewtree",
            "show snmp user",
        ):
            result = server.show(command)
            assert "session_log" not in captured, command
            assert not _secret_in(result, SECRET)
        server.show("show system information")
        assert "session_log" in captured
    assert not log.exists() or log.read_text(encoding="utf-8") == ""


def test_cody_session_log_redacts_community_name_by_label(
    tmp_path, community_env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Retest C / re2: Community Name fields are masked even if not the env secret."""
    foreign = "OldSecretComm77"
    path = tmp_path / "session.log"
    path.write_text(
        "LGS# show snmp community\n"
        "Community Index: old\n"
        f"Community Name: {foreign}\n"
        "Security Name: old_sec\n"
        "------\n"
        f"Community Name: {SECRET}\n"
        "Security Name: ifmib_sec\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SWITCH_SESSION_LOG", str(path))
    redact_session_log_file()
    body = path.read_text(encoding="utf-8")
    assert foreign not in body
    assert SECRET not in body
    assert "Community Name: [REDACTED]" in body
    assert "Community Index: old" in body
    assert "Security Name: old_sec" in body


def test_cody_no_terminal_width_helper() -> None:
    """Retest D: cisco_s300 already sends terminal width 511; no extra helper."""
    import inspect

    from netmiko_mcp_linksys import connection

    assert not hasattr(connection, "_set_terminal_width_best_effort")
    assert "wide_terminal" not in inspect.signature(connection.session).parameters
    assert "wide_terminal" not in inspect.signature(connection.run_in_session).parameters
    assert "wide_terminal" not in inspect.signature(
        connection.run_config_and_readbacks
    ).parameters



_CODY_PROMPT_LIKE_SAMPLES = (
    "Port#  Name   Status",
    "Entry#1 active",
    "Total>  5",
    "LGS328PC# show interfaces status",
)


@pytest.mark.parametrize("with_secret", [False, True], ids=["no-env-secret", "with-env-secret"])
@pytest.mark.parametrize("sample", _CODY_PROMPT_LIKE_SAMPLES)
def test_cody_redact_secrets_preserves_hash_and_gt_line_starts(
    monkeypatch: pytest.MonkeyPatch, with_secret: bool, sample: str
) -> None:
    """Prompt-like 'Word#' / 'Word>' text must stay byte-identical.

    Normalization runs only when the text contains 'snmp community' and
    a valid community is configured. These samples contain neither a
    wrap mid-secret nor that phrase, so they must not change — with or
    without SWITCH_SNMP_COMMUNITY.
    """
    if with_secret:
        monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", SECRET)
    else:
        monkeypatch.delenv("SWITCH_SNMP_COMMUNITY", raising=False)
    assert redact_secrets(sample) == sample



def test_cody_show_snmp_community_listing_keeps_hash_and_gt_headers(
    community_env: str,
) -> None:
    """A show-snmp-community echo must not strip '#-headers' or 'Status> ' lines."""
    listing = (
        "LGS328PC# show snmp community\n"
        "No# Community Index: 1\n"
        f"Community Name: {SECRET}\n"
        "Status> active\n"
        "Security Name: ifmib_sec\n"
    )
    out = redact_secrets(listing)
    assert SECRET not in out
    assert "No# Community Index: 1" in out
    assert "Status> active" in out
    assert "LGS328PC# show snmp community" in out
    assert "Community Name: [REDACTED]" in out
    # Only the secret was replaced; the rest of the listing is intact.
    assert out == listing.replace(SECRET, "[REDACTED]")


# ---------------------------------------------------------------------------
# Write-view hardening (Redy): ifAdminStatus exclusions for protected ports,
# POWER-ETHERNET-MIB only in the read view, separate read/write views.
# ---------------------------------------------------------------------------

def _view_block(name: str, oid: str, view_type: str, mask: str = "") -> str:
    return (
        f"View Name: {name}\nSubtree OID: {oid}\nSubtree Mask: {mask}\n"
        f"View Type: {view_type}\nStorage Type: nonVolatile\nRow Status: active\n"
    )


def _views(*blocks: str) -> str:
    return "------------------------------\n".join(blocks)


WRITE_VIEW_OK = _views(
    _view_block("ifmib_w", "1.3.6.1.2.1.2.2.1.7", "included"),
    _view_block("ifmib_w", EXCLUDED_OIDS[0], "excluded"),
    _view_block("ifmib_w", EXCLUDED_OIDS[1], "excluded"),
)


def test_ifindex_env_valid_mapping() -> None:
    assert parse_protected_ifindexes() == {"0/24": "124", "0/25": "125"}
    assert parse_protected_ifindexes(" 0/25 = 125 , 0/24=124 ") == {
        "0/25": "125",
        "0/24": "124",
    }
    assert protected_admin_status_oids({"0/24": "124", "0/25": "9"}) == [
        "1.3.6.1.2.1.2.2.1.7.9",
        "1.3.6.1.2.1.2.2.1.7.124",
    ]


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "is empty"),
        (" , ", "is empty"),
        ("0/24,0/25=125", "invalid entry"),
        ("0/24=0,0/25=125", "invalid entry"),
        ("0/24=0124,0/25=125", "invalid entry"),
        ("0/24=-1,0/25=125", "invalid entry"),
        ("0/24=abc,0/25=125", "invalid entry"),
        ("0/24=2147483648,0/25=125", "invalid entry"),
        ("0/24=1.2,0/25=125", "invalid entry"),
        ("0/99=1,0/25=125", "invalid entry"),
        ("0/24=124,0/24=125", "more than once"),
        ("0/24=124,0/25=124", "same ifIndex"),
        ("0/24=124", "missing protected port(s) 0/25"),
        ("0/24=124,0/25=125,0/10=110", "not in SWITCH_PROTECTED_PORTS 0/10"),
    ],
)
def test_ifindex_env_rejects_bad_values(raw: str, message: str) -> None:
    with pytest.raises(ValidationError, match=__import__("re").escape(message)):
        parse_protected_ifindexes(raw)


def test_ifindex_env_unset_or_protected_ports_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SWITCH_SNMP_PROTECTED_IFINDEXES")
    with pytest.raises(ValidationError, match="SWITCH_SNMP_PROTECTED_IFINDEXES is not set"):
        parse_protected_ifindexes()
    monkeypatch.setenv("SWITCH_SNMP_PROTECTED_IFINDEXES", IFINDEX_ENV)
    monkeypatch.delenv("SWITCH_PROTECTED_PORTS")
    with pytest.raises(ValidationError, match="SWITCH_PROTECTED_PORTS is not set"):
        parse_protected_ifindexes()


def test_write_view_commands_send_exclusions_first() -> None:
    cmds = build_write_view_commands("ifmib_w", "1.3.6.1.2.1.2", EXCLUDED_OIDS)
    assert cmds == [
        "snmp view ifmib_w 1.3.6.1.2.1.2.2.1.7.124 excluded",
        "snmp view ifmib_w 1.3.6.1.2.1.2.2.1.7.125 excluded",
        "snmp view ifmib_w 1.3.6.1.2.1.2 included",
    ]
    with pytest.raises(ValidationError, match="No ifAdminStatus exclusions"):
        build_write_view_commands("ifmib_w", "1.3.6.1.2.1.2", [])


def test_write_subtrees_are_columns_only() -> None:
    assert normalize_write_subtree("ifAdminStatus") == "1.3.6.1.2.1.2.2.1.7"
    assert normalize_write_subtree("ifadminstatus") == "1.3.6.1.2.1.2.2.1.7"
    assert normalize_write_subtree("1.3.6.1.2.1.2.2.1.7") == "1.3.6.1.2.1.2.2.1.7"
    assert normalize_write_subtree("ifAlias") == "1.3.6.1.2.1.31.1.1.1.18"
    assert normalize_write_subtree(" 1.3.6.1.2.1.31.1.1.1.18 ") == "1.3.6.1.2.1.31.1.1.1.18"
    assert (
        normalize_write_subtree("pethPsePortAdminEnable") == "1.3.6.1.2.1.105.1.1.1.3"
    )
    assert normalize_write_subtree("1.3.6.1.2.1.105.1.1.1.3") == "1.3.6.1.2.1.105.1.1.1.3"
    for bad in (
        "power-ethernet",
        "POWER-ETHERNET-MIB",
        "1.3.6.1.2.1.105",
        "interfaces",
        "1.3.6.1.2.1.2",
        "ifmib",
        "1.3.6.1.2.1.31",
        # Instances and other columns are not write subtrees either.
        "1.3.6.1.2.1.2.2.1.7.10",
        "1.3.6.1.2.1.105.1.1.1.3.1.10",
        "1.3.6.1.2.1.105.1.1.1.4",
        ".1.3.6.1.2.1.2.2.1.7",
        "1",
        "",
    ):
        with pytest.raises(ValidationError, match="not allowed in a write view"):
            normalize_write_subtree(bad)


def test_community_commands_require_split_views() -> None:
    with pytest.raises(ValidationError, match="separate write_view"):
        build_community_create_commands("ifmib", "rw", SECRET)
    with pytest.raises(ValidationError, match="must differ"):
        build_community_create_commands("ifmib", "rw", SECRET, "IFMIB")
    with pytest.raises(ValidationError, match="only valid with access 'rw'"):
        build_community_create_commands("ifmib", "ro", SECRET, "ifmib_w")
    cmds = build_community_create_commands("ifmib", "rw", SECRET, "ifmib_w")
    assert cmds[1] == "snmp access ifmib_grp v2c read ifmib write ifmib_w notify none"


def test_mask_is_exact() -> None:
    for mask in ("", " ", "-", "none", "1", "1.1.1.1", "ff", "FF:FF", "0xff", "ff ff"):
        assert mask_is_exact(mask), mask
    for mask in ("0", "1.0.1", "fe", "7f", "ff:00", "1.1.0", "?"):
        assert not mask_is_exact(mask), mask


def test_view_is_write_safe_accepts_complete_write_view() -> None:
    ok, note = view_is_write_safe(
        parse_snmp_viewtree(WRITE_VIEW_OK), "ifmib_w", EXCLUDED_OIDS
    )
    assert ok, note
    assert "excludes 1.3.6.1.2.1.2.2.1.7.124, 1.3.6.1.2.1.2.2.1.7.125" in note


@pytest.mark.parametrize(
    ("listing", "message"),
    [
        (
            _views(
                _view_block("ifmib_w", "1.3.6.1.2.1.2.2.1.7", "included"),
                _view_block("ifmib_w", EXCLUDED_OIDS[0], "excluded"),
            ),
            "missing the ifAdminStatus exclusion(s) 1.3.6.1.2.1.2.2.1.7.125",
        ),
        (
            WRITE_VIEW_OK + "------------------------------\n"
            + _view_block("ifmib_w", "1.3.6.1.2.1.105", "included"),
            "POWER-ETHERNET-MIB",
        ),
        (
            WRITE_VIEW_OK + "------------------------------\n"
            + _view_block("ifmib_w", "1", "included"),
            "not allowed in a write view",
        ),
        (
            _views(
                _view_block("ifmib_w", "1.3.6.1.2.1.2.2.1.7", "included"),
                _view_block("ifmib_w", EXCLUDED_OIDS[0], ""),
                _view_block("ifmib_w", EXCLUDED_OIDS[1], "excluded"),
            ),
            "included/excluded type",
        ),
        (
            _views(
                _view_block("ifmib_w", "1.3.6.1.2.1.2.2.1.7", "included"),
                _view_block("ifmib_w", EXCLUDED_OIDS[0], "excluded", mask="ff:ff:00"),
                _view_block("ifmib_w", EXCLUDED_OIDS[1], "excluded"),
            ),
            "unrecognised mask",
        ),
        (
            # Exclusions written as "included" do not count.
            _views(
                _view_block("ifmib_w", "1.3.6.1.2.1.2.2.1.7", "included"),
                _view_block("ifmib_w", EXCLUDED_OIDS[0], "included"),
                _view_block("ifmib_w", EXCLUDED_OIDS[1], "included"),
            ),
            "not allowed in a write view",
        ),
        (
            _views(
                _view_block("ifmib_w", EXCLUDED_OIDS[0], "excluded"),
                _view_block("ifmib_w", EXCLUDED_OIDS[1], "excluded"),
            ),
            "no included subtrees",
        ),
        (VIEW_SHOW_RESTRICTED.replace("ifmib_w", "other"), "was not found"),
    ],
)
def test_view_is_write_safe_rejects(listing: str, message: str) -> None:
    ok, note = view_is_write_safe(parse_snmp_viewtree(listing), "ifmib_w", EXCLUDED_OIDS)
    assert not ok
    assert message in note


def test_view_is_write_safe_without_exclusions_refuses() -> None:
    ok, note = view_is_write_safe(parse_snmp_viewtree(WRITE_VIEW_OK), "ifmib_w", [])
    assert not ok
    assert "no ifAdminStatus exclusions configured" in note


def test_read_view_with_wildcard_mask_is_not_restricted() -> None:
    listing = _view_block("ifmib", "1.3.6.1.2.1.2", "included", mask="ff:00")
    ok, note = view_is_restricted(parse_snmp_viewtree(listing), "ifmib")
    assert not ok
    assert "unrecognised mask" in note


def _ready(access: str, views: str, **kwargs: Any) -> str:
    return assert_configured_community_ready(
        community_output=COMMUNITY_SHOW,
        group_output=GROUP_SHOW,
        access_output=access,
        view_output=views,
        community=SECRET,
        **kwargs,
    )


def test_ready_verifies_split_and_exclusions(community_env: str) -> None:
    status = _ready(
        ACCESS_SHOW_RW,
        VIEW_SHOW_WITH_POE,
        expected_read_view="ifmib",
        expected_write_view="ifmib_w",
    )
    assert "read view ifmib includes only allow-listed subtrees" in status
    assert "1.3.6.1.2.1.105" in status  # PoE in the read view is fine
    assert "write view ifmib_w includes only 1.3.6.1.2.1.2" in status
    assert "excludes 1.3.6.1.2.1.2.2.1.7.124" in status
    assert SECRET not in status


def test_ready_refuses_rw_without_ifindex_env(
    community_env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SWITCH_SNMP_PROTECTED_IFINDEXES")
    with pytest.raises(ValidationError, match="SWITCH_SNMP_PROTECTED_IFINDEXES") as exc:
        _ready(ACCESS_SHOW_RW, VIEW_SHOW_RESTRICTED)
    assert SECRET not in str(exc.value)


def test_ready_ro_community_does_not_need_ifindex_env(
    community_env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SWITCH_SNMP_PROTECTED_IFINDEXES")
    ro = ACCESS_SHOW_RW.replace("Write View: ifmib_w", "Write View: none")
    status = _ready(ro, VIEW_SHOW_RESTRICTED, expected_read_view="ifmib")
    assert "read-only" in status


def test_ready_refuses_same_read_and_write_view(community_env: str) -> None:
    same = ACCESS_SHOW_RW.replace("Write View: ifmib_w", "Write View: IFMIB")
    with pytest.raises(ValidationError, match="same view for read and write"):
        _ready(same, VIEW_SHOW_RESTRICTED)


def test_ready_refuses_write_view_with_poe(community_env: str) -> None:
    poe = VIEW_SHOW_RESTRICTED + "------------------------------\n" + _view_block(
        "ifmib_w", "1.3.6.1.2.1.105", "included"
    )
    with pytest.raises(ValidationError, match="POWER-ETHERNET-MIB"):
        _ready(ACCESS_SHOW_RW, poe)


def test_ready_refuses_write_view_missing_exclusion(community_env: str) -> None:
    missing = VIEW_SHOW_RESTRICTED.replace(
        "Subtree OID: 1.3.6.1.2.1.2.2.1.7.125", "Subtree OID: 1.3.6.1.2.1.2.2.1.7.126"
    )
    with pytest.raises(ValidationError, match=r"missing the ifAdminStatus exclusion"):
        _ready(ACCESS_SHOW_RW, missing)


def test_ready_expected_views_are_exact(community_env: str) -> None:
    with pytest.raises(ValidationError, match="does not use the requested views"):
        _ready(
            ACCESS_SHOW_RW,
            VIEW_SHOW_RESTRICTED,
            expected_read_view="ifmib",
            expected_write_view="other_w",
        )
    with pytest.raises(ValidationError, match="does not use the requested views"):
        _ready(ACCESS_SHOW_RW, VIEW_SHOW_RESTRICTED, expected_read_view="ifmib")
    with pytest.raises(ValidationError, match="does not use the requested views"):
        _ready(
            ACCESS_SHOW_RW,
            VIEW_SHOW_RESTRICTED,
            expected_read_view="IFMIB",
            expected_write_view="ifmib_w",
        )


def _rw_listing(new_view: str) -> dict[str, str]:
    return {
        READBACK_SNMP_VIEW: new_view,
        READBACK_SNMP_COMMUNITY: COMMUNITY_SHOW,
        READBACK_SNMP_GROUP: GROUP_SHOW,
        READBACK_SNMP_ACCESS: ACCESS_SHOW_RW,
    }


def test_snmp_write_view_create_happy_path(community_env: str, audit_log) -> None:
    from netmiko_mcp_linksys.server import snmp_write_view_create

    sent: list[list[str]] = []
    session = _fake_snmp_session({READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED}, sent)
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        result = snmp_write_view_create("ifmib_w", "ifAdminStatus")
    assert sent == [
        [
            "snmp view ifmib_w 1.3.6.1.2.1.2.2.1.7.124 excluded",
            "snmp view ifmib_w 1.3.6.1.2.1.2.2.1.7.125 excluded",
            "snmp view ifmib_w 1.3.6.1.2.1.2.2.1.7 included",
        ]
    ]
    assert (
        "Read-back check: write view ifmib_w includes only 1.3.6.1.2.1.2.2.1.7 "
        "and excludes" in result
    )
    assert not _secret_in(result, SECRET)
    assert not _secret_in(audit_log.read_text(encoding="utf-8"), SECRET)


@pytest.mark.parametrize(
    "subtree",
    ["power-ethernet", "1.3.6.1.2.1.105", "interfaces", "1.3.6.1.2.1.31", "ifmib"],
)
def test_snmp_write_view_create_refuses_whole_subtrees(subtree: str) -> None:
    from netmiko_mcp_linksys.server import snmp_write_view_create

    with patch("netmiko_mcp_linksys.server.run_in_session") as run:
        result = snmp_write_view_create("ifmib_w", subtree)
    run.assert_not_called()
    assert result.startswith("Rejected:")
    assert "not allowed in a write view" in result


def test_snmp_write_view_create_refuses_without_ifindexes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netmiko_mcp_linksys.server import snmp_write_view_create

    monkeypatch.delenv("SWITCH_SNMP_PROTECTED_IFINDEXES")
    with patch("netmiko_mcp_linksys.server.run_in_session") as run:
        result = snmp_write_view_create("ifmib_w", "ifAdminStatus")
    run.assert_not_called()
    assert result.startswith("Rejected:")
    assert "SWITCH_SNMP_PROTECTED_IFINDEXES is not set" in result


@pytest.mark.parametrize(
    ("listing", "message"),
    [
        # The read view "ifmib" holds whole MIB subtrees (IF-MIB, PoE-MIB).
        (VIEW_SHOW_WITH_POE, "already includes 1.3.6.1.2.1.2,"),
        ("garbage without keys", "Could not parse show snmp viewtree"),
    ],
)
def test_snmp_write_view_create_prechecks_before_send(listing: str, message: str) -> None:
    from netmiko_mcp_linksys.server import snmp_write_view_create

    sent: list[list[str]] = []
    session = _fake_snmp_session({READBACK_SNMP_VIEW: listing}, sent)
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        # "ifmib" is a read view with whole subtrees, so it cannot become a write view.
        result = snmp_write_view_create("ifmib", "ifAdminStatus")
    assert sent == []
    assert result.startswith("Rejected:")
    assert message in result


def test_snmp_write_view_create_verification_failed_after_send(community_env: str) -> None:
    from netmiko_mcp_linksys.server import snmp_write_view_create

    calls: list[str] = []
    incomplete = _views(
        _view_block("ifmib_w", "1.3.6.1.2.1.2.2.1.7", "included"),
        _view_block("ifmib_w", EXCLUDED_OIDS[0], "excluded"),
    )

    def shows(command: str) -> str:
        calls.append(command)
        # Before: no ifmib_w yet. After: the device dropped one exclusion.
        return VIEW_SHOW_WITH_POE if len(calls) == 1 else incomplete

    sent: list[list[str]] = []
    with patch(
        "netmiko_mcp_linksys.server.run_in_session",
        side_effect=_fake_snmp_session(shows, sent),
    ):
        result = snmp_write_view_create("ifmib_w", "ifAdminStatus")
    assert len(sent) == 1
    assert result.startswith("Error: Configuration was sent, verification failed:")
    assert "1.3.6.1.2.1.2.2.1.7.125" in result
    assert SECRET not in result


def test_snmp_view_create_poe_allowed_on_read_view() -> None:
    from netmiko_mcp_linksys.server import snmp_view_create

    sent: list[list[str]] = []
    session = _fake_snmp_session(
        {READBACK_SNMP_ACCESS: ACCESS_SHOW_RW, READBACK_SNMP_VIEW: VIEW_SHOW_WITH_POE},
        sent,
    )
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        result = snmp_view_create("ifmib", "power-ethernet")
    assert sent == [["snmp view ifmib 1.3.6.1.2.1.105 included"]]
    assert "Read-back check: view ifmib includes 1.3.6.1.2.1.105" in result


@pytest.mark.parametrize(
    ("view", "access", "message"),
    [
        ("ifmib_w", ACCESS_SHOW_RW, "is used as a write view"),
        ("IFMIB_W", ACCESS_SHOW_RW, "is used as a write view"),
        (
            # Not bound yet, but it carries ifAdminStatus exclusions.
            "ifmib_w",
            ACCESS_SHOW_RW.replace("Write View: ifmib_w", "Write View: none"),
            "has protected-port exclusions",
        ),
        ("ifmib", "garbage without keys", "Could not parse show snmp group access"),
    ],
)
def test_snmp_view_create_refuses_poe_in_write_view(
    view: str, access: str, message: str
) -> None:
    from netmiko_mcp_linksys.server import snmp_view_create

    sent: list[list[str]] = []
    session = _fake_snmp_session(
        {READBACK_SNMP_ACCESS: access, READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED}, sent
    )
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        result = snmp_view_create(view, "power-ethernet")
    assert sent == []
    assert result.startswith("Rejected:")
    assert message in result


def test_snmp_community_create_rw_split_and_redaction(
    community_env: str, audit_log
) -> None:
    from netmiko_mcp_linksys.server import snmp_community_create

    sent: list[list[str]] = []
    session = _fake_snmp_session(_rw_listing(VIEW_SHOW_WITH_POE), sent)
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        result = snmp_community_create("ifmib", "rw", "ifmib_w")
    assert len(sent) == 1
    assert sent[0][1] == "snmp access ifmib_grp v2c read ifmib write ifmib_w notify none"
    assert sent[0][2] == f"snmp community name {SECRET} security ifmib_sec"
    assert not _secret_in(result, SECRET)
    assert "snmp community name [REDACTED] security ifmib_sec" in result
    assert "excludes 1.3.6.1.2.1.2.2.1.7.124" in result
    assert not _secret_in(audit_log.read_text(encoding="utf-8"), SECRET)


def test_snmp_community_create_rw_refuses_without_ifindexes(
    community_env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netmiko_mcp_linksys.server import snmp_community_create

    monkeypatch.delenv("SWITCH_SNMP_PROTECTED_IFINDEXES")
    with patch("netmiko_mcp_linksys.server.run_in_session") as run:
        result = snmp_community_create("ifmib", "rw", "ifmib_w")
    run.assert_not_called()
    assert result.startswith("Rejected:")
    assert "SWITCH_SNMP_PROTECTED_IFINDEXES is not set" in result
    assert SECRET not in result


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("ifmib", "rw"), "separate write_view"),
        (("ifmib", "rw", "ifmib"), "must differ"),
        (("ifmib", "ro", "ifmib_w"), "only valid with access 'rw'"),
        (("ifmib", "rw", "bad name"), "Invalid SNMP write view name"),
    ],
)
def test_snmp_community_create_rejects_bad_view_args(
    community_env: str, args: tuple[str, ...], message: str
) -> None:
    from netmiko_mcp_linksys.server import snmp_community_create

    with patch("netmiko_mcp_linksys.server.run_in_session") as run:
        result = snmp_community_create(*args)
    run.assert_not_called()
    assert result.startswith("Rejected:")
    assert message in result
    assert SECRET not in result


@pytest.mark.parametrize(
    ("listing", "message"),
    [
        (
            VIEW_SHOW_RESTRICTED.replace(
                "Subtree OID: 1.3.6.1.2.1.2.2.1.7.124", "Subtree OID: 1.3.6.1.2.1.2.2.1.7.24"
            ),
            "missing the ifAdminStatus exclusion(s) 1.3.6.1.2.1.2.2.1.7.124",
        ),
        (
            VIEW_SHOW_RESTRICTED + "------------------------------\n"
            + _view_block("ifmib_w", "1.3.6.1.2.1.105", "included"),
            "POWER-ETHERNET-MIB",
        ),
        (VIEW_SHOW_RESTRICTED.replace("ifmib_w", "zzz"), "was not found"),
    ],
)
def test_snmp_community_create_rw_prechecks_write_view(
    community_env: str, listing: str, message: str
) -> None:
    from netmiko_mcp_linksys.server import snmp_community_create

    sent: list[list[str]] = []
    session = _fake_snmp_session(_rw_listing(listing), sent)
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        result = snmp_community_create("ifmib", "rw", "ifmib_w")
    assert sent == []
    assert result.startswith("Rejected:")
    assert message in result
    assert "snmp_write_view_create" in result
    assert SECRET not in result


def test_snmp_community_create_rw_access_mismatch_is_verification_failed(
    community_env: str,
) -> None:
    from netmiko_mcp_linksys.server import snmp_community_create

    listing = _rw_listing(VIEW_SHOW_RESTRICTED)
    # The device bound the community with write none instead of ifmib_w.
    listing[READBACK_SNMP_ACCESS] = ACCESS_SHOW_RW.replace(
        "Write View: ifmib_w", "Write View: none"
    )
    sent: list[list[str]] = []
    with patch(
        "netmiko_mcp_linksys.server.run_in_session",
        side_effect=_fake_snmp_session(listing, sent),
    ):
        result = snmp_community_create("ifmib", "rw", "ifmib_w")
    assert len(sent) == 1
    assert result.startswith("Error: Configuration was sent, verification failed:")
    assert "does not use the requested views" in result
    assert SECRET not in result


def test_snmp_community_remove_refuses_rw_without_ifindexes(
    community_env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netmiko_mcp_linksys.server import snmp_community_remove

    monkeypatch.delenv("SWITCH_SNMP_PROTECTED_IFINDEXES")
    sent: list[list[str]] = []
    session = _fake_snmp_session(_rw_listing(VIEW_SHOW_RESTRICTED), sent)
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        result = snmp_community_remove("public")
    assert sent == []
    assert result.startswith("Rejected:")
    assert "SWITCH_SNMP_PROTECTED_IFINDEXES" in result
    assert SECRET not in result


# ---------------------------------------------------------------------------
# View names are compared exactly; case-only variants are refused
# (Cody, PR #8 review of 063cfd7). It is not live-confirmed whether ISS
# treats view names case-sensitively, so a "wv"/"WV" pair is ambiguous.
# ---------------------------------------------------------------------------

CASE_SPLIT_VIEWS = _views(
    # "wv" is a read view without exclusions; "WV" is a complete write view.
    _view_block("wv", "1.3.6.1.2.1.2", "included"),
    _view_block("WV", EXCLUDED_OIDS[0], "excluded"),
    _view_block("WV", EXCLUDED_OIDS[1], "excluded"),
    _view_block("WV", "1.3.6.1.2.1.2.2.1.7", "included"),
)


def test_case_variant_view_names() -> None:
    views = parse_snmp_viewtree(CASE_SPLIT_VIEWS)
    assert case_variant_view_names(views, "wv") == ["WV"]
    assert case_variant_view_names(views, "WV") == ["wv"]
    assert case_variant_view_names(views, "Wv") == ["WV", "wv"]
    assert case_variant_view_names(views, "other") == []


@pytest.mark.parametrize("name", ["wv", "WV"])
def test_view_is_write_safe_refuses_case_merge(name: str) -> None:
    ok, note = view_is_write_safe(parse_snmp_viewtree(CASE_SPLIT_VIEWS), name, EXCLUDED_OIDS)
    assert not ok
    assert "differs only in letter case" in note


def test_view_checks_are_case_sensitive() -> None:
    views = parse_snmp_viewtree(WRITE_VIEW_OK)
    ok, note = view_is_write_safe(views, "IFMIB_W", EXCLUDED_OIDS)
    assert not ok
    assert "differs only in letter case" in note
    ok, note = view_is_restricted(parse_snmp_viewtree(VIEW_SHOW_RESTRICTED), "IFMIB")
    assert not ok
    assert "differs only in letter case" in note


def test_cody_probe_r5(monkeypatch: pytest.MonkeyPatch) -> None:
    """Port of Cody's probe /tmp/cody/r5.py (write view hardening)."""
    from netmiko_mcp_linksys.snmp_cli import required_write_exclusions

    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/10,0/24")
    monkeypatch.setenv("SWITCH_SNMP_PROTECTED_IFINDEXES", "0/10=10,0/24=24")
    ex = required_write_exclusions()
    assert ex == ["1.3.6.1.2.1.2.2.1.7.10", "1.3.6.1.2.1.2.2.1.7.24"]
    assert build_write_view_commands("wv", "1.3.6.1.2.1.2.2.1.7", ex) == [
        "snmp view wv 1.3.6.1.2.1.2.2.1.7.10 excluded",
        "snmp view wv 1.3.6.1.2.1.2.2.1.7.24 excluded",
        "snmp view wv 1.3.6.1.2.1.2.2.1.7 included",
    ]
    for subtree in ("power-ethernet", "1.3.6.1.2.1.105", "1.3.6.1.2.1.2", "1.3.6.1"):
        with pytest.raises(ValidationError):
            normalize_write_subtree(subtree)

    def blk(name: str, oid: str, typ: str, mask: str = "") -> str:
        return f"View Name: {name}\nSubtree OID: {oid}\nSubtree Mask: {mask}\nView Type: {typ}\n"

    def tree(*blocks: str) -> list[Any]:
        return parse_snmp_viewtree("\n------------------------------\n".join(blocks))

    good = [
        blk("wv", "1.3.6.1.2.1.2.2.1.7.10", "excluded"),
        blk("wv", "1.3.6.1.2.1.2.2.1.7.24", "excluded"),
        blk("wv", "1.3.6.1.2.1.2.2.1.7", "included"),
    ]
    assert view_is_write_safe(tree(*good), "wv", ex)[0]
    ok, note = view_is_write_safe(tree(*good, blk("wv", "1.3.6.1.2.1.105", "included")), "wv", ex)
    assert not ok
    assert "POWER-ETHERNET-MIB" in note
    # Case merge: "wv" lacks the exclusions, "WV" has them.
    case_merge = tree(
        blk("wv", "1.3.6.1.2.1.2.2.1.7", "included"),
        blk("WV", "1.3.6.1.2.1.2.2.1.7.10", "excluded"),
        blk("WV", "1.3.6.1.2.1.2.2.1.7.24", "excluded"),
        blk("WV", "1.3.6.1.2.1.2.2.1.7", "included"),
    )
    ok, note = view_is_write_safe(case_merge, "wv", ex)
    assert not ok
    assert "differs only in letter case" in note
    leading_dot = tree(
        blk("wv", ".1.3.6.1.2.1.2.2.1.7.10", "excluded"),
        blk("wv", ".1.3.6.1.2.1.2.2.1.7.24", "excluded"),
        blk("wv", "1.3.6.1.2.1.2.2.1.7", "included"),
    )
    assert not view_is_write_safe(leading_dot, "wv", ex)[0]
    wildcard = tree(*good[:2], blk("wv", "1.3.6.1.2.1.2.2.1.7", "included", "ff:7f"))
    assert not view_is_write_safe(wildcard, "wv", ex)[0]
    for ports, idx in [
        (None, "0/10=10"),
        ("", "0/10=10"),
        ("0/10,0/24", None),
        ("0/10,0/24", "0/10=10"),
        ("0/10", "0/10=10,0/24=24"),
        ("0/10", "0/10=010"),
        ("0/10", "0/10=0"),
        ("0/10,0/24", "0/10=5,0/24=5"),
    ]:
        for key, value in (("SWITCH_PROTECTED_PORTS", ports), ("SWITCH_SNMP_PROTECTED_IFINDEXES", idx)):
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)
        with pytest.raises(ValidationError):
            parse_protected_ifindexes()


def test_attack_path_write_view_case_variant_refused_before_send() -> None:
    """snmp_view_create("wv") then snmp_write_view_create("WV") must fail."""
    from netmiko_mcp_linksys.server import snmp_write_view_create

    read_only_wv = _views(
        VIEW_SHOW_RESTRICTED, _view_block("wv", "1.3.6.1.2.1.2", "included")
    )
    sent: list[list[str]] = []
    session = _fake_snmp_session({READBACK_SNMP_VIEW: read_only_wv}, sent)
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        result = snmp_write_view_create("WV", "ifAdminStatus")
    assert sent == []
    assert result.startswith("Rejected:")
    assert "differs only in letter case" in result


def test_attack_path_community_rw_case_variant_refused(community_env: str) -> None:
    """A community with write view "wv" must not pass via the "WV" exclusions."""
    from netmiko_mcp_linksys.server import snmp_community_create

    listing = _rw_listing(_views(VIEW_SHOW_RESTRICTED, CASE_SPLIT_VIEWS))
    sent: list[list[str]] = []
    with patch(
        "netmiko_mcp_linksys.server.run_in_session",
        side_effect=_fake_snmp_session(listing, sent),
    ):
        result = snmp_community_create("ifmib", "rw", "wv")
    assert sent == []
    assert result.startswith("Rejected:")
    assert "differs only in letter case" in result
    assert SECRET not in result


@pytest.mark.parametrize(
    ("view", "subtree", "access"),
    [
        ("WV", "interfaces", ACCESS_SHOW_RW),
        ("IFMIB", "interfaces", ACCESS_SHOW_RW),
        # Read view case variant of an existing view: PoE path.
        ("IFMIB", "power-ethernet", ACCESS_SHOW_RW),
    ],
)
def test_snmp_view_create_refuses_case_variant(view: str, subtree: str, access: str) -> None:
    from netmiko_mcp_linksys.server import snmp_view_create

    views = _views(VIEW_SHOW_RESTRICTED, _view_block("wv", "1.3.6.1.2.1.2", "included"))
    sent: list[list[str]] = []
    session = _fake_snmp_session(
        {READBACK_SNMP_VIEW: views, READBACK_SNMP_ACCESS: access}, sent
    )
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        result = snmp_view_create(view, subtree)
    assert sent == []
    assert result.startswith("Rejected:")
    assert "differs only in letter case" in result


def test_snmp_view_create_refuses_unparseable_viewtree() -> None:
    from netmiko_mcp_linksys.server import snmp_view_create

    sent: list[list[str]] = []
    session = _fake_snmp_session(
        {READBACK_SNMP_ACCESS: ACCESS_SHOW_RW, READBACK_SNMP_VIEW: "garbage without keys"},
        sent,
    )
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        result = snmp_view_create("ifmib", "interfaces")
    assert sent == []
    assert result.startswith("Rejected:")
    assert "Could not parse show snmp viewtree" in result


# ---------------------------------------------------------------------------
# PoE switching via SNMP (Vikunja task 48, Redy's plan approved by Roland):
# the write view may include pethPsePortAdminEnable, with hard exclusions
# for the protected ports from SWITCH_SNMP_PROTECTED_POE_INDEXES (fail-closed).
# 0/15 is documentation-only and must not be locked technically.
# ---------------------------------------------------------------------------

POE_COL = "1.3.6.1.2.1.105.1.1.1.3"
ADMIN_COL = "1.3.6.1.2.1.2.2.1.7"
ALIAS_COL = "1.3.6.1.2.1.31.1.1.1.18"
# Dummy indexes; deliberately not equal to the port numbers or ifIndexes.
LIVE_PORTS_IFINDEX_ENV = "0/10=110,0/24=124"
LIVE_PORTS_POE_ENV = "0/10=1.10,0/24=1.24"
LIVE_ADMIN_EXCL = [f"{ADMIN_COL}.110", f"{ADMIN_COL}.124"]
LIVE_POE_EXCL = [f"{POE_COL}.1.10", f"{POE_COL}.1.24"]


@pytest.fixture
def poe_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Production-like protected ports 0/24,0/10 with both index mappings."""
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24,0/10")
    monkeypatch.setenv("SWITCH_SNMP_PROTECTED_IFINDEXES", LIVE_PORTS_IFINDEX_ENV)
    monkeypatch.setenv("SWITCH_SNMP_PROTECTED_POE_INDEXES", LIVE_PORTS_POE_ENV)


def _poe_write_view(name: str = "ifmib_w", *, drop: str | None = None) -> str:
    blocks = [
        _view_block(name, oid, "excluded")
        for oid in LIVE_ADMIN_EXCL + LIVE_POE_EXCL
        if oid != drop
    ]
    blocks += [
        _view_block(name, ADMIN_COL, "included"),
        _view_block(name, POE_COL, "included"),
    ]
    return _views(*blocks)


def _read_view_ifmib() -> str:
    return _views(
        _view_block("ifmib", "1.3.6.1.2.1.2", "included"),
        _view_block("ifmib", "1.3.6.1.2.1.31", "included"),
        _view_block("ifmib", "1.3.6.1.2.1.105", "included"),
    )


def _admin_only_write_view(name: str = "ifmib_w") -> str:
    return _views(
        _view_block(name, LIVE_ADMIN_EXCL[0], "excluded"),
        _view_block(name, LIVE_ADMIN_EXCL[1], "excluded"),
        _view_block(name, ADMIN_COL, "included"),
    )


def test_poe_index_env_valid_mapping(poe_env: None) -> None:
    from netmiko_mcp_linksys.validation import parse_protected_poe_indexes

    assert parse_protected_poe_indexes() == {"0/10": "1.10", "0/24": "1.24"}
    assert parse_protected_poe_indexes(" 0/24 = 2.24 , 0/10=1.3 ") == {
        "0/24": "2.24",
        "0/10": "1.3",
    }
    assert parse_protected_poe_indexes("0/10=2147483647.1,0/24=1.2147483647")


def test_poe_index_env_covers_only_poe_ports_of_protected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """conftest protects 0/24,0/25; 0/25 is an SFP port without a PoE row."""
    from netmiko_mcp_linksys.validation import parse_protected_poe_indexes

    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24,0/25")
    assert parse_protected_poe_indexes("0/24=1.24") == {"0/24": "1.24"}
    with pytest.raises(ValidationError, match="invalid entry '0/25=1.25'"):
        parse_protected_poe_indexes("0/24=1.24,0/25=1.25")


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "is empty"),
        (" , ", "is empty"),
        ("0/10,0/24=1.24", "invalid entry"),
        ("0/10=10,0/24=1.24", "invalid entry"),  # needs <group>.<port>
        ("0/10=1.2.3,0/24=1.24", "invalid entry"),
        ("0/10=0.10,0/24=1.24", "invalid entry"),
        ("0/10=1.0,0/24=1.24", "invalid entry"),
        ("0/10=01.10,0/24=1.24", "invalid entry"),
        ("0/10=1.010,0/24=1.24", "invalid entry"),
        ("0/10=-1.10,0/24=1.24", "invalid entry"),
        ("0/10=1.-10,0/24=1.24", "invalid entry"),
        ("0/10=+1.10,0/24=1.24", "invalid entry"),
        ("0/10=a.b,0/24=1.24", "invalid entry"),
        ("0/10=1.,0/24=1.24", "invalid entry"),
        ("0/10=.10,0/24=1.24", "invalid entry"),
        ("0/10=1 .10,0/24=1.24", "invalid entry"),
        ("0/10=2147483648.10,0/24=1.24", "invalid entry"),
        ("0/10=1.2147483648,0/24=1.24", "invalid entry"),
        ("0/010=1.10,0/24=1.24", "invalid entry"),
        ("0/99=1.10,0/24=1.24", "invalid entry"),
        ("0/10=1.10,0/24=1.24,0/10=1.11", "more than once"),
        ("0/10=1.24,0/24=1.24", "same PoE index"),
        ("0/24=1.24", "missing protected port(s) 0/10"),
        (
            "0/10=1.10,0/24=1.24,0/15=1.15",
            "not in the PoE ports of SWITCH_PROTECTED_PORTS 0/15",
        ),
    ],
)
def test_poe_index_env_rejects_bad_values(poe_env: None, raw: str, message: str) -> None:
    import re as _re

    from netmiko_mcp_linksys.validation import parse_protected_poe_indexes

    with pytest.raises(ValidationError, match=_re.escape(message)):
        parse_protected_poe_indexes(raw)


def test_poe_index_env_unset_or_protected_ports_unset(
    poe_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netmiko_mcp_linksys.validation import parse_protected_poe_indexes

    monkeypatch.delenv("SWITCH_SNMP_PROTECTED_POE_INDEXES")
    with pytest.raises(ValidationError, match="SWITCH_SNMP_PROTECTED_POE_INDEXES is not set"):
        parse_protected_poe_indexes()
    monkeypatch.setenv("SWITCH_SNMP_PROTECTED_POE_INDEXES", LIVE_PORTS_POE_ENV)
    monkeypatch.delenv("SWITCH_PROTECTED_PORTS")
    with pytest.raises(ValidationError, match="SWITCH_PROTECTED_PORTS is not set"):
        parse_protected_poe_indexes()


def test_poe_exclusion_oid_format_and_numeric_sort() -> None:
    from netmiko_mcp_linksys.snmp_cli import protected_poe_admin_oids

    assert protected_poe_admin_oids({"0/24": "1.24", "0/10": "1.10", "0/9": "1.9"}) == [
        f"{POE_COL}.1.9",
        f"{POE_COL}.1.10",
        f"{POE_COL}.1.24",
    ]
    assert protected_poe_admin_oids({"0/10": "2.1", "0/24": "1.30"}) == [
        f"{POE_COL}.1.30",
        f"{POE_COL}.2.1",
    ]


def test_poe_write_view_commands_send_all_exclusions_before_include(poe_env: None) -> None:
    from netmiko_mcp_linksys.snmp_cli import write_view_exclusions

    exclusions = write_view_exclusions([], "ifmib_w", adding=POE_COL)
    assert exclusions == LIVE_ADMIN_EXCL + LIVE_POE_EXCL
    cmds = build_write_view_commands("ifmib_w", POE_COL, exclusions)
    assert cmds == [
        f"snmp view ifmib_w {ADMIN_COL}.110 excluded",
        f"snmp view ifmib_w {ADMIN_COL}.124 excluded",
        f"snmp view ifmib_w {POE_COL}.1.10 excluded",
        f"snmp view ifmib_w {POE_COL}.1.24 excluded",
        f"snmp view ifmib_w {POE_COL} included",
    ]
    # Every excluded line comes before the only included line.
    assert all(line.endswith(" excluded") for line in cmds[:-1])
    assert cmds[-1].endswith(" included")
    with pytest.raises(ValidationError, match="No pethPsePortAdminEnable exclusions"):
        build_write_view_commands("ifmib_w", POE_COL, LIVE_ADMIN_EXCL)


def test_write_view_exclusions_need_poe_env_only_with_poe(
    poe_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netmiko_mcp_linksys.snmp_cli import write_view_exclusions

    monkeypatch.delenv("SWITCH_SNMP_PROTECTED_POE_INDEXES")
    admin_only = parse_snmp_viewtree(_admin_only_write_view())
    assert write_view_exclusions(admin_only, "ifmib_w") == LIVE_ADMIN_EXCL
    assert write_view_exclusions(admin_only, "ifmib_w", adding=ALIAS_COL) == LIVE_ADMIN_EXCL
    with pytest.raises(ValidationError, match="SWITCH_SNMP_PROTECTED_POE_INDEXES is not set"):
        write_view_exclusions(admin_only, "ifmib_w", adding=POE_COL)
    with pytest.raises(ValidationError, match="SWITCH_SNMP_PROTECTED_POE_INDEXES is not set"):
        write_view_exclusions(parse_snmp_viewtree(_poe_write_view()), "ifmib_w")


def test_view_is_write_safe_with_poe(poe_env: None) -> None:
    ok, note = view_is_write_safe(
        parse_snmp_viewtree(_poe_write_view()),
        "ifmib_w",
        LIVE_ADMIN_EXCL + LIVE_POE_EXCL,
    )
    assert ok, note
    assert f"includes only {ADMIN_COL}, {POE_COL}" in note
    assert f"{POE_COL}.1.10" in note and f"{POE_COL}.1.24" in note


@pytest.mark.parametrize(
    ("listing", "exclusions", "message"),
    [
        (
            _poe_write_view(drop=f"{POE_COL}.1.10"),
            LIVE_ADMIN_EXCL + LIVE_POE_EXCL,
            f"missing the pethPsePortAdminEnable exclusion(s) {POE_COL}.1.10",
        ),
        (
            _poe_write_view(drop=f"{ADMIN_COL}.124"),
            LIVE_ADMIN_EXCL + LIVE_POE_EXCL,
            f"missing the ifAdminStatus exclusion(s) {ADMIN_COL}.124",
        ),
        (
            # A caller that forgot the PoE exclusions must not pass.
            _poe_write_view(),
            LIVE_ADMIN_EXCL,
            "no PoE exclusions are configured",
        ),
        (
            _views(_poe_write_view(), _view_block("ifmib_w", "1.3.6.1.2.1.105", "included")),
            LIVE_ADMIN_EXCL + LIVE_POE_EXCL,
            "whole POWER-ETHERNET-MIB",
        ),
        (
            _views(_poe_write_view(), _view_block("ifmib_w", "1.3.6.1.2.1.2", "included")),
            LIVE_ADMIN_EXCL + LIVE_POE_EXCL,
            "includes subtree 1.3.6.1.2.1.2, which is not allowed",
        ),
        (
            # A PoE exclusion written as "included" widens instead of narrowing.
            _views(_poe_write_view(), _view_block("ifmib_w", f"{POE_COL}.1.10", "included")),
            LIVE_ADMIN_EXCL + LIVE_POE_EXCL,
            "not allowed in a write view",
        ),
    ],
)
def test_view_is_write_safe_rejects_poe_gaps(
    poe_env: None, listing: str, exclusions: list[str], message: str
) -> None:
    ok, note = view_is_write_safe(parse_snmp_viewtree(listing), "ifmib_w", exclusions)
    assert not ok
    assert message in note


def test_port_0_15_is_not_locked(monkeypatch: pytest.MonkeyPatch) -> None:
    """0/15 (EoC converter with Zigbee router) is a README note, not a lock."""
    from netmiko_mcp_linksys.snmp_cli import write_view_exclusions
    from netmiko_mcp_linksys.validation import parse_protected_poe_indexes

    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24,0/10")
    monkeypatch.setenv("SWITCH_SNMP_PROTECTED_IFINDEXES", "0/10=110,0/24=124")
    # Port-number-like indexes make a hidden 0/15 entry easy to spot.
    monkeypatch.setenv("SWITCH_SNMP_PROTECTED_POE_INDEXES", "0/10=1.10,0/24=1.24")
    exclusions = write_view_exclusions([], "wv", adding=POE_COL)
    assert exclusions == LIVE_ADMIN_EXCL + LIVE_POE_EXCL
    assert not any(oid.endswith(".15") or ".15." in oid for oid in exclusions)
    cmds = build_write_view_commands("wv", POE_COL, exclusions)
    assert not any("0/15" in line or line.split()[3].endswith(".15") for line in cmds)
    # Listing 0/15 in the env is refused instead of silently adding a lock.
    with pytest.raises(ValidationError, match="not in the PoE ports of SWITCH_PROTECTED_PORTS 0/15"):
        parse_protected_poe_indexes("0/10=1.10,0/24=1.24,0/15=1.15")


def test_snmp_write_view_create_poe_happy_path(poe_env: None, audit_log) -> None:
    from netmiko_mcp_linksys.server import snmp_write_view_create

    calls: list[str] = []
    before = _views(_read_view_ifmib(), _admin_only_write_view())

    def shows(command: str) -> str:
        calls.append(command)
        return before if len(calls) == 1 else _views(_read_view_ifmib(), _poe_write_view())

    sent: list[list[str]] = []
    with patch(
        "netmiko_mcp_linksys.server.run_in_session",
        side_effect=_fake_snmp_session(shows, sent),
    ):
        result = snmp_write_view_create("ifmib_w", "pethPsePortAdminEnable")
    assert sent == [
        [
            f"snmp view ifmib_w {ADMIN_COL}.110 excluded",
            f"snmp view ifmib_w {ADMIN_COL}.124 excluded",
            f"snmp view ifmib_w {POE_COL}.1.10 excluded",
            f"snmp view ifmib_w {POE_COL}.1.24 excluded",
            f"snmp view ifmib_w {POE_COL} included",
        ]
    ]
    assert result.startswith("Configuration sent:")
    assert f"Read-back check: write view ifmib_w includes only {ADMIN_COL}, {POE_COL}" in result
    assert f"{POE_COL}.1.24" in result


def test_snmp_write_view_create_ifalias_keeps_poe_exclusions(poe_env: None) -> None:
    """Adding a column to a view that already has PoE re-sends the PoE exclusions."""
    from netmiko_mcp_linksys.server import snmp_write_view_create

    sent: list[list[str]] = []
    after = _views(_poe_write_view(), _view_block("ifmib_w", ALIAS_COL, "included"))
    calls: list[str] = []

    def shows(command: str) -> str:
        calls.append(command)
        return _poe_write_view() if len(calls) == 1 else after

    with patch(
        "netmiko_mcp_linksys.server.run_in_session",
        side_effect=_fake_snmp_session(shows, sent),
    ):
        result = snmp_write_view_create("ifmib_w", "ifAlias")
    assert sent[0][:4] == [
        f"snmp view ifmib_w {oid} excluded" for oid in LIVE_ADMIN_EXCL + LIVE_POE_EXCL
    ]
    assert sent[0][4:] == [f"snmp view ifmib_w {ALIAS_COL} included"]
    assert "Read-back check: write view ifmib_w includes only" in result


@pytest.mark.parametrize(
    ("poe_value", "message"),
    [
        (None, "SWITCH_SNMP_PROTECTED_POE_INDEXES is not set"),
        ("", "SWITCH_SNMP_PROTECTED_POE_INDEXES is empty"),
        ("0/10=1.10", "missing protected port(s) 0/24"),
        ("0/10=1.10,0/24=1.10", "same PoE index"),
        ("0/10=1.10,0/24=24", "invalid entry"),
    ],
)
def test_snmp_write_view_create_poe_fail_closed(
    poe_env: None, monkeypatch: pytest.MonkeyPatch, poe_value: str | None, message: str
) -> None:
    from netmiko_mcp_linksys.server import snmp_write_view_create

    if poe_value is None:
        monkeypatch.delenv("SWITCH_SNMP_PROTECTED_POE_INDEXES")
    else:
        monkeypatch.setenv("SWITCH_SNMP_PROTECTED_POE_INDEXES", poe_value)
    with patch("netmiko_mcp_linksys.server.run_in_session") as run:
        result = snmp_write_view_create("ifmib_w", POE_COL)
    run.assert_not_called()
    assert result.startswith("Rejected:")
    assert message in result


def test_snmp_write_view_create_column_on_poe_view_needs_poe_env(
    poe_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netmiko_mcp_linksys.server import snmp_write_view_create

    monkeypatch.delenv("SWITCH_SNMP_PROTECTED_POE_INDEXES")
    sent: list[list[str]] = []
    session = _fake_snmp_session({READBACK_SNMP_VIEW: _poe_write_view()}, sent)
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        result = snmp_write_view_create("ifmib_w", "ifAlias")
    assert sent == []
    assert result.startswith("Rejected:")
    assert "SWITCH_SNMP_PROTECTED_POE_INDEXES is not set" in result


def test_snmp_write_view_create_poe_requires_write_flag(
    poe_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netmiko_mcp_linksys.server import snmp_write_view_create

    monkeypatch.delenv("SWITCH_SNMP_WRITE_ENABLED")
    with patch("netmiko_mcp_linksys.server.run_in_session") as run:
        result = snmp_write_view_create("ifmib_w", "pethPsePortAdminEnable")
    run.assert_not_called()
    assert result.startswith("Rejected:")
    assert "SWITCH_SNMP_WRITE_ENABLED" in result


def test_snmp_write_view_create_poe_verification_failed_after_send(poe_env: None) -> None:
    from netmiko_mcp_linksys.server import snmp_write_view_create

    calls: list[str] = []

    def shows(command: str) -> str:
        calls.append(command)
        # After the send the device lost the 0/10 PoE exclusion.
        if len(calls) == 1:
            return _admin_only_write_view()
        return _poe_write_view(drop=f"{POE_COL}.1.10")

    sent: list[list[str]] = []
    with patch(
        "netmiko_mcp_linksys.server.run_in_session",
        side_effect=_fake_snmp_session(shows, sent),
    ):
        result = snmp_write_view_create("ifmib_w", POE_COL)
    assert len(sent) == 1
    assert result.startswith("Error: Configuration was sent, verification failed:")
    assert f"pethPsePortAdminEnable exclusion(s) {POE_COL}.1.10" in result


def _poe_rw_listing() -> dict[str, str]:
    return _rw_listing(_views(_read_view_ifmib(), _poe_write_view()))


def test_snmp_community_create_rw_with_poe_write_view(poe_env: None, community_env: str) -> None:
    from netmiko_mcp_linksys.server import snmp_community_create

    sent: list[list[str]] = []
    with patch(
        "netmiko_mcp_linksys.server.run_in_session",
        side_effect=_fake_snmp_session(_poe_rw_listing(), sent),
    ):
        result = snmp_community_create("ifmib", "rw", "ifmib_w")
    assert len(sent) == 1
    assert "Read-back check:" in result
    assert f"{POE_COL}.1.10" in result
    assert not _secret_in(result, SECRET)


def test_snmp_community_create_rw_poe_view_refused_without_poe_env(
    poe_env: None, community_env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netmiko_mcp_linksys.server import snmp_community_create

    monkeypatch.delenv("SWITCH_SNMP_PROTECTED_POE_INDEXES")
    sent: list[list[str]] = []
    with patch(
        "netmiko_mcp_linksys.server.run_in_session",
        side_effect=_fake_snmp_session(_poe_rw_listing(), sent),
    ):
        result = snmp_community_create("ifmib", "rw", "ifmib_w")
    assert sent == []
    assert result.startswith("Rejected:")
    assert "SWITCH_SNMP_PROTECTED_POE_INDEXES is not set" in result
    assert SECRET not in result


def test_snmp_community_create_rw_poe_view_missing_poe_exclusion(
    poe_env: None, community_env: str
) -> None:
    from netmiko_mcp_linksys.server import snmp_community_create

    listing = _rw_listing(
        _views(_read_view_ifmib(), _poe_write_view(drop=f"{POE_COL}.1.24"))
    )
    sent: list[list[str]] = []
    with patch(
        "netmiko_mcp_linksys.server.run_in_session",
        side_effect=_fake_snmp_session(listing, sent),
    ):
        result = snmp_community_create("ifmib", "rw", "ifmib_w")
    assert sent == []
    assert result.startswith("Rejected:")
    assert f"pethPsePortAdminEnable exclusion(s) {POE_COL}.1.24" in result


def test_ready_with_poe_write_view_needs_poe_env(
    poe_env: None, community_env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    views = _views(_read_view_ifmib(), _poe_write_view())
    status = _ready(ACCESS_SHOW_RW, views)
    assert f"excludes {', '.join(LIVE_ADMIN_EXCL + LIVE_POE_EXCL)}" in status
    monkeypatch.delenv("SWITCH_SNMP_PROTECTED_POE_INDEXES")
    with pytest.raises(ValidationError, match="SWITCH_SNMP_PROTECTED_POE_INDEXES is not set"):
        _ready(ACCESS_SHOW_RW, views)


@pytest.mark.parametrize("subtree", ["interfaces", "ifmib", "power-ethernet"])
def test_snmp_view_create_refuses_whole_subtree_in_poe_write_view(
    poe_env: None, subtree: str
) -> None:
    """A whole MIB added to a write view would bypass the column narrowing."""
    from netmiko_mcp_linksys.server import snmp_view_create

    unbound = ACCESS_SHOW_RW.replace("Write View: ifmib_w", "Write View: none")
    for access, message in (
        (ACCESS_SHOW_RW, "is used as a write view"),
        (unbound, "has protected-port exclusions"),
    ):
        sent: list[list[str]] = []
        session = _fake_snmp_session(
            {READBACK_SNMP_ACCESS: access, READBACK_SNMP_VIEW: _poe_write_view()}, sent
        )
        with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
            result = snmp_view_create("ifmib_w", subtree)
        assert sent == []
        assert result.startswith("Rejected:")
        assert message in result


def test_snmp_view_create_refuses_view_with_only_poe_exclusions(poe_env: None) -> None:
    from netmiko_mcp_linksys.server import snmp_view_create

    only_poe = _views(
        _view_block("pw", LIVE_POE_EXCL[0], "excluded"),
        _view_block("pw", POE_COL, "included"),
    )
    unbound = ACCESS_SHOW_RW.replace("Write View: ifmib_w", "Write View: none")
    sent: list[list[str]] = []
    session = _fake_snmp_session(
        {READBACK_SNMP_ACCESS: unbound, READBACK_SNMP_VIEW: only_poe}, sent
    )
    with patch("netmiko_mcp_linksys.server.run_in_session", side_effect=session):
        result = snmp_view_create("pw", "power-ethernet")
    assert sent == []
    assert "has protected-port exclusions" in result
