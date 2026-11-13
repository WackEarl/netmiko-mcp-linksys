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
    format_sent_commands,
    group_name_for_view,
    normalize_subtree,
    parse_snmp_access,
    parse_snmp_community,
    parse_snmp_group,
    parse_snmp_user,
    parse_snmp_viewtree,
    redact_community_listing,
    resolve_removable_community_name,
    security_name_for_view,
    user_present,
    view_is_restricted,
)
from netmiko_mcp_linksys.validation import (
    ValidationError,
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
Write View: ifmib
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
    cmds = build_community_create_commands("ifmib", "rw", SECRET)
    assert cmds[0] == "snmp group ifmib_grp user ifmib_sec security-model v2c"
    assert cmds[1] == "snmp access ifmib_grp v2c read ifmib write ifmib notify none"
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
    assert access[0].write_view == "ifmib"
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
    with pytest.raises(ValidationError, match="broad subtree") as exc:
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


def test_snmp_view_create_tool() -> None:
    from netmiko_mcp_linksys.server import snmp_view_create

    with patch(
        "netmiko_mcp_linksys.server.run_config_and_readbacks",
        return_value="Configuration sent.\n--- show snmp viewtree ---\n" + VIEW_SHOW_RESTRICTED,
    ) as run:
        result = snmp_view_create("ifmib", "interfaces")
    run.assert_called_once()
    commands, readbacks = run.call_args.args
    assert commands == ["snmp view ifmib 1.3.6.1.2.1.2 included"]
    assert readbacks == [READBACK_SNMP_VIEW]
    assert "Read-back check: view ifmib includes 1.3.6.1.2.1.2" in result
    assert "Not live-confirmed" in result or "not live-confirmed" in result.lower()


def test_snmp_view_create_rejects_bad_oid() -> None:
    from netmiko_mcp_linksys.server import snmp_view_create

    with patch("netmiko_mcp_linksys.server.run_config_and_readbacks") as run:
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

    def fake_session(callback: Any) -> str:
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
        result = snmp_community_create("ifmib", "rw")
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

    def fake_session(callback: Any) -> str:
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

    def fake_session(callback: Any) -> str:
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

    def fake_session(callback: Any) -> str:
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

    def fake_session_present(callback: Any) -> str:
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

    def fake_session_absent(callback: Any) -> str:
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
