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


@pytest.fixture(autouse=True)
def enable_snmp_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_SNMP_WRITE_ENABLED", "1")


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
        server.snmp_community_create("ifmib", "rw")
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
    )

    monkeypatch.delenv("SWITCH_SNMP_WRITE_ENABLED", raising=False)
    with (
        patch("netmiko_mcp_linksys.server.run_in_session") as run,
        patch("netmiko_mcp_linksys.server.run_config_and_readbacks") as run_rb,
    ):
        view = snmp_view_create("ifmib", "interfaces")
        create = snmp_community_create("ifmib", "rw")
        remove = snmp_community_remove("public")
        user = snmp_user_remove("noAuthUser")
    run.assert_not_called()
    run_rb.assert_not_called()
    for result in (view, create, remove, user):
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
