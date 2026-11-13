"""ISS / Linksys LGS SNMP CLI templates, parsers, and safety checks.

Command templates below follow the official Linksys LGSXXX CLI User
Manual, chapter "19 SNMP" (MAN_LGSXXX_LNKPG-00878_Rev_A00.pdf):

  https://downloads.linksys.com/support/assets/others/MAN_LGSXXX_LNKPG-00878_Rev_A00.pdf

That is the primary source for this firmware family (LGS328PC
1.01.02.02 is an Aricent ISS CLI). Generic Aricent ISS references
(Super Micro SNMP Configuration Guide; Cisco Skylight/Flex "SNMP
Commands") use a closely related syntax that often includes an
explicit community *index* and a volatile|nonvolatile storage flag.
Those variants are recorded here as unconfirmed fallbacks and are
**not** sent by the tools.

NONE of these commands have been confirmed live on the LGS328PC.
Do not use the SNMP write tools against the switch until Redy has
verified the syntax (see the README live-test checklist).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from netmiko_mcp_linksys.validation import (
    ValidationError,
    redact_secrets,
    valid_community_for_redaction,
)

# ---------------------------------------------------------------------------
# Sources (keep this block next to the templates)
# ---------------------------------------------------------------------------
#
# CONFIRMED IN DOCUMENTATION (not yet live):
#   Linksys LGSXXX CLI User Manual, MAN_LGSXXX_LNKPG-00878_Rev_A00.pdf,
#   pages 101-109, Global Configuration / Privileged EXEC:
#
#     snmp view <ViewName> <OIDTree> [mask <OIDMask>] {included | excluded}
#     no snmp view <ViewName> <OIDTree>
#     snmp group <GroupName> user <UserName> security-model {v1 | v2c | v3}
#     snmp access <GroupName> {v1 | v2c | v3 {auth | noauth | priv}}
#         [read <ReadView | none>] [write <WriteView | none>]
#         [notify <NotifyView | none>]
#     snmp community name <CommunityName> security <SecurityName>
#         [transporttag <TransportTagIdentifier | none>]
#         [contextengineid <ContextEngineID>]
#     no snmp community name <CommunityName>
#     no snmp user <UserName>
#     show snmp community
#     show snmp viewtree
#     show snmp group
#     show snmp group access
#     show snmp user
#
# UNCONFIRMED (generic Aricent ISS / Super Micro / Cisco Skylight) — do not
# send until a live test shows the Linksys form is rejected:
#
#     snmp community index <Index> name <Name> security <Security>
#         [context <Name>] [{volatile | nonvolatile}] ...
#     no snmp community index <Index>
#     ... plus a trailing {volatile | nonvolatile} on view / group / access
#
#   show snmp view is not in the Linksys CLI manual; the documented
#   read-back is show snmp viewtree. show snmp view is allow-listed only
#   as a possible alias and is unconfirmed.
#
# UNCONFIRMED on firmware 1.01.02.02: default storage type (volatile vs
# nonvolatile vs running-config + save), exact show-output layout,
# whether enable snmpagent is required, exact spelling of default
# communities / the noAuthUser user, and whether POWER-ETHERNET-MIB
# 1.3.6.1.2.1.105 is implemented on the LGS328PC.

CLI_SOURCE = (
    "Linksys LGSXXX CLI User Manual, MAN_LGSXXX_LNKPG-00878_Rev_A00.pdf, "
    "chapter 19 SNMP "
    "(https://downloads.linksys.com/support/assets/others/"
    "MAN_LGSXXX_LNKPG-00878_Rev_A00.pdf). "
    "Not live-confirmed on LGS328PC firmware 1.01.02.02."
)

# Official Linksys names for the read-back commands.
READBACK_SNMP_COMMUNITY = "show snmp community"
READBACK_SNMP_VIEW = "show snmp viewtree"
READBACK_SNMP_GROUP = "show snmp group"
READBACK_SNMP_ACCESS = "show snmp group access"
READBACK_SNMP_USER = "show snmp user"

# Fixed included-subtree allowlist. Symbolic aliases are accepted as
# input and normalized to the numeric OID.
ALLOWED_SUBTREES: dict[str, str] = {
    "1.3.6.1.2.1.2": "interfaces (IF-MIB): ifAdminStatus, ifOperStatus, counters",
    "1.3.6.1.2.1.31": "ifMIB: ifXTable, ifAlias, ifHC* bandwidth counters",
    "1.3.6.1.2.1.105": (
        "POWER-ETHERNET-MIB: PoE admin/detection/budget (optional; "
        "needed for Home Assistant PoE read or control; RW then also "
        "allows PoE off via SNMP)"
    ),
}

OID_ALIASES: dict[str, str] = {
    "interfaces": "1.3.6.1.2.1.2",
    "if-mib-interfaces": "1.3.6.1.2.1.2",
    "ifmib": "1.3.6.1.2.1.31",
    "if-mib": "1.3.6.1.2.1.31",
    "ifmib-ifxtable": "1.3.6.1.2.1.31",
    "power-ethernet": "1.3.6.1.2.1.105",
    "power-ethernet-mib": "1.3.6.1.2.1.105",
}

# Views that cover the whole tree (or equally broad roots) are never
# "expected" access for the new community.
BROAD_OIDS = frozenset(
    {
        "1",
        "1.3",
        "1.3.6",
        "1.3.6.1",
        "1.3.6.1.2",
        "1.3.6.1.2.1",
    }
)

REDACTED = "[REDACTED]"

_RECORD_SPLIT_RE = re.compile(r"\n\s*-{5,}\s*\n")
_COMMUNITY_NAME_LABEL_RE = re.compile(
    r"(?im)^(\s*(?:Community\s*Name|CommunityName)\s*:\s*)(\S.*)$"
)


def group_name_for_view(view_name: str) -> str:
    return f"{view_name}_grp"


def security_name_for_view(view_name: str) -> str:
    return f"{view_name}_sec"


def normalize_subtree(subtree: str) -> str:
    """Return an allow-listed numeric OID, or raise ValidationError."""
    if not isinstance(subtree, str):
        raise ValidationError(
            "subtree must be an allow-listed OID or alias "
            "(interfaces, ifmib, power-ethernet)."
        )
    key = subtree.strip()
    if not key:
        raise ValidationError(
            "subtree must be an allow-listed OID or alias "
            "(interfaces, ifmib, power-ethernet)."
        )
    alias = OID_ALIASES.get(key.lower())
    if alias is not None:
        return alias
    if key in ALLOWED_SUBTREES:
        return key
    allowed = ", ".join(f"{oid} ({desc.split(':')[0]})" for oid, desc in ALLOWED_SUBTREES.items())
    raise ValidationError(
        "subtree is not on the OID allowlist. Allowed: "
        + allowed
        + ". Aliases: "
        + ", ".join(sorted(OID_ALIASES))
        + "."
    )


def build_view_create_commands(view_name: str, oid: str) -> list[str]:
    """Linksys CLI: snmp view <ViewName> <OIDTree> included."""
    return [f"snmp view {view_name} {oid} included"]


def build_community_create_commands(
    view_name: str, access: str, community: str
) -> list[str]:
    """ISS v2c mapping: group + access + community (Linksys name/security form).

    The community string is used only as the ``name`` value and is never
    reused as the security/group name, so show snmp group does not repeat
    the secret. The caller must redact any echo of these commands.
    """
    group = group_name_for_view(view_name)
    security = security_name_for_view(view_name)
    write = view_name if access == "rw" else "none"
    return [
        f"snmp group {group} user {security} security-model v2c",
        (
            f"snmp access {group} v2c read {view_name} "
            f"write {write} notify none"
        ),
        f"snmp community name {community} security {security}",
    ]


def redact_command_list(commands: list[str]) -> list[str]:
    return [redact_secrets(command) for command in commands]


def build_community_remove_commands(name: str) -> list[str]:
    """Linksys CLI: no snmp community name <CommunityName>."""
    return [f"no snmp community name {name}"]


def build_user_remove_commands(name: str) -> list[str]:
    """Linksys CLI: no snmp user <UserName>."""
    return [f"no snmp user {name}"]


def _strip_readback_wrapper(output: str) -> str:
    match = re.search(r"^--- .+ ---\n", output, re.MULTILINE)
    return output[match.end() :] if match else output


def _records(output: str) -> list[str]:
    text = _strip_readback_wrapper(output).replace("\r\n", "\n").strip()
    if not text:
        return []
    parts = _RECORD_SPLIT_RE.split(text)
    return [part.strip() for part in parts if part.strip()]


def _fields(record: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in record.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key_n = re.sub(r"\s+", " ", key).strip().lower()
        if key_n:
            fields[key_n] = value.strip()
    return fields


def _field(fields: dict[str, str], *names: str) -> str:
    for name in names:
        value = fields.get(name)
        if value:
            return value
    return ""


@dataclass(frozen=True)
class CommunityEntry:
    index: str
    name: str
    security_name: str
    raw: str


@dataclass(frozen=True)
class ViewSubtree:
    name: str
    oid: str
    view_type: str
    raw: str


@dataclass(frozen=True)
class GroupEntry:
    group: str
    user: str
    model: str
    raw: str


@dataclass(frozen=True)
class AccessEntry:
    group: str
    model: str
    read_view: str
    write_view: str
    notify_view: str
    raw: str


@dataclass(frozen=True)
class UserEntry:
    name: str
    raw: str


def parse_snmp_community(output: str) -> list[CommunityEntry]:
    """Parse show snmp community. Assumed ISS key: value blocks; unconfirmed live."""
    entries: list[CommunityEntry] = []
    for record in _records(output):
        fields = _fields(record)
        name = _field(fields, "community name", "communityname")
        # Do not treat a bare "Index:" label as a community index: other
        # tables use that word, and a later global replace would corrupt them.
        index = _field(fields, "community index", "communityindex")
        security = _field(fields, "security name", "securityname")
        if not name and not index:
            continue
        entries.append(
            CommunityEntry(
                index=index,
                name=name,
                security_name=security,
                raw=record,
            )
        )
    return entries


def parse_snmp_viewtree(output: str) -> list[ViewSubtree]:
    """Parse show snmp viewtree. Assumed ISS key: value blocks; unconfirmed live."""
    entries: list[ViewSubtree] = []
    for record in _records(output):
        fields = _fields(record)
        name = _field(fields, "view name", "viewname")
        oid = _field(fields, "subtree oid", "subtreeoid", "oid tree", "oidtree", "subtree")
        view_type = _field(fields, "view type", "viewtype", "type").lower()
        if not name or not oid:
            continue
        entries.append(
            ViewSubtree(name=name, oid=oid, view_type=view_type, raw=record)
        )
    return entries


def parse_snmp_group(output: str) -> list[GroupEntry]:
    entries: list[GroupEntry] = []
    for record in _records(output):
        fields = _fields(record)
        group = _field(fields, "group name", "groupname", "group")
        user = _field(fields, "user name", "username", "user")
        model = _field(fields, "security model", "security-model", "securitymodel", "model")
        if not group and not user:
            continue
        entries.append(GroupEntry(group=group, user=user, model=model, raw=record))
    return entries


def parse_snmp_access(output: str) -> list[AccessEntry]:
    entries: list[AccessEntry] = []
    for record in _records(output):
        fields = _fields(record)
        group = _field(fields, "group name", "groupname", "group")
        model = _field(
            fields,
            "security model",
            "security-model",
            "securitymodel",
            "version",
            "model",
        )
        read_view = _field(fields, "read view", "readview", "read")
        write_view = _field(fields, "write view", "writeview", "write")
        notify_view = _field(fields, "notify view", "notifyview", "notify")
        if not group and not read_view:
            continue
        entries.append(
            AccessEntry(
                group=group,
                model=model,
                read_view=read_view,
                write_view=write_view,
                notify_view=notify_view,
                raw=record,
            )
        )
    return entries


def parse_snmp_user(output: str) -> list[UserEntry]:
    entries: list[UserEntry] = []
    for record in _records(output):
        fields = _fields(record)
        name = _field(fields, "user", "user name", "username")
        if not name:
            continue
        entries.append(UserEntry(name=name, raw=record))
    return entries


UNPARSEABLE_COMMUNITY_LISTING = (
    "[REDACTED: unparseable show snmp community output]"
)

_COMMUNITY_INDEX_LABEL_RE = re.compile(
    r"(?im)^(\s*(?:Community\s*Index|CommunityIndex)\s*:\s*)(\S.*)$"
)


def redact_community_listing(text: str, *, names: list[str] | None = None) -> str:
    """Redact community strings in show snmp community (and similar) text.

    If the ISS key: value parser yields no entries, the whole listing
    body is replaced (fail closed: an unknown layout must not show
    foreign communities in the clear). Otherwise only Community Name
    fields (and a Community Index field that equals the configured
    secret) are redacted; values are never globally replaced.
    """
    del names  # no longer used for global replacement
    parsed = parse_snmp_community(text)
    if not parsed:
        match = re.search(r"^--- .+ ---\n", text, re.MULTILINE)
        prefix = text[: match.end()] if match else ""
        return prefix + UNPARSEABLE_COMMUNITY_LISTING
    redacted = redact_secrets(text)
    redacted = _COMMUNITY_NAME_LABEL_RE.sub(
        lambda match: match.group(1) + REDACTED, redacted
    )
    # Per-field only: mask an index that is itself the configured secret.
    community = valid_community_for_redaction()
    if community:
        def _redact_index(match: re.Match[str]) -> str:
            value = match.group(2)
            if value == community or value.lower() == community.lower():
                return match.group(1) + REDACTED
            return match.group(0)

        redacted = _COMMUNITY_INDEX_LABEL_RE.sub(_redact_index, redacted)
    return redacted


def view_included_oids(entries: list[ViewSubtree], view_name: str) -> list[str]:
    oids: list[str] = []
    for entry in entries:
        if entry.name.lower() != view_name.lower():
            continue
        if entry.view_type and entry.view_type not in {"included", "include"}:
            continue
        oids.append(entry.oid)
    return oids


def view_is_restricted(entries: list[ViewSubtree], view_name: str) -> tuple[bool, str]:
    """True if every included subtree of the view is on the OID allowlist."""
    oids = view_included_oids(entries, view_name)
    if not oids:
        return False, f"view {view_name!r} has no included subtrees in the read-back"
    for oid in oids:
        compact = oid.strip().rstrip(".")
        if compact in BROAD_OIDS:
            return False, (
                f"view {view_name!r} includes a broad subtree {oid} "
                "(refusing to treat this as restricted access)"
            )
        if compact not in ALLOWED_SUBTREES:
            return False, (
                f"view {view_name!r} includes subtree {oid}, which is not "
                "on the OID allowlist"
            )
    return True, (
        f"view {view_name} includes only allow-listed subtrees: "
        + ", ".join(oids)
    )


def _model_is_v2c(model: str) -> bool:
    compact = re.sub(r"[\s._-]", "", model.lower())
    return compact in {"v2c", "snmpv2c", "snmpv2", "v2"}


def _model_is_missing(model: str) -> bool:
    return not model.strip()


def _view_is_none(name: str) -> bool:
    return name.strip().lower() in {"", "none", "n/a", "-"}


def find_community_entry(
    entries: list[CommunityEntry], community: str
) -> CommunityEntry | None:
    for entry in entries:
        if entry.name == community or entry.index == community:
            return entry
    return None


def assert_configured_community_ready(
    *,
    community_output: str,
    group_output: str,
    access_output: str,
    view_output: str,
    community: str,
) -> str:
    """Verify the configured community is present and view-restricted.

    Raises ValidationError on failure. The secret never appears in the
    error text or the returned status.
    """
    communities = parse_snmp_community(community_output)
    if not communities:
        raise ValidationError(
            "Could not parse show snmp community (unknown table layout). "
            "Refusing to remove another community until the configured "
            "community can be verified. Confirm the output format live."
        )
    entry = find_community_entry(communities, community)
    if entry is None:
        raise ValidationError(
            "Configured SWITCH_SNMP_COMMUNITY is not present in "
            "show snmp community. Refusing to remove another community."
        )
    security = entry.security_name.strip()
    if not security or security.lower() in {"none", "n/a", "-"}:
        raise ValidationError(
            "Configured community has no security name in the read-back. "
            "Refusing to remove another community."
        )

    groups = parse_snmp_group(group_output)
    matched_groups = [
        item
        for item in groups
        if item.user.lower() == security.lower() and _model_is_v2c(item.model)
    ]
    if not matched_groups and groups:
        # Fallback only when the model field is empty, never for v1/v3.
        matched_groups = [
            item
            for item in groups
            if item.user.lower() == security.lower() and _model_is_missing(item.model)
        ]
    if not matched_groups:
        raise ValidationError(
            "Configured community is not mapped to an SNMP group "
            "(show snmp group). Refusing to remove another community."
        )
    group_names = {item.group for item in matched_groups if item.group}

    accesses = parse_snmp_access(access_output)
    matched_access = [
        item
        for item in accesses
        if item.group in group_names and _model_is_v2c(item.model)
    ]
    if not matched_access and accesses:
        matched_access = [
            item
            for item in accesses
            if item.group in group_names and _model_is_missing(item.model)
        ]
    if not matched_access:
        raise ValidationError(
            "Configured community's group has no v2c access entry "
            "(show snmp group access). Refusing to remove another community."
        )

    views = parse_snmp_viewtree(view_output)
    notes: list[str] = []
    for item in matched_access:
        if _view_is_none(item.read_view):
            raise ValidationError(
                "Configured community's access has no read view. "
                "Refusing to remove another community."
            )
        ok, note = view_is_restricted(views, item.read_view)
        if not ok:
            raise ValidationError(
                note + ". Refusing to remove another community."
            )
        notes.append("read " + note)
        write = item.write_view.strip()
        if write.lower() == "none":
            notes.append("write view is none (read-only access)")
        elif not write:
            raise ValidationError(
                "Configured community's access has no write view "
                "(missing or unrecognised label). Refusing to remove "
                "another community."
            )
        else:
            ok, note = view_is_restricted(views, item.write_view)
            if not ok:
                raise ValidationError(
                    "write " + note + ". Refusing to remove another community."
                )
            notes.append("write " + note)
    return (
        "Configured community is present, bound to group(s) "
        + ", ".join(sorted(group_names))
        + ", "
        + "; ".join(notes)
        + "."
    )


def resolve_removable_community_name(
    requested: str, entries: list[CommunityEntry], configured: str
) -> str:
    """Return the device's exact spelling of an allow-listed default name."""
    if requested == configured or requested.lower() == configured.lower():
        raise ValidationError(
            "Refusing to remove the configured SWITCH_SNMP_COMMUNITY community."
        )
    target = requested.lower()
    for entry in entries:
        for candidate in (entry.name, entry.index):
            if candidate and candidate.lower() == target:
                if candidate == configured or candidate.lower() == configured.lower():
                    raise ValidationError(
                        "Refusing to remove the configured "
                        "SWITCH_SNMP_COMMUNITY community."
                    )
                return candidate
    # Not in the listing: still allow the canonical name so a missing
    # default can be reported after the no-command, but only public/private.
    return requested


def format_sent_commands(commands: list[str]) -> str:
    lines = "\n".join(f"  {line}" for line in redact_command_list(commands))
    return "Configuration sent:\n" + lines


def community_present(output: str, community: str) -> bool:
    return find_community_entry(parse_snmp_community(output), community) is not None


def user_present(output: str, name: str) -> bool:
    return any(entry.name.lower() == name.lower() for entry in parse_snmp_user(output))
