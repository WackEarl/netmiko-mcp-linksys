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
    parse_protected_ifindexes,
    parse_protected_poe_indexes,
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
#
# UNCONFIRMED: the LGS328PC port -> ifIndex mapping (hence the explicit
# SWITCH_SNMP_PROTECTED_IFINDEXES), the port -> pethPsePortTable
# <group>.<port> mapping (hence SWITCH_SNMP_PROTECTED_POE_INDEXES),
# whether an instance OID such as 1.3.6.1.2.1.2.2.1.7.<ifIndex> or
# 1.3.6.1.2.1.105.1.1.1.3.<group>.<port> is accepted as an excluded subtree
# without a mask, and how show snmp viewtree prints the view type and
# the mask (the parser accepts only empty or all-ones masks).

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
        "POWER-ETHERNET-MIB: PoE admin/detection/budget (read view; "
        "PoE switching goes through the pethPsePortAdminEnable column "
        "of a write view)"
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

POE_SUBTREE = "1.3.6.1.2.1.105"

# IF-MIB ifTable ifAdminStatus column; .<ifIndex> selects one interface.
IF_ADMIN_STATUS_OID = "1.3.6.1.2.1.2.2.1.7"
# IF-MIB ifXTable ifAlias column (port description).
IF_ALIAS_OID = "1.3.6.1.2.1.31.1.1.1.18"
# POWER-ETHERNET-MIB pethPsePortTable pethPsePortAdminEnable column;
# .<pethPsePortGroupIndex>.<pethPsePortIndex> selects one PoE port.
POE_ADMIN_ENABLE_OID = "1.3.6.1.2.1.105.1.1.1.3"

# The only columns a *write* view may include (Task 48, Redy's plan
# approved by Roland): port admin state, port description, PoE on/off.
# Whole MIB subtrees stay read-view only. Every write view also excludes
# ifAdminStatus.<ifIndex> of the protected ports, and a write view with
# pethPsePortAdminEnable also excludes pethPsePortAdminEnable.<group>.<port>
# of the protected PoE ports (0/10 powers the Unraid server through a PoE
# splitter; 0/24 is the uplink).
WRITE_ALLOWED_SUBTREES: dict[str, str] = {
    IF_ADMIN_STATUS_OID: "ifAdminStatus",
    IF_ALIAS_OID: "ifAlias",
    POE_ADMIN_ENABLE_OID: "pethPsePortAdminEnable",
}

WRITE_OID_ALIASES: dict[str, str] = {
    name.lower(): oid for oid, name in WRITE_ALLOWED_SUBTREES.items()
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


def redact_community_name_fields(text: str) -> str:
    """Mask values after a Community Name / CommunityName label, per field."""
    return _COMMUNITY_NAME_LABEL_RE.sub(
        lambda match: match.group(1) + REDACTED, text
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


def _oid_key(oid: str) -> list[int]:
    return [int(part) for part in oid.split(".")]


def protected_admin_status_oids(ifindexes: dict[str, str]) -> list[str]:
    """ifAdminStatus.<ifIndex> OIDs to exclude from every write view."""
    return sorted(
        (f"{IF_ADMIN_STATUS_OID}.{ifindex}" for ifindex in ifindexes.values()),
        key=_oid_key,
    )


def protected_poe_admin_oids(poe_indexes: dict[str, str]) -> list[str]:
    """pethPsePortAdminEnable.<group>.<port> OIDs to exclude from PoE write views."""
    return sorted(
        (f"{POE_ADMIN_ENABLE_OID}.{index}" for index in poe_indexes.values()),
        key=_oid_key,
    )


def _write_allowed_text() -> str:
    return ", ".join(
        f"{name} ({oid})" for oid, name in WRITE_ALLOWED_SUBTREES.items()
    )


def normalize_write_subtree(subtree: str) -> str:
    """Return a column OID a write view may include, or raise ValidationError."""
    key = subtree.strip() if isinstance(subtree, str) else ""
    oid = WRITE_OID_ALIASES.get(key.lower(), key)
    if oid not in WRITE_ALLOWED_SUBTREES:
        raise ValidationError(
            f"subtree {key or subtree!r} is not allowed in a write view. Write "
            "views may include only " + _write_allowed_text() + ". Whole MIB "
            "subtrees (interfaces, ifmib, power-ethernet) belong in the read "
            "view (snmp_view_create)."
        )
    return oid


def build_write_view_commands(
    view_name: str, oid: str, excluded_oids: list[str]
) -> list[str]:
    """Linksys CLI: snmp view <ViewName> <OIDTree> {included | excluded}.

    Exclusions are sent first so the view never includes a writable
    column without the protected-port exclusions, even for a moment.
    """
    if not excluded_oids:
        raise ValidationError(
            "No ifAdminStatus exclusions configured. Refusing to build a "
            "write view (fail-closed)."
        )
    if oid == POE_ADMIN_ENABLE_OID and not _poe_exclusions(excluded_oids):
        raise ValidationError(
            "No pethPsePortAdminEnable exclusions configured. Refusing to "
            "add PoE to a write view (fail-closed)."
        )
    return [f"snmp view {view_name} {item} excluded" for item in excluded_oids] + [
        f"snmp view {view_name} {oid} included"
    ]


def build_community_create_commands(
    view_name: str, access: str, community: str, write_view: str | None = None
) -> list[str]:
    """ISS v2c mapping: group + access + community (Linksys name/security form).

    ``view_name`` is the read view. For ``rw`` a separate ``write_view``
    is required (read/write split); for ``ro`` it must be omitted.

    The community string is used only as the ``name`` value and is never
    reused as the security/group name, so show snmp group does not repeat
    the secret. The caller must redact any echo of these commands.
    """
    if access == "rw":
        if not write_view:
            raise ValidationError(
                "rw access needs a separate write_view (created with "
                "snmp_write_view_create). Refusing to grant write access "
                "through the read view."
            )
        if write_view.lower() == view_name.lower():
            raise ValidationError(
                "write_view must differ from the read view (view_name). "
                "The read view holds whole MIB subtrees; the write view "
                "only the writable columns with the protected-port "
                "exclusions."
            )
        write = write_view
    else:
        if write_view:
            raise ValidationError(
                "write_view is only valid with access 'rw'."
            )
        write = "none"
    group = group_name_for_view(view_name)
    security = security_name_for_view(view_name)
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
    mask: str = ""


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
        mask = _field(fields, "subtree mask", "subtreemask", "oid mask", "oidmask", "mask")
        if not name or not oid:
            continue
        entries.append(
            ViewSubtree(
                name=name, oid=oid, view_type=view_type, raw=record, mask=mask
            )
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
    redacted = redact_community_name_fields(redacted)
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


# Accepted spellings of an all-ones mask (exact subtree match, no
# wildcard). RFC 3415: a missing or short mask is extended with ones. Any
# other mask could wildcard sub-identifiers and is treated as unknown.
_EXACT_MASK_RE = re.compile(
    r"^(?:|-|none|n/a|1(?:\.1)*|(?:0x)?f+|ff(?:[:\s]ff)*)$", re.IGNORECASE
)


def mask_is_exact(mask: str) -> bool:
    return bool(_EXACT_MASK_RE.fullmatch(mask.strip()))


_OID_ARC_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")


def oid_arcs(oid: str) -> tuple[int, ...] | None:
    """Parse an OID as printed by the switch into its arcs, or None.

    The one central OID normalization (Cody, review of bc96149): surrounding
    whitespace, one leading dot, a leading ``iso`` arc (= 1) and trailing
    dots are accepted, so ``.1.3.6.1``, ``iso.3.6.1``, ``.iso.3.6.1.`` and
    ``1.3.6.1`` are the same OID. Anything else (empty arcs, signs, leading
    zeros, other names, masks or extra tokens) is None, and callers must
    treat None as "refuse" (fail-closed).
    """
    if not isinstance(oid, str):
        return None
    text = oid.strip().removeprefix(".").rstrip(".")
    if not text:
        return None
    parts = text.split(".")
    if parts[0].lower() == "iso":
        parts[0] = "1"
    if not all(_OID_ARC_RE.fullmatch(part) for part in parts):
        return None
    return tuple(int(part) for part in parts)


def canonical_oid(oid: str) -> str | None:
    """Dotted numeric form of ``oid`` (see oid_arcs), or None if unparseable."""
    arcs = oid_arcs(oid)
    return None if arcs is None else ".".join(str(arc) for arc in arcs)


def oid_within(oid: str, subtree: str) -> bool:
    """True if ``oid`` equals ``subtree`` or lies below it, compared by arcs.

    1.3.6.1.2.1.105 is not within 1.3.6.1.2.1.10. Unparseable input is
    never within anything (callers refuse it separately).
    """
    arcs, prefix = oid_arcs(oid), oid_arcs(subtree)
    if arcs is None or prefix is None:
        return False
    return arcs[: len(prefix)] == prefix


def view_entry_problem(entries: list[ViewSubtree], view_name: str) -> str | None:
    """Why the entries of exactly ``view_name`` cannot be trusted, or None.

    Every entry needs a parseable OID and an exact (empty or all-ones)
    mask; a partial mask could wildcard sub-identifiers, so the entry
    would cover more (or other) OIDs than it shows (fail-closed).
    """
    for entry in entries:
        if entry.name != view_name:
            continue
        if oid_arcs(entry.oid) is None:
            return (
                f"view {view_name!r} has subtree {entry.oid!r} in an "
                "unrecognised OID format"
            )
        if not mask_is_exact(entry.mask):
            return (
                f"view {view_name!r} has subtree {canonical_oid(entry.oid)} with an "
                "unrecognised mask (could be a wildcard)"
            )
    return None


def case_variant_view_names(entries: list[ViewSubtree], view_name: str) -> list[str]:
    """Other view names that differ from ``view_name`` only in letter case.

    It is not known whether ISS treats view names case-sensitively, so such
    a pair is ambiguous: the device may merge them (or not) while our checks
    see two views. Callers must refuse (fail-closed).
    """
    target = view_name.casefold()
    return sorted(
        {
            entry.name
            for entry in entries
            if entry.name != view_name and entry.name.casefold() == target
        }
    )


def case_variant_note(view_name: str, variants: list[str]) -> str:
    return (
        f"view {view_name!r} differs only in letter case from existing "
        f"view(s) {', '.join(repr(name) for name in variants)} (refusing: "
        "it is not confirmed whether the switch treats view names "
        "case-sensitively)"
    )


def view_included_oids(entries: list[ViewSubtree], view_name: str) -> list[str]:
    """Included subtrees of exactly ``view_name`` (case-sensitive), canonical.

    An unparseable OID is returned stripped as-is, so it matches no
    allowlist; checks refuse it via view_entry_problem first.
    """
    oids: list[str] = []
    for entry in entries:
        if entry.name != view_name:
            continue
        if entry.view_type and entry.view_type not in {"included", "include"}:
            continue
        oids.append(canonical_oid(entry.oid) or entry.oid.strip())
    return oids


def view_entry_set(entries: list[ViewSubtree]) -> set[tuple[str, str, str, str]]:
    """Comparable snapshot of a viewtree (name, OID, type, mask)."""
    return {
        (
            entry.name,
            canonical_oid(entry.oid) or entry.oid.strip(),
            entry.view_type,
            entry.mask.strip(),
        )
        for entry in entries
    }


def view_is_restricted(entries: list[ViewSubtree], view_name: str) -> tuple[bool, str]:
    """True if every included subtree of the view is on the OID allowlist."""
    variants = case_variant_view_names(entries, view_name)
    if variants:
        return False, case_variant_note(view_name, variants)
    oids = view_included_oids(entries, view_name)
    if not oids:
        return False, f"view {view_name!r} has no included subtrees in the read-back"
    problem = view_entry_problem(entries, view_name)
    if problem:
        return False, problem
    for oid in oids:
        compact = oid
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


def view_is_write_safe(
    entries: list[ViewSubtree], view_name: str, excluded_oids: list[str]
) -> tuple[bool, str]:
    """Strict check of a write view (fail-closed).

    Every entry of the view must have an explicit included/excluded type
    and an exact mask; included subtrees must be columns in
    WRITE_ALLOWED_SUBTREES (never a whole MIB subtree); every exclusion in
    ``excluded_oids`` must be present as an excluded entry. A view that
    includes pethPsePortAdminEnable must also be checked against PoE
    exclusions (see write_view_exclusions); without any, it is refused.
    """
    if not excluded_oids:
        return False, (
            f"no ifAdminStatus exclusions configured for write view {view_name!r}"
        )
    variants = case_variant_view_names(entries, view_name)
    if variants:
        return False, "write " + case_variant_note(view_name, variants)
    own = [entry for entry in entries if entry.name == view_name]
    if not own:
        return False, f"write view {view_name!r} was not found in the read-back"
    problem = view_entry_problem(entries, view_name)
    if problem:
        return False, "write " + problem
    included: list[str] = []
    excluded: set[str] = set()
    for entry in own:
        oid = canonical_oid(entry.oid) or entry.oid.strip()
        if entry.view_type in {"included", "include"}:
            included.append(oid)
        elif entry.view_type in {"excluded", "exclude"}:
            excluded.add(oid)
        else:
            return False, (
                f"write view {view_name!r} has subtree {oid} without a "
                "recognised included/excluded type"
            )
    if not included:
        return False, f"write view {view_name!r} has no included subtrees"
    for oid in included:
        if oid == POE_SUBTREE:
            return False, (
                f"write view {view_name!r} includes the whole "
                f"POWER-ETHERNET-MIB {oid} (only the pethPsePortAdminEnable "
                f"column {POE_ADMIN_ENABLE_OID} is allowed)"
            )
        if oid not in WRITE_ALLOWED_SUBTREES:
            return False, (
                f"write view {view_name!r} includes subtree {oid}, which is "
                "not allowed in a write view"
            )
    if POE_ADMIN_ENABLE_OID in included and not _poe_exclusions(excluded_oids):
        return False, (
            f"write view {view_name!r} includes pethPsePortAdminEnable but no "
            "PoE exclusions are configured (SWITCH_SNMP_PROTECTED_POE_INDEXES)"
        )
    missing = [oid for oid in excluded_oids if oid not in excluded]
    missing_admin = [oid for oid in missing if not _is_poe_exclusion(oid)]
    missing_poe = [oid for oid in missing if _is_poe_exclusion(oid)]
    if missing_admin:
        return False, (
            f"write view {view_name!r} is missing the ifAdminStatus "
            "exclusion(s) " + ", ".join(missing_admin)
        )
    if missing_poe:
        return False, (
            f"write view {view_name!r} is missing the pethPsePortAdminEnable "
            "exclusion(s) " + ", ".join(missing_poe)
        )
    return True, (
        f"write view {view_name} includes only "
        + ", ".join(included)
        + " and excludes "
        + ", ".join(excluded_oids)
    )


def _is_poe_exclusion(oid: str) -> bool:
    return oid_within(oid, POE_ADMIN_ENABLE_OID) and oid_arcs(oid) != oid_arcs(
        POE_ADMIN_ENABLE_OID
    )


def _poe_exclusions(oids: list[str]) -> list[str]:
    return [oid for oid in oids if _is_poe_exclusion(oid)]


def required_write_exclusions() -> list[str]:
    """ifAdminStatus exclusions from SWITCH_SNMP_PROTECTED_IFINDEXES (or raise)."""
    return protected_admin_status_oids(parse_protected_ifindexes())


def required_poe_exclusions() -> list[str]:
    """pethPsePortAdminEnable exclusions from SWITCH_SNMP_PROTECTED_POE_INDEXES (or raise)."""
    return protected_poe_admin_oids(parse_protected_poe_indexes())


def write_view_exclusions(
    entries: list[ViewSubtree], view_name: str, *, adding: str | None = None
) -> list[str]:
    """Exclusions a write view must carry, or raise ValidationError (fail-closed).

    ifAdminStatus of the protected ports is always excluded. If the view
    includes (or ``adding`` adds) pethPsePortAdminEnable, the protected PoE
    ports are excluded as well, which requires a valid
    SWITCH_SNMP_PROTECTED_POE_INDEXES.
    """
    included = set(view_included_oids(entries, view_name))
    if adding is not None:
        included.add(adding)
    exclusions = required_write_exclusions()
    if POE_ADMIN_ENABLE_OID in included:
        exclusions += required_poe_exclusions()
    return exclusions


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
    expected_read_view: str | None = None,
    expected_write_view: str | None = None,
) -> str:
    """Verify the configured community is present and view-restricted.

    A write view (anything other than ``none``) must differ from the read
    view and pass view_is_write_safe with the exclusions from
    write_view_exclusions (ifAdminStatus always, pethPsePortAdminEnable
    when the write view includes PoE). If expected views are given
    (after a create), the access entries must name exactly those views;
    ``expected_write_view=None`` then means the write view must be none.

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
    if expected_read_view is not None:
        _assert_expected_access_views(
            matched_access, expected_read_view, expected_write_view
        )
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
            if write.lower() == item.read_view.strip().lower():
                raise ValidationError(
                    "Configured community's access uses the same view for "
                    "read and write (no read/write split). Refusing to "
                    "remove another community."
                )
            try:
                exclusions = write_view_exclusions(views, write)
            except ValidationError as exc:
                raise ValidationError(
                    "Configured community has write access, but the "
                    f"protected-port exclusions are not usable: {exc}"
                ) from None
            ok, note = view_is_write_safe(views, write, exclusions)
            if not ok:
                raise ValidationError(
                    note[:1].upper() + note[1:] + ". Refusing to remove another community."
                )
            notes.append(note)
    return (
        "Configured community is present, bound to group(s) "
        + ", ".join(sorted(group_names))
        + ", "
        + "; ".join(notes)
        + "."
    )


def _assert_expected_access_views(
    matched_access: list[AccessEntry],
    expected_read_view: str,
    expected_write_view: str | None,
) -> None:
    """Exact comparison of the access entries against the requested views."""
    want_write = expected_write_view if expected_write_view else "none"
    for item in matched_access:
        read = item.read_view.strip()
        write = item.write_view.strip()
        write_matches = (
            write.lower() == "none" if want_write == "none" else write == want_write
        )
        if read != expected_read_view or not write_matches:
            raise ValidationError(
                "Configured community's access does not use the requested "
                f"views (expected read {expected_read_view}, write {want_write})."
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
