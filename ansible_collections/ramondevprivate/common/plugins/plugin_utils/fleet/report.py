# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Merge fleet snapshots and prepare everything the Markdown templates print (runs on the controller)."""

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal, TypedDict

from ansible.errors import AnsibleFilterError  # pyright: ignore[reportMissingTypeStubs] - no stubs

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import (
    Data,
    as_list,
    as_mapping,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    Address,
    AuthorizedKey,
    Snapshot,
    Sudo,
    User,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.users import sudo_runas
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.network_view import (
    ContainerView,
    DaemonView,
    PortView,
    UfwView,
    container_views,
    daemon_views,
    docker_modes,
    port_views,
    ufw_view,
)
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.security_view import (
    Finding,
    auto_update_status,
    findings,
)
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.snapshot import parse_snapshot

_STEP: Final = 1024
_MIB: Final = _STEP * _STEP
_UNITS: Final = ("KiB", "MiB", "GiB", "TiB", "PiB")
DEFAULT_INACTIVE_DAYS: Final = 365
DEFAULT_UPDATE_MAX_AGE_DAYS: Final = 7
# Mermaid xychart sizes: title and value axis plus one row per host; with a title, 206 px or less renders nothing
CHART_MIN_HEIGHT: Final = 300
CHART_BASE_HEIGHT: Final = 120
CHART_ROW_HEIGHT: Final = 24
OPTION_KEYS: Final = frozenset({"inactive_days", "stopped_containers", "update_max_age_days"})


class MountView(TypedDict):
    """A mount row on the server page."""

    mount: str
    device: str
    fstype: str
    size: str


class UserView(TypedDict):
    """One row of the users table on a server page."""

    name: str
    groups: list[str]
    sudo: str
    authorized_keys: list[str] | None
    status: Literal["active", "inactive", "unknown"]  # from the last login; the date itself is not shown


class HostView(TypedDict):
    """Everything the server page and the overview print about one host."""

    host: str
    reached: bool
    last_updated: str
    os: str
    kernel: str
    cores: int
    ram: str
    disk: str
    mounts: list[MountView]
    addresses: list[Address]
    users: list[UserView]
    keys_from_command: bool
    key_files_assumed: bool
    ufw: UfwView
    ports: list[PortView]
    ports_unknown: bool  # ss was not available; the table only has Docker-published ports
    daemons: list[DaemonView]
    containers: list[ContainerView]
    docker: str  # Docker modes for the overview
    tags: list[str]
    fail2ban: str  # state: active, failed, not installed, ...
    fail2ban_jails: list[str] | None
    auto_updates: str  # status from auto_update_status
    auto_updates_last: str  # date of the last successful run, "" if none
    findings: list[Finding]
    exposure: str  # public, internal, unknown
    exposure_answered: list[str]
    exposure_checked: str  # date of the probe, "" if never probed


class Metric(TypedDict):
    """Total, average, minimum and maximum of one capacity across the fleet."""

    label: str
    total: str
    average: str
    minimum: str
    maximum: str


class OsCount(TypedDict):
    """Number of servers running one OS version."""

    os: str
    servers: int


class Charts(TypedDict):
    """Raw numbers for the optional Mermaid charts, in host order."""

    labels: list[str]  # host names without the domain they all share
    height: int  # pixels; horizontal bars need room for one row per host
    cores: list[int]
    ram_gib: list[float]
    disk_gib: list[float]


class Totals(TypedDict):
    """Totals row of the hardware table."""

    cores: int
    ram: str
    disk: str


class Report(TypedDict):
    """Input for the overview and all server pages."""

    last_updated: str
    servers: int
    unreachable: int
    public: int
    internal: int
    os_counts: list[OsCount]
    metrics: list[Metric]
    totals: Totals
    containers: int
    attention: list[Finding]
    hosts: list[HostView]
    charts: Charts


@dataclass(frozen=True)
class ReportOptions:
    """Role settings that shape the report."""

    inactive_days: int = DEFAULT_INACTIVE_DAYS
    include_stopped: bool = True
    update_max_age_days: int = DEFAULT_UPDATE_MAX_AGE_DAYS


def parse_options(value: object) -> ReportOptions:
    """Options from the filter argument; missing keys use the defaults, invalid values raise AnsibleFilterError.

    A wrong value must not silently fall back to a default (e.g. a typo in an option name would be ignored).
    """
    if value is None:
        return ReportOptions()
    data = as_mapping(value)
    if not data and value != {}:
        message = f"fleet_report options must be a mapping, got {type(value).__name__}"
        raise AnsibleFilterError(message)
    if unknown := sorted(set(data) - OPTION_KEYS):
        message = f"fleet_report: unknown options {', '.join(unknown)}"
        raise AnsibleFilterError(message)
    stopped = data.get("stopped_containers", True)
    if not isinstance(stopped, bool):
        message = f"fleet_report: stopped_containers must be a bool, got {stopped!r}"
        raise AnsibleFilterError(message)
    return ReportOptions(
        inactive_days=_option_days(data, "inactive_days", DEFAULT_INACTIVE_DAYS),
        include_stopped=stopped,
        update_max_age_days=_option_days(data, "update_max_age_days", DEFAULT_UPDATE_MAX_AGE_DAYS),
    )


def _option_days(data: Data, key: str, default: int) -> int:
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        message = f"fleet_report: {key} must be a positive integer, got {value!r}"
        raise AnsibleFilterError(message)
    return value


def build_report(current: object, stored: object, unreachable: object, options: object = None) -> Report:
    """Merge stored and current snapshots and derive the report.

    Args:
        current: Snapshots collected in this run. They win over stored ones of the same host.
        stored: Snapshots read from fleet_data_dir, including hosts not collected in this run.
        unreachable: Names of hosts that were targeted in this run but not collected. Hosts whose stored snapshot
            has `unreached_since` (an earlier run couldn't collect them) count as not updated too.
        options: Mapping with inactive_days, stopped_containers and update_max_age_days (see ReportOptions);
            missing keys use the defaults.
    """
    settings = parse_options(options)
    snapshots: dict[str, Snapshot] = {}
    for item in [*as_list(stored), *as_list(current)]:
        snapshot = parse_snapshot(item)
        if snapshot is not None:
            snapshots[snapshot["host"]] = snapshot
    missing = {name for name in as_list(unreachable) if isinstance(name, str)}
    ordered = [snapshots[name] for name in sorted(snapshots)]
    hosts = [_host_view(s, reached=s["host"] not in missing and "unreached_since" not in s, options=settings) for s in ordered]

    cores = [s["system"]["cores"] for s in ordered]
    ram = [s["system"]["ram_mb"] * _MIB for s in ordered]
    disk = [s["system"]["disk"]["total_bytes"] for s in ordered]
    return {
        "last_updated": max((s["collected_at"][:10] for s in ordered), default=""),
        "servers": len(ordered),
        "unreachable": sum(not h["reached"] for h in hosts),
        "public": sum(h["exposure"] == "public" for h in hosts),
        "internal": sum(h["exposure"] == "internal" for h in hosts),
        "os_counts": _os_counts(ordered),
        "metrics": [
            _metric("Cores", cores, str, lambda v: f"{v:.1f}"),
            _metric("RAM", ram, format_bytes, lambda v: format_bytes(round(v))),
            _metric("Disk", disk, format_bytes, lambda v: format_bytes(round(v))),
        ],
        "totals": {"cores": sum(cores), "ram": format_bytes(sum(ram)), "disk": format_bytes(sum(disk))},
        "containers": sum(len(h["containers"]) for h in hosts),
        "attention": [finding for h in hosts for finding in h["findings"]],
        "hosts": hosts,
        "charts": {
            "labels": chart_labels([s["host"] for s in ordered]),
            "height": max(CHART_MIN_HEIGHT, CHART_BASE_HEIGHT + CHART_ROW_HEIGHT * len(ordered)),
            "cores": cores,
            "ram_gib": [round(v / _STEP**3, 1) for v in ram],
            "disk_gib": [round(v / _STEP**3, 1) for v in disk],
        },
    }


def _host_view(snapshot: Snapshot, *, reached: bool, options: ReportOptions) -> HostView:
    system = snapshot["system"]
    daemons = snapshot["docker"]
    ufw = snapshot["ufw"]
    listeners = snapshot["listeners"]
    ports = port_views(listeners, ufw, daemons)
    fail2ban = snapshot["fail2ban"]
    auto_updates = snapshot["auto_updates"]
    update_status = auto_update_status(auto_updates, snapshot["collected_at"], options.update_max_age_days)
    exposure = snapshot.get("exposure") or {"state": "unknown", "checked_at": "", "answered": []}
    return {
        "host": snapshot["host"],
        "reached": reached,
        "last_updated": snapshot["collected_at"][:10],
        "os": f"{system['distribution']} {system['version']}".strip(),
        "kernel": system["kernel"],
        "cores": system["cores"],
        "ram": format_bytes(system["ram_mb"] * _MIB),
        "disk": format_bytes(system["disk"]["total_bytes"]),
        "mounts": [
            {"mount": m["mount"], "device": m["device"], "fstype": m["fstype"], "size": format_bytes(m["size_bytes"])} for m in system["disk"]["mounts"]
        ],
        "addresses": [a for a in snapshot["addresses"] if not is_ipv6_link_local(a["address"])],
        "users": [_user_view(u, snapshot["collected_at"], options.inactive_days) for u in snapshot["users"]],
        "keys_from_command": snapshot["ssh"]["keys_command"],
        "key_files_assumed": snapshot["ssh"]["key_files_source"] == "default",
        "ufw": ufw_view(ufw),
        "ports": ports,
        "ports_unknown": listeners is None,
        "daemons": daemon_views(daemons),
        "containers": container_views(daemons, include_stopped=options.include_stopped),
        "docker": docker_modes(daemons),
        "tags": [*([exposure["state"]] if exposure["state"] != "unknown" else []), *(["docker"] if daemons else [])],
        "fail2ban": fail2ban["state"],
        "fail2ban_jails": fail2ban["jails"],
        "auto_updates": update_status,
        "auto_updates_last": (auto_updates["last_success"] or "")[:10],
        "findings": findings(snapshot, update_status),
        "exposure": exposure["state"],
        "exposure_answered": exposure["answered"],
        "exposure_checked": exposure["checked_at"][:10],
    }


def _user_view(user: User, collected_at: str, inactive_days: int) -> UserView:
    sudo = user["sudo"]
    keys = user["authorized_keys"]
    return {
        "name": user["name"],
        "groups": user["groups"],
        "sudo": sudo_label(sudo),
        "authorized_keys": None if keys is None else [_key_label(k) for k in keys],
        "status": login_status(user["last_login"], collected_at, inactive_days),
    }


def sudo_label(sudo: Sudo) -> str:
    """Level, for limited also as whom (`limited (dockeruser)`), plus NOPASSWD; the rules stay in the JSON."""
    label = sudo["level"]
    if sudo["level"] == "limited" and (targets := sudo_runas(sudo["rules"])):
        label += f" ({', '.join(targets)})"
    return label + (", NOPASSWD" if sudo["nopasswd"] else "")


def _key_label(key: AuthorizedKey) -> str:
    label = key["comment"] or key["fingerprint"]
    if key["allowed_from"]:
        label += f" (from {key['allowed_from']})"
    if key["forced_command"]:
        label += " (forced command)"
    return label


def login_status(last_login: str | None, collected_at: str, inactive_days: int) -> Literal["active", "inactive", "unknown"]:
    """Inactive if the last login is older than inactive_days at collection time; unknown without a record."""
    if not last_login:
        return "unknown"
    try:
        age = datetime.fromisoformat(collected_at) - datetime.fromisoformat(last_login)
    except ValueError:
        return "unknown"
    except TypeError:  # one of the timestamps has no timezone
        return "unknown"
    return "inactive" if age.days > inactive_days else "active"


def is_ipv6_link_local(address: str) -> bool:
    """Return whether an address is IPv6 link-local (fe80::/10); those are hidden on the pages."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return isinstance(ip, ipaddress.IPv6Address) and ip.is_link_local


def _os_counts(snapshots: list[Snapshot]) -> list[OsCount]:
    """Servers per OS major version: Debian 13.1 and 13.3 both count as Debian 13."""
    counts: dict[tuple[str, str], int] = {}
    for snapshot in snapshots:
        key = (snapshot["system"]["distribution"], snapshot["system"]["version"].split(".")[0])
        counts[key] = counts.get(key, 0) + 1
    return [{"os": f"{name} {major}".strip(), "servers": counts[name, major]} for name, major in sorted(counts, key=_os_order)]


def _os_order(key: tuple[str, str]) -> tuple[str, int]:
    # numeric order (9 before 12); the guard only keeps a missing version from failing the report
    name, major = key
    return (name, int(major) if major.isdecimal() else 0)


def _metric(label: str, values: list[int], fmt: Callable[[int], str], fmt_avg: Callable[[float], str]) -> Metric:
    if not values:
        return {"label": label, "total": "", "average": "", "minimum": "", "maximum": ""}
    return {
        "label": label,
        "total": fmt(sum(values)),
        "average": fmt_avg(sum(values) / len(values)),
        "minimum": fmt(min(values)),
        "maximum": fmt(max(values)),
    }


def chart_labels(hosts: list[str]) -> list[str]:
    """Host names without the trailing domain labels all of them share (web.example.org -> web).

    At least one label is kept per host.
    """
    if len(hosts) <= 1:
        return list(hosts)
    parts = [host.split(".") for host in hosts]
    shared = 0
    while all(len(p) > shared + 1 for p in parts) and len({p[-1 - shared] for p in parts}) == 1:
        shared += 1
    return [".".join(p[: len(p) - shared]) for p in parts]


def format_bytes(size: int) -> str:
    """Format a byte count with binary units and one decimal, e.g. 491.9 GiB."""
    if abs(size) < _STEP:
        return f"{size} B"
    value = size / _STEP
    for unit in _UNITS[:-1]:
        if abs(value) < _STEP:
            return f"{value:.1f} {unit}"
        value /= _STEP
    return f"{value:.1f} {_UNITS[-1]}"
