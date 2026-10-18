# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Build a host's fleet snapshot from its facts, and read stored snapshots back (runs on the controller)."""

import ipaddress
import re
from typing import Final, Literal

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import (
    Data,
    as_list,
    as_mapping,
    get_int,
    get_list,
    get_mapping,
    get_str,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    SCHEMA_VERSION,
    Address,
    Disk,
    Mount,
    Snapshot,
    SystemInfo,
)
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.network_data import (
    parse_docker,
    parse_listeners,
    parse_ufw,
)
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.security_data import (
    parse_auto_updates,
    parse_exposure,
    parse_fail2ban,
)
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.users_data import parse_ssh, parse_users

# Pseudo filesystems. Ansible usually drops them already (device must start with "/"); kept as a safety net.
EXCLUDED_FSTYPES: Final = frozenset({"tmpfs", "devtmpfs", "overlay", "squashfs", "nsfs"})
# Mounts below Docker's data dirs belong to containers, not to the host.
EXCLUDED_MOUNT_PARTS: Final = ("/var/lib/docker/", "/var/lib/containerd/", "/run/docker/", "/.local/share/docker/")

SKIPPED_INTERFACES: Final = frozenset({"lo", "docker0"})
SKIPPED_INTERFACE_PREFIXES: Final = ("br-", "veth")

PRIVATE_NETWORKS: Final = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",  # CGNAT
        "169.254.0.0/16",  # link-local
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
    )
)


def build_snapshot(facts: object, host: str, collected_at: str, collected: object) -> Snapshot:
    """Build the snapshot of one host from its ansible_facts and the fleet_info module result."""
    data = as_mapping(facts)
    module_result = as_mapping(collected)
    return {
        "schema_version": SCHEMA_VERSION,
        "host": host,
        "collected_at": collected_at,
        "system": _system(data),
        "addresses": addresses(data),
        "users": parse_users(module_result.get("users")),
        "ssh": parse_ssh(module_result.get("ssh")),
        "ufw": parse_ufw(module_result.get("ufw")),
        "listeners": parse_listeners(module_result.get("listeners")),
        "docker": parse_docker(module_result.get("docker")),
        "fail2ban": parse_fail2ban(module_result.get("fail2ban")),
        "auto_updates": parse_auto_updates(module_result.get("auto_updates")),
    }


def _system(facts: Data) -> SystemInfo:
    return {
        "distribution": get_str(facts, "distribution", "unknown"),
        "version": get_str(facts, "distribution_version"),
        "release": get_str(facts, "distribution_release"),
        "kernel": get_str(facts, "kernel"),
        "cores": get_int(facts, "processor_vcpus"),
        "ram_mb": get_int(facts, "memtotal_mb"),
        "disk": disk(get_list(facts, "mounts")),
    }


def disk(mounts: list[object]) -> Disk:
    """Sum the capacity of real filesystems, counting every device once."""
    seen_devices: set[str] = set()
    counted: list[Mount] = []
    for item in mounts:
        mount = as_mapping(item)
        path = get_str(mount, "mount")
        device = get_str(mount, "device")
        if not path or _is_excluded(mount, path) or device in seen_devices:
            continue
        seen_devices.add(device)
        counted.append(
            {
                "mount": path,
                "device": device,
                "fstype": get_str(mount, "fstype"),
                "size_bytes": get_int(mount, "size_total"),
            }
        )
    counted.sort(key=lambda m: m["mount"])
    return {"total_bytes": sum(m["size_bytes"] for m in counted), "mounts": counted}


def _is_excluded(mount: Data, path: str) -> bool:
    options = get_str(mount, "options").split(",")
    return "bind" in options or get_str(mount, "fstype") in EXCLUDED_FSTYPES or any(part in path for part in EXCLUDED_MOUNT_PARTS)


def addresses(facts: Data) -> list[Address]:
    """List the IP addresses of all relevant interfaces."""
    result: list[Address] = []
    names = sorted(n for n in get_list(facts, "interfaces") if isinstance(n, str))
    for name in names:
        if name in SKIPPED_INTERFACES or name.startswith(SKIPPED_INTERFACE_PREFIXES):
            continue
        # Ansible stores interface facts under the name with "-" replaced by "_"
        interface = get_mapping(facts, name.replace("-", "_"))
        ipv4 = [interface.get("ipv4"), *get_list(interface, "ipv4_secondaries")]
        result.extend(_address(name, "ipv4", entry) for entry in ipv4 if as_mapping(entry))
        result.extend(_address(name, "ipv6", entry) for entry in get_list(interface, "ipv6") if as_mapping(entry))
    return [a for a in result if a["address"]]


def _address(interface: str, family: Literal["ipv4", "ipv6"], entry: object) -> Address:
    data = as_mapping(entry)
    address = get_str(data, "address")
    return {
        "interface": interface,
        "address": address,
        "prefix": get_int(data, "prefix"),
        "family": family,
        "private": is_private(address),
    }


def is_private(address: str) -> bool:
    """Return whether an address is not publicly routable (unparseable counts as private).

    Documentation ranges (192.0.2.0/24, 2001:db8::/32) count as public, so test data can stand for public hosts.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    return any(ip.version == net.version and ip in net for net in PRIVATE_NETWORKS)


# Stored snapshots

# the host name becomes a file name (Servers/<host>.md): no path separators, no leading dot
HOST_NAME: Final = re.compile(r"[A-Za-z0-9_:][A-Za-z0-9._:-]*")


def mark_unreached(stored: object, unreachable: object, timestamp: str) -> list[dict[str, object]]:
    """Stored snapshots of the unreached hosts, with `unreached_since` set (kept if an earlier run already set it).

    The snapshots are returned as stored, only with that field added, so writing them back changes nothing else and
    a repeated unreached run writes identical files. Hosts without a stored snapshot have nothing to mark.
    """
    names = {name for name in as_list(unreachable) if isinstance(name, str)}
    marked: list[dict[str, object]] = []
    for item in as_list(stored):
        snapshot = parse_snapshot(item)
        if snapshot is None or snapshot["host"] not in names:
            continue
        raw = dict(as_mapping(item))
        raw["unreached_since"] = snapshot.get("unreached_since") or timestamp
        marked.append(raw)
    return marked


def parse_snapshot(value: object) -> Snapshot | None:
    """Validate a snapshot read from JSON or hostvars; None if it has another schema version or no valid host name."""
    data = as_mapping(value)
    host = get_str(data, "host")
    if not HOST_NAME.fullmatch(host) or get_int(data, "schema_version", -1) != SCHEMA_VERSION:
        return None
    system = get_mapping(data, "system")
    disk = get_mapping(system, "disk")
    snapshot: Snapshot = {
        "schema_version": SCHEMA_VERSION,
        "host": host,
        "collected_at": get_str(data, "collected_at"),
        "system": {
            "distribution": get_str(system, "distribution", "unknown"),
            "version": get_str(system, "version"),
            "release": get_str(system, "release"),
            "kernel": get_str(system, "kernel"),
            "cores": get_int(system, "cores"),
            "ram_mb": get_int(system, "ram_mb"),
            "disk": {
                "total_bytes": get_int(disk, "total_bytes"),
                "mounts": [_parse_mount(as_mapping(m)) for m in get_list(disk, "mounts")],
            },
        },
        "addresses": [_parse_address(as_mapping(a)) for a in get_list(data, "addresses")],
        "users": parse_users(data.get("users")),
        "ssh": parse_ssh(data.get("ssh")),
        "ufw": parse_ufw(data.get("ufw")),
        "listeners": parse_listeners(data.get("listeners")),
        "docker": parse_docker(data.get("docker")),
        "fail2ban": parse_fail2ban(data.get("fail2ban")),
        "auto_updates": parse_auto_updates(data.get("auto_updates")),
    }
    _add_optional_sections(snapshot, data)
    return snapshot


def _add_optional_sections(snapshot: Snapshot, data: Data) -> None:
    """Exposure (added by the probe step) and unreached_since (set by a run that couldn't collect the host)."""
    if "exposure" in data:
        snapshot["exposure"] = parse_exposure(data["exposure"])
    if unreached := get_str(data, "unreached_since"):
        snapshot["unreached_since"] = unreached


def _parse_mount(data: Data) -> Mount:
    return {
        "mount": get_str(data, "mount"),
        "device": get_str(data, "device"),
        "fstype": get_str(data, "fstype"),
        "size_bytes": get_int(data, "size_bytes"),
    }


def _parse_address(data: Data) -> Address:
    return {
        "interface": get_str(data, "interface"),
        "address": get_str(data, "address"),
        "prefix": get_int(data, "prefix"),
        "family": _family(get_str(data, "family")),
        "private": data.get("private") is not False,
    }


def _family(value: str) -> Literal["ipv4", "ipv6", "unknown"]:
    if value == "ipv4":
        return "ipv4"
    if value == "ipv6":
        return "ipv6"
    return "unknown"
