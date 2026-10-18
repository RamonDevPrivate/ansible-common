# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Prepare UFW, ports and containers for the server page (runs on the controller)."""

import ipaddress
from typing import Final, TypedDict

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import is_number
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    Container,
    DockerDaemon,
    Family,
    Listener,
    PublishedPort,
    Ufw,
    UfwRule,
)

ANY_ADDRESSES: Final = frozenset({"any", "0.0.0.0/0", "::/0"})
WILDCARD_IPS: Final = frozenset({"0.0.0.0", "::"})  # noqa: S104 - compared, never bound
# UDP traffic that ufw's default before.rules / before6.rules accept before any user rule is checked
BEFORE_RULES: Final[dict[tuple[str, int], str]] = {
    ("ipv4", 68): "DHCP replies",
    ("ipv6", 546): "DHCPv6 replies",
    ("ipv4", 5353): "mDNS multicast",
    ("ipv6", 5353): "mDNS multicast",
    ("ipv4", 1900): "UPnP multicast",
    ("ipv6", 1900): "UPnP multicast",
}
# processes that hold the host side of published container ports
DOCKER_PROXIES: Final = frozenset({"docker-proxy", "rootlesskit"})


class UfwRuleView(TypedDict):
    """One row of the UFW rules table, in the style of `ufw status`."""

    to: str
    action: str
    source: str
    comment: str


class UfwView(TypedDict):
    """UFW block of the server page."""

    state: str
    logging: str
    defaults: str
    rules: list[UfwRuleView] | None  # None: rules unknown


class PortView(TypedDict):
    """One row of the ports table: a port/proto with its bind addresses."""

    port: int
    proto: str
    addresses: list[str]
    processes: list[str]
    containers: list[str]
    families: list[Family]  # address families of the bind addresses
    ufw: str  # what UFW does with incoming traffic to this port
    bypass: bool  # published by a rootful daemon on a non-loopback address: UFW doesn't filter it


class ContainerView(TypedDict):
    """One row of the containers table."""

    name: str
    image: str
    version: str
    state: str
    compose_dir: str
    ports: list[str]
    daemon: str


class DaemonView(TypedDict):
    """One Docker daemon on the server page."""

    label: str
    version: str
    state: str


def daemon_label(daemon: DockerDaemon) -> str:
    """`rootful`, or `rootless (owner)`."""
    return f"rootless ({daemon['owner']})" if daemon["mode"] == "rootless" else "rootful"


def docker_modes(daemons: list[DockerDaemon]) -> str:
    """Docker modes of a host for the overview, without owners: `rootful`, `rootless`, `rootful, rootless`."""
    modes = sorted({d["mode"] for d in daemons})
    return ", ".join(modes) if modes else "—"


def visible_containers(daemons: list[DockerDaemon], *, include_stopped: bool) -> list[tuple[DockerDaemon, Container]]:
    """All containers with their daemon; without stopped ones if include_stopped is false."""
    return [(daemon, container) for daemon in daemons for container in daemon["containers"] if include_stopped or container["state"] == "running"]


def daemon_views(daemons: list[DockerDaemon]) -> list[DaemonView]:
    """Daemon lines of the server page."""
    return [{"label": daemon_label(d), "version": d["version"], "state": d["state"]} for d in daemons]


def container_views(daemons: list[DockerDaemon], *, include_stopped: bool) -> list[ContainerView]:
    """Rows of the containers table, sorted by name."""
    rows: list[ContainerView] = [
        {
            "name": container["name"],
            "image": container["image"].split("@")[0],  # the digest stays in the JSON
            "version": container["version"],
            "state": container["state"],
            "compose_dir": container["compose_dir"],
            "ports": _port_labels(container["ports"]),
            "daemon": daemon_label(daemon),
        }
        for daemon, container in visible_containers(daemons, include_stopped=include_stopped)
    ]
    return sorted(rows, key=lambda row: (row["name"], row["daemon"]))


def _port_labels(ports: list[PublishedPort]) -> list[str]:
    """`443→443/tcp`; with the host IPs only if they are not all-address wildcards."""
    grouped: dict[tuple[int, int, str], list[str]] = {}
    for port in ports:
        ips = grouped.setdefault((port["host_port"], port["container_port"], port["proto"]), [])
        if port["host_ip"] not in ips:
            ips.append(port["host_ip"])
    labels: list[str] = []
    for (host_port, container_port, proto), ips in grouped.items():
        label = f"{host_port}→{container_port}/{proto}"
        specific = [ip for ip in ips if ip not in WILDCARD_IPS]
        labels.append(f"{label} on {', '.join(specific)}" if specific else label)
    return labels


# UFW


def ufw_view(ufw: Ufw) -> UfwView:
    """Status line, defaults and rules table."""
    policies = (
        ("incoming", ufw["default_incoming"]),
        ("outgoing", ufw["default_outgoing"]),
        ("routed", ufw["default_routed"]),
    )
    return {
        "state": ufw["state"],
        "logging": ufw["logging"],
        "defaults": ", ".join(f"{policy} ({chain})" for chain, policy in policies if policy),
        "rules": None if ufw["rules"] is None else [_rule_view(rule) for rule in ufw["rules"]],
    }


def _rule_view(rule: UfwRule) -> UfwRuleView:
    to = rule["app"] or _port_proto(rule["to_port"], rule["proto"])
    if rule["to_address"] not in ANY_ADDRESSES:
        to = f"{rule['to_address']} {to}" if to else rule["to_address"]
    to = to or "Anywhere"
    if rule["family"] == "ipv6":
        to += " (v6)"
    if rule["interface_in"]:
        to += f" on {rule['interface_in']}"
    source = "Anywhere" if rule["from_address"] in ANY_ADDRESSES else rule["from_address"]
    if rule["from_port"] != "any":
        source += f" port {rule['from_port']}"
    if rule["interface_out"]:
        source += f" (out on {rule['interface_out']})"
    direction = "FWD" if rule["route"] else rule["direction"].upper()
    return {"to": to, "action": f"{rule['action'].upper()} {direction}", "source": source, "comment": rule["comment"]}


def _port_proto(port: str, proto: str) -> str:
    if port == "any":
        return "" if proto == "any" else f"Anywhere/{proto}"
    return port if proto == "any" else f"{port}/{proto}"


def ufw_effect(ufw: Ufw, proto: str, port: int, families: list[Family]) -> str:
    """What UFW does with incoming traffic to a port: matching rules, else the default policy.

    Rules are matched per address family because ufw keeps separate IPv4 and IPv6 rule sets. A family-specific
    prefix is only added when the families differ. Like ufw, the first matching rule decides for a packet: the list
    stops at the first rule that applies to every source, because no rule after it is ever reached.
    """
    if ufw["state"] != "active":
        return ufw["state"]
    rules = ufw["rules"]
    if rules is None:
        return "rules unknown"
    effects: dict[Family, str] = {family: _family_effect(ufw, rules, proto, port, family) for family in families}
    if len(set(effects.values())) <= 1:
        return next(iter(effects.values()), "")
    labels: dict[Family, str] = {"ipv4": "IPv4", "ipv6": "IPv6"}
    return "; ".join(f"{labels[family]}: {effect}" for family, effect in effects.items())


def _family_effect(ufw: Ufw, rules: list[UfwRule], proto: str, port: int, family: Family) -> str:
    if proto == "udp" and (builtin := BEFORE_RULES.get((family, port))):
        return f"ALLOW {builtin} (before.rules)"
    matches = [
        rule
        for rule in rules
        if rule["family"] == family
        and not rule["route"]
        and rule["direction"] == "in"
        and rule["proto"] in {"any", proto}
        and port_matches(rule["to_port"], port)
    ]
    if not matches:
        return f"default {ufw['default_incoming'] or 'unknown'}"
    reached: list[UfwRule] = []
    for rule in matches:
        reached.append(rule)
        if _applies_to_every_source(rule):
            break
    return ", ".join(_match_label(rule) for rule in reached)


def _applies_to_every_source(rule: UfwRule) -> bool:
    """Whether the rule matches all traffic to its port, so later rules for that port are never reached."""
    return rule["from_address"] in ANY_ADDRESSES and rule["from_port"] == "any" and rule["to_address"] in ANY_ADDRESSES and not rule["interface_in"]


def _match_label(rule: UfwRule) -> str:
    source = "Anywhere" if rule["from_address"] in ANY_ADDRESSES else rule["from_address"]
    label = f"{rule['action'].upper()} from {source}"
    if rule["to_address"] not in ANY_ADDRESSES:
        label += f" to {rule['to_address']}"
    if rule["interface_in"]:
        label += f" on {rule['interface_in']}"
    return label


def port_matches(spec: str, port: int) -> bool:
    """Whether a ufw port spec (`any`, `22`, `80,443`, `8000:8010`, mixed) includes port."""
    if spec == "any":
        return True
    for item in spec.split(","):
        start, _sep, end = item.partition(":")
        if is_number(start) and int(start) <= port <= int(end if is_number(end) else start):
            return True
    return False


# Ports


def is_loopback(address: str) -> bool:
    """127.0.0.0/8 and ::1; wildcards and unparsable addresses are not loopback."""
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def _families(addresses: list[str]) -> list[Family]:
    families: set[Family] = set()
    for address in addresses:
        base = address.split("%")[0]
        if base == "*":
            families.update(("ipv4", "ipv6"))
        else:
            families.add("ipv6" if ":" in base else "ipv4")
    return [family for family in ("ipv4", "ipv6") if family in families]


def port_views(listeners: list[Listener] | None, ufw: Ufw, daemons: list[DockerDaemon]) -> list[PortView]:
    """Ports table: listening sockets plus ports published by running containers, without loopback-only ones.

    Published ports are merged into the row of the proxy process that holds them (docker-proxy, rootlesskit).
    A rootful daemon without userland proxy publishes ports without any listening socket; those get their own row.
    """
    rows: dict[tuple[str, int, tuple[str, ...]], PortView] = {}
    for listener in listeners or []:
        if is_loopback(listener["address"]):
            continue
        key = (listener["proto"], listener["port"], tuple(listener["processes"]))
        row = rows.setdefault(key, _row(listener["proto"], listener["port"], list(listener["processes"])))
        address = listener["address"] + (f"%{listener['interface']}" if listener["interface"] else "")
        if address not in row["addresses"]:
            row["addresses"].append(address)

    for daemon in daemons:
        if daemon["state"] != "running":
            continue
        for container in daemon["containers"]:
            if container["state"] != "running":
                continue
            for published in container["ports"]:
                _add_published(rows, daemon, container, published)

    result = sorted(rows.values(), key=lambda r: (r["port"], r["proto"], r["processes"]))
    for row in result:
        row["families"] = _families(row["addresses"])
        row["ufw"] = ufw_effect(ufw, row["proto"], row["port"], row["families"])
    return result


def _row(proto: str, port: int, processes: list[str]) -> PortView:
    return {
        "port": port,
        "proto": proto,
        "addresses": [],
        "processes": processes,
        "containers": [],
        "families": [],
        "ufw": "",
        "bypass": False,
    }


def _add_published(
    rows: dict[tuple[str, int, tuple[str, ...]], PortView],
    daemon: DockerDaemon,
    container: Container,
    published: PublishedPort,
) -> None:
    host_ip = published["host_ip"]
    if is_loopback(host_ip):
        return
    proto, port = published["proto"], published["host_port"]
    row = next(
        (r for (r_proto, r_port, processes), r in rows.items() if r_proto == proto and r_port == port and set(processes) <= DOCKER_PROXIES),
        None,
    )
    if row is None:
        row = rows.setdefault((proto, port, ()), _row(proto, port, []))
        if host_ip not in row["addresses"]:
            row["addresses"].append(host_ip)
    if container["name"] not in row["containers"]:
        row["containers"].append(container["name"])
    if daemon["mode"] == "rootful":
        row["bypass"] = True
