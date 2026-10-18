# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the UFW, ports and containers views of the server page."""

from __future__ import annotations

from typing import TypedDict, Unpack

import pytest

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    Container,
    DaemonMode,
    DockerDaemon,
    Family,
    Listener,
    PublishedPort,
    Ufw,
    UfwRule,
    ufw_without_details,
)
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.network_view import (
    container_views,
    daemon_label,
    daemon_views,
    docker_modes,
    is_loopback,
    port_matches,
    port_views,
    ufw_effect,
    ufw_view,
    visible_containers,
)


class RuleFields(TypedDict, total=False):
    """Optional rule fields; unset ones are those of a plain `ufw allow <port>/tcp`."""

    proto: str
    source: str  # "" or unset: anywhere in the rule's family
    to_address: str  # "" or unset: anywhere in the rule's family
    from_port: str
    app: str
    interface_in: str
    interface_out: str
    route: bool
    comment: str
    action: str


def rule(port: str, family: Family = "ipv4", **fields: Unpack[RuleFields]) -> UfwRule:
    """An incoming allow rule for TCP from anywhere, with the given fields changed."""
    anywhere = "0.0.0.0/0" if family == "ipv4" else "::/0"
    return {
        "action": fields.get("action", "allow"),
        "direction": "in",
        "route": fields.get("route", False),
        "proto": fields.get("proto", "tcp"),
        "to_port": port,
        "to_address": fields.get("to_address") or anywhere,
        "from_port": fields.get("from_port", "any"),
        "from_address": fields.get("source") or anywhere,
        "app": fields.get("app", ""),
        "interface_in": fields.get("interface_in", ""),
        "interface_out": fields.get("interface_out", ""),
        "comment": fields.get("comment", ""),
        "family": family,
    }


def active(*rules: UfwRule) -> Ufw:
    """Active UFW with Debian's default policies."""
    ufw = ufw_without_details("active")
    ufw.update(default_incoming="deny", default_outgoing="allow", default_routed="disabled", rules=list(rules))
    return ufw


def listener(port: int, address: str = "0.0.0.0", *processes: str, proto: str = "tcp") -> Listener:
    """A listening socket."""
    return {"proto": proto, "address": address, "interface": "", "port": port, "processes": list(processes)}


def published(port: int, host_ip: str = "0.0.0.0") -> PublishedPort:
    """A TCP port published on the same port number."""
    return {"host_ip": host_ip, "host_port": port, "container_port": port, "proto": "tcp"}


def container(name: str, *ports: PublishedPort, state: str = "running", image: str = "") -> Container:
    """A container with published ports."""
    return {
        "name": name,
        "image": image or f"{name}:1",
        "version": "",
        "state": state,
        "compose_dir": "",
        "ports": list(ports),
    }


def daemon(mode: DaemonMode, *containers: Container, state: str = "running") -> DockerDaemon:
    """A daemon; rootless ones belong to dockeruser."""
    return {
        "mode": mode,
        "owner": "dockeruser" if mode == "rootless" else "",
        "socket": "/var/run/docker.sock",
        "state": "running" if state == "running" else "not running",
        "version": "29.7.1",
        "containers": list(containers),
    }


# UFW effect per port


def test_matching_rules_per_family() -> None:
    """IPv4 and IPv6 have separate rule sets; the difference is shown per family."""
    ufw = active(rule("22", proto="any", source="10.0.0.0/8"), rule("22"))

    effect = ufw_effect(ufw, "tcp", 22, ["ipv4", "ipv6"])

    assert effect == "IPv4: ALLOW from 10.0.0.0/8, ALLOW from Anywhere; IPv6: default deny"


@pytest.mark.parametrize(
    ("rules", "expected"),
    [
        pytest.param(
            [rule("22", source="10.0.0.0/8"), rule("22")],
            "ALLOW from 10.0.0.0/8, ALLOW from Anywhere",
            id="restricted-first",
        ),
        pytest.param([rule("22"), rule("22", source="10.0.0.0/8")], "ALLOW from Anywhere", id="catch-all-first"),
    ],
)
def test_rules_after_a_catch_all_are_never_reached(rules: list[UfwRule], expected: str) -> None:
    """The first matching rule decides, as in ufw: after one that matches every source, later rules never count."""
    assert ufw_effect(active(*rules), "tcp", 22, ["ipv4"]) == expected


@pytest.mark.parametrize(
    ("limited", "label"),
    [
        pytest.param(rule("22", interface_in="eth0"), "ALLOW from Anywhere on eth0", id="one-interface"),
        pytest.param(rule("22", to_address="192.0.2.10"), "ALLOW from Anywhere to 192.0.2.10", id="one-address"),
        pytest.param(rule("22", from_port="1024"), "ALLOW from Anywhere", id="one-source-port"),
    ],
)
def test_limited_rule_from_anywhere_is_no_catch_all(limited: UfwRule, label: str) -> None:
    """A rule limited to an interface, a destination or a source port doesn't match all traffic: later rules count."""
    assert ufw_effect(active(limited, rule("22")), "tcp", 22, ["ipv4"]) == f"{label}, ALLOW from Anywhere"


def test_deny_before_allow_hides_the_allow() -> None:
    """`deny 22` before `allow 22 from 10.0.0.0/8`: the port is closed for everyone."""
    deny = rule("22", action="deny")

    assert ufw_effect(active(deny, rule("22", source="10.0.0.0/8")), "tcp", 22, ["ipv4"]) == "DENY from Anywhere"


def test_same_effect_in_both_families_has_no_prefix() -> None:
    """The common case stays short."""
    ufw = active(rule("80"), rule("80", "ipv6"))

    assert ufw_effect(ufw, "tcp", 80, ["ipv4", "ipv6"]) == "ALLOW from Anywhere"


def test_no_matching_rule_shows_default_policy() -> None:
    """E.g. a second sshd port without a rule."""
    assert ufw_effect(active(rule("22")), "tcp", 2222, ["ipv4"]) == "default deny"


@pytest.mark.parametrize(
    ("port", "family", "expected"),
    [
        pytest.param(68, "ipv4", "ALLOW DHCP replies (before.rules)", id="dhcp"),
        pytest.param(546, "ipv6", "ALLOW DHCPv6 replies (before.rules)", id="dhcpv6"),
        pytest.param(5353, "ipv4", "ALLOW mDNS multicast (before.rules)", id="mdns"),
        pytest.param(5353, "ipv6", "ALLOW mDNS multicast (before.rules)", id="mdns-v6"),
        pytest.param(1900, "ipv4", "ALLOW UPnP multicast (before.rules)", id="upnp"),
        pytest.param(1900, "ipv6", "ALLOW UPnP multicast (before.rules)", id="upnp-v6"),
        pytest.param(546, "ipv4", "default deny", id="dhcpv6-port-in-ipv4"),
    ],
)
def test_default_before_rules(port: int, family: Family, expected: str) -> None:
    """The default before.rules of ufw accept some UDP traffic before user rules and policies apply."""
    assert ufw_effect(active(), "udp", port, [family]) == expected


def test_protocol_must_match() -> None:
    """A TCP rule doesn't open the UDP port."""
    assert ufw_effect(active(rule("443")), "udp", 443, ["ipv4"]) == "default deny"


@pytest.mark.parametrize(
    ("matching", "expected"),
    [
        pytest.param(rule("443", to_address="192.0.2.10"), "ALLOW from Anywhere to 192.0.2.10", id="destination"),
        pytest.param(rule("443", interface_in="eth0"), "ALLOW from Anywhere on eth0", id="interface"),
    ],
)
def test_effect_names_destination_and_interface(matching: UfwRule, expected: str) -> None:
    """A rule limited to one address or interface says so, as it may not cover every socket of the row."""
    assert ufw_effect(active(matching), "tcp", 443, ["ipv4"]) == expected


def test_port_independent_rule_matches() -> None:
    """`ufw allow from 10.0.0.0/8` opens every port for that network."""
    ufw = active(rule("any", proto="any", source="10.0.0.0/8"))

    assert ufw_effect(ufw, "tcp", 9000, ["ipv4"]) == "ALLOW from 10.0.0.0/8"


@pytest.mark.parametrize(
    ("ufw", "expected"),
    [
        pytest.param(ufw_without_details("inactive"), "inactive", id="inactive"),
        pytest.param(ufw_without_details("not installed"), "not installed", id="not-installed"),
        pytest.param(ufw_without_details("active"), "rules unknown", id="rules-unknown"),
    ],
)
def test_effect_without_active_rules(ufw: Ufw, expected: str) -> None:
    """Without an active UFW and known rules there is nothing to match."""
    assert ufw_effect(ufw, "tcp", 22, ["ipv4"]) == expected


@pytest.mark.parametrize(
    ("spec", "port", "expected"),
    [
        pytest.param("any", 1, True, id="any"),
        pytest.param("22", 22, True, id="single"),
        pytest.param("22", 2222, False, id="single-other"),
        pytest.param("80,443", 443, True, id="list"),
        pytest.param("8000:8010", 8005, True, id="range"),
        pytest.param("8000:8010", 8011, False, id="outside-range"),
        pytest.param("80,8000:8010", 8010, True, id="mixed"),
        pytest.param("abc", 80, False, id="not-a-port"),
        pytest.param("80,,443", 443, True, id="empty-list-item"),
    ],
)
def test_port_specs(spec: str, port: int, *, expected: bool) -> None:
    """Ufw port syntax: lists and ranges."""
    assert port_matches(spec, port) is expected


# UFW table


def test_default_policies_in_ufw_status_style() -> None:
    """Policy (chain), like the Default line of `ufw status verbose`."""
    assert ufw_view(active())["defaults"] == "deny (incoming), allow (outgoing), disabled (routed)"


def test_rules_table_in_ufw_status_style() -> None:
    """To, Action, From like `ufw status`, IPv6 rules marked (v6), comments kept."""
    view = ufw_view(active(rule("22", source="10.0.0.0/8"), rule("80", "ipv6", comment="traefik web")))

    assert view["rules"] == [
        {"to": "22/tcp", "action": "ALLOW IN", "source": "10.0.0.0/8", "comment": ""},
        {"to": "80/tcp (v6)", "action": "ALLOW IN", "source": "Anywhere", "comment": "traefik web"},
    ]


def test_rule_for_any_protocol_has_no_suffix() -> None:
    """`ufw allow 22` opens TCP and UDP."""
    view = ufw_view(active(rule("22", proto="any")))

    assert [r["to"] for r in view["rules"] or []] == ["22"]


@pytest.mark.parametrize(
    ("ufw_rule", "to", "action", "source"),
    [
        pytest.param(rule("443", to_address="192.0.2.10"), "192.0.2.10 443/tcp", "ALLOW IN", "Anywhere", id="to-address"),
        pytest.param(rule("any", proto="any", to_address="192.0.2.10"), "192.0.2.10", "ALLOW IN", "Anywhere", id="to-host"),
        pytest.param(rule("any"), "Anywhere/tcp", "ALLOW IN", "Anywhere", id="protocol-only"),
        pytest.param(rule("any", proto="any"), "Anywhere", "ALLOW IN", "Anywhere", id="everything"),
        pytest.param(rule("22", app="OpenSSH"), "OpenSSH", "ALLOW IN", "Anywhere", id="app-profile"),
        pytest.param(rule("22", interface_in="eth0"), "22/tcp on eth0", "ALLOW IN", "Anywhere", id="interface"),
        pytest.param(rule("68", proto="udp", from_port="67"), "68/udp", "ALLOW IN", "Anywhere port 67", id="from-port"),
        pytest.param(
            rule("80", route=True, interface_in="eth0", interface_out="docker0"),
            "80/tcp on eth0",
            "ALLOW FWD",
            "Anywhere (out on docker0)",
            id="route",
        ),
    ],
)
def test_rule_columns(ufw_rule: UfwRule, to: str, action: str, source: str) -> None:
    """Destination, action and source for each kind of rule."""
    row = (ufw_view(active(ufw_rule))["rules"] or [])[0]

    assert (row["to"], row["action"], row["source"]) == (to, action, source)


def test_unknown_rules_stay_unknown() -> None:
    """None, not an empty table."""
    assert ufw_view(ufw_without_details("unknown"))["rules"] is None


# Ports table


def test_loopback_listeners_are_hidden() -> None:
    """Only reachable from the host itself; they stay in the JSON."""
    rows = port_views([listener(53, "127.0.0.53", "systemd-resolve"), listener(631, "::1", "cupsd")], active(), [])

    assert rows == []


def test_ipv4_and_ipv6_sockets_of_one_process_share_a_row() -> None:
    """Sshd on 0.0.0.0:22 and [::]:22 is one row with both addresses."""
    rows = port_views([listener(22, "0.0.0.0", "sshd"), listener(22, "::", "sshd")], active(), [])

    assert [(r["port"], r["addresses"], r["processes"]) for r in rows] == [(22, ["0.0.0.0", "::"], ["sshd"])]


@pytest.mark.parametrize(
    ("address", "families"),
    [
        pytest.param("*", ["ipv4", "ipv6"], id="ss-wildcard"),
        pytest.param("0.0.0.0", ["ipv4"], id="ipv4-any"),
        pytest.param("::", ["ipv6"], id="ipv6-any"),
    ],
)
def test_row_families_follow_the_socket_address(address: str, families: list[str]) -> None:
    """Ss prints `*` for a socket on all addresses of both families; that row is checked against both rule sets."""
    rows = port_views([listener(22, address, "sshd")], active(), [])

    assert rows[0]["families"] == families


def test_ufw_effect_uses_the_row_families() -> None:
    """The IPv6 socket of sshd is checked against the IPv6 rules."""
    rows = port_views([listener(22, "0.0.0.0", "sshd"), listener(22, "::", "sshd")], active(rule("22")), [])

    assert rows[0]["ufw"] == "IPv4: ALLOW from Anywhere; IPv6: default deny"


def test_rootful_published_port_bypasses_ufw() -> None:
    """docker-proxy holds the port; the container is named and the row flagged."""
    listeners = [listener(443, "0.0.0.0", "docker-proxy"), listener(443, "::", "docker-proxy")]
    daemons = [daemon("rootful", container("traefik", published(443), published(443, "::")))]

    rows = port_views(listeners, active(rule("443")), daemons)

    assert [(r["port"], r["containers"], r["bypass"]) for r in rows] == [(443, ["traefik"], True)]


def test_rootless_published_port_is_filtered_by_ufw() -> None:
    """Rootlesskit listens in the host network namespace, so UFW applies."""
    daemons = [daemon("rootless", container("traefik", published(6687)))]

    rows = port_views([listener(6687, "0.0.0.0", "rootlesskit")], active(rule("6687", source="10.0.0.0/8")), daemons)

    assert [(r["containers"], r["bypass"], r["ufw"]) for r in rows] == [(["traefik"], False, "ALLOW from 10.0.0.0/8")]


def test_published_port_without_proxy_gets_its_own_row() -> None:
    """Rootful daemon without userland proxy: iptables only, no listening socket."""
    daemons = [daemon("rootful", container("app", published(8080)))]

    rows = port_views([], active(), daemons)

    assert [(r["port"], r["addresses"], r["processes"], r["bypass"]) for r in rows] == [(8080, ["0.0.0.0"], [], True)]


def test_published_port_is_not_merged_into_another_process() -> None:
    """A port held by a non-proxy process is a different socket (e.g. host network)."""
    daemons = [daemon("rootful", container("app", published(8080)))]

    rows = port_views([listener(8080, "0.0.0.0", "java")], active(), daemons)

    assert sorted((r["processes"], r["containers"]) for r in rows) == [([], ["app"]), (["java"], [])]


def test_loopback_published_port_is_hidden_and_no_bypass() -> None:
    """127.0.0.1:5432 is only reachable from the host."""
    daemons = [daemon("rootful", container("db", published(5432, "127.0.0.1")))]

    assert port_views([listener(5432, "127.0.0.1", "docker-proxy")], active(), daemons) == []


@pytest.mark.parametrize(
    "daemons",
    [
        pytest.param([daemon("rootful", container("app", published(8080), state="exited"))], id="stopped-container"),
        pytest.param([daemon("rootful", container("app", published(8080)), state="stopped")], id="daemon-not-running"),
    ],
)
def test_ports_of_stopped_containers_are_not_open(daemons: list[DockerDaemon]) -> None:
    """Configured but not published right now."""
    assert port_views([], active(), daemons) == []


def test_ports_without_ss_still_show_published_ports() -> None:
    """Listeners None (ss missing): only what Docker reports."""
    rows = port_views(None, active(), [daemon("rootful", container("app", published(80)))])

    assert [r["port"] for r in rows] == [80]


# Containers


def test_image_digest_is_left_out() -> None:
    """`image:tag@sha256:…` is shown as `image:tag`; the digest stays in the JSON."""
    app = container("traefik", image="traefik:v3.7.13@sha256:f86a")

    assert container_views([daemon("rootful", app)], include_stopped=True)[0]["image"] == "traefik:v3.7.13"


def test_ports_of_both_families_are_one_label() -> None:
    """The same port published on 0.0.0.0 and :: is one `443→443/tcp`."""
    app = container("traefik", published(443), published(443, "::"))

    assert container_views([daemon("rootful", app)], include_stopped=True)[0]["ports"] == ["443→443/tcp"]


def test_daemon_label_names_the_rootless_owner() -> None:
    """On the server page the rootless daemon names its account."""
    rows = container_views([daemon("rootless", container("traefik"))], include_stopped=True)

    assert rows[0]["daemon"] == "rootless (dockeruser)"


def test_specific_host_ip_is_shown() -> None:
    """Only all-address bindings are left implicit."""
    rows = container_views([daemon("rootful", container("db", published(5432, "127.0.0.1")))], include_stopped=True)

    assert rows[0]["ports"] == ["5432→5432/tcp on 127.0.0.1"]


@pytest.mark.parametrize(("include_stopped", "expected"), [(True, ["db", "web"]), (False, ["web"])])
def test_stopped_containers_are_optional(*, include_stopped: bool, expected: list[str]) -> None:
    """fleet_inventory_stopped_containers decides at render time."""
    daemons = [daemon("rootful", container("web"), container("db", state="exited"))]

    rows = container_views(daemons, include_stopped=include_stopped)

    assert [r["name"] for r in rows] == expected


@pytest.mark.parametrize(
    ("modes", "expected"),
    [
        pytest.param([], "—", id="none"),
        pytest.param(["rootless"], "rootless", id="rootless"),
        pytest.param(["rootless", "rootful"], "rootful, rootless", id="both"),
    ],
)
def test_docker_modes_without_owner(modes: list[DaemonMode], expected: str) -> None:
    """The overview names modes only, never the owning account."""
    assert docker_modes([daemon(mode) for mode in modes]) == expected


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        pytest.param("127.0.0.53", True, id="ipv4-loopback-net"),
        pytest.param("::1", True, id="ipv6-loopback"),
        pytest.param("0.0.0.0", False, id="wildcard"),
        pytest.param("*", False, id="ss-wildcard"),
        pytest.param("192.0.2.1", False, id="public"),
    ],
)
def test_is_loopback(address: str, *, expected: bool) -> None:
    """Only 127.0.0.0/8 and ::1; wildcards and unparsable addresses are not loopback (they are reachable)."""
    assert is_loopback(address) is expected


@pytest.mark.parametrize(
    ("mode", "label"),
    [
        pytest.param("rootful", "rootful", id="rootful"),
        pytest.param("rootless", "rootless (dockeruser)", id="rootless"),
    ],
)
def test_daemon_label(mode: DaemonMode, label: str) -> None:
    """The page names the owner of a rootless daemon."""
    assert daemon_label(daemon(mode)) == label


def test_daemon_views_without_daemons() -> None:
    """No Docker: no daemon lines."""
    assert daemon_views([]) == []


def test_daemon_views() -> None:
    """One line per daemon with label, version and state."""
    assert daemon_views([daemon("rootful", state="stopped")]) == [{"label": "rootful", "version": "29.7.1", "state": "not running"}]


@pytest.mark.parametrize(
    ("include_stopped", "expected"),
    [pytest.param(True, ["web", "db"], id="all"), pytest.param(False, ["web"], id="running")],
)
def test_visible_containers(*, include_stopped: bool, expected: list[str]) -> None:
    """All containers with their daemon, or only running ones."""
    daemons = [daemon("rootful", container("web"), container("db", state="exited"))]

    assert [c["name"] for _d, c in visible_containers(daemons, include_stopped=include_stopped)] == expected
