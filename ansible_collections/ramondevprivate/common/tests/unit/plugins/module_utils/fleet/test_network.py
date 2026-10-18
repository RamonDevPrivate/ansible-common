# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the UFW and ss parsers."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.network import (
    parse_ss,
    parse_ss_line,
    parse_ufw_rules,
    parse_ufw_status,
    parse_ufw_tuple,
)

if TYPE_CHECKING:
    from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import Family

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    """Read a captured (anonymized) command output or file."""
    return (FIXTURES / name).read_text()


# ufw status verbose


def test_active_status_with_policies_and_logging() -> None:
    """Captured on a host with routing disabled."""
    ufw = parse_ufw_status(fixture("rootless_ufw_status.txt"))

    assert ufw["state"] == "active"
    assert ufw["logging"] == "on (low)"
    assert (ufw["default_incoming"], ufw["default_outgoing"], ufw["default_routed"]) == ("deny", "allow", "disabled")


def test_status_leaves_rules_to_the_rule_files() -> None:
    """The table in `ufw status` is not parsed; rules come from user.rules."""
    assert parse_ufw_status(fixture("rootful_ufw_status.txt"))["rules"] is None


def test_inactive_status() -> None:
    """An inactive ufw prints only its status."""
    ufw = parse_ufw_status("Status: inactive\n")

    assert ufw["state"] == "inactive"
    assert ufw["default_incoming"] == ""


@pytest.mark.parametrize(
    "output",
    [
        pytest.param("ERROR: You need to be root to run this script\n", id="not-root"),
        pytest.param("", id="empty"),
        pytest.param("Status: confused\n", id="unexpected-state"),
    ],
)
def test_unrecognized_status_is_unknown(output: str) -> None:
    """Output without a known status line never counts as active or inactive."""
    assert parse_ufw_status(output)["state"] == "unknown"


# user.rules / user6.rules


def test_rules_from_captured_files() -> None:
    """Every tuple becomes a rule, in file order; the iptables lines are ignored."""
    rules = parse_ufw_rules(fixture("rootless_ufw_user_rules.txt"), "ipv4")

    assert [(r["to_port"], r["proto"], r["from_address"]) for r in rules[:3]] == [
        ("22", "any", "10.0.0.0/8"),
        ("18050", "tcp", "10.0.0.0/8"),
        ("18050", "udp", "10.0.0.0/8"),
    ]
    assert len(rules) == 10
    assert {r["family"] for r in rules} == {"ipv4"}


def test_hex_comments_are_decoded() -> None:
    """Ufw stores comments hex-encoded."""
    rules = parse_ufw_rules(fixture("rootless_ufw_user6_rules.txt"), "ipv6")

    assert [r["comment"] for r in rules] == ["traefik web", "traefik websecure"]


@pytest.mark.parametrize(
    ("name", "family"),
    [
        pytest.param("rootless_ufw_user_rules.txt", "ipv4", id="user.rules"),
        pytest.param("rootless_ufw_user6_rules.txt", "ipv6", id="user6.rules"),
    ],
)
def test_rules_carry_the_family_of_their_file(name: str, family: Family) -> None:
    """IPv4 and IPv6 are separate rule sets; each rule keeps the family of the file it came from."""
    assert {r["family"] for r in parse_ufw_rules(fixture(name), family)} == {family}


def test_rule_fields() -> None:
    """A plain incoming rule from the captured files."""
    rule = parse_ufw_rules(fixture("rootful_ufw_user_rules.txt"), "ipv4")[1]

    assert rule["action"] == "allow"
    assert rule["direction"] == "in"
    assert not rule["route"]
    assert (rule["proto"], rule["to_port"], rule["to_address"]) == ("tcp", "80", "0.0.0.0/0")
    assert (rule["from_port"], rule["from_address"]) == ("any", "0.0.0.0/0")
    assert (rule["app"], rule["interface_in"], rule["interface_out"], rule["comment"]) == ("", "", "", "")


def test_application_profile_rule() -> None:
    """Synthetic: app rules have 9 fields; the profile's ports are already resolved in dport."""
    rule = parse_ufw_tuple(" allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 Nginx%20Full - in", "ipv4")

    assert rule is not None
    assert rule["app"] == "Nginx Full"
    assert rule["to_port"] == "80,443"


def test_interface_rule() -> None:
    """Synthetic: `allow in on eth0 to any port 22` stores the interface with the direction."""
    rule = parse_ufw_tuple(" allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in_eth0", "ipv4")

    assert rule is not None
    assert (rule["direction"], rule["interface_in"]) == ("in", "eth0")


ROUTE_RULE = " route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_eth1!out_eth2"


def test_route_prefix_marks_a_route_rule() -> None:
    """Synthetic: `route:allow` is a route rule with the action allow."""
    rule = parse_ufw_tuple(ROUTE_RULE, "ipv4")

    assert rule is not None
    assert (rule["route"], rule["action"]) == (True, "allow")


def test_route_rule_with_both_interfaces() -> None:
    """Synthetic: a route rule may name an in and an out interface (`in_eth1!out_eth2`)."""
    rule = parse_ufw_tuple(ROUTE_RULE, "ipv4")

    assert rule is not None
    assert (rule["interface_in"], rule["interface_out"]) == ("eth1", "eth2")


@pytest.mark.parametrize("action", ["limit_log", "limit_log-all"])
def test_log_option_is_not_part_of_the_action(action: str) -> None:
    """Synthetic: `ufw limit log ...` appends the log type to the action."""
    rule = parse_ufw_tuple(f" {action} tcp 22 0.0.0.0/0 any 0.0.0.0/0 in", "ipv4")

    assert rule is not None
    assert rule["action"] == "limit"


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(" allow tcp 22 0.0.0.0/0 any", id="too-short"),
        pytest.param(" allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in extra", id="eight-fields"),
    ],
)
def test_malformed_tuple_is_skipped(text: str) -> None:
    """Only the 7- and 9-field tuples current ufw writes are rules (ufw's reader also takes older 6/8-field ones)."""
    assert parse_ufw_tuple(text, "ipv4") is None


def test_malformed_tuple_in_a_rule_file_leaves_the_other_rules() -> None:
    """One broken tuple line costs only that rule."""
    content = "### tuple ### allow tcp 22 0.0.0.0/0 any\n### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in\n"

    assert [rule["to_port"] for rule in parse_ufw_rules(content, "ipv4")] == ["443"]


def test_non_hex_comment_is_kept() -> None:
    """Synthetic: a comment that is not hex is shown as it is instead of being dropped."""
    rule = parse_ufw_tuple(" allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=not-hex", "ipv4")

    assert rule is not None
    assert rule["comment"] == "not-hex"


# ss -H -t -u -l -n -p


def test_listeners_from_rootful_host() -> None:
    """docker-proxy holds the published ports; IPv4 and IPv6 sockets are separate entries."""
    listeners = parse_ss(fixture("rootful_ss.txt"))

    https = [(item["address"], item["processes"]) for item in listeners if item["port"] == 443]
    assert https == [("0.0.0.0", ["docker-proxy"]), ("::", ["docker-proxy"])]


def test_listeners_from_rootless_host() -> None:
    """Rootlesskit holds the published ports of a rootless daemon."""
    listeners = parse_ss(fixture("rootless_ss.txt"))

    assert {item["port"] for item in listeners if item["processes"] == ["rootlesskit"]} == {80, 443, 6687, 6688}


def test_dual_stack_wildcard() -> None:
    """`*` is one socket for IPv4 and IPv6."""
    listeners = parse_ss(fixture("rootless_ss.txt"))

    assert [item["address"] for item in listeners if item["port"] == 18050] == ["*"]


def test_interface_suffix_is_split_off() -> None:
    """`127.0.0.53%lo:53` is bound to the loopback interface."""
    listeners = parse_ss(fixture("rootless_ss.txt"))

    resolver = [item for item in listeners if item["address"] == "127.0.0.53"]
    assert {item["interface"] for item in resolver} == {"lo"}
    assert {item["proto"] for item in resolver} == {"tcp", "udp"}


def test_listeners_are_sorted() -> None:
    """Ordered by proto and port, whatever order ss prints (uniqueness: test_sockets_of_several_workers_…)."""
    listeners = parse_ss(fixture("rootful_ss.txt"))

    keys = [(item["proto"], item["port"], item["address"]) for item in listeners]
    assert keys == sorted(keys)


@pytest.mark.parametrize(
    ("line", "address", "interface"),
    [
        pytest.param("tcp LISTEN 0 4096 [::1]:631 [::]:*", "::1", "", id="ipv6-loopback"),
        pytest.param("udp UNCONN 0 0 [fe80::1]%eth0:546 [::]:*", "fe80::1", "eth0", id="ipv6-scope-outside"),
        pytest.param("udp UNCONN 0 0 [fe80::1%eth0]:546 [::]:*", "fe80::1", "eth0", id="ipv6-scope-inside"),
    ],
)
def test_ipv6_addresses(line: str, address: str, interface: str) -> None:
    """Synthetic: brackets are removed and the scope becomes the interface."""
    listener = parse_ss_line(line)

    assert listener is not None
    assert (listener["address"], listener["interface"]) == (address, interface)


def test_without_root_processes_are_unknown() -> None:
    """Synthetic: ss shows no process column for other users' sockets without root."""
    listener = parse_ss_line("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*")

    assert listener is not None
    assert listener["processes"] == []


def test_several_processes_share_a_socket() -> None:
    """Synthetic: pre-forked servers list every worker; names are reported once."""
    listener = parse_ss_line('tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=12,fd=6),("nginx",pid=11,fd=6))')

    assert listener is not None
    assert listener["processes"] == ["nginx"]


def test_sockets_of_several_workers_are_one_listener() -> None:
    """With SO_REUSEPORT every worker has its own socket on the same port; without PIDs they are the same listener."""
    output = 'tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=11,fd=6))\ntcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=12,fd=6))\n'

    assert [(item["port"], item["processes"]) for item in parse_ss(output)] == [(80, ["nginx"])]


def test_lines_that_are_not_listeners_are_left_out_of_the_list() -> None:
    """A unix socket line between two listeners doesn't end or break the list."""
    output = (
        'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
        "u_str LISTEN 0 4096 /run/x.sock 1 * 0\n"
        'tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=11,fd=6))\n'
    )

    assert [item["port"] for item in parse_ss(output)] == [22, 80]


@pytest.mark.parametrize(
    "line",
    [
        pytest.param("u_str LISTEN 0 4096 /run/x.sock 1 * 0", id="unix-socket"),
        pytest.param("tcp LISTEN 0 4096 0.0.0.0:* 0.0.0.0:*", id="no-port"),
        pytest.param("garbage", id="garbage"),
    ],
)
def test_other_lines_are_skipped(line: str) -> None:
    """Only TCP and UDP sockets with a numeric port count."""
    assert parse_ss_line(line) is None


def test_unicode_digit_port_is_skipped() -> None:
    """Synthetic: a port that only looks numeric is not a port."""
    assert parse_ss_line("tcp LISTEN 0 128 0.0.0.0:² 0.0.0.0:*") is None
