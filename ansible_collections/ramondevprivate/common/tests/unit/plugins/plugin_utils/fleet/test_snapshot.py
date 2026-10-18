# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for building a host snapshot from Ansible facts and reading stored snapshots back."""

import json
from pathlib import Path
from typing import cast

import pytest

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import as_mapping
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import Address
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.snapshot import (
    addresses,
    build_snapshot,
    disk,
    is_private,
    mark_unreached,
    parse_snapshot,
)

FIXTURES = Path(__file__).parent / "fixtures"


def load_facts(name: str) -> dict[str, object]:
    """Load anonymized ansible_facts captured from a real host."""
    return cast("dict[str, object]", json.loads((FIXTURES / name).read_text()))


def mount(path: str, device: str, size: int = 100, fstype: str = "ext4", options: str = "rw") -> dict[str, object]:
    """Build a mount fact as Ansible reports it."""
    return {"mount": path, "device": device, "fstype": fstype, "options": options, "size_total": size}


def summary(found: list[Address]) -> list[tuple[str, str, str, bool]]:
    """Reduce addresses to the fields under test: interface, address, family, private."""
    return [(a["interface"], a["address"], a["family"], a["private"]) for a in found]


# Real hosts (anonymized fixtures)


def test_debian13_system() -> None:
    """OS, kernel and capacity of a real Debian 13 VM."""
    system = build_snapshot(load_facts("debian13.json"), "host-a", "", {})["system"]

    assert (system["distribution"], system["version"], system["release"]) == ("Debian", "13.7", "trixie")
    assert system["kernel"] == "6.12.107+deb13-amd64"
    assert (system["cores"], system["ram_mb"]) == (10, 32101)
    assert system["disk"]["total_bytes"] == 528223088640 + 129718272


def test_debian13_addresses() -> None:
    """A plain VM: public IPv4 and link-local IPv6 on eth0, loopback skipped."""
    found = addresses(load_facts("debian13.json"))

    assert summary(found) == [
        ("eth0", "203.0.113.23", "ipv4", False),
        ("eth0", "fe80::ff:fe00:1", "ipv6", True),
    ]


def test_debian12_docker_host_addresses() -> None:
    """A rootful Docker host: docker0, br-* and veth* are skipped, only ens192 remains."""
    found = addresses(load_facts("debian12.json"))

    assert summary(found) == [
        ("ens192", "203.0.113.54", "ipv4", False),
        ("ens192", "fe80::ff:fe00:2", "ipv6", True),
    ]


def test_snapshot_records_host_and_time() -> None:
    """The snapshot is labelled with what the caller passes in."""
    snapshot = build_snapshot({}, "host-x", "2026-10-10T12:00:00Z", {})

    assert (snapshot["host"], snapshot["collected_at"]) == ("host-x", "2026-10-10T12:00:00Z")


def test_module_result_adds_users_and_ssh() -> None:
    """The fleet_info result is validated and stored with the snapshot."""
    collected = {
        "users": [{"name": "alice", "uid": 1000, "groups": ["sudo"], "sudo": {"level": "full"}, "authorized_keys": [], "x": 1}],
        "ssh": {"key_files": [".ssh/authorized_keys"], "key_files_source": "sshd", "keys_command": False},
    }

    snapshot = build_snapshot({}, "host-x", "", collected)

    assert [u["name"] for u in snapshot["users"]] == ["alice"]
    assert snapshot["ssh"]["key_files_source"] == "sshd"


def test_module_result_adds_network_and_docker() -> None:
    """UFW, listeners and daemons are validated and stored with the snapshot."""
    collected: dict[str, object] = {
        "ufw": {"state": "active", "default_incoming": "deny", "rules": []},
        "listeners": [{"proto": "tcp", "address": "0.0.0.0", "port": 22, "processes": ["sshd"]}],
        "docker": [{"mode": "rootless", "owner": "dockeruser", "state": "running", "containers": [{"name": "web"}]}],
    }

    snapshot = build_snapshot({}, "host-x", "", collected)

    assert snapshot["ufw"]["state"] == "active"
    assert [item["port"] for item in snapshot["listeners"] or []] == [22]
    assert [c["name"] for d in snapshot["docker"] for c in d["containers"]] == ["web"]


def test_missing_listeners_stay_unknown() -> None:
    """A module result without ss output keeps listeners None (unknown), not an empty list."""
    snapshot = build_snapshot({}, "host-x", "", {"listeners": None})

    assert snapshot["listeners"] is None


def test_module_result_adds_fail2ban_and_auto_updates() -> None:
    """Security settings are validated and stored with the snapshot; unknown values stay None."""
    collected: dict[str, object] = {
        "fail2ban": {"state": "failed", "jails": None},
        "auto_updates": {"installed": True, "update_lists": "1", "timer": "enabled", "last_success": ""},
    }

    snapshot = build_snapshot({}, "host-x", "", collected)

    assert snapshot["fail2ban"] == {"state": "failed", "jails": None}
    assert snapshot["auto_updates"]["unattended_upgrade"] is None


@pytest.mark.parametrize(
    ("collected", "section", "expected"),
    [
        pytest.param({"users": "alice"}, "users", [], id="users-as-string"),
        pytest.param({"ufw": 5}, "ufw", "unknown", id="ufw-as-number"),
    ],
)
def test_broken_module_result_does_not_fail_the_host(collected: dict[str, object], section: str, expected: object) -> None:
    """A section of the wrong shape becomes empty or unknown; the snapshot is still built (readers: own tests)."""
    value = as_mapping(build_snapshot({}, "host-x", "", collected)).get(section)

    assert (value if section == "users" else as_mapping(value).get("state")) == expected


def test_missing_facts_fall_back_to_defaults() -> None:
    """Facts that were not gathered must not fail the host."""
    system = build_snapshot({}, "host-x", "", {})["system"]

    assert system["distribution"] == "unknown"
    assert system["cores"] == 0
    assert system["disk"]["total_bytes"] == 0


# Disk capacity


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param(mount("/srv/data", "/dev/vdb1", options="rw,bind"), id="bind-mount"),
        pytest.param(mount("/merged", "overlay", fstype="overlay"), id="pseudo-filesystem"),
        pytest.param(mount("/var/lib/docker/volumes/x", "/dev/vdc1"), id="below-docker-data-dir"),
        pytest.param(mount("/home/ops/.local/share/docker/x", "/dev/vdd1"), id="below-rootless-docker-data-dir"),
        pytest.param(mount("/second-view", "/dev/vda1"), id="device-already-counted"),
    ],
)
def test_disk_ignores_mounts_that_are_not_host_capacity(extra: dict[str, object]) -> None:
    """Mounts that would count capacity twice or belong to containers are ignored."""
    result = disk([mount("/", "/dev/vda1", size=100), extra])

    assert result["total_bytes"] == 100


def test_disk_counts_separate_partition_for_docker() -> None:
    """A real partition mounted at Docker's data dir itself is host capacity."""
    result = disk([mount("/", "/dev/vda1", size=100), mount("/var/lib/docker", "/dev/vdb1", size=50)])

    assert result["total_bytes"] == 150


# Addresses


def test_addresses_find_interface_facts_stored_with_underscores() -> None:
    """Ansible stores facts of "ens-1" under "ens_1"."""
    facts: dict[str, object] = {"interfaces": ["ens-1"], "ens_1": {"ipv4": {"address": "198.51.100.7", "prefix": "24"}}}

    assert summary(addresses(facts)) == [("ens-1", "198.51.100.7", "ipv4", False)]


@pytest.mark.parametrize(
    "facts",
    [
        pytest.param({}, id="no-interfaces"),
        pytest.param({"interfaces": ["eth0"]}, id="interface-without-facts"),
        pytest.param({"interfaces": "eth0", "eth0": {"ipv4": {"address": "192.0.2.1"}}}, id="interfaces-not-a-list"),
        pytest.param({"interfaces": ["eth0"], "eth0": {"ipv4": {"prefix": "24"}}}, id="no-address"),
    ],
)
def test_addresses_without_usable_facts_are_empty(facts: dict[str, object]) -> None:
    """Missing or broken interface facts give no addresses, never an error."""
    assert addresses(facts) == []


def test_addresses_include_secondary_ipv4() -> None:
    """Secondary IPv4 addresses are part of the host's addresses."""
    facts: dict[str, object] = {
        "interfaces": ["eth0"],
        "eth0": {
            "ipv4": {"address": "198.51.100.7", "prefix": "24"},
            "ipv4_secondaries": [{"address": "10.0.0.7", "prefix": "8"}],
        },
    }

    assert [a["address"] for a in addresses(facts)] == ["198.51.100.7", "10.0.0.7"]


# Private ranges per spec: RFC 1918, CGNAT, link-local, unique local


@pytest.mark.parametrize(
    "address",
    [
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "100.64.0.1",
        "100.127.255.255",
        "169.254.1.1",
        "fd12::1",
        "fe80::1",
        "not-an-ip",
    ],
)
def test_is_private(address: str) -> None:
    """Private ranges and their upper bounds; unparseable addresses never count as public."""
    assert is_private(address)


@pytest.mark.parametrize("address", ["172.32.0.1", "100.128.0.1", "203.0.113.23", "2001:db8::1"])
def test_is_public(address: str) -> None:
    """Addresses just outside the private ranges are public."""
    assert not is_private(address)


# Stored snapshots

NOW = "2026-10-11T12:00:00Z"


def stored_snapshot(host: str) -> dict[str, object]:
    """A stored snapshot as it appears in the JSON files; the module sections empty or unknown."""
    return {
        "schema_version": 1,
        "host": host,
        "collected_at": "2026-10-09T10:00:00Z",
        "system": {
            "distribution": "Debian",
            "version": "13.7",
            "release": "trixie",
            "kernel": "6.12",
            "cores": 4,
            "ram_mb": 8192,
            "disk": {
                "total_bytes": 1000,
                "mounts": [{"mount": "/", "device": "/dev/vda1", "fstype": "ext4", "size_bytes": 1000}],
            },
        },
        "addresses": [],
        "users": [],
        "ssh": {"key_files": [".ssh/authorized_keys"], "key_files_source": "sshd", "keys_command": False},
        "ufw": {
            "state": "unknown",
            "logging": "",
            "default_incoming": "",
            "default_outgoing": "",
            "default_routed": "",
            "rules": None,
        },
        "listeners": [],
        "docker": [],
        "fail2ban": {"state": "unknown", "jails": None},
        "auto_updates": {
            "installed": None,
            "update_lists": None,
            "unattended_upgrade": None,
            "timer": "",
            "last_success": None,
        },
    }


@pytest.mark.parametrize(
    "value",
    [
        pytest.param({**stored_snapshot("a"), "schema_version": 0}, id="other-schema-version"),
        pytest.param({**stored_snapshot("a"), "host": ""}, id="no-host"),
        pytest.param("garbage", id="not-a-dict"),
        pytest.param(None, id="none"),
    ],
)
def test_parse_snapshot_rejects_invalid_data(value: object) -> None:
    """Invalid stored data is ignored instead of breaking the run."""
    assert parse_snapshot(value) is None


@pytest.mark.parametrize("host", ["../x", "a/b", ".hidden", ""])
def test_stored_snapshot_with_unsafe_host_name_is_ignored(host: str) -> None:
    """The host name becomes a file name: path separators and leading dots are refused."""
    assert parse_snapshot(stored_snapshot(host)) is None


@pytest.mark.parametrize("host", ["web.example.org", "192.168.56.4", "host_b", "2001:db8::1"])
def test_ordinary_host_names_are_accepted(host: str) -> None:
    """Inventory names, IPv4 and IPv6 addresses stay valid."""
    assert parse_snapshot(stored_snapshot(host)) is not None


def test_parse_snapshot_marks_unexpected_family() -> None:
    """A damaged family value stays visible as "unknown" instead of being guessed."""
    stored = stored_snapshot("a")
    stored["addresses"] = [{"interface": "eth0", "address": "x", "prefix": 0, "family": "ipv5", "private": True}]

    parsed = parse_snapshot(stored)

    assert parsed is not None
    assert parsed["addresses"][0]["family"] == "unknown"


def test_corrupt_number_in_stored_snapshot_is_a_default() -> None:
    """A damaged value like "²" (str.isdigit accepts it, int() doesn't) becomes the default, not an error."""
    stored = stored_snapshot("a")
    system = stored["system"]
    assert isinstance(system, dict)
    system["cores"] = "²"

    parsed = parse_snapshot(stored)

    assert parsed is not None
    assert parsed["system"]["cores"] == 0


def test_parse_snapshot_reads_a_missing_section_as_unknown() -> None:
    """A stored snapshot without a module section is still shown; the section reads as unknown, not as absent."""
    stored = stored_snapshot("a")
    del stored["ufw"]
    del stored["fail2ban"]

    parsed = parse_snapshot(stored)

    assert parsed is not None
    assert (parsed["ufw"]["state"], parsed["fail2ban"]["state"]) == ("unknown", "unknown")


def test_parse_snapshot_round_trip() -> None:
    """Writing and reading a snapshot loses nothing."""
    stored = stored_snapshot("a")

    assert parse_snapshot(stored) == stored


def test_parse_snapshot_round_trip_with_network() -> None:
    """Writing and reading a snapshot with UFW rules, listeners and Docker loses nothing."""
    stored = stored_snapshot("a")
    stored["ufw"] = {
        "state": "active",
        "logging": "on (low)",
        "default_incoming": "deny",
        "default_outgoing": "allow",
        "default_routed": "disabled",
        "rules": [
            {
                "action": "allow",
                "direction": "in",
                "route": False,
                "proto": "tcp",
                "to_port": "80",
                "to_address": "0.0.0.0/0",
                "from_port": "any",
                "from_address": "0.0.0.0/0",
                "app": "",
                "interface_in": "",
                "interface_out": "",
                "comment": "web",
                "family": "ipv4",
            }
        ],
    }
    stored["listeners"] = [{"proto": "tcp", "address": "0.0.0.0", "interface": "", "port": 80, "processes": ["docker-proxy"]}]
    stored["docker"] = [
        {
            "mode": "rootful",
            "owner": "",
            "socket": "/var/run/docker.sock",
            "state": "running",
            "version": "29.3.0",
            "containers": [
                {
                    "name": "web",
                    "image": "web:1",
                    "version": "1.0",
                    "state": "running",
                    "compose_dir": "/srv/web",
                    "ports": [{"host_ip": "0.0.0.0", "host_port": 80, "container_port": 8080, "proto": "tcp"}],
                }
            ],
        }
    ]

    assert parse_snapshot(stored) == stored


def test_unreached_host_gets_the_marker() -> None:
    """A targeted host that wasn't reached keeps its snapshot, now with unreached_since."""
    marked = mark_unreached([stored_snapshot("c")], ["c"], NOW)

    assert [(m["host"], m["unreached_since"]) for m in marked] == [("c", NOW)]


def test_marker_keeps_the_first_unreached_time() -> None:
    """Repeated unreached runs write the same file."""
    stored = stored_snapshot("c")
    stored["unreached_since"] = "2026-10-01T00:00:00Z"

    assert mark_unreached([stored], ["c"], NOW)[0]["unreached_since"] == "2026-10-01T00:00:00Z"


def test_marking_keeps_everything_else_as_stored() -> None:
    """Only the marker is added; fields the parser doesn't know survive too."""
    stored = stored_snapshot("c")
    stored["future_section"] = {"x": 1}

    marked = mark_unreached([stored], ["c"], NOW)[0]

    assert {k: v for k, v in marked.items() if k != "unreached_since"} == stored


def test_only_unreached_hosts_with_a_snapshot_are_marked() -> None:
    """Reached and unknown hosts are not returned; an unreached host without stored snapshot has nothing to mark."""
    marked = mark_unreached([stored_snapshot("a"), stored_snapshot("c")], ["c", "d"], NOW)

    assert [m["host"] for m in marked] == ["c"]
