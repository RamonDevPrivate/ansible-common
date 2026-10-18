# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for merging snapshots and preparing the report."""

from typing import TYPE_CHECKING, cast

import pytest
from ansible.errors import AnsibleFilterError  # pyright: ignore[reportMissingTypeStubs] - no stubs

from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.report import (
    CHART_MIN_HEIGHT,
    Report,
    build_report,
    chart_labels,
    format_bytes,
    is_ipv6_link_local,
    login_status,
    sudo_label,
)

if TYPE_CHECKING:
    from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import Sudo
    from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.report import Metric

GIB = 1024**3
MIB = 1024**2


def snapshot(host: str, collected_at: str = "2026-10-09T10:00:00Z", *, cores: int = 4, ram_mb: int = 8192, disk: int = 100 * GIB) -> dict[str, object]:
    """Build a stored snapshot as it appears in the JSON files; the module sections empty or unknown."""
    return {
        "schema_version": 1,
        "host": host,
        "collected_at": collected_at,
        "system": {
            "distribution": "Debian",
            "version": "13.7",
            "release": "trixie",
            "kernel": "6.12",
            "cores": cores,
            "ram_mb": ram_mb,
            "disk": {
                "total_bytes": disk,
                "mounts": [{"mount": "/", "device": "/dev/vda1", "fstype": "ext4", "size_bytes": disk}],
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


def metrics_by_label(metrics: "list[Metric]") -> "dict[str, Metric]":
    """Index metrics by label so tests don't depend on their order."""
    return {m["label"]: m for m in metrics}


# Merging


def test_current_snapshot_replaces_stored_one() -> None:
    """A host collected in this run shows its new data."""
    report = build_report(
        current=[snapshot("a", "2026-10-09T10:00:00Z", cores=8)],
        stored=[snapshot("a", "2026-10-01T10:00:00Z", cores=2)],
        unreachable=[],
    )

    assert [(h["host"], h["cores"], h["last_updated"]) for h in report["hosts"]] == [("a", 8, "2026-10-09")]


def test_stored_hosts_not_in_this_run_are_kept() -> None:
    """Hosts outside --limit keep their page."""
    report = build_report(current=[snapshot("b")], stored=[snapshot("a")], unreachable=[])

    assert [h["host"] for h in report["hosts"]] == ["a", "b"]


def test_unreachable_host_keeps_last_snapshot_and_is_marked() -> None:
    """A targeted host that was not reached is shown with its last data."""
    report = build_report(current=[], stored=[snapshot("a")], unreachable=["a"])

    assert report["hosts"][0]["reached"] is False
    assert report["unreachable"] == 1


def test_overview_date_is_the_newest_collection() -> None:
    """last_updated of the overview is the newest snapshot date."""
    report = build_report(current=[snapshot("a", "2026-10-09T10:00:00Z")], stored=[snapshot("b", "2026-10-01T10:00:00Z")], unreachable=[])

    assert report["last_updated"] == "2026-10-09"


# Addresses on the pages


def test_ipv6_link_local_addresses_are_hidden_on_pages() -> None:
    """fe80::/10 exists on every interface and is noise on a server page; everything else is shown."""
    stored = snapshot("a")
    stored["addresses"] = [
        {"interface": "eth0", "address": a, "prefix": 64, "family": "ipv6" if ":" in a else "ipv4", "private": True}
        for a in ("203.0.113.23", "fe80::1", "fd12::1", "169.254.1.1")
    ]

    report = build_report(current=[stored], stored=[], unreachable=[])

    assert [a["address"] for a in report["hosts"][0]["addresses"]] == ["203.0.113.23", "fd12::1", "169.254.1.1"]


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        pytest.param("fe80::1", True, id="ipv6-link-local"),
        pytest.param("febf:ffff::1", True, id="upper-end-of-fe80-10"),
        pytest.param("fec0::1", False, id="just-outside"),
        pytest.param("169.254.1.1", False, id="ipv4-link-local-stays-visible"),
        pytest.param("not-an-ip", False, id="unparseable-stays-visible"),
    ],
)
def test_is_ipv6_link_local(address: str, *, expected: bool) -> None:
    """Only IPv6 link-local is hidden; IPv4 link-local on a server points to a problem and stays visible."""
    assert is_ipv6_link_local(address) is expected


# Users


def with_users(host: str, users: list[dict[str, object]], *, keys_command: bool = False) -> dict[str, object]:
    """Stored snapshot of a host collected 2026-10-11 with the given users."""
    return {
        **snapshot(host, "2026-10-11T12:00:00Z"),
        "users": users,
        "ssh": {"key_files": [".ssh/authorized_keys"], "key_files_source": "sshd", "keys_command": keys_command},
    }


def user(name: str, **fields: object) -> dict[str, object]:
    """A user with defaults: no sudo, no keys, no login record."""
    base: dict[str, object] = {
        "name": name,
        "uid": 1000,
        "groups": [],
        "sudo": {"level": "none"},
        "authorized_keys": [],
    }
    return base | {"last_login": ""} | fields


def alice_view(**fields: object) -> dict[str, object]:
    """Alice's row in the users table of host a."""
    users = build_report(current=[with_users("a", [user("alice", **fields)])], stored=[], unreachable=[])["hosts"][0]
    return dict(users["users"][0])


def test_user_groups_on_the_page() -> None:
    """The collected supplementary groups as they are."""
    assert alice_view(groups=["docker", "sudo"])["groups"] == ["docker", "sudo"]


def test_user_status_on_the_page_without_the_login_date() -> None:
    """The status is shown; the login date itself stays in the JSON."""
    view = alice_view(last_login="2026-10-01T08:00:00+02:00")

    assert view["status"] == "active"
    assert "last_login" not in view


def key(comment: str = "", *, allowed_from: str = "", forced: bool = False) -> dict[str, object]:
    """An authorized key as stored, with fingerprint SHA256:k."""
    return {
        "comment": comment,
        "fingerprint": "SHA256:k",
        "allowed_from": allowed_from,
        "forced_command": forced,
    }


@pytest.mark.parametrize(
    ("stored", "label"),
    [
        pytest.param(key("alice@example.org"), "alice@example.org", id="comment"),
        pytest.param(key(), "SHA256:k", id="fingerprint-without-comment"),
        pytest.param(key("ci", allowed_from="10.0.0.0/8"), "ci (from 10.0.0.0/8)", id="from"),
        pytest.param(key("ci", forced=True), "ci (forced command)", id="forced-command"),
        pytest.param(
            key(allowed_from="192.0.2.0/24", forced=True),
            "SHA256:k (from 192.0.2.0/24) (forced command)",
            id="all-together",
        ),
    ],
)
def test_key_label_on_the_page(stored: dict[str, object], label: str) -> None:
    """Comment (or fingerprint), then the restrictions in a fixed order."""
    assert alice_view(authorized_keys=[stored])["authorized_keys"] == [label]


@pytest.mark.parametrize(
    ("sudo", "label"),
    [
        pytest.param({"level": "full", "rules": ["(ALL : ALL) ALL"]}, "full", id="full"),
        pytest.param({"level": "full", "nopasswd": True, "rules": ["(ALL) NOPASSWD: ALL"]}, "full, NOPASSWD", id="full-nopasswd"),
        pytest.param(
            {
                "level": "limited",
                "nopasswd": True,
                "rules": ["(dockeruser) NOPASSWD: SETENV: /usr/bin/env XDG_RUNTIME_DIR=/run/user/1001 docker ps"],
            },
            "limited (dockeruser), NOPASSWD",
            id="limited-as-other-user",
        ),
        pytest.param(
            {"level": "limited", "rules": ["(root) /usr/bin/systemctl restart nginx", "(www-data) /usr/bin/git pull"]},
            "limited (root, www-data)",
            id="limited-several-targets",
        ),
        pytest.param({"level": "none"}, "none", id="none"),
        pytest.param({"level": "unknown"}, "unknown", id="unknown"),
    ],
)
def test_sudo_label_on_the_page(sudo: dict[str, object], label: str) -> None:
    """Level, as whom (only for limited) and NOPASSWD; the rules themselves are not on the page."""
    view = build_report(current=[with_users("a", [user("u", sudo=sudo)])], stored=[], unreachable=[])["hosts"][0]

    assert view["users"][0]["sudo"] == label


def test_unreadable_keys_stay_unknown() -> None:
    """A key file that couldn't be read is not shown as "no keys"."""
    bob = user("bob", authorized_keys=None)
    view = build_report(current=[with_users("a", [bob])], stored=[], unreachable=[])["hosts"][0]

    assert view["users"][0]["authorized_keys"] is None


def test_keys_command_and_assumed_key_files_are_flagged() -> None:
    """The page can say where the key information may be incomplete."""
    host = with_users("a", [], keys_command=True)
    host["ssh"] = {"key_files": [], "key_files_source": "default", "keys_command": True}

    view = build_report(current=[host], stored=[], unreachable=[])["hosts"][0]

    assert (view["keys_from_command"], view["key_files_assumed"]) == (True, True)


@pytest.mark.parametrize(
    ("last_login", "expected"),
    [
        pytest.param("2026-10-01T08:00:00+02:00", "active", id="recent"),
        pytest.param("2025-10-11T12:00:00Z", "active", id="exactly-the-limit"),
        pytest.param("2025-10-10T11:00:00Z", "inactive", id="older-than-the-limit"),
        pytest.param("", "unknown", id="no-record"),
        pytest.param(None, "unknown", id="no-source"),
        pytest.param("yesterday", "unknown", id="unparseable"),
        pytest.param("2026-10-01T08:00:00", "unknown", id="without-timezone"),
    ],
)
def test_login_status(last_login: str | None, expected: str) -> None:
    """Measured from the collection time, so pages don't change between identical runs."""
    assert login_status(last_login, "2026-10-11T12:00:00Z", 365) == expected


def test_inactive_days_is_configurable() -> None:
    """A stricter threshold turns the same login inactive."""
    alice = user("alice", last_login="2026-09-01T00:00:00Z")

    report = build_report(current=[with_users("a", [alice])], stored=[], unreachable=[], options={"inactive_days": 30})

    assert report["hosts"][0]["users"][0]["status"] == "inactive"


# Statistics


FLEET = [
    snapshot("a", cores=2, ram_mb=4096, disk=50 * GIB),
    snapshot("b", cores=6, ram_mb=12288, disk=150 * GIB),
]


@pytest.mark.parametrize(
    ("label", "statistic", "expected"),
    [
        pytest.param("Cores", "total", "8", id="cores-total"),
        pytest.param("Cores", "minimum", "2", id="cores-minimum"),
        pytest.param("Cores", "maximum", "6", id="cores-maximum"),
        pytest.param("Cores", "average", "4.0", id="cores-average"),
        pytest.param("RAM", "total", format_bytes(16384 * MIB), id="ram-total"),
        pytest.param("RAM", "average", format_bytes(8192 * MIB), id="ram-average"),
        pytest.param("Disk", "total", format_bytes(200 * GIB), id="disk-total"),
        pytest.param("Disk", "average", format_bytes(100 * GIB), id="disk-average"),
        pytest.param("Disk", "minimum", format_bytes(50 * GIB), id="disk-minimum"),
        pytest.param("Disk", "maximum", format_bytes(150 * GIB), id="disk-maximum"),
    ],
)
def test_statistics_over_the_fleet(label: str, statistic: str, expected: str) -> None:
    """Total, average, minimum and maximum per capacity, over all hosts."""
    metric = metrics_by_label(build_report(current=FLEET, stored=[], unreachable=[])["metrics"])[label]

    assert dict(metric).get(statistic) == expected


def test_total_cores_for_the_stats_line() -> None:
    """The overview's stats line uses the raw total."""
    assert build_report(current=FLEET, stored=[], unreachable=[])["totals"]["cores"] == 8


def with_version(host: str, version: str) -> dict[str, object]:
    """A snapshot of a host running Debian with the given version."""
    data = snapshot(host)
    cast("dict[str, object]", data["system"])["version"] = version
    return data


def test_servers_are_counted_per_os_major_version() -> None:
    """Point releases of one major version are one row; majors in numeric order."""
    current = [
        with_version("a", "13.1"),
        with_version("b", "13.3"),
        with_version("c", "12.12"),
        with_version("d", "9.13"),
    ]

    report = build_report(current=current, stored=[], unreachable=[])

    assert report["os_counts"] == [
        {"os": "Debian 9", "servers": 1},
        {"os": "Debian 12", "servers": 1},
        {"os": "Debian 13", "servers": 2},
    ]


def test_missing_os_version_is_counted_without_major() -> None:
    """A snapshot without a version doesn't fail the report; it gets its own row."""
    report = build_report(current=[with_version("a", ""), with_version("b", "13.1")], stored=[], unreachable=[])

    assert report["os_counts"] == [{"os": "Debian", "servers": 1}, {"os": "Debian 13", "servers": 1}]


def test_pages_keep_the_full_os_version() -> None:
    """Only the overview stats are grouped; the servers table and pages show the point release."""
    report = build_report(current=[with_version("a", "13.1")], stored=[], unreachable=[])

    assert report["hosts"][0]["os"] == "Debian 13.1"


@pytest.mark.parametrize(
    ("hosts", "labels"),
    [
        pytest.param(["web.example.org", "db.example.org"], ["web", "db"], id="shared-domain"),
        pytest.param(["a.x.example.org", "b.y.example.org"], ["a.x", "b.y"], id="only-shared-labels"),
        pytest.param(["web.example.org", "db.example.net"], ["web.example.org", "db.example.net"], id="nothing-shared"),
        pytest.param(["web.example.org"], ["web.example.org"], id="single-host"),
        pytest.param(["a.example.org", "example.org"], ["a.example", "example"], id="one-label-kept"),
    ],
)
def test_chart_labels(hosts: list[str], labels: list[str]) -> None:
    """Chart labels drop the domain all hosts share and keep one label at least."""
    assert chart_labels(hosts) == labels


@pytest.mark.parametrize(
    ("hosts", "height"),
    [
        pytest.param(1, CHART_MIN_HEIGHT, id="one-host-minimum"),
        pytest.param(7, CHART_MIN_HEIGHT, id="seven-hosts-still-minimum"),
        pytest.param(8, 312, id="eight-hosts"),
        pytest.param(30, 840, id="thirty-hosts"),
    ],
)
def test_chart_height_grows_with_the_fleet(hosts: int, height: int) -> None:
    """120 px plus 24 px per host, never below the 300 px where Mermaid stops rendering."""
    assert build_report([snapshot(f"h{i}") for i in range(hosts)], [], [])["charts"]["height"] == height


def test_empty_fleet_renders_without_values() -> None:
    """No snapshots at all: no servers, empty metric values, no error."""
    report = build_report(current=[], stored=[], unreachable=[])

    assert report["servers"] == 0
    assert all(m["total"] == "" for m in report["metrics"])


# Stored snapshots in the report


def test_invalid_stored_snapshot_is_left_out_of_the_report() -> None:
    """A damaged file costs only its own host; the others are still reported."""
    report = build_report(current=[], stored=["garbage", snapshot("b")], unreachable=[])

    assert [view["host"] for view in report["hosts"]] == ["b"]


# Network and Docker


def with_network(host: str, containers: list[dict[str, object]]) -> dict[str, object]:
    """Snapshot of a host with an active UFW and one rootful daemon."""
    data = snapshot(host)
    data["ufw"] = {
        "state": "active",
        "logging": "on (low)",
        "default_incoming": "deny",
        "default_outgoing": "allow",
        "default_routed": "disabled",
        "rules": [],
    }
    data["listeners"] = []
    data["docker"] = [
        {
            "mode": "rootful",
            "owner": "",
            "socket": "/var/run/docker.sock",
            "state": "running",
            "version": "29.3.0",
            "containers": containers,
        }
    ]
    return data


def running(name: str, state: str = "running") -> dict[str, object]:
    """A container without ports."""
    return {"name": name, "image": f"{name}:1", "state": state, "ports": []}


def docker_report() -> Report:
    """Report for host a with a rootful daemon and two running containers."""
    return build_report(current=[with_network("a", [running("web"), running("db")])], stored=[], unreachable=[])


def test_docker_host_is_tagged() -> None:
    """Frontmatter tag docker."""
    assert docker_report()["hosts"][0]["tags"] == ["docker"]


def test_docker_mode_for_the_overview_and_the_page() -> None:
    """Mode in the overview column, daemon label on the page."""
    host = docker_report()["hosts"][0]

    assert (host["docker"], [d["label"] for d in host["daemons"]]) == ("rootful", ["rootful"])


def test_containers_are_counted_over_the_fleet() -> None:
    """The container total for the stats line."""
    assert docker_report()["containers"] == 2


@pytest.mark.parametrize(("stopped_containers", "expected"), [(True, 2), (False, 1)])
def test_stopped_containers_can_be_left_out(*, stopped_containers: bool, expected: int) -> None:
    """The role variable filters at render time; the snapshot keeps all containers."""
    current = [with_network("a", [running("web"), running("old", "exited")])]

    report = build_report(current, [], [], {"stopped_containers": stopped_containers})

    assert report["containers"] == expected
    assert len(report["hosts"][0]["containers"]) == expected


def test_ports_unknown_without_ss() -> None:
    """The page can say that the ports table is incomplete."""
    current = with_network("a", [])
    current["listeners"] = None

    view = build_report(current=[current], stored=[], unreachable=[])["hosts"][0]

    assert view["ports_unknown"] is True


# Security and needs attention

LAST_RUN = "2026-10-07T04:00:00+00:00"  # two days before the collection time of snapshot()


def with_security(host: str, *, fail2ban: str = "active", last_success: str = LAST_RUN) -> dict[str, object]:
    """Snapshot with fail2ban and fully configured auto-updates."""
    data = snapshot(host)
    data["fail2ban"] = {"state": fail2ban, "jails": ["sshd"] if fail2ban == "active" else None}
    data["auto_updates"] = {
        "installed": True,
        "update_lists": "1",
        "unattended_upgrade": "1",
        "timer": "enabled",
        "last_success": last_success,
    }
    data["ufw"] = {"state": "inactive", "rules": None}
    return data


def test_fail2ban_on_the_page() -> None:
    """fail2ban state and jails."""
    view = build_report(current=[with_security("a")], stored=[], unreachable=[])["hosts"][0]

    assert (view["fail2ban"], view["fail2ban_jails"]) == ("active", ["sshd"])


def test_auto_updates_on_the_page() -> None:
    """Auto-update status and the date of the last successful run."""
    view = build_report(current=[with_security("a")], stored=[], unreachable=[])["hosts"][0]

    assert (view["auto_updates"], view["auto_updates_last"]) == ("ok", "2026-10-07")


def test_update_max_age_is_configurable() -> None:
    """A stricter threshold turns the same run into a problem status."""
    report = build_report([with_security("a")], [], [], {"update_max_age_days": 2})

    assert report["hosts"][0]["auto_updates"] == "no successful run in 2 days"


@pytest.mark.parametrize(
    ("options", "message"),
    [
        pytest.param({"update_max_age_days": 0}, "positive integer", id="zero-days"),
        pytest.param({"inactive_days": "30"}, "positive integer", id="days-as-string"),
        pytest.param({"stopped_containers": "false"}, "must be a bool", id="bool-as-string"),
        pytest.param({"attention_rules": ["ufw_off"]}, "unknown options attention_rules", id="removed-option"),
        pytest.param({"inactive_dayz": 30}, "unknown options inactive_dayz", id="typo-in-key"),
        pytest.param(["inactive_days"], "must be a mapping", id="not-a-mapping"),
    ],
)
def test_invalid_options_fail_loudly(options: object, message: str) -> None:
    """A wrong value must not silently fall back to a default."""
    with pytest.raises(AnsibleFilterError, match=message):
        _report = build_report([snapshot("a")], [], [], options)


def option_sensitive() -> dict[str, object]:
    """A host where every option changes the report: a user, a stopped container, auto-updates two days old."""
    data = with_security("a")
    data["users"] = [user("alice", last_login="2026-01-01T00:00:00Z")]  # about 280 days before the collection
    network = with_network("a", [running("web"), running("old", "exited")])
    data["docker"] = network["docker"]
    return data


DOCUMENTED_DEFAULTS = {"inactive_days": 365, "stopped_containers": True, "update_max_age_days": 7}


@pytest.mark.parametrize("options", [pytest.param(None, id="none"), pytest.param({}, id="empty")])
def test_missing_options_use_the_documented_defaults(options: dict[str, object] | None) -> None:
    """No options, or an empty mapping, give the same report as the documented defaults."""
    current = [option_sensitive()]

    assert build_report(current, [], [], options) == build_report(current, [], [], DOCUMENTED_DEFAULTS)


@pytest.mark.parametrize(
    "option",
    [
        pytest.param({"inactive_days": 200}, id="inactive-days"),
        pytest.param({"stopped_containers": False}, id="stopped-containers"),
        pytest.param({"update_max_age_days": 1}, id="update-max-age-days"),
    ],
)
def test_each_option_changes_the_test_report(option: dict[str, object]) -> None:
    """Guards the defaults test above: with this data, each option makes a difference."""
    current = [option_sensitive()]

    assert build_report(current, [], [], option) != build_report(current, [], [], DOCUMENTED_DEFAULTS)


def test_docker_bypass_is_marked_on_the_page_but_never_a_finding() -> None:
    """A rootful port that UFW would block is flagged in the ports table, not listed in Needs attention."""
    port = {"host_ip": "0.0.0.0", "host_port": 8080, "container_port": 80, "proto": "tcp"}
    report = build_report([with_network("a", [running("app") | {"ports": [port]}])], [], [])

    assert report["hosts"][0]["ports"][0]["bypass"] is True
    assert report["attention"] == []


def test_attention_list_collects_all_hosts() -> None:
    """Findings of every host, in host order."""
    report = build_report([with_security("b"), with_security("a")], [], [])

    assert [(f["host"], f["rule"]) for f in report["attention"]] == [("a", "ufw_off"), ("b", "ufw_off")]


# Exposure


def exposed(host: str, state: str) -> dict[str, object]:
    """Snapshot with an exposure from the probe."""
    data = snapshot(host)
    data["exposure"] = {"state": state, "checked_at": "2026-10-09T10:00:00Z", "answered": ["203.0.113.10"]}
    return data


def test_servers_are_counted_by_exposure() -> None:
    """Public and internal counts for the stats; unknown is neither."""
    report = build_report([exposed("a", "public"), exposed("b", "internal"), snapshot("c")], [], [])

    assert (report["public"], report["internal"], report["servers"]) == (1, 1, 3)


def test_exposure_on_the_page() -> None:
    """State, answering addresses and probe date."""
    view = build_report([exposed("a", "public")], [], [])["hosts"][0]

    assert (view["exposure"], view["exposure_answered"], view["exposure_checked"]) == (
        "public",
        ["203.0.113.10"],
        "2026-10-09",
    )


def test_exposure_becomes_a_tag() -> None:
    """The probed state is a frontmatter tag."""
    assert "public" in build_report([exposed("a", "public")], [], [])["hosts"][0]["tags"]


def test_unknown_exposure_has_no_tag() -> None:
    """Never probed: no public/internal tag."""
    view = build_report([snapshot("a")], [], [])["hosts"][0]

    assert view["exposure"] == "unknown"
    assert view["tags"] == []


# Formatting: the only tests that pin the exact number format


@pytest.mark.parametrize(
    ("size", "text"),
    [
        pytest.param(0, "0 B", id="zero"),
        pytest.param(1023, "1023 B", id="below-kib"),
        pytest.param(1024, "1.0 KiB", id="kib"),
        pytest.param(32101 * MIB, "31.3 GiB", id="ram-of-real-host"),
        pytest.param(528223088640, "491.9 GiB", id="disk-of-real-host"),
        pytest.param(3 * 1024**4, "3.0 TiB", id="tib"),
        pytest.param(2048 * 1024**5, "2048.0 PiB", id="largest-unit"),
    ],
)
def test_format_bytes(size: int, text: str) -> None:
    """Binary units with one decimal."""
    assert format_bytes(size) == text


# Unreached hosts across runs


NOW = "2026-10-11T12:00:00Z"


def test_stored_marker_means_not_reached() -> None:
    """A --limit run doesn't target the host, but its stored marker still shows it as not reached."""
    stored = snapshot("c")
    stored["unreached_since"] = NOW

    report = build_report(current=[snapshot("a")], stored=[stored], unreachable=[])

    assert [(h["host"], h["reached"]) for h in report["hosts"]] == [("a", True), ("c", False)]
    assert report["unreachable"] == 1


def test_new_snapshot_clears_the_marker() -> None:
    """Once reached again, the current snapshot (without marker) replaces the stored one."""
    stored = snapshot("c")
    stored["unreached_since"] = NOW

    report = build_report(current=[snapshot("c")], stored=[stored], unreachable=[])

    assert report["hosts"][0]["reached"] is True


@pytest.mark.parametrize(
    ("sudo", "label"),
    [
        pytest.param({"level": "full", "nopasswd": True, "rules": ["(ALL) NOPASSWD: ALL"]}, "full, NOPASSWD", id="full"),
        pytest.param({"level": "limited", "nopasswd": False, "rules": ["(root) /bin/x"]}, "limited (root)", id="limited"),
        pytest.param({"level": "limited", "nopasswd": False, "rules": ["not a rule"]}, "limited", id="limited-no-target"),
        pytest.param({"level": "none", "nopasswd": False, "rules": []}, "none", id="none"),
    ],
)
def test_sudo_label(sudo: "Sudo", label: str) -> None:
    """Level, as whom only for limited (if the rules say), then NOPASSWD."""
    assert sudo_label(sudo) == label
