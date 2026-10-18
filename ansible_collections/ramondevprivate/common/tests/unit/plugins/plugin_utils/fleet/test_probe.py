# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the probe targets and the exposure derived from ping results."""

from __future__ import annotations

import pytest

from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.probe import (
    exposures,
    probe_errors,
    probe_targets,
)

COLLECTED = "2026-10-11T12:00:00Z"
STORED_EXPOSURE = {"state": "public", "checked_at": "2026-10-01T12:00:00Z", "answered": ["203.0.113.10"]}


def address(value: str, family: str = "ipv4", *, private: bool = False) -> dict[str, object]:
    """One interface address as stored in a snapshot."""
    return {"interface": "eth0", "address": value, "prefix": 24, "family": family, "private": private}


def snapshot(host: str, *addresses: dict[str, object], exposure: object = None) -> dict[str, object]:
    """Minimal snapshot with addresses and an optional stored exposure."""
    data: dict[str, object] = {
        "schema_version": 1,
        "host": host,
        "collected_at": COLLECTED,
        "system": {},
        "addresses": list(addresses),
    }
    if exposure is not None:
        data["exposure"] = exposure
    return data


def ping(host: str, target: str, rc: int = 0, **extra: object) -> dict[str, object]:
    """One registered loop result of the role's ping task (loop_var __fleet_inventory_target)."""
    family = "ipv6" if ":" in target else "ipv4"
    item = {"host": host, "address": target, "family": family}
    return {"__fleet_inventory_target": item, "ansible_loop_var": "__fleet_inventory_target", "rc": rc, **extra}


PUBLIC_HOST = snapshot("a", address("203.0.113.10"), address("2001:db8::10", "ipv6"), address("10.0.0.5", private=True))


# Targets


def test_targets_are_public_addresses_of_both_families() -> None:
    """Private addresses are never pinged."""
    assert probe_targets([PUBLIC_HOST]) == [
        {"host": "a", "address": "203.0.113.10", "family": "ipv4"},
        {"host": "a", "address": "2001:db8::10", "family": "ipv6"},
    ]


def test_targets_are_unique_per_host() -> None:
    """The same address on two interfaces is pinged once."""
    host = snapshot("a", address("203.0.113.10"), address("203.0.113.10"))

    assert len(probe_targets([host])) == 1


# Exposure


def test_any_answer_makes_a_host_public() -> None:
    """IPv4 answered, IPv6 didn't: still public; the answering address is recorded."""
    results = [ping("a", "203.0.113.10", 0), ping("a", "2001:db8::10", 1)]

    assert exposures([PUBLIC_HOST], results, []) == {"a": {"state": "public", "checked_at": COLLECTED, "answered": ["203.0.113.10"]}}


def test_results_of_a_plain_loop() -> None:
    """Without loop_control.loop_var the target is stored under item."""
    results = [{"item": {"host": "a", "address": "203.0.113.10", "family": "ipv4"}, "rc": 0}]

    assert exposures([PUBLIC_HOST], results, [])["a"]["state"] == "public"


def test_no_answer_makes_a_host_internal() -> None:
    """Every public address was pinged and none answered (blocked ICMP counts as internal, accepted limitation)."""
    results = [ping("a", "203.0.113.10", 1), ping("a", "2001:db8::10", 1)]

    assert exposures([PUBLIC_HOST], results, [])["a"]["state"] == "internal"


def test_host_without_public_address_is_internal_without_probe() -> None:
    """Nothing to ping: internal, even when no probe host is configured."""
    host = snapshot("b", address("10.0.0.5", private=True))

    assert exposures([host], [], []) == {"b": {"state": "internal", "checked_at": COLLECTED, "answered": []}}


@pytest.mark.parametrize(
    "results",
    [
        pytest.param([], id="no-probe"),
        pytest.param(
            [ping("a", "203.0.113.10", unreachable=True), ping("a", "2001:db8::10", unreachable=True)],
            id="probe-unreachable",
        ),
        pytest.param([ping("a", "203.0.113.10", 1), ping("a", "2001:db8::10", 2)], id="no-ipv6-on-probe"),
        pytest.param([ping("a", "203.0.113.10", skipped=True)], id="skipped"),
    ],
)
def test_unprobed_host_keeps_stored_exposure(results: list[dict[str, object]]) -> None:
    """A run without a usable probe result doesn't overwrite what an earlier probe found."""
    stored = [snapshot("a", exposure=STORED_EXPOSURE)]

    assert exposures([PUBLIC_HOST], results, stored)["a"] == STORED_EXPOSURE


def test_unprobed_host_without_history_is_unknown() -> None:
    """Never probed before: unknown, not internal."""
    assert exposures([PUBLIC_HOST], [], [])["a"] == {"state": "unknown", "checked_at": "", "answered": []}


def test_only_current_hosts_are_returned() -> None:
    """Stored hosts that were not reached keep their snapshot as it is; they are not part of the result."""
    assert set(exposures([PUBLIC_HOST], [], [snapshot("c", exposure=STORED_EXPOSURE)])) == {"a"}


# Errors


@pytest.mark.parametrize(
    ("result", "error"),
    [
        pytest.param(
            ping("a", "203.0.113.10", unreachable=True, msg="Failed to connect to the host via ssh"),
            "203.0.113.10 (a): Failed to connect to the host via ssh",
            id="probe-unreachable",
        ),
        pytest.param(
            {**ping("a", "2001:db8::10"), "rc": None, "msg": "/usr/bin/python3: not found"},
            "2001:db8::10 (a): /usr/bin/python3: not found",
            id="no-interpreter",
        ),
        pytest.param(
            ping("b", "198.51.100.42", 2, stderr="ping: connect: Network is unreachable\n"),
            "198.51.100.42 (b): ping: connect: Network is unreachable",
            id="ping-error",
        ),
    ],
)
def test_errors_name_address_host_and_reason(result: dict[str, object], error: str) -> None:
    """A ping that couldn't be sent is listed as `address (host): reason`."""
    assert probe_errors([result]) == [error]


@pytest.mark.parametrize(
    "result",
    [
        pytest.param(ping("b", "198.51.100.43", 0), id="answered"),
        pytest.param(ping("b", "198.51.100.44", 1), id="no-answer"),
        pytest.param(ping("a", "203.0.113.10", skipped=True), id="skipped"),
    ],
)
def test_results_are_no_errors(result: dict[str, object]) -> None:
    """An answer and a no-answer are results; a skipped ping (no probe host) is not an error either."""
    assert probe_errors([result]) == []
