# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for reading UFW and Docker data from stored snapshots."""

from __future__ import annotations

import pytest

from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.network_data import (
    parse_docker,
    parse_listeners,
    parse_ufw,
)


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        pytest.param("active", "active", id="active"),
        pytest.param("inactive", "inactive", id="inactive"),
        pytest.param("not installed", "not installed", id="not-installed"),
        pytest.param("enabled", "unknown", id="unexpected"),
    ],
)
def test_ufw_state(state: str, expected: str) -> None:
    """Known states are kept; anything else is unknown rather than guessed."""
    assert parse_ufw({"state": state, "rules": []})["state"] == expected


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        pytest.param("running", "running", id="running"),
        pytest.param("not running", "not running", id="not-running"),
        pytest.param("crashed", "unreachable", id="unexpected"),
    ],
)
def test_daemon_state(state: str, expected: str) -> None:
    """Known states are kept; anything else counts as unreachable, so its ports are never shown as open."""
    assert parse_docker([{"mode": "rootful", "state": state}])[0]["state"] == expected


def test_listeners_are_read() -> None:
    """A stored listener comes back with its port and processes."""
    stored = [{"proto": "tcp", "address": "0.0.0.0", "interface": "", "port": 22, "processes": ["sshd"]}]

    assert parse_listeners(stored) == stored


def test_listeners_unknown_stay_unknown() -> None:
    """None (ss was not available) stays None, not "nothing listens"."""
    assert parse_listeners(None) is None


@pytest.mark.parametrize(
    "stored",
    [pytest.param([{"proto": "tcp", "port": 0}], id="port-zero"), pytest.param([{"proto": "tcp"}], id="no-port")],
)
def test_listeners_without_a_port_are_dropped(stored: object) -> None:
    """An entry without a usable port is no listener."""
    assert parse_listeners(stored) == []
