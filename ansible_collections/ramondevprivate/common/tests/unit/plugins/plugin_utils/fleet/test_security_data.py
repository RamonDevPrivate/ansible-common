# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for reading fail2ban, auto-update and exposure data from stored snapshots."""

from __future__ import annotations

import pytest

from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.security_data import (
    parse_auto_updates,
    parse_exposure,
    parse_fail2ban,
)


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        pytest.param("public", "public", id="public"),
        pytest.param("internal", "internal", id="internal"),
        pytest.param("exposed", "unknown", id="unexpected"),
    ],
)
def test_exposure_state(state: str, expected: str) -> None:
    """Known states are kept; anything else is unknown, so no public/internal tag is guessed."""
    assert parse_exposure({"state": state})["state"] == expected


def test_fail2ban_is_read() -> None:
    """State and jails as stored."""
    assert parse_fail2ban({"state": "active", "jails": ["sshd"]}) == {"state": "active", "jails": ["sshd"]}


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        pytest.param({}, {"state": "unknown", "jails": None}, id="empty"),
        pytest.param({"state": "failed", "jails": None}, {"state": "failed", "jails": None}, id="jails-unknown"),
    ],
)
def test_fail2ban_unknown_parts_stay_unknown(stored: object, expected: object) -> None:
    """A missing state is unknown, and unknown jails stay None rather than "no jails"."""
    assert parse_fail2ban(stored) == expected


def test_auto_updates_are_read() -> None:
    """Every setting as stored."""
    stored = {
        "installed": True,
        "update_lists": "1",
        "unattended_upgrade": "1",
        "timer": "enabled",
        "last_success": "2026-10-11T04:38:35+00:00",
    }

    assert parse_auto_updates(stored) == stored


@pytest.mark.parametrize(
    "stored",
    [pytest.param({"installed": "yes", "update_lists": 1}, id="wrong-types"), pytest.param({}, id="empty")],
)
def test_auto_updates_wrong_values_are_unknown(stored: object) -> None:
    """Values of the wrong type are unknown (None), not guessed."""
    auto_updates = parse_auto_updates(stored)

    assert (auto_updates["installed"], auto_updates["update_lists"]) == (None, None)
