# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for reading users and SSH settings from stored snapshots."""

from __future__ import annotations

import pytest

from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.users_data import parse_ssh, parse_users


def test_users_are_read_with_their_fields() -> None:
    """A stored user comes back with its name, sudo level and keys."""
    stored: list[dict[str, object]] = [{"name": "alice", "uid": 1000, "sudo": {"level": "full"}, "authorized_keys": [], "last_login": ""}]

    users = parse_users(stored)

    assert [(u["name"], u["sudo"]["level"], u["authorized_keys"]) for u in users] == [("alice", "full", [])]


@pytest.mark.parametrize(
    "stored",
    [
        pytest.param([{"uid": 1000}], id="no-name"),
        pytest.param(["alice"], id="not-a-mapping"),
        pytest.param("alice", id="not-a-list"),
    ],
)
def test_users_without_a_name_are_dropped(stored: object) -> None:
    """An entry that can't name an account is no user."""
    assert parse_users(stored) == []


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        pytest.param({"level": "limited"}, "limited", id="known"),
        pytest.param({"level": "root"}, "unknown", id="unexpected"),
    ],
)
def test_sudo_level_is_known_or_unknown(stored: dict[str, object], expected: str) -> None:
    """Known levels are kept; anything else is unknown, never guessed."""
    assert parse_users([{"name": "u", "sudo": stored}])[0]["sudo"]["level"] == expected


def test_unreadable_keys_stay_unknown() -> None:
    """None (key files not readable) is not turned into "no keys"."""
    assert parse_users([{"name": "u", "authorized_keys": None}])[0]["authorized_keys"] is None


def test_ssh_settings_are_read() -> None:
    """Key files, their source and the keys-command flag as stored."""
    stored = {"key_files": [".ssh/k"], "key_files_source": "sshd", "keys_command": True}

    assert parse_ssh(stored) == stored


@pytest.mark.parametrize("stored", [pytest.param({}, id="empty"), pytest.param("x", id="not-a-mapping")])
def test_ssh_settings_fall_back_to_sshd_defaults(stored: object) -> None:
    """Without usable data: sshd's default key files, marked as assumed, no keys command."""
    assert parse_ssh(stored) == {
        "key_files": [".ssh/authorized_keys", ".ssh/authorized_keys2"],
        "key_files_source": "default",
        "keys_command": False,
    }
