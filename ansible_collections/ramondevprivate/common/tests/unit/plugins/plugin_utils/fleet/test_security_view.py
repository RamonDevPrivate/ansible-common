# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the auto-update status and the needs-attention findings."""

from __future__ import annotations

import pytest

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    AutoUpdates,
    ExposureState,
    Snapshot,
    SudoLevel,
    Ufw,
    UfwState,
    User,
    ufw_without_details,
)
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.security_view import (
    auto_update_status,
    findings,
)

COLLECTED = "2026-10-11T12:00:00Z"


def auto_updates(**changes: object) -> AutoUpdates:
    """Fully configured unattended upgrades that ran a day before the collection, with some values changed."""
    values: dict[str, object] = {
        "installed": True,
        "update_lists": "1",
        "unattended_upgrade": "1",
        "timer": "enabled",
        "last_success": "2026-10-10T04:38:35+00:00",
        **changes,
    }
    installed, lists, upgrade = values["installed"], values["update_lists"], values["unattended_upgrade"]
    timer, last = values["timer"], values["last_success"]
    return {
        "installed": installed if isinstance(installed, bool) else None,
        "update_lists": lists if isinstance(lists, str) else None,
        "unattended_upgrade": upgrade if isinstance(upgrade, str) else None,
        "timer": str(timer),
        "last_success": last if isinstance(last, str) else None,
    }


def user(name: str, *, level: SudoLevel = "none", nopasswd: bool = False, comment: str = "x@y", keys_known: bool = True) -> User:
    """A user with one key; keys_known=False: the key files couldn't be read."""
    return {
        "name": name,
        "uid": 1000,
        "groups": [],
        "sudo": {"level": level, "nopasswd": nopasswd, "rules": []},
        "authorized_keys": [
            {
                "key_type": "ssh-ed25519",
                "comment": comment,
                "fingerprint": "SHA256:abc",
                "allowed_from": "",
                "forced_command": False,
            }
        ]
        if keys_known
        else None,
        "last_login": "",
    }


def snapshot(
    *,
    ufw: Ufw | None = None,
    users: list[User] | None = None,
    fail2ban: str = "active",
    exposure: ExposureState | None = None,
) -> Snapshot:
    """A host snapshot without findings, except for the sections given."""
    data: Snapshot = {
        "schema_version": 1,
        "host": "h",
        "collected_at": COLLECTED,
        "system": {
            "distribution": "Debian",
            "version": "13",
            "release": "trixie",
            "kernel": "",
            "cores": 1,
            "ram_mb": 1,
            "disk": {"total_bytes": 0, "mounts": []},
        },
        "addresses": [],
        "users": users or [],
        "ssh": {"key_files": [".ssh/authorized_keys"], "key_files_source": "sshd", "keys_command": False},
        "ufw": ufw or ufw_without_details("active"),
        "listeners": [],
        "docker": [],
        "fail2ban": {"state": fail2ban, "jails": None},
        "auto_updates": auto_updates(),
    }
    if exposure is not None:
        data["exposure"] = {"state": exposure, "checked_at": COLLECTED, "answered": []}
    return data


# Auto-update status


def test_auto_update_status_recent_run_is_ok() -> None:
    """Configured and successful within the threshold."""
    assert auto_update_status(auto_updates(), COLLECTED, 7) == "ok"


def test_auto_update_status_old_run_needs_attention() -> None:
    """The threshold is part of the status, as in the spec."""
    assert auto_update_status(auto_updates(last_success="2026-10-01T04:00:00+00:00"), COLLECTED, 7) == ("no successful run in 7 days")


def test_auto_update_status_never_run() -> None:
    """Configured but no stamp yet."""
    assert auto_update_status(auto_updates(last_success=""), COLLECTED, 7) == "no successful run recorded"


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"installed": False}, id="package-missing"),
        pytest.param({"update_lists": "0"}, id="lists-disabled"),
        pytest.param({"unattended_upgrade": ""}, id="upgrade-unset"),
        pytest.param({"timer": "disabled"}, id="timer-disabled"),
        pytest.param({"timer": "masked"}, id="timer-masked"),
    ],
)
def test_auto_update_status_not_configured(changes: dict[str, object]) -> None:
    """Any missing piece means unattended upgrades won't run."""
    assert auto_update_status(auto_updates(**changes), COLLECTED, 7) == "not configured"


def test_auto_update_status_interval_values_count_as_enabled() -> None:
    """APT::Periodic values are intervals; anything but 0 or empty enables them."""
    assert auto_update_status(auto_updates(update_lists="always", unattended_upgrade="7"), COLLECTED, 7) == "ok"


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"installed": None}, id="package-unknown"),
        pytest.param({"update_lists": None}, id="settings-unknown"),
        pytest.param({"timer": ""}, id="timer-unknown"),
        pytest.param({"last_success": "yesterday"}, id="last-run-unparseable"),
        pytest.param({"last_success": "2026-10-10T04:38:35"}, id="last-run-without-timezone"),
    ],
)
def test_auto_update_status_unknown(changes: dict[str, object]) -> None:
    """Unknown pieces are not reported as misconfiguration."""
    assert auto_update_status(auto_updates(**changes), COLLECTED, 7) == "unknown"


# Findings


@pytest.mark.parametrize("state", ["inactive", "not installed"])
def test_finding_ufw_off(state: UfwState) -> None:
    """Inactive or missing UFW is listed with its state."""
    found = findings(snapshot(ufw=ufw_without_details(state)), "ok")

    assert [(f["rule"], f["detail"]) for f in found] == [("ufw_off", state)]


@pytest.mark.parametrize("state", ["active", "unknown"])
def test_finding_ufw_off_not_for_active_or_unknown(state: UfwState) -> None:
    """Active is fine; unknown (no root) is no claim that UFW is off."""
    assert findings(snapshot(ufw=ufw_without_details(state)), "ok") == []


@pytest.mark.parametrize("status", ["not configured", "no successful run in 7 days", "no successful run recorded"])
def test_finding_auto_updates(status: str) -> None:
    """Every status but ok and unknown is listed, with the status as detail."""
    found = findings(snapshot(), status)

    assert [(f["rule"], f["detail"]) for f in found] == [("auto_updates", status)]


@pytest.mark.parametrize("status", ["ok", "unknown"])
def test_finding_auto_updates_not_for_ok_or_unknown(status: str) -> None:
    """A recent run is fine; unknown settings are no claim of a problem."""
    assert findings(snapshot(), status) == []


def test_finding_sudo_full_nopasswd_names_the_account() -> None:
    """Full sudo without password, with the account name (allowed in the overview, thread 49)."""
    found = findings(snapshot(users=[user("alice", level="full", nopasswd=True)]), "ok")

    assert [(f["rule"], f["detail"]) for f in found] == [("sudo_full_nopasswd", "alice")]


def test_finding_key_without_comment_names_account_and_fingerprint() -> None:
    """A key without comment is only identifiable by its fingerprint."""
    found = findings(snapshot(users=[user("bob", comment="")]), "ok")

    assert [(f["rule"], f["detail"]) for f in found] == [("key_without_comment", "bob: SHA256:abc")]


def test_finding_key_without_comment_not_for_unreadable_keys() -> None:
    """Keys unknown (file not readable): nothing to judge."""
    assert findings(snapshot(users=[user("bob", keys_known=False)]), "ok") == []


@pytest.mark.parametrize(
    ("level", "nopasswd"),
    [
        pytest.param("full", False, id="full-with-password"),
        pytest.param("limited", True, id="limited-nopasswd"),
    ],
)
def test_finding_not_for_other_sudo_rights(level: SudoLevel, *, nopasswd: bool) -> None:
    """Only full sudo without password is listed; sudo users are never listed for being inactive (Ramon)."""
    assert findings(snapshot(users=[user("carol", level=level, nopasswd=nopasswd)]), "ok") == []


@pytest.mark.parametrize("state", ["failed", "inactive", "not installed"])
def test_finding_fail2ban_off_on_public_host(state: str) -> None:
    """Public hosts should run fail2ban."""
    found = findings(snapshot(fail2ban=state, exposure="public"), "ok")

    assert [(f["rule"], f["detail"]) for f in found] == [("fail2ban_public", state)]


@pytest.mark.parametrize("exposure", ["internal", "unknown", None])
def test_finding_fail2ban_off_elsewhere_is_fine(exposure: ExposureState | None) -> None:
    """Internal hosts, and hosts whose exposure is unknown, are not listed."""
    assert findings(snapshot(fail2ban="failed", exposure=exposure), "ok") == []


def test_finding_fail2ban_running_on_public_host_is_fine() -> None:
    """The intended state."""
    assert findings(snapshot(fail2ban="active", exposure="public"), "ok") == []


def test_finding_none_for_a_host_without_problems() -> None:
    """Active UFW and fail2ban, auto-updates ok, no users: nothing to list."""
    assert findings(snapshot(), "ok") == []


def test_finding_none_for_unknown_fail2ban_state() -> None:
    """Without root the state is unknown: no claim that fail2ban isn't running."""
    assert findings(snapshot(fail2ban="unknown", exposure="public"), "ok") == []
