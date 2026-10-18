# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Collect fail2ban and auto-update settings through a System interface.

Like collect.py, all host access goes through the system, so this logic can be tested with a fake system.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, Protocol

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect import System
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.security import (
    parse_apt_periodic,
    parse_fail2ban_jails,
)

if TYPE_CHECKING:
    from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import AutoUpdates, Fail2ban

# apt.systemd.daily touches this file only when unattended-upgrade exits successfully; its messages in the
# unattended-upgrades log are translated, so the stamp is the locale-independent record of the last success
UPGRADE_STAMP: Final = "/var/lib/apt/periodic/upgrade-stamp"


class SecuritySystem(System, Protocol):
    """System plus what the security collection needs."""

    def file_mtime(self, path: str) -> float | None:
        """Modification time (seconds since the epoch); None if the file doesn't exist or can't be read."""
        raise NotImplementedError


@dataclass
class SecurityResult:
    """What collect_security found."""

    fail2ban: Fail2ban
    auto_updates: AutoUpdates


def collect_security(system: SecuritySystem) -> SecurityResult:
    """Collect fail2ban state and jails, and the unattended-upgrades setup."""
    return SecurityResult(fail2ban=_fail2ban(system), auto_updates=_auto_updates(system))


def _fail2ban(system: SecuritySystem) -> Fail2ban:
    # only queries the running server; fail2ban-client never starts it
    status = system.run(["fail2ban-client", "status"])
    if status is None:
        return {"state": "not installed", "jails": None}
    return {
        "state": _systemctl(system, "is-active", "fail2ban.service") or "unknown",
        "jails": parse_fail2ban_jails(status.stdout) if status.rc == 0 else None,
    }


def _auto_updates(system: SecuritySystem) -> AutoUpdates:
    package = system.run(["dpkg-query", "-W", "-f=${db:Status-Status}", "unattended-upgrades"])
    config = system.run(["apt-config", "dump"])
    if config is None or config.rc != 0:
        update_lists, unattended_upgrade = None, None
    else:
        update_lists, unattended_upgrade = parse_apt_periodic(config.stdout)
    mtime = system.file_mtime(UPGRADE_STAMP)
    return {
        "installed": None if package is None else package.rc == 0 and package.stdout.strip() == "installed",
        "update_lists": update_lists,
        "unattended_upgrade": unattended_upgrade,
        "timer": _systemctl(system, "is-enabled", "apt-daily-upgrade.timer"),
        "last_success": "" if mtime is None else _iso(mtime),
    }


def _systemctl(system: SecuritySystem, verb: str, unit: str) -> str:
    """First line of `systemctl <verb> <unit>` (also printed with a non-zero rc); "" without systemctl."""
    result = system.run(["systemctl", verb, unit])
    if result is None:
        return ""
    lines = result.stdout.strip().splitlines()
    return lines[0].strip() if lines else ""


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(int(timestamp), tz=UTC).isoformat()
