# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for collecting fail2ban and auto-updates through the System interface (with a fake system)."""

from __future__ import annotations

from dataclasses import dataclass, field

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect import Account, CommandResult
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect_security import (
    UPGRADE_STAMP,
    collect_security,
)

JAILS = "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n"
PERIODIC = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
STAMP = 1791693515.7  # 2026-10-11T04:38:35Z


@dataclass
class FakeSecuritySystem:
    """Canned commands by program and arguments; file modification times."""

    commands: dict[str, CommandResult] = field(default_factory=dict)
    missing_programs: set[str] = field(default_factory=set)
    mtimes: dict[str, float] = field(default_factory=dict)

    def accounts(self) -> list[Account]:
        """Not used."""
        return []

    def group_names(self, account: Account) -> list[str]:
        """Not used."""
        return [account.name]

    def primary_group(self, account: Account) -> str:
        """Not used."""
        return account.name

    def is_root(self) -> bool:
        """Not used."""
        return True

    def read_file(self, path: str) -> str | None:
        """Not used."""
        del path
        return None

    def read_user_file(self, path: str, account: Account) -> str | None:
        """Not used."""
        del path, account
        return None

    def run(self, args: list[str]) -> CommandResult | None:
        """Canned result by the full command line, None for missing programs."""
        if args[0] in self.missing_programs:
            return None
        return self.commands.get(" ".join(args), CommandResult(1, ""))

    def file_mtime(self, path: str) -> float | None:
        """Configured modification time."""
        return self.mtimes.get(path)


def host() -> FakeSecuritySystem:
    """fail2ban running with one jail, unattended upgrades fully configured and run."""
    return FakeSecuritySystem(
        commands={
            "fail2ban-client status": CommandResult(0, JAILS),
            "systemctl is-active fail2ban.service": CommandResult(0, "active\n"),
            "dpkg-query -W -f=${db:Status-Status} unattended-upgrades": CommandResult(0, "installed"),
            "apt-config dump": CommandResult(0, PERIODIC),
            "systemctl is-enabled apt-daily-upgrade.timer": CommandResult(0, "enabled\n"),
        },
        mtimes={UPGRADE_STAMP: STAMP},
    )


def test_fail2ban_running() -> None:
    """State from systemd, jails from fail2ban-client."""
    assert collect_security(host()).fail2ban == {"state": "active", "jails": ["sshd"]}


def test_fail2ban_failed() -> None:
    """Captured on a real host: the unit failed, the client can't reach the server."""
    system = host()
    system.commands["systemctl is-active fail2ban.service"] = CommandResult(3, "failed\n")
    system.commands["fail2ban-client status"] = CommandResult(255, "", "ERROR Failed to access socket path")

    assert collect_security(system).fail2ban == {"state": "failed", "jails": None}


def test_fail2ban_running_but_client_refused() -> None:
    """Without root the client can't reach the server socket: the state is known, the jails are not."""
    system = host()
    # stdout that would parse to jails: only rc 0 counts, a failed call never yields a jail list
    system.commands["fail2ban-client status"] = CommandResult(255, JAILS, "ERROR Permission denied to socket")

    assert collect_security(system).fail2ban == {"state": "active", "jails": None}


def test_fail2ban_without_systemctl_is_unknown() -> None:
    """Installed, but no systemd to ask: the state is unknown, not a claim that it is down."""
    system = host()
    system.missing_programs.add("systemctl")

    assert collect_security(system).fail2ban["state"] == "unknown"


def test_fail2ban_not_installed() -> None:
    """No client binary: not installed, nothing else asked."""
    system = host()
    system.missing_programs.add("fail2ban-client")

    assert collect_security(system).fail2ban == {"state": "not installed", "jails": None}


def test_auto_updates_configured() -> None:
    """All settings plus the stamp time as ISO 8601 in UTC."""
    auto_updates = collect_security(host()).auto_updates

    assert auto_updates == {
        "installed": True,
        "update_lists": "1",
        "unattended_upgrade": "1",
        "timer": "enabled",
        "last_success": "2026-10-11T04:38:35+00:00",
    }


def test_auto_updates_package_not_installed() -> None:
    """dpkg-query fails for unknown packages."""
    system = host()
    system.commands["dpkg-query -W -f=${db:Status-Status} unattended-upgrades"] = CommandResult(1, "")

    assert collect_security(system).auto_updates["installed"] is False


def test_auto_updates_package_removed_config_left() -> None:
    """`config-files` is not installed."""
    system = host()
    system.commands["dpkg-query -W -f=${db:Status-Status} unattended-upgrades"] = CommandResult(0, "config-files")

    assert collect_security(system).auto_updates["installed"] is False


def test_auto_updates_never_run() -> None:
    """No stamp: no successful run, which is different from unknown."""
    system = host()
    system.mtimes.clear()

    assert collect_security(system).auto_updates["last_success"] == ""


def test_auto_updates_timer_disabled_reported_as_is() -> None:
    """is-enabled prints the state with a non-zero rc."""
    system = host()
    system.commands["systemctl is-enabled apt-daily-upgrade.timer"] = CommandResult(1, "disabled\n")

    assert collect_security(system).auto_updates["timer"] == "disabled"


def test_auto_updates_apt_config_failing_means_settings_unknown() -> None:
    """`apt-config dump` failing: both APT::Periodic settings are unknown (None), not disabled."""
    system = host()
    system.commands["apt-config dump"] = CommandResult(100, "", "E: Syntax error /etc/apt/apt.conf.d/50x")

    auto_updates = collect_security(system).auto_updates

    assert (auto_updates["update_lists"], auto_updates["unattended_upgrade"]) == (None, None)


def test_auto_updates_without_package_tools_everything_is_unknown() -> None:
    """Not a Debian system (or a broken one): unknown, never a failure; the stamp is still read."""
    system = host()
    system.missing_programs.update({"dpkg-query", "apt-config", "systemctl"})

    assert collect_security(system).auto_updates == {
        "installed": None,
        "update_lists": None,
        "unattended_upgrade": None,
        "timer": "",
        "last_success": "2026-10-11T04:38:35+00:00",
    }
