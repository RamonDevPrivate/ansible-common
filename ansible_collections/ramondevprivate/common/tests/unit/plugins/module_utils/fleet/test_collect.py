# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for collecting users through the System interface (with a fake system)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect import (
    Account,
    CommandResult,
    UnreadableFileError,
    collect_users,
)

if TYPE_CHECKING:
    from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import User

KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
SUDO_FULL = "User {user} may run the following commands on h:\n    (ALL : ALL) ALL\n"
SUDO_NONE = "User {user} is not allowed to run sudo on h.\n"
SSHD = "sshd -T"
LSLOGINS = "lslogins --raw --noheadings --time-format=iso -o USER,LAST-LOGIN -l root,alice,deploy"


@dataclass
class FakeSystem:
    """In-memory host: accounts, groups, files and canned command results."""

    accounts_list: list[Account] = field(default_factory=list)
    groups: dict[str, list[str]] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    unreadable: set[str] = field(default_factory=set)
    commands: dict[str, CommandResult] = field(default_factory=dict)
    missing_programs: set[str] = field(default_factory=set)
    calls: list[list[str]] = field(default_factory=list)
    root: bool = True
    user_reads: list[tuple[str, str]] = field(default_factory=list)

    def is_root(self) -> bool:
        """Root unless a test says otherwise."""
        return self.root

    def accounts(self) -> list[Account]:
        """All accounts."""
        return self.accounts_list

    def group_names(self, account: Account) -> list[str]:
        """Primary group plus configured supplementary groups."""
        return [account.name, *self.groups.get(account.name, [])]

    def primary_group(self, account: Account) -> str:
        """Primary group has the account's name, as on Debian."""
        return account.name

    def read_file(self, path: str) -> str | None:
        """Configured content, None if missing."""
        if path in self.unreadable:
            message = "permission denied"
            raise UnreadableFileError(message)
        return self.files.get(path)

    def read_user_file(self, path: str, account: Account) -> str | None:
        """Same files, but records which account read which path."""
        self.user_reads.append((account.name, path))
        return self.read_file(path)

    def run(self, args: list[str]) -> CommandResult | None:
        """Canned result by full command line; sudo for an unknown user says "not allowed", anything else fails."""
        self.calls.append(args)
        if args[0] in self.missing_programs:
            return None
        command = " ".join(args)
        if command in self.commands:
            return self.commands[command]
        if args[0] == "sudo":
            return CommandResult(0, SUDO_NONE.format(user=args[-1]))
        return CommandResult(1, "", f"{command} failed")


def account(name: str, uid: int, shell: str = "/bin/bash") -> Account:
    """Account with a home under /home (root: /root)."""
    return Account(name, uid, uid, "/root" if uid == 0 else f"/home/{name}", shell)


def host() -> FakeSystem:
    """A typical Debian host: root, a service account, a login user, a service user with a key."""
    return FakeSystem(
        accounts_list=[
            account("root", 0),
            account("daemon", 1, "/usr/sbin/nologin"),
            account("www-data", 33, "/usr/sbin/nologin"),
            account("alice", 1000),
            account("deploy", 999, "/usr/sbin/nologin"),
            account("nobody", 65534, "/usr/sbin/nologin"),
        ],
        groups={"alice": ["sudo", "docker", "cdrom", "audio"]},
        files={
            "/etc/login.defs": "UID_MIN 1000\n",
            "/home/alice/.ssh/authorized_keys": f"ssh-ed25519 {KEY} alice@example.org\n",
            "/home/deploy/.ssh/authorized_keys": f"ssh-ed25519 {KEY} ci@example.org\n",
        },
        commands={
            SSHD: CommandResult(0, "authorizedkeysfile .ssh/authorized_keys\nauthorizedkeyscommand none\n"),
            LSLOGINS: CommandResult(0, "alice 2026-10-11T00:41:21+02:00\nroot \ndeploy \n"),
            "sudo -n -l -U alice": CommandResult(0, SUDO_FULL.format(user="alice")),
        },
    )


def names(system: FakeSystem) -> list[str]:
    """Names of the collected users."""
    return [user["name"] for user in collect_users(system, ["cdrom", "audio"]).users]


def test_selects_root_login_users_and_accounts_with_keys() -> None:
    """Service accounts are skipped unless they have authorized keys."""
    assert names(host()) == ["alice", "deploy", "root"]


def test_user_filter_leaves_accounts_out_entirely() -> None:
    """Filtered accounts are neither listed nor queried (no sudo call for them)."""
    system = host()

    result = collect_users(system, [], ["root", "alice"])

    assert [u["name"] for u in result.users] == ["deploy"]
    assert not any(call[-1] in {"root", "alice"} for call in system.calls if call[0] == "sudo")


def test_uid_min_from_login_defs_decides_who_is_a_login_user() -> None:
    """A higher UID_MIN turns alice (uid 1000, her key removed) into a system account."""
    system = host()
    system.files["/etc/login.defs"] = "UID_MIN 2000\n"
    del system.files["/home/alice/.ssh/authorized_keys"]

    assert names(system) == ["deploy", "root"]


def alice(system: FakeSystem, group_filter: list[str] | None = None) -> User:
    """Alice as collected from the host."""
    return next(u for u in collect_users(system, group_filter or []).users if u["name"] == "alice")


def test_groups_without_primary_group_and_filtered_noise() -> None:
    """Supplementary groups, sorted; the primary group and the filtered ones are left out."""
    assert alice(host(), ["cdrom", "audio"])["groups"] == ["docker", "sudo"]


def test_sudo_level_of_a_user() -> None:
    """The user's own `sudo -l -U` answer decides."""
    assert alice(host())["sudo"]["level"] == "full"


def test_keys_of_a_user() -> None:
    """The keys from the user's key file."""
    assert [k["comment"] for k in alice(host())["authorized_keys"] or []] == ["alice@example.org"]


def test_last_login_of_a_user() -> None:
    """The lslogins date of the user."""
    assert alice(host())["last_login"] == "2026-10-11T00:41:21+02:00"


def test_no_login_record_is_empty_not_unknown() -> None:
    """No lslogins record gives "" (shown as unknown status later), not None."""
    root = next(u for u in collect_users(host(), []).users if u["name"] == "root")

    assert root["last_login"] == ""


def test_key_files_are_read_as_their_account() -> None:
    """Key files go through read_user_file with the owning account, like sshd reads them."""
    system = host()

    _result = collect_users(system, [])

    assert ("alice", "/home/alice/.ssh/authorized_keys") in system.user_reads
    assert all(path.startswith(("/root/", f"/home/{name}/")) for name, path in system.user_reads)


def test_without_root_sudo_is_not_asked() -> None:
    """Only root may list other users' rules; asking anyway only fills the auth log with denials."""
    system = host()
    system.root = False

    result = collect_users(system, [])

    assert not [call for call in system.calls if call[0] == "sudo"]
    assert {user["sudo"]["level"] for user in result.users} == {"unknown"}


def test_sudo_runs_non_interactively_for_each_user() -> None:
    """The sudo call never waits for a password (-n)."""
    system = host()
    _result = collect_users(system, [])

    assert ["sudo", "-n", "-l", "-U", "alice"] in system.calls


def test_ssh_settings_from_sshd() -> None:
    """Key file locations come from sshd -T."""
    result = collect_users(host(), [])

    assert result.ssh == {
        "key_files": [".ssh/authorized_keys"],
        "key_files_source": "sshd",
        "keys_command": False,
    }


def test_without_sudo_the_sudo_level_is_unknown() -> None:
    """No sudo binary: unknown, never "none"."""
    system = host()
    system.missing_programs = {"sudo"}

    alice = next(u for u in collect_users(system, []).users if u["name"] == "alice")

    assert alice["sudo"]["level"] == "unknown"


def test_without_lslogins_the_last_login_is_unknown() -> None:
    """None (unknown), not "" (no record)."""
    system = host()
    system.missing_programs = {"lslogins"}

    alice = next(u for u in collect_users(system, []).users if u["name"] == "alice")

    assert alice["last_login"] is None


def test_without_sshd_default_key_locations_are_assumed() -> None:
    """No sshd -T: the default key files, and a warning that they were assumed."""
    system = host()
    system.missing_programs = {"sshd"}

    result = collect_users(system, [])

    assert result.ssh["key_files_source"] == "default"
    assert any("sshd" in warning for warning in result.warnings)


def test_lslogins_is_asked_for_the_selected_users_only() -> None:
    """One lslogins call for the collected accounts, not for service accounts."""
    system = host()

    _result = collect_users(system, [])

    assert [call[-1] for call in system.calls if call[0] == "lslogins"] == ["root,alice,deploy"]


def test_no_selected_users_means_no_lslogins_call() -> None:
    """With every account filtered out there is nothing to ask for."""
    system = host()

    result = collect_users(system, [], ["root", "alice", "deploy"])

    assert result.users == []
    assert not [call for call in system.calls if call[0] == "lslogins"]


def test_unreadable_login_defs_falls_back_to_the_debian_uid_min() -> None:
    """UID_MIN 1000 is assumed: uid 1000 is a login user, uid 999 isn't (both without key), with a warning."""
    system = host()
    system.unreadable.add("/etc/login.defs")
    del system.files["/home/alice/.ssh/authorized_keys"]
    system.accounts_list.append(account("bob", 999))

    result = collect_users(system, [])

    assert [u["name"] for u in result.users if u["name"] in {"alice", "bob"}] == ["alice"]
    assert any("/etc/login.defs not readable" in warning for warning in result.warnings)


def test_unreadable_key_file_gives_unknown_keys_and_a_warning() -> None:
    """A key file that exists but can't be read: keys None, never an empty list."""
    system = host()
    system.unreadable.add("/home/alice/.ssh/authorized_keys")

    result = collect_users(system, [])
    alice = next(u for u in result.users if u["name"] == "alice")

    assert alice["authorized_keys"] is None
    assert any("alice" in warning for warning in result.warnings)
