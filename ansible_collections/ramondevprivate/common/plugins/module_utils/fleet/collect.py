# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Collect users, their access and their last login through a System interface.

The System is the only part that touches the host (accounts, files, commands), so this logic can be tested
with a fake system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    DEFAULT_KEY_FILES,
    AuthorizedKey,
    Ssh,
    Sudo,
    User,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.users import (
    expand_key_file,
    is_login_shell,
    parse_authorized_keys,
    parse_lslogins,
    parse_sshd_config,
    parse_sudo_list,
    parse_uid_min,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

UNKNOWN_SUDO: Sudo = {"level": "unknown", "nopasswd": False, "rules": []}


@dataclass(frozen=True)
class Account:
    """One entry of the account database."""

    name: str
    uid: int
    gid: int
    home: str
    shell: str


@dataclass(frozen=True)
class CommandResult:
    """Exit code and output of a command."""

    rc: int
    stdout: str
    stderr: str = ""


class UnreadableFileError(Exception):
    """A file exists but can't be read (permissions, not a regular file, too large)."""


class System(Protocol):
    """Everything the collector needs from the host."""

    def accounts(self) -> list[Account]:
        """All accounts (passwd database)."""
        raise NotImplementedError

    def group_names(self, account: Account) -> list[str]:
        """Names of all groups of the account, including its primary group."""
        raise NotImplementedError

    def primary_group(self, account: Account) -> str:
        """Name of the account's primary group."""
        raise NotImplementedError

    def is_root(self) -> bool:
        """Whether the collection runs as root."""
        raise NotImplementedError

    def read_file(self, path: str) -> str | None:
        """File content; None if the file doesn't exist; raises UnreadableFileError if it can't be read."""
        raise NotImplementedError

    def read_user_file(self, path: str, account: Account) -> str | None:
        """Like read_file, but with the account's permissions (how sshd reads authorized_keys)."""
        raise NotImplementedError

    def run(self, args: list[str]) -> CommandResult | None:
        """Run a command in a parsable locale; None if the program isn't installed."""
        raise NotImplementedError


@dataclass
class UsersResult:
    """What collect_users found, plus warnings for the Ansible output."""

    users: list[User]
    ssh: Ssh
    warnings: list[str] = field(default_factory=list)


def collect_users(system: System, group_filter: Iterable[str], user_filter: Iterable[str] = ()) -> UsersResult:
    """Collect login accounts, root and every account with authorized keys, except those in user_filter."""
    warnings: list[str] = []
    ssh = _ssh_config(system, warnings)
    uid_min = parse_uid_min(_read(system, "/etc/login.defs", warnings))
    ignored_groups = set(group_filter)
    ignored_users = set(user_filter)

    selected: list[tuple[Account, list[AuthorizedKey] | None]] = []
    for account in system.accounts():
        if account.name in ignored_users:
            continue
        keys = _keys(system, account, ssh, warnings)
        is_login = account.uid >= uid_min and is_login_shell(account.shell)
        if account.uid == 0 or is_login or keys:
            selected.append((account, keys))

    logins = _last_logins(system, [account.name for account, _keys in selected])
    users: list[User] = [
        {
            "name": account.name,
            "uid": account.uid,
            "groups": _groups(system, account, ignored_groups),
            "sudo": _sudo(system, account),
            "authorized_keys": keys,
            "last_login": None if logins is None else logins.get(account.name, ""),
        }
        for account, keys in sorted(selected, key=lambda item: item[0].name)
    ]
    return UsersResult(users=users, ssh=ssh, warnings=warnings)


def _ssh_config(system: System, warnings: list[str]) -> Ssh:
    result = system.run(["sshd", "-T"])
    if result is None or result.rc != 0:
        warnings.append("sshd -T failed; assuming the default authorized_keys locations")
        return {
            "key_files": list(DEFAULT_KEY_FILES),
            "key_files_source": "default",
            "keys_command": False,
        }
    config = parse_sshd_config(result.stdout)
    return {
        "key_files": config.key_files,
        "key_files_source": "sshd",
        "keys_command": config.keys_command,
    }


def _keys(system: System, account: Account, ssh: Ssh, warnings: list[str]) -> list[AuthorizedKey] | None:
    """Keys from all key files of the account; None if any of them exists but can't be read."""
    keys: list[AuthorizedKey] = []
    for pattern in ssh["key_files"]:
        path = expand_key_file(pattern, account.name, account.uid, account.home)
        try:
            content = system.read_user_file(path, account)
        except UnreadableFileError as error:
            warnings.append(f"{account.name}: {path} not readable ({error})")
            return None
        if content is not None:
            keys.extend(parse_authorized_keys(content))
    return keys


def _groups(system: System, account: Account, ignored: set[str]) -> list[str]:
    primary = system.primary_group(account)
    return sorted({name for name in system.group_names(account) if name != primary and name not in ignored})


def _sudo(system: System, account: Account) -> Sudo:
    if not system.is_root():
        # only root may list other users' rules; trying anyway leaves denials in the auth log (and may send mail)
        return UNKNOWN_SUDO
    result = system.run(["sudo", "-n", "-l", "-U", account.name])
    if result is None:
        return UNKNOWN_SUDO
    return parse_sudo_list(result.stdout)


def _last_logins(system: System, names: list[str]) -> dict[str, str] | None:
    if not names:
        return {}
    result = system.run(["lslogins", "--raw", "--noheadings", "--time-format=iso", "-o", "USER,LAST-LOGIN", "-l", ",".join(names)])
    if result is None or result.rc != 0:
        return None
    return parse_lslogins(result.stdout)


def _read(system: System, path: str, warnings: list[str]) -> str | None:
    try:
        return system.read_file(path)
    except UnreadableFileError as error:
        warnings.append(f"{path} not readable ({error})")
        return None
