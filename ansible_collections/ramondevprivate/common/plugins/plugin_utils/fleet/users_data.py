# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Read users and SSH settings from untyped data (module result or stored JSON), runs on the controller."""

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import (
    Data,
    as_list,
    as_mapping,
    get_int,
    get_list,
    get_mapping,
    get_str,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    DEFAULT_KEY_FILES,
    AuthorizedKey,
    Ssh,
    Sudo,
    SudoLevel,
    User,
)


def parse_users(value: object) -> list[User]:
    """Users from untyped data; entries without a name are dropped."""
    return [_user(as_mapping(item)) for item in as_list(value) if get_str(as_mapping(item), "name")]


def parse_ssh(value: object) -> Ssh:
    """SSH settings from untyped data; unknown values fall back to sshd's defaults."""
    data = as_mapping(value)
    files = [f for f in get_list(data, "key_files") if isinstance(f, str)]
    return {
        "key_files": files or list(DEFAULT_KEY_FILES),
        "key_files_source": "sshd" if get_str(data, "key_files_source") == "sshd" else "default",
        "keys_command": data.get("keys_command") is True,
    }


def _user(data: Data) -> User:
    keys = data.get("authorized_keys")
    last_login = data.get("last_login")
    return {
        "name": get_str(data, "name"),
        "uid": get_int(data, "uid", -1),
        "groups": [g for g in get_list(data, "groups") if isinstance(g, str)],
        "sudo": _sudo(get_mapping(data, "sudo")),
        "authorized_keys": None if keys is None else [_key(as_mapping(k)) for k in as_list(keys)],
        "last_login": last_login if isinstance(last_login, str) else None,
    }


def _sudo(data: Data) -> Sudo:
    return {
        "level": _level(get_str(data, "level")),
        "nopasswd": data.get("nopasswd") is True,
        "rules": [r for r in get_list(data, "rules") if isinstance(r, str)],
    }


def _level(value: str) -> SudoLevel:
    if value == "full":
        return "full"
    if value == "limited":
        return "limited"
    if value == "none":
        return "none"
    return "unknown"


def _key(data: Data) -> AuthorizedKey:
    return {
        "key_type": get_str(data, "key_type"),
        "comment": get_str(data, "comment"),
        "fingerprint": get_str(data, "fingerprint"),
        "allowed_from": get_str(data, "allowed_from"),
        "forced_command": data.get("forced_command") is True,
    }
