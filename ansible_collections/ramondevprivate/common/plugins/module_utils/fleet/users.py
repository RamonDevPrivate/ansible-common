# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Parse account, sudo, SSH key and login information.

Pure functions: they get command output or file content and never touch the system. Command output is
expected in a parsable (English) locale; the module sets it for every command.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import TYPE_CHECKING, Final, NamedTuple

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    DEFAULT_KEY_FILES,
    AuthorizedKey,
    Sudo,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

DEFAULT_UID_MIN: Final = 1000
NO_LOGIN_SHELLS: Final = frozenset({"", "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"})

_UID_MIN = re.compile(r"^\s*UID_MIN\s+(\d+)\s*$", re.MULTILINE)
_SUDO_NOT_ALLOWED = re.compile(r"^User \S+ is not allowed to run sudo on ", re.MULTILINE)
_SUDO_RULES_HEADER = re.compile(r"^User \S+ may run the following commands on .*:$", re.MULTILINE)
_SUDO_RULE = re.compile(r"^\((?P<runas>[^)]*)\)\s*(?P<tags>(?:[A-Z_]+:\s*)*)(?P<commands>.+)$")
_KEY_TYPES = (
    r"(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521))(?:-cert-v01@openssh\.com)?",
    r"sk-(?:ecdsa-sha2-nistp256|ssh-ed25519)(?:@openssh\.com|-cert-v01@openssh\.com)",
)
_KEY_TYPE = re.compile(f"^(?:{'|'.join(_KEY_TYPES)})$")


# Accounts


def parse_uid_min(login_defs: str | None) -> int:
    """UID_MIN from /etc/login.defs; Debian's default if the file or the setting is missing."""
    match = _UID_MIN.search(login_defs or "")
    return int(match.group(1)) if match else DEFAULT_UID_MIN


def is_login_shell(shell: str) -> bool:
    """Accounts with nologin or false can't log in interactively."""
    return shell.strip() not in NO_LOGIN_SHELLS


# sudo -l -U <user>


def parse_sudo_list(output: str) -> Sudo:
    """Classify the rules from `sudo -l -U <user>`.

    full: may run any command as root ((ALL) ALL, (ALL : ALL) ALL, (root) ALL); limited: anything else;
    none: not allowed to run sudo; unknown: output not recognized (e.g. sudo couldn't list the rules).
    NOPASSWD refers to the rules that define the level.
    """
    if _SUDO_NOT_ALLOWED.search(output):
        return {"level": "none", "nopasswd": False, "rules": []}
    header = _SUDO_RULES_HEADER.search(output)
    if header is None:
        return {"level": "unknown", "nopasswd": False, "rules": []}

    rules: list[str] = []
    for line in output[header.end() :].splitlines()[1:]:
        if not line.startswith((" ", "\t")):
            break
        rule = " ".join(line.split())
        if rule and rule not in rules:
            rules.append(rule)

    full = [rule for rule in rules if _is_full_rule(rule)]
    level = "full" if full else ("limited" if rules else "none")
    relevant = full or rules
    return {"level": level, "nopasswd": any("NOPASSWD:" in rule for rule in relevant), "rules": rules}


def sudo_runas(rules: list[str]) -> list[str]:
    """Users the rules let you run commands as, in order: "(dockeruser) NOPASSWD: ..." gives dockeruser."""
    targets: list[str] = []
    for rule in rules:
        match = _SUDO_RULE.match(rule)
        if match is None:
            continue
        runas = match.group("runas")
        user, _sep, group = (part.strip() for part in runas.partition(":"))
        target = user or f":{group}"
        if target and target not in targets:
            targets.append(target)
    return targets


def _is_full_rule(rule: str) -> bool:
    match = _SUDO_RULE.match(rule)
    if match is None:
        return False
    runas_user = match.group("runas").split(":")[0].strip()
    return match.group("commands").strip() == "ALL" and runas_user in {"ALL", "root"}


# sshd -T


class SshdConfig(NamedTuple):
    """What `sshd -T` says about where logins can come from."""

    key_files: list[str]
    keys_command: bool  # AuthorizedKeysCommand set


def parse_sshd_config(output: str) -> SshdConfig:
    """Key file patterns and whether an AuthorizedKeysCommand is set, from `sshd -T`."""
    files: list[str] = list(DEFAULT_KEY_FILES)
    keys_command = False
    for line in output.splitlines():
        keyword, _sep, value = line.strip().partition(" ")
        name = keyword.lower()  # sshd keywords are case-insensitive; `sshd -T` prints some in mixed case
        if name == "authorizedkeysfile" and value.strip():
            files = value.split()
        elif name == "authorizedkeyscommand":
            keys_command = value.strip() not in {"", "none"}
    return SshdConfig(files, keys_command)


def expand_key_file(pattern: str, user: str, uid: int, home: str) -> str:
    """Expand sshd's tokens (%%, %h, %u, %U); relative paths are relative to the home directory."""
    tokens = {"%": "%", "h": home, "u": user, "U": str(uid)}
    path = re.sub(r"%(.)", lambda m: tokens.get(m.group(1), m.group(0)), pattern)
    return path if path.startswith("/") else f"{home.rstrip('/')}/{path}"


# authorized_keys


def parse_authorized_keys(content: str) -> list[AuthorizedKey]:
    """All valid keys of an authorized_keys file; comments, blank and broken lines are skipped."""
    keys: list[AuthorizedKey] = []
    for line in content.splitlines():
        key = parse_key_line(line)
        if key is not None:
            keys.append(key)
    return keys


def parse_key_line(line: str) -> AuthorizedKey | None:
    """Parse `[options] keytype base64 [comment]`; None if the line is not a key."""
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    options, rest = "", text
    if not _KEY_TYPE.match(text.split(maxsplit=1)[0]):
        options, rest = _split_options(text)
    match rest.split(maxsplit=2):
        case [key_type, key_text, *comment] if _KEY_TYPE.match(key_type):
            blob = _decode_key(key_text)
        case _:
            return None
    if blob is None:
        return None
    allowed_from, forced_command = _restrictions(options)
    return {
        "key_type": key_type,
        "comment": " ".join(comment).strip(),
        "fingerprint": fingerprint(blob),
        "allowed_from": allowed_from,
        "forced_command": forced_command,
    }


def fingerprint(blob: bytes) -> str:
    """SHA256 fingerprint in OpenSSH's format, as `ssh-keygen -lf` prints it."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _decode_key(text: str) -> bytes | None:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _outside_quotes(text: str) -> Iterator[tuple[int, str]]:
    """Characters outside double quotes, with their index; a backslash only escapes a quote (as sshd reads options)."""
    in_quotes = False
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == "\\" and text[index + 1 : index + 2] == '"':
            escaped = True
        elif char == '"':
            in_quotes = not in_quotes
        elif not in_quotes:
            yield index, char


def _split_options(text: str) -> tuple[str, str]:
    """Split the options field (may contain quoted spaces) from the rest of the line."""
    for index, char in _outside_quotes(text):
        if char in " \t":
            return text[:index], text[index:]
    return text, ""


def _restrictions(options: str) -> tuple[str, bool]:
    """from="..." value and whether command="..." forces a command (its content is not kept)."""
    allowed_from = ""
    forced_command = False
    for option in _split_on_unquoted_commas(options):
        name, _sep, value = option.partition("=")
        if name.lower() == "from":
            allowed_from = value.strip('"')
        elif name.lower() == "command":
            forced_command = True
    return allowed_from, forced_command


def _split_on_unquoted_commas(options: str) -> list[str]:
    parts: list[str] = []
    start = 0
    for index, char in _outside_quotes(options):
        if char == ",":
            parts.append(options[start:index])
            start = index + 1
    parts.append(options[start:])
    return [part.strip() for part in parts if part.strip()]


# lslogins --raw --noheadings --time-format=iso -o USER,LAST-LOGIN -l <users>


def parse_lslogins(output: str) -> dict[str, str]:
    """Last login per user as ISO 8601 string; "" if lslogins has no record."""
    logins: dict[str, str] = {}
    for line in output.splitlines():
        user, _sep, last_login = line.strip().partition(" ")
        if user:
            logins[user] = last_login.strip()
    return logins
