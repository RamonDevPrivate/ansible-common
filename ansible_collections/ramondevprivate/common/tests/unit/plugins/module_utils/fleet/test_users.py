# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the account, sudo, SSH key and login parsers."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.users import (
    expand_key_file,
    fingerprint,
    is_login_shell,
    parse_authorized_keys,
    parse_key_line,
    parse_lslogins,
    parse_sshd_config,
    parse_sudo_list,
    parse_uid_min,
    sudo_runas,
)

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    """Read a captured (anonymized) or synthetic command output."""
    return (FIXTURES / name).read_text()


# Accounts


def test_uid_min_from_login_defs() -> None:
    """The configured value wins; comments don't count."""
    assert parse_uid_min("# UID_MIN 500\nUID_MIN\t\t 2000\nUID_MAX 60000\n") == 2000


@pytest.mark.parametrize("content", [pytest.param(None, id="file-missing"), pytest.param("UID_MAX 60000\n", id="unset")])
def test_uid_min_defaults_to_debian_value(content: str | None) -> None:
    """Without a setting, Debian's default applies."""
    assert parse_uid_min(content) == 1000


@pytest.mark.parametrize("shell", ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""])
def test_no_login_shells(shell: str) -> None:
    """Service accounts can't log in interactively."""
    assert not is_login_shell(shell)


@pytest.mark.parametrize("shell", ["/bin/bash", "/usr/bin/zsh", "/bin/sh"])
def test_login_shells(shell: str) -> None:
    """Real shells count as login accounts."""
    assert is_login_shell(shell)


# sudo -l -U <user>: one test per aspect (level, NOPASSWD, rule list, as whom)


def rules_output(*rules: str) -> str:
    """`sudo -l -U u` output with the given rule lines."""
    return "User u may run the following commands on h:\n" + "".join(f"    {rule}\n" for rule in rules)


@pytest.mark.parametrize(
    ("output", "level"),
    [
        pytest.param(fixture("sudo_full_duplicate.txt"), "full", id="real-full"),
        pytest.param(rules_output("(ALL) ALL"), "full", id="all"),
        pytest.param(rules_output("(ALL : ALL) ALL"), "full", id="all-all"),
        pytest.param(rules_output("(root) ALL"), "full", id="root-all"),
        pytest.param(rules_output("(root) /usr/bin/apt update", "(ALL) ALL"), "full", id="full-wins"),
        pytest.param(fixture("sudo_limited_nopasswd_synthetic.txt"), "limited", id="specific-commands"),
        pytest.param(rules_output("(dockeruser) ALL"), "limited", id="all-as-another-user"),
        pytest.param(fixture("sudo_not_allowed.txt"), "none", id="real-not-allowed"),
    ],
)
def test_sudo_level(output: str, level: str) -> None:
    """Full: any command as root; limited: anything else; none: not allowed to run sudo."""
    assert parse_sudo_list(output)["level"] == level


@pytest.mark.parametrize(
    "output",
    [
        pytest.param("sudo: a password is required\n", id="not-root"),
        pytest.param("", id="empty"),
    ],
)
def test_sudo_unrecognized_output_is_unknown(output: str) -> None:
    """If sudo couldn't list the rules, the level is unknown, never none."""
    assert parse_sudo_list(output)["level"] == "unknown"


@pytest.mark.parametrize(
    ("output", "nopasswd"),
    [
        pytest.param(fixture("sudo_full_nopasswd_synthetic.txt"), True, id="full-nopasswd"),
        pytest.param(fixture("sudo_limited_nopasswd_synthetic.txt"), True, id="limited-nopasswd"),
        pytest.param(rules_output("(root) NOPASSWD: /usr/bin/apt update", "(ALL) ALL"), False, id="full-with-password"),
        pytest.param(fixture("sudo_full_duplicate.txt"), False, id="real-with-password"),
    ],
)
def test_sudo_nopasswd(output: str, *, nopasswd: bool) -> None:
    """NOPASSWD counts on the rules that define the level: a password-less apt rule doesn't make full sudo so."""
    assert parse_sudo_list(output)["nopasswd"] is nopasswd


@pytest.mark.parametrize(
    ("output", "rules"),
    [
        pytest.param(fixture("sudo_full_duplicate.txt"), ["(ALL : ALL) ALL"], id="duplicates-and-defaults-left-out"),
        pytest.param(
            fixture("sudo_limited_nopasswd_synthetic.txt"),
            ["(root) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/journalctl", "(www-data) /usr/bin/git pull"],
            id="in-order",
        ),
        pytest.param(
            rules_output("(root) /usr/bin/apt update") + "sudo: note\n    (ALL) ALL\n",
            ["(root) /usr/bin/apt update"],
            id="section-ends-at-unindented-line",
        ),
        pytest.param(fixture("sudo_not_allowed.txt"), [], id="not-allowed"),
    ],
)
def test_sudo_rules(output: str, rules: list[str]) -> None:
    """The rules below the header, once each, as sudo prints them; Defaults lines grant nothing and are no rules."""
    assert parse_sudo_list(output)["rules"] == rules


@pytest.mark.parametrize(
    ("rules", "targets"),
    [
        pytest.param(["(dockeruser) NOPASSWD: SETENV: /usr/bin/env docker ps"], ["dockeruser"], id="other-user"),
        pytest.param(["(root) /usr/bin/a", "(root) /usr/bin/b", "(www-data) /usr/bin/c"], ["root", "www-data"], id="dedup"),
        pytest.param(["(ALL : ALL) ALL"], ["ALL"], id="user-and-group"),
        pytest.param(["( : docker) /usr/bin/docker ps"], [":docker"], id="group-only"),
        pytest.param([], [], id="no-rules"),
    ],
)
def test_sudo_runas(rules: list[str], targets: list[str]) -> None:
    """As whom the rules let you run commands, in order."""
    assert sudo_runas(rules) == targets


# sshd -T


def test_sshd_config_key_files() -> None:
    """Real output of a Debian host: the Debian default."""
    assert parse_sshd_config(fixture("sshd_t.txt")) == ([".ssh/authorized_keys", ".ssh/authorized_keys2"], False)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        pytest.param("authorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys", True, id="set"),
        pytest.param("authorizedkeyscommand none", False, id="none"),
        pytest.param("AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys", True, id="mixed-case"),
    ],
)
def test_sshd_config_keys_command(line: str, *, expected: bool) -> None:
    """An AuthorizedKeysCommand means keys may come from elsewhere; sshd keywords are case-insensitive."""
    assert parse_sshd_config(f"{line}\n").keys_command is expected


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        pytest.param(".ssh/authorized_keys", "/home/alice/.ssh/authorized_keys", id="relative-to-home"),
        pytest.param("%h/.ssh/keys", "/home/alice/.ssh/keys", id="home-token"),
        pytest.param("/etc/ssh/keys/%u", "/etc/ssh/keys/alice", id="user-token"),
        pytest.param("/etc/ssh/keys/%U", "/etc/ssh/keys/1001", id="uid-token"),
        pytest.param("/etc/ssh/100%%/%u", "/etc/ssh/100%/alice", id="literal-percent"),
    ],
)
def test_expand_key_file(pattern: str, expected: str) -> None:
    """Tokens are expanded the way sshd does it."""
    assert expand_key_file(pattern, "alice", 1001, "/home/alice") == expected


# authorized_keys


def test_authorized_keys_file() -> None:
    """Real structure (anonymized) plus synthetic lines: comments, options, missing comment, broken key."""
    keys = parse_authorized_keys(fixture("authorized_keys.txt"))

    assert [(k["key_type"], k["comment"]) for k in keys] == [
        ("ssh-rsa", "Doe, Jane, jane@example.org"),
        ("ssh-ed25519", "alice@example.org"),
        ("ssh-ed25519", "bob-it.example"),
        ("ssh-ed25519", "backup@example.org"),
        ("ssh-ed25519", ""),
    ]


def test_key_options_are_recorded_without_the_command() -> None:
    """from= is kept; command= only as a flag, because the command may contain anything."""
    keys = parse_authorized_keys(fixture("authorized_keys.txt"))
    backup = next(k for k in keys if k["comment"] == "backup@example.org")

    assert backup["allowed_from"] == "10.0.0.0/8,192.0.2.1"
    assert backup["forced_command"] is True
    assert "borg" not in str(backup)


def test_every_key_has_a_fingerprint() -> None:
    """Keys without comment are identified by their fingerprint."""
    keys = parse_authorized_keys(fixture("authorized_keys.txt"))

    assert all(k["fingerprint"].startswith("SHA256:") for k in keys)


# Published by GitHub (api.github.com/meta, retrieved 2026-10-11, ECDSA 2026-10-17): its host keys (fixture) and their
# fingerprints
GITHUB_FINGERPRINTS = {
    "ssh-ed25519": "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
    "ecdsa-sha2-nistp256": "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
    "ssh-rsa": "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
}
GITHUB_KEYS = [pytest.param(line, GITHUB_FINGERPRINTS[line.split()[0]], id=line.split()[0]) for line in fixture("github_host_keys.txt").splitlines()]


@pytest.mark.parametrize(("line", "expected"), GITHUB_KEYS)
def test_fingerprint_matches_openssh(line: str, expected: str) -> None:
    """Same result as `ssh-keygen -lf`, checked against fingerprints GitHub publishes for its keys."""
    key = parse_key_line(line)

    assert key is not None
    assert key["fingerprint"] == expected


def test_fingerprint_of_raw_blob() -> None:
    """fingerprint() works on the decoded key blob."""
    blob = base64.b64decode("AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl")

    assert fingerprint(blob) == "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"


KEY_TYPES = [
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "ssh-dss-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
]


@pytest.mark.parametrize("key_type", KEY_TYPES)
def test_every_key_type_sshd_accepts_is_a_key(key_type: str) -> None:
    """Plain, ECDSA, FIDO (sk-) and certificate types; the blob only has to be valid base64 here."""
    key = parse_key_line(f"{key_type} AAAAC3NzaC1lZDI1NTE5 user@example.org")

    assert key is not None
    assert key["key_type"] == key_type


@pytest.mark.parametrize(
    "line",
    [
        pytest.param("", id="blank"),
        pytest.param("# ssh-ed25519 AAAA comment", id="comment-line"),
        pytest.param("ssh-ed25519", id="type-only"),
        pytest.param("ssh-unknown AAAAC3NzaC1lZDI1NTE5 x", id="unknown-type"),
        pytest.param("ecdsa-sha2-nistp512 AAAAC3NzaC1lZDI1NTE5 x", id="no-such-curve"),
        pytest.param("sk-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 x", id="fido-without-suffix"),
        pytest.param("ssh-ed25519 %%%% x", id="not-base64"),
        pytest.param('from="10.0.0.1" no-key-here', id="options-without-key"),
        pytest.param('from="10.0.0.1"', id="options-only"),
    ],
)
def test_lines_that_are_not_keys(line: str) -> None:
    """Anything that isn't a valid key line is ignored."""
    assert parse_key_line(line) is None


def test_quoted_option_with_spaces() -> None:
    """Options may contain quoted spaces before the key type."""
    blob = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
    key = parse_key_line(f'command="echo a b",from="192.0.2.0/24" ssh-ed25519 {blob} ci runner')

    assert key is not None
    assert (key["comment"], key["allowed_from"], key["forced_command"]) == ("ci runner", "192.0.2.0/24", True)


def test_escaped_quote_inside_an_option() -> None:
    """A backslash-escaped quote doesn't end the quoted option value (sshd's authorized_keys format)."""
    blob = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
    key = parse_key_line(f'command="echo \\"a b\\"" ssh-ed25519 {blob} backup')

    assert key is not None
    assert (key["key_type"], key["comment"], key["forced_command"]) == ("ssh-ed25519", "backup", True)


def test_escaped_quote_does_not_end_the_value_when_splitting_options() -> None:
    """A comma after an escaped quote is still inside the command; it doesn't start a new from= option."""
    blob = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
    key = parse_key_line(f'from="10.0.0.0/8",command="echo \\"x,from=evil\\"" ssh-ed25519 {blob} backup')

    assert key is not None
    assert key["allowed_from"] == "10.0.0.0/8"


def test_backslash_before_a_closing_quote_escapes_it() -> None:
    """A backslash before a quote escapes it even after another backslash (as in sshd): the value never ends, no key."""
    blob = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
    assert parse_key_line(f'command="C:\\\\",from="10.0.0.1" ssh-ed25519 {blob} backup') is None


# lslogins


@pytest.mark.parametrize("output", [pytest.param("", id="empty"), pytest.param("\n  \n", id="blank-lines")])
def test_lslogins_without_records(output: str) -> None:
    """No user lines: no login records, no error."""
    assert parse_lslogins(output) == {}


def test_lslogins_iso_dates_and_missing_records() -> None:
    """Real output format (anonymized): ISO date, or nothing if there is no record."""
    assert parse_lslogins(fixture("lslogins.txt")) == {"user": "2026-10-11T00:41:21+02:00", "newhire": ""}
