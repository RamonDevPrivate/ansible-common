# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for collecting UFW, listeners and Docker daemons through the System interface (with a fake system)."""

from __future__ import annotations

from dataclasses import dataclass, field

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect import (
    Account,
    CommandResult,
    UnreadableFileError,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect_network import (
    DockerApiError,
    collect_network,
)

UFW_STATUS = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
RULE_V4 = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n"
RULE_V6 = "### tuple ### allow tcp 22 ::/0 any ::/0 in\n"
SS = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
ROOTFUL = "/var/run/docker.sock"
ROOTLESS = "/run/user/1005/docker.sock"
UFW = "ufw status verbose"
SS_LIST = "ss -H -t -u -l -n -p"
DOCKER_ACTIVE = "systemctl is-active docker.service"


def inspect(name: str, state: str = "running") -> dict[str, object]:
    """Minimal GET /containers/<id>/json answer."""
    return {"Name": f"/{name}", "State": {"Status": state}, "Config": {"Image": f"{name}:1", "Env": ["X=secret"]}}


@dataclass
class FakeHostSystem:
    """In-memory host: canned commands, files, sockets and Docker API answers per socket."""

    commands: dict[str, CommandResult] = field(default_factory=dict)  # by full command line
    missing_programs: set[str] = field(default_factory=set)
    files: dict[str, str] = field(default_factory=dict)
    unreadable: set[str] = field(default_factory=set)
    sockets: set[str] = field(default_factory=set)
    symlinked_sockets: set[str] = field(default_factory=set)  # paths that are symlinks to a socket
    run_user: list[str] = field(default_factory=list)
    api: dict[str, dict[str, object]] = field(default_factory=dict)
    api_errors: dict[str, DockerApiError] = field(default_factory=dict)  # by socket (all requests) or API path
    api_calls: list[tuple[str, str]] = field(default_factory=list)
    api_owners: dict[str, tuple[int, bool]] = field(default_factory=dict)  # socket → (owner_uid, follow_symlinks)

    def is_root(self) -> bool:
        """The collector runs as root."""
        return True

    def read_user_file(self, path: str, account: Account) -> str | None:
        """Not used by the network collector."""
        del account
        return self.read_file(path)

    def accounts(self) -> list[Account]:
        """Root and the rootless Docker user."""
        return [Account("root", 0, 0, "/root", "/bin/bash"), Account("dockeruser", 1005, 1005, "/home/d", "/bin/sh")]

    def group_names(self, account: Account) -> list[str]:
        """Not used by the network collector."""
        return [account.name]

    def primary_group(self, account: Account) -> str:
        """Not used by the network collector."""
        return account.name

    def read_file(self, path: str) -> str | None:
        """Configured content, None if missing."""
        if path in self.unreadable:
            message = "permission denied"
            raise UnreadableFileError(message)
        return self.files.get(path)

    def run(self, args: list[str]) -> CommandResult | None:
        """Canned result by full command line; a command without one fails."""
        if args[0] in self.missing_programs:
            return None
        command = " ".join(args)
        return self.commands.get(command, CommandResult(1, "", f"{command} failed"))

    def list_dir(self, path: str) -> list[str]:
        """Entries of /run/user."""
        return self.run_user if path == "/run/user" else []

    def is_socket(self, path: str, *, follow_symlinks: bool) -> bool:
        """Configured sockets; a symlink to a socket only counts when symlinks are followed."""
        return path in self.sockets or (follow_symlinks and path in self.symlinked_sockets)

    def docker_api(self, socket_path: str, api_path: str, owner_uid: int, *, follow_symlinks: bool) -> object:
        """Canned answer per socket and path; errors by socket or path; 404 for unknown paths."""
        self.api_calls.append((socket_path, api_path))
        self.api_owners[socket_path] = (owner_uid, follow_symlinks)
        error = self.api_errors.get(socket_path) or self.api_errors.get(api_path)
        if error is not None:
            raise error
        answers = self.api.get(socket_path, {})
        if api_path not in answers:
            message = "HTTP 404"
            raise DockerApiError(message, 404)
        return answers[api_path]


def host() -> FakeHostSystem:
    """A host with UFW, ss, a rootful daemon (service active) and a rootless daemon."""
    return FakeHostSystem(
        commands={
            UFW: CommandResult(0, UFW_STATUS),
            SS_LIST: CommandResult(0, SS),
            DOCKER_ACTIVE: CommandResult(0, "active\n"),
        },
        files={"/etc/ufw/user.rules": RULE_V4, "/etc/ufw/user6.rules": RULE_V6},
        sockets={ROOTFUL, ROOTLESS},
        run_user=["0", "1005", "lock"],
        api={
            ROOTFUL: {
                "/version": {"Version": "29.3.0"},
                "/containers/json?all=1": [{"Id": "b"}, {"Id": "a"}],
                "/containers/a/json": inspect("web"),
                "/containers/b/json": inspect("db", "exited"),
            },
            ROOTLESS: {
                "/version": {"Version": "29.7.1"},
                "/containers/json?all=1": [{"Id": "c"}],
                "/containers/c/json": inspect("proxy"),
            },
        },
    )


# UFW


def test_ufw_status_and_rules_of_both_families() -> None:
    """Policies from `ufw status verbose`, rules from user.rules and user6.rules."""
    ufw = collect_network(host()).ufw

    assert ufw["state"] == "active"
    assert ufw["default_incoming"] == "deny"
    assert [(r["to_port"], r["family"]) for r in ufw["rules"] or []] == [("22", "ipv4"), ("22", "ipv6")]


def test_ufw_not_installed() -> None:
    """No ufw binary is a valid state, not a failure."""
    system = host()
    system.missing_programs.add("ufw")

    result = collect_network(system)

    assert result.ufw["state"] == "not installed"
    assert result.warnings == []


def test_ufw_status_fails() -> None:
    """Without root, ufw refuses to run: state unknown, with a warning."""
    system = host()
    system.commands[UFW] = CommandResult(1, "", "ERROR: You need to be root to run this script")

    result = collect_network(system)

    assert result.ufw["state"] == "unknown"
    assert any("ufw status failed" in w for w in result.warnings)


def test_unreadable_rule_file_means_rules_unknown() -> None:
    """The rules are unknown rather than incomplete."""
    system = host()
    system.unreadable.add("/etc/ufw/user6.rules")

    result = collect_network(system)

    assert result.ufw["state"] == "active"
    assert result.ufw["rules"] is None
    assert any("user6.rules" in w for w in result.warnings)


def test_missing_rule_files_mean_no_rules() -> None:
    """A fresh ufw without added rules."""
    system = host()
    system.files.clear()

    assert collect_network(system).ufw["rules"] == []


# Listeners


def test_listeners_from_ss() -> None:
    """Listening sockets with their process names."""
    listeners = collect_network(host()).listeners

    assert listeners is not None
    assert [(item["port"], item["processes"]) for item in listeners] == [(22, ["sshd"])]


def test_listeners_unknown_without_ss() -> None:
    """None, not empty: no ss means unknown, not "nothing listens"."""
    system = host()
    system.missing_programs.add("ss")

    assert collect_network(system).listeners is None


def test_failing_ss_means_listeners_unknown() -> None:
    """A failing ss is reported, and its listeners are unknown rather than none."""
    system = host()
    system.commands[SS_LIST] = CommandResult(1, "", "Cannot open netlink socket")

    result = collect_network(system)

    assert result.listeners is None
    assert any("ss failed: Cannot open netlink socket" in w for w in result.warnings)


# Docker


def test_rootful_and_rootless_daemons() -> None:
    """The rootful socket first, then rootless sockets by uid; the owner is the account name."""
    daemons = collect_network(host()).docker

    assert [(d["mode"], d["owner"], d["version"], d["state"]) for d in daemons] == [
        ("rootful", "", "29.3.0", "running"),
        ("rootless", "dockeruser", "29.7.1", "running"),
    ]


def test_containers_include_stopped_ones_sorted_by_name() -> None:
    """All containers are collected (the role decides what to show), sorted by name."""
    rootful = collect_network(host()).docker[0]

    assert [(c["name"], c["state"]) for c in rootful["containers"]] == [("db", "exited"), ("web", "running")]


def test_containers_are_reduced_on_the_host() -> None:
    """The inspect answer goes through the allowlist: the environment (with its secret) is not collected."""
    assert "secret" not in str(collect_network(host()).docker)


def test_runtime_dirs_without_socket_are_ignored() -> None:
    """Only /run/user/<uid>/docker.sock counts, and only for numeric entries."""
    system = host()
    system.sockets = {ROOTLESS}

    daemons = collect_network(system).docker

    assert [(d["mode"], d["socket"]) for d in daemons] == [("rootless", ROOTLESS)]


def test_sockets_must_belong_to_their_daemon_owner() -> None:
    """Rootful: root, path may be a symlink (/var/run); rootless: the uid of its runtime dir, never through a link."""
    system = host()

    _result = collect_network(system)

    assert system.api_owners == {ROOTFUL: (0, True), ROOTLESS: (1005, False)}


def test_symlinked_rootless_socket_is_ignored() -> None:
    """A user could point /run/user/<uid>/docker.sock at another (root) service's socket."""
    system = host()
    system.sockets = {ROOTFUL}
    system.symlinked_sockets = {ROOTLESS}

    result = collect_network(system)

    assert [d["mode"] for d in result.docker] == ["rootful"]
    assert all(socket != ROOTLESS for socket, _path in system.api_calls)
    assert any(ROOTLESS in warning and "symlink" in warning for warning in result.warnings)


def test_rootless_owner_without_account() -> None:
    """A uid without passwd entry is shown as the number."""
    system = host()
    system.run_user = ["2000"]
    system.sockets = {"/run/user/2000/docker.sock"}

    assert [d["owner"] for d in collect_network(system).docker] == ["2000"]


def test_inactive_rootful_service_is_not_queried() -> None:
    """With docker.socket activation, a request would start the daemon; the inventory must not do that."""
    system = host()
    system.commands[DOCKER_ACTIVE] = CommandResult(3, "inactive\n")

    rootful = collect_network(system).docker[0]

    assert rootful["state"] == "not running"
    assert all(socket != ROOTFUL for socket, _path in system.api_calls)


def test_rootful_without_systemd_is_queried() -> None:
    """Without systemctl the socket belongs to a running daemon."""
    system = host()
    system.missing_programs.add("systemctl")

    assert collect_network(system).docker[0]["state"] == "running"


def test_unreachable_daemon() -> None:
    """A stale socket (daemon stopped) is reported with a warning, the other daemon still counts."""
    system = host()
    system.api_errors[ROOTLESS] = DockerApiError("[Errno 111] Connection refused")

    result = collect_network(system)

    assert [d["state"] for d in result.docker] == ["running", "unreachable"]
    assert any(ROOTLESS in w and "Connection refused" in w for w in result.warnings)


def test_container_removed_between_list_and_inspect() -> None:
    """404 on inspect: the container is gone, no warning."""
    system = host()
    del system.api[ROOTFUL]["/containers/b/json"]

    result = collect_network(system)

    assert [c["name"] for c in result.docker[0]["containers"]] == ["web"]
    assert result.warnings == []


def test_inspect_answer_without_name_is_dropped() -> None:
    """A container the daemon can't name is left out; the others still count."""
    system = host()
    system.api[ROOTFUL]["/containers/b/json"] = {"State": {"Status": "running"}}

    rootful = collect_network(system).docker[0]

    assert [c["name"] for c in rootful["containers"]] == ["web"]


def test_failing_inspect_warns() -> None:
    """Other inspect errors are reported, the remaining containers still count."""
    system = host()
    system.api_errors["/containers/b/json"] = DockerApiError("HTTP 500", 500)

    result = collect_network(system)

    assert [c["name"] for c in result.docker[0]["containers"]] == ["web"]
    assert any("container b" in w for w in result.warnings)


def test_no_docker() -> None:
    """No sockets: no daemons, no warnings."""
    system = host()
    system.sockets = set()

    result = collect_network(system)

    assert result.docker == []
    assert result.warnings == []
