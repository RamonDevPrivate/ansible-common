# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Collect UFW, listening sockets and Docker daemons through a System interface.

Like collect.py, all host access goes through the system, so this logic can be tested with a fake system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, Protocol

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect import System, UnreadableFileError
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import is_number
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.docker import (
    parse_container,
    parse_container_ids,
    parse_version,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.network import (
    parse_ss,
    parse_ufw_rules,
    parse_ufw_status,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    Container,
    DaemonMode,
    DockerDaemon,
    Family,
    Listener,
    Ufw,
    UfwRule,
    ufw_without_details,
)

if TYPE_CHECKING:
    from collections.abc import Callable

UFW_RULE_FILES: Final[tuple[tuple[str, Family], ...]] = (
    ("/etc/ufw/user.rules", "ipv4"),
    ("/etc/ufw/user6.rules", "ipv6"),
)
ROOTFUL_SOCKET: Final = "/var/run/docker.sock"
RUNTIME_DIR: Final = "/run/user"  # rootless daemons: /run/user/<uid>/docker.sock
HTTP_NOT_FOUND: Final = 404


class DockerApiError(Exception):
    """A Docker Engine API request failed (connection, HTTP status or invalid JSON)."""

    def __init__(self, message: str, status: int = 0) -> None:
        """Remember the HTTP status (0 if the request didn't get a response)."""
        super().__init__(message)
        self.status: int = status


class HostSystem(System, Protocol):
    """System plus what network and Docker collection need."""

    def list_dir(self, path: str) -> list[str]:
        """Entry names of a directory; empty if it doesn't exist or can't be read."""
        raise NotImplementedError

    def is_socket(self, path: str, *, follow_symlinks: bool) -> bool:
        """Whether path is a unix socket; without follow_symlinks a symlink never is."""
        raise NotImplementedError

    def docker_api(self, socket_path: str, api_path: str, owner_uid: int, *, follow_symlinks: bool) -> object:
        """GET api_path from the daemon at socket_path, decoded JSON; raises DockerApiError.

        The socket and the process serving it must belong to owner_uid.
        """
        raise NotImplementedError


@dataclass
class NetworkResult:
    """What collect_network found, plus warnings for the Ansible output."""

    ufw: Ufw
    listeners: list[Listener] | None
    docker: list[DockerDaemon]
    warnings: list[str] = field(default_factory=list)


def collect_network(system: HostSystem) -> NetworkResult:
    """Collect UFW, listening sockets and Docker daemons with their containers."""
    warnings: list[str] = []
    return NetworkResult(
        ufw=_ufw(system, warnings),
        listeners=_listeners(system, warnings),
        docker=_docker(system, warnings),
        warnings=warnings,
    )


def _ufw(system: HostSystem, warnings: list[str]) -> Ufw:
    result = system.run(["ufw", "status", "verbose"])
    if result is None:
        return ufw_without_details("not installed")
    if result.rc != 0:
        warnings.append(f"ufw status failed: {(result.stderr or result.stdout).strip()}")
        return ufw_without_details("unknown")
    ufw = parse_ufw_status(result.stdout)
    rules: list[UfwRule] = []
    for path, family in UFW_RULE_FILES:
        try:
            content = system.read_file(path)
        except UnreadableFileError as error:
            warnings.append(f"{path} not readable ({error})")
            return ufw  # rules stay None: unknown
        rules.extend(parse_ufw_rules(content or "", family))
    ufw["rules"] = rules
    return ufw


def _listeners(system: HostSystem, warnings: list[str]) -> list[Listener] | None:
    result = system.run(["ss", "-H", "-t", "-u", "-l", "-n", "-p"])
    if result is None:
        return None
    if result.rc != 0:
        warnings.append(f"ss failed: {result.stderr.strip()}")
        return None
    return parse_ss(result.stdout)


def _docker(system: HostSystem, warnings: list[str]) -> list[DockerDaemon]:
    daemons: list[DockerDaemon] = []
    # /var/run is a symlink to /run, so the rootful path is followed; it must belong to root
    if system.is_socket(ROOTFUL_SOCKET, follow_symlinks=True):
        daemons.append(_daemon(system, _Socket("rootful", "", ROOTFUL_SOCKET, 0), warnings))
    owners = {account.uid: account.name for account in system.accounts()}
    uids = sorted(int(name) for name in system.list_dir(RUNTIME_DIR) if is_number(name))
    for uid in uids:
        # /run/user/<uid> belongs to the user: a symlink there could point root at any other socket
        path = f"{RUNTIME_DIR}/{uid}/docker.sock"
        if system.is_socket(path, follow_symlinks=False):
            daemons.append(_daemon(system, _Socket("rootless", owners.get(uid, str(uid)), path, uid), warnings))
        elif system.is_socket(path, follow_symlinks=True):
            warnings.append(f"{path} is a symlink, not queried (a rootless daemon's socket must be the file itself)")
    return daemons


@dataclass(frozen=True)
class _Socket:
    """Where a daemon listens and who must own it."""

    mode: DaemonMode
    owner: str
    path: str
    uid: int

    def get(self, system: HostSystem, api_path: str) -> object:
        """GET from this daemon; the rootful path may be a symlink (/var/run), a rootless one never."""
        return system.docker_api(self.path, api_path, self.uid, follow_symlinks=self.mode == "rootful")


def _daemon(system: HostSystem, sock: _Socket, warnings: list[str]) -> DockerDaemon:
    daemon: DockerDaemon = {
        "mode": sock.mode,
        "owner": sock.owner,
        "socket": sock.path,
        "state": "running",
        "version": "",
        "containers": [],
    }
    if sock.mode == "rootful" and not _rootful_service_active(system):
        # docker.socket would start the daemon on the first request; a read-only inventory must not do that
        daemon["state"] = "not running"
        return daemon
    try:
        daemon["version"] = parse_version(sock.get(system, "/version"))
        ids = parse_container_ids(sock.get(system, "/containers/json?all=1"))
    except DockerApiError as error:
        warnings.append(f"Docker daemon at {sock.path} not reachable ({error})")
        daemon["state"] = "unreachable"
        return daemon
    daemon["containers"] = _containers(ids, lambda path: sock.get(system, path), sock.path, warnings)
    return daemon


def _rootful_service_active(system: HostSystem) -> bool:
    result = system.run(["systemctl", "is-active", "docker.service"])
    if result is None:
        return True  # no systemd: the socket belongs to a running daemon
    return result.stdout.strip() == "active"


def _containers(ids: list[str], get: Callable[[str], object], socket: str, warnings: list[str]) -> list[Container]:
    containers: list[Container] = []
    for container_id in ids:
        try:
            container = parse_container(get(f"/containers/{container_id}/json"))
        except DockerApiError as error:
            if error.status != HTTP_NOT_FOUND:  # 404: removed since the list was fetched
                warnings.append(f"Docker daemon at {socket}: container {container_id[:12]} not readable ({error})")
            continue
        if container is not None:
            containers.append(container)
    return sorted(containers, key=lambda c: c["name"])
