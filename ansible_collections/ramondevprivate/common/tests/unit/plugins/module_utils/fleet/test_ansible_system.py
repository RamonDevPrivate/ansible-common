# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the System adapter used on real hosts (files in tmp_path, a fake module for commands)."""

from __future__ import annotations

import contextlib
import errno
import grp
import os
import pwd
import signal
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, final

import pytest

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet import ansible_system
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.ansible_system import AnsibleSystem
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect import Account, UnreadableFileError
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect_network import DockerApiError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


@dataclass
class FakeModule:
    """Records commands; programs in `installed` exist under /usr/sbin."""

    installed: set[str] = field(default_factory=set)
    calls: list[tuple[list[str], dict[str, str] | None]] = field(default_factory=list)
    options: list[dict[str, bool]] = field(default_factory=list)  # expand_user_and_vars, handle_exceptions per call
    exec_error: OSError | None = None  # raised by run_command, like a binary that can't be executed

    def get_bin_path(self, arg: str, *, opt_dirs: list[str] | None = None) -> str | None:
        """Path of an installed program."""
        del opt_dirs
        return f"/usr/sbin/{arg}" if arg in self.installed else None

    def run_command(
        self,
        args: list[str],
        *,
        environ_update: dict[str, str] | None = None,
        expand_user_and_vars: bool = True,
        handle_exceptions: bool = True,
    ) -> tuple[int, str, str]:
        """Record the call, succeed with no output (or raise the configured exec error)."""
        self.calls.append((args, environ_update))
        self.options.append({"expand_user_and_vars": expand_user_and_vars, "handle_exceptions": handle_exceptions})
        if self.exec_error is not None:
            raise self.exec_error
        return 0, "", ""


def write(path: Path, text: str) -> None:
    """Create a test file."""
    _size = path.write_text(text)


def fixed_locale(_module: object) -> str:
    """Stand-in for Ansible's locale detection (avoids running `locale -a`)."""
    return "C.UTF-8"


@pytest.fixture
def module() -> FakeModule:
    """A host with sshd installed."""
    return FakeModule(installed={"sshd"})


@pytest.fixture
def system(module: FakeModule, monkeypatch: pytest.MonkeyPatch) -> AnsibleSystem:
    """System on the fake module with a fixed parsable locale."""
    monkeypatch.setattr(ansible_system, "get_best_parsable_locale", fixed_locale)
    return AnsibleSystem(module)


# Files


def test_reads_regular_file(system: AnsibleSystem, tmp_path: Path) -> None:
    """A normal key file is read."""
    path = tmp_path / "authorized_keys"
    write(path, "ssh-ed25519 AAAA x\n")

    assert system.read_file(str(path)) == "ssh-ed25519 AAAA x\n"


def test_missing_file_is_none(system: AnsibleSystem, tmp_path: Path) -> None:
    """Most users have no authorized_keys2: not an error."""
    assert system.read_file(str(tmp_path / "missing")) is None


def test_symlink_is_followed(system: AnsibleSystem, tmp_path: Path) -> None:
    """Like sshd: a key file managed via symlink (e.g. dotfiles) is read."""
    target = tmp_path / "dotfiles_authorized_keys"
    write(target, "ssh-ed25519 AAAA alice@example.org\n")
    link = tmp_path / "authorized_keys"
    link.symlink_to(target)

    assert system.read_file(str(link)) == "ssh-ed25519 AAAA alice@example.org\n"


def test_dangling_symlink_is_missing(system: AnsibleSystem, tmp_path: Path) -> None:
    """A link to nothing is the same as no key file."""
    (tmp_path / "authorized_keys").symlink_to(tmp_path / "gone")

    assert system.read_file(str(tmp_path / "authorized_keys")) is None


def test_symlink_loop_is_unreadable(system: AnsibleSystem, tmp_path: Path) -> None:
    """A link loop is reported, not followed forever."""
    (tmp_path / "authorized_keys").symlink_to(tmp_path / "authorized_keys")

    with pytest.raises(UnreadableFileError, match="loop"):
        _content = system.read_file(str(tmp_path / "authorized_keys"))


def test_symlink_to_fifo_does_not_hang(system: AnsibleSystem, tmp_path: Path) -> None:
    """A link to a named pipe is refused instead of blocking the module."""
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    (tmp_path / "authorized_keys").symlink_to(fifo)

    with pytest.raises(UnreadableFileError, match="regular file"):
        _content = system.read_file(str(tmp_path / "authorized_keys"))


def test_directory_is_not_read(system: AnsibleSystem, tmp_path: Path) -> None:
    """Only regular files are key files."""
    with pytest.raises(UnreadableFileError, match="regular file"):
        _content = system.read_file(str(tmp_path))


def test_large_file_is_not_read(system: AnsibleSystem, tmp_path: Path) -> None:
    """Oversized files are refused instead of being read into memory."""
    path = tmp_path / "authorized_keys"
    write(path, "x" * (ansible_system.MAX_FILE_SIZE + 1))

    with pytest.raises(UnreadableFileError, match="larger"):
        _content = system.read_file(str(path))


# Commands


def test_missing_program_is_none(system: AnsibleSystem) -> None:
    """A program that isn't installed gives None, not an error."""
    assert system.run(["lslogins", "-l", "x"]) is None


def test_commands_run_with_resolved_path_and_parsable_locale(system: AnsibleSystem, module: FakeModule) -> None:
    """German (or any) server locale must not reach the parsers."""
    _result = system.run(["sshd", "-T"])

    args, environment = module.calls[0]
    assert args == ["/usr/sbin/sshd", "-T"]
    assert environment == {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "LC_MESSAGES": "C.UTF-8", "LANGUAGE": "C.UTF-8"}


def test_arguments_are_passed_without_expansion(system: AnsibleSystem, module: FakeModule) -> None:
    """`${db:Status-Status}` is a dpkg format and `~` a literal; exec errors come back instead of failing the module."""
    _result = system.run(["sshd", "-f=${HOME}", "~"])

    assert module.calls[0][0] == ["/usr/sbin/sshd", "-f=${HOME}", "~"]
    assert module.options == [{"expand_user_and_vars": False, "handle_exceptions": False}]


def test_program_that_cannot_be_executed_is_a_failed_command(system: AnsibleSystem, module: FakeModule) -> None:
    """E.g. a binary without execute permission: rc 126 with the reason, not a failed module (thus a failed host)."""
    module.exec_error = PermissionError(errno.EACCES, "Permission denied")

    result = system.run(["sshd", "-T"])

    assert result is not None
    assert (result.rc, result.stderr) == (126, "sshd could not be run: Permission denied")


def test_locale_is_determined_once(module: FakeModule, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ansible's locale detection runs `locale -a`; once per module run is enough."""
    lookups: list[object] = []

    def counting_locale(module: object) -> str:
        lookups.append(module)
        return "C.UTF-8"

    monkeypatch.setattr(ansible_system, "get_best_parsable_locale", counting_locale)
    system = AnsibleSystem(module)

    _first = system.run(["sshd", "-T"])
    _second = system.run(["sshd", "-T"])

    assert len(lookups) == 1


# Accounts and groups (passwd and group database replaced)

GROUPS = {1000: "alice", 27: "sudo"}


def getgrgid(gid: int) -> grp.struct_group:
    """Group database with alice's primary group and sudo; other gids have no entry."""
    if gid not in GROUPS:
        raise KeyError(gid)
    return grp.struct_group((GROUPS[gid], "x", gid, []))


def grouplist_with_unnamed_gid(_name: str, gid: int) -> list[int]:
    """The primary group, sudo and a gid that has no group entry."""
    return [gid, 27, 4711]


def test_accounts_from_the_passwd_database(system: AnsibleSystem, monkeypatch: pytest.MonkeyPatch) -> None:
    """Name, ids, home and shell of every passwd entry."""
    entry = pwd.struct_passwd(("alice", "x", 1000, 1000, "Alice", "/home/alice", "/bin/bash"))
    monkeypatch.setattr(pwd, "getpwall", lambda: [entry])

    assert system.accounts() == [Account("alice", 1000, 1000, "/home/alice", "/bin/bash")]


def test_group_names_keep_gids_without_a_name(system: AnsibleSystem, monkeypatch: pytest.MonkeyPatch) -> None:
    """All groups by name, like `id -nG`; a gid without group entry stays visible as its number."""
    monkeypatch.setattr(os, "getgrouplist", grouplist_with_unnamed_gid)
    monkeypatch.setattr(grp, "getgrgid", getgrgid)

    assert system.group_names(Account("alice", 1000, 1000, "/home/alice", "/bin/bash")) == ["alice", "sudo", "4711"]


@pytest.mark.parametrize(
    ("gid", "expected"),
    [
        pytest.param(1000, "alice", id="named"),
        pytest.param(4711, "4711", id="without-group-entry"),
    ],
)
def test_primary_group(system: AnsibleSystem, monkeypatch: pytest.MonkeyPatch, gid: int, expected: str) -> None:
    """The primary group's name, or its number if the group database has no entry."""
    monkeypatch.setattr(grp, "getgrgid", getgrgid)

    assert system.primary_group(Account("alice", 1000, gid, "/home/alice", "/bin/bash")) == expected


# Directories, sockets and modification times


def test_file_mtime(system: AnsibleSystem, tmp_path: Path) -> None:
    """The stamp's modification time, as set by `touch`."""
    path = tmp_path / "upgrade-stamp"
    write(path, "")
    os.utime(path, (1_000_000_000, 1_791_693_515))

    assert system.file_mtime(str(path)) == 1_791_693_515


def test_file_mtime_missing(system: AnsibleSystem, tmp_path: Path) -> None:
    """No stamp: None."""
    assert system.file_mtime(str(tmp_path / "missing")) is None


def test_list_dir_sorted(system: AnsibleSystem, tmp_path: Path) -> None:
    """Entry names, sorted."""
    (tmp_path / "1005").mkdir()
    (tmp_path / "0").mkdir()

    assert system.list_dir(str(tmp_path)) == ["0", "1005"]


def test_list_missing_dir_is_empty(system: AnsibleSystem, tmp_path: Path) -> None:
    """No /run/user (e.g. in a container) means no rootless daemons."""
    assert system.list_dir(str(tmp_path / "missing")) == []


@pytest.mark.parametrize(
    ("name", "follow", "expected"),
    [
        pytest.param("docker.sock", False, True, id="socket"),
        pytest.param("link.sock", True, True, id="link-followed"),
        pytest.param("link.sock", False, False, id="link-not-followed"),
        pytest.param("file", True, False, id="file"),
        pytest.param("missing", True, False, id="missing"),
    ],
)
def test_is_socket(system: AnsibleSystem, tmp_path_factory: pytest.TempPathFactory, name: str, *, follow: bool, expected: bool) -> None:
    """A socket, behind a symlink only when symlinks are followed (rootless dirs are never followed)."""
    base = tmp_path_factory.mktemp("s")  # short path: unix socket paths are limited to 107 bytes
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(base / "docker.sock"))
    (base / "link.sock").symlink_to(base / "docker.sock")
    write(base / "file", "")
    try:
        assert system.is_socket(str(base / name), follow_symlinks=follow) is expected
    finally:
        server.close()


# Docker Engine API


DOCKER_ANSWERS: dict[str, tuple[int, bytes]] = {
    "/version": (200, b'{"Version": "29.7.1"}'),
    "/containers/json?all=1": (200, b'[{"Id": "abc"}]'),
    "/broken": (200, b"not json"),
    "/deep": (200, b"[" * 200_000),  # nested far beyond Python's recursion limit, well within the size cap
}
NOT_FOUND = (404, b'{"message": "page not found"}')
ME = os.getuid()  # the fake daemon runs as the test user, so it owns its socket and serves it


@dataclass
class FakeDocker:
    """A fake dockerd on a unix socket: one GET per connection, answered from DOCKER_ANSWERS.

    Plain sockets instead of http.server: its handler classes need method overrides, and typing.override doesn't
    exist on Python 3.11, where module_utils tests also run.
    """

    path: str
    requests: list[str] = field(default_factory=list)
    stop: threading.Event = field(default_factory=threading.Event)

    def serve(self, server: socket.socket) -> None:
        """Answer connections until stopped."""
        server.settimeout(0.01)
        while not self.stop.is_set():
            try:
                connection = server.accept()[0]
            except TimeoutError:
                continue
            with connection:
                self._answer(connection)

    def _answer(self, connection: socket.socket) -> None:
        request = b""
        while b"\r\n\r\n" not in request and (chunk := connection.recv(4096)):
            request += chunk
        path = request.split(b" ")[1].decode() if request.count(b" ") >= 2 else ""
        self.requests.append(path)
        status, body = DOCKER_ANSWERS.get(path, NOT_FOUND)
        head = (
            f"HTTP/1.1 {status} {'OK' if status == 200 else 'Not Found'}",
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
            "Connection: close",
            "",
            "",
        )
        # the client may hang up before asking (e.g. it refused the peer)
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            connection.sendall("\r\n".join(head).encode() + body)


def serve_fake_docker(tmp_path_factory: pytest.TempPathFactory) -> Iterator[FakeDocker]:
    """A fake Docker daemon, served in a background thread until the generator is closed."""
    fake = FakeDocker(str(tmp_path_factory.mktemp("d") / "docker.sock"))
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(fake.path)
    server.listen()
    thread = threading.Thread(target=fake.serve, args=(server,), daemon=True)
    thread.start()
    yield fake
    fake.stop.set()
    thread.join()
    server.close()


@pytest.fixture
def docker(tmp_path_factory: pytest.TempPathFactory) -> Iterator[FakeDocker]:
    """A fake Docker daemon."""
    yield from serve_fake_docker(tmp_path_factory)


def test_docker_api_returns_decoded_json(system: AnsibleSystem, docker: FakeDocker) -> None:
    """GET over the unix socket, JSON decoded."""
    assert system.docker_api(docker.path, "/version", ME, follow_symlinks=False) == {"Version": "29.7.1"}


def test_docker_api_passes_query(system: AnsibleSystem, docker: FakeDocker) -> None:
    """The query string reaches the daemon unchanged (all=1 includes stopped containers)."""
    assert system.docker_api(docker.path, "/containers/json?all=1", ME, follow_symlinks=False) == [{"Id": "abc"}]
    assert docker.requests == ["/containers/json?all=1"]


def test_docker_api_http_error_keeps_status(system: AnsibleSystem, docker: FakeDocker) -> None:
    """The collector tells "container gone" (404) from other errors."""
    with pytest.raises(DockerApiError) as error:
        _answer = system.docker_api(docker.path, "/containers/gone/json", ME, follow_symlinks=False)

    assert error.value.status == 404


def test_docker_api_invalid_json(system: AnsibleSystem, docker: FakeDocker) -> None:
    """A non-JSON answer is an error, not a crash."""
    with pytest.raises(DockerApiError, match="invalid JSON"):
        _answer = system.docker_api(docker.path, "/broken", ME, follow_symlinks=False)


def test_docker_api_oversized_answer(system: AnsibleSystem, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch) -> None:
    """Answers are size-limited instead of read into memory without bound."""
    monkeypatch.setattr(ansible_system, "MAX_API_RESPONSE", 5)

    with pytest.raises(DockerApiError, match="larger"):
        _answer = system.docker_api(docker.path, "/version", ME, follow_symlinks=False)


def test_docker_api_without_daemon(system: AnsibleSystem, tmp_path_factory: pytest.TempPathFactory) -> None:
    """A missing socket is an error the collector reports, not a crash."""
    path = str(tmp_path_factory.mktemp("n") / "docker.sock")

    with pytest.raises(DockerApiError, match="No such file"):
        _answer = system.docker_api(path, "/version", ME, follow_symlinks=False)


def test_docker_api_stale_socket(system: AnsibleSystem, tmp_path_factory: pytest.TempPathFactory) -> None:
    """A socket file left behind by a stopped daemon: nobody listens, the connect is refused."""
    path = str(tmp_path_factory.mktemp("s") / "docker.sock")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
        stale.bind(path)  # bound, never listening: what a crashed daemon leaves

    with pytest.raises(DockerApiError, match="Connection refused"):
        _answer = system.docker_api(path, "/version", ME, follow_symlinks=False)


def test_docker_api_hung_daemon_times_out(system: AnsibleSystem, tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """A stuck dockerd takes the connection and never answers: the request ends after the timeout."""
    monkeypatch.setattr(ansible_system, "DOCKER_TIMEOUT", 0.2)
    path = str(tmp_path_factory.mktemp("h") / "docker.sock")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as hung:
        hung.bind(path)
        hung.listen()  # the kernel completes the connect; nobody ever reads or answers
        started = time.monotonic()

        with pytest.raises(DockerApiError, match="timed out"):
            _answer = system.docker_api(path, "/version", ME, follow_symlinks=False)

    assert time.monotonic() - started < 5


def test_docker_api_socket_of_another_owner(system: AnsibleSystem, docker: FakeDocker) -> None:
    """A socket that doesn't belong to the daemon's owner is refused before connecting."""
    with pytest.raises(DockerApiError, match="belongs to uid"):
        _answer = system.docker_api(docker.path, "/version", ME + 1, follow_symlinks=False)

    assert docker.requests == []


def test_docker_api_symlink_not_followed(system: AnsibleSystem, docker: FakeDocker) -> None:
    """Without follow_symlinks a link to a socket is refused, whatever it points at."""
    link = Path(docker.path).with_name("link.sock")
    link.symlink_to(docker.path)

    with pytest.raises(DockerApiError, match="not a socket"):
        _answer = system.docker_api(str(link), "/version", ME, follow_symlinks=False)

    assert docker.requests == []


def test_docker_api_symlink_followed_for_rootful(system: AnsibleSystem, docker: FakeDocker) -> None:
    """The rootful path /var/run/docker.sock goes through the /var/run → /run link."""
    link = Path(docker.path).with_name("link.sock")
    link.symlink_to(docker.path)

    assert system.docker_api(str(link), "/version", ME, follow_symlinks=True) == {"Version": "29.7.1"}


@final
class OtherPeer:
    """struct ucred as if another uid served the socket."""

    size = ansible_system.PEERCRED.size

    @staticmethod
    def unpack(_data: bytes) -> tuple[int, int, int]:
        """pid, uid, gid of the listener."""
        return (ME, ME + 1, ME)  # pid and gid equal the expected uid: only the uid field may be read


def test_docker_api_served_by_another_uid(system: AnsibleSystem, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch) -> None:
    """The socket file is the owner's, but someone else listens on it (SO_PEERCRED): refused."""
    monkeypatch.setattr(ansible_system, "PEERCRED", OtherPeer)

    with pytest.raises(DockerApiError, match="served by uid"):
        _answer = system.docker_api(docker.path, "/version", ME, follow_symlinks=False)


# Reading as the user


@dataclass
class DropRecorder:
    """Stand-in for dropping privileges in the forked child; writes the call to a file the parent can read."""

    log: Path
    fail: bool = False
    rewrite: Path | None = None  # overwritten during the drop: shows whether the file is opened after it

    def __call__(self, uid: int, gid: int, groups: list[int]) -> None:
        """Record the ids (in the child), optionally fail like a refused setresuid."""
        _size = self.log.write_text(f"{uid} {gid} {sorted(groups)}")
        if self.rewrite is not None:
            _size = self.rewrite.write_text("after-drop\n")
        if self.fail:
            message = "Operation not permitted"
            raise PermissionError(message)


def account(uid: int = 4242) -> Account:
    """Account of another user (not the test user, not root)."""
    return Account("alice", uid, uid, "/home/alice", "/bin/bash")


def grouplist(_name: str, gid: int) -> list[int]:
    """The account's groups: its primary group plus 27 (sudo on Debian)."""
    return [gid, 27]


def make_dir(path: Path) -> None:
    """A directory where a key file is expected."""
    path.mkdir()


def make_loop(path: Path) -> None:
    """A symlink pointing at itself."""
    path.symlink_to(path)


@pytest.fixture
def as_root(module: FakeModule, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[AnsibleSystem, DropRecorder]:
    """A system that believes it runs as root, with privilege dropping recorded instead of done."""
    monkeypatch.setattr(ansible_system, "get_best_parsable_locale", fixed_locale)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getgrouplist", grouplist)
    drop = DropRecorder(tmp_path / "drop.log")
    return AnsibleSystem(module, drop), drop


def test_user_file_read_after_dropping_to_the_account(as_root: tuple[AnsibleSystem, DropRecorder], tmp_path: Path) -> None:
    """As root, a child drops to the account's uid, gid and groups and then reads the file."""
    system, drop = as_root
    path = tmp_path / "authorized_keys"
    write(path, "ssh-ed25519 AAAA x\n")

    content = system.read_user_file(str(path), account())

    assert content == "ssh-ed25519 AAAA x\n"
    assert drop.log.read_text() == "4242 4242 [27, 4242]"


@pytest.mark.parametrize(
    ("make", "error"),
    [
        pytest.param(make_dir, "regular file", id="directory"),
        pytest.param(make_loop, "symlink loop", id="loop"),
    ],
)
def test_user_file_errors_reach_the_parent(as_root: tuple[AnsibleSystem, DropRecorder], tmp_path: Path, make: Callable[[Path], None], error: str) -> None:
    """The child's reason why a file can't be read comes back as UnreadableFileError."""
    system, _drop = as_root
    path = tmp_path / "authorized_keys"
    make(path)

    with pytest.raises(UnreadableFileError, match=error):
        _content = system.read_user_file(str(path), account())


def test_missing_user_file(as_root: tuple[AnsibleSystem, DropRecorder], tmp_path: Path) -> None:
    """No file: None, as for root reads."""
    system, _drop = as_root

    assert system.read_user_file(str(tmp_path / "missing"), account()) is None


def test_failed_drop_never_reads(as_root: tuple[AnsibleSystem, DropRecorder], tmp_path: Path) -> None:
    """If the child can't become the user, nothing is read with root's rights."""
    system, drop = as_root
    drop.fail = True
    path = tmp_path / "authorized_keys"
    write(path, "ssh-ed25519 AAAA x\n")

    with pytest.raises(UnreadableFileError, match="Operation not permitted"):
        _content = system.read_user_file(str(path), account())


def test_large_user_file_comes_back_whole(as_root: tuple[AnsibleSystem, DropRecorder], tmp_path: Path) -> None:
    """Content larger than a pipe buffer arrives complete (the parent reads while the child writes)."""
    system, _drop = as_root
    path = tmp_path / "authorized_keys"
    write(path, "x" * 300_000)

    content = system.read_user_file(str(path), account())

    assert content is not None
    assert len(content) == 300_000


def test_oversized_answer_from_the_child_is_refused(as_root: tuple[AnsibleSystem, DropRecorder], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An answer over MAX_ANSWER is refused instead of being cut short (limit set low for the test)."""
    system, _drop = as_root
    monkeypatch.setattr(ansible_system, "MAX_ANSWER", 10)
    path = tmp_path / "authorized_keys"
    write(path, "x" * 100)

    with pytest.raises(UnreadableFileError, match="answer too large"):
        _content = system.read_user_file(str(path), account())


def no_fork() -> int:
    """Fail if a code path forks although it must not."""
    message = "must not fork"
    raise AssertionError(message)


def test_without_root_user_files_are_read_directly(system: AnsibleSystem, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without root there is nothing to drop: read with the module's own (non-root) rights, no fork."""
    monkeypatch.setattr(os, "fork", no_fork)
    path = tmp_path / "authorized_keys"
    write(path, "k\n")

    assert system.read_user_file(str(path), account()) == "k\n"


def test_roots_own_key_file_is_read_directly(as_root: tuple[AnsibleSystem, DropRecorder], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Root reading root's file is already "as the user"."""
    system, _drop = as_root
    monkeypatch.setattr(os, "fork", no_fork)
    path = tmp_path / "authorized_keys"
    write(path, "k\n")

    assert system.read_user_file(str(path), account(0)) == "k\n"


@pytest.mark.parametrize(("euid", "expected"), [pytest.param(0, True, id="root"), pytest.param(1000, False, id="user")])
def test_is_root(system: AnsibleSystem, monkeypatch: pytest.MonkeyPatch, euid: int, *, expected: bool) -> None:
    """Root is euid 0 (become); anything else is not."""
    monkeypatch.setattr(os, "geteuid", lambda: euid)

    assert system.is_root() is expected


@dataclass
class IdRecorder:
    """Fake setgroups/setresgid/setresuid that record calls; getres* report what was set (or stay put)."""

    calls: list[str] = field(default_factory=list)
    uid: tuple[int, int, int] = (1000, 1000, 1000)
    gid: tuple[int, int, int] = (1000, 1000, 1000)
    stuck: bool = False  # the kernel refused silently: ids don't change

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Replace the os functions."""
        monkeypatch.setattr(os, "setgroups", self.setgroups)
        monkeypatch.setattr(os, "setresgid", self.setresgid)
        monkeypatch.setattr(os, "setresuid", self.setresuid)
        monkeypatch.setattr(os, "getresuid", self.getresuid)
        monkeypatch.setattr(os, "getresgid", self.getresgid)

    def setgroups(self, groups: list[int]) -> None:
        """Record."""
        self.calls.append(f"groups {groups}")

    def setresgid(self, *ids: int) -> None:
        """Record and (unless stuck) apply."""
        self.calls.append(f"gid {ids}")
        if not self.stuck:
            self.gid = (ids[0], ids[1], ids[2])

    def setresuid(self, *ids: int) -> None:
        """Record and (unless stuck) apply."""
        self.calls.append(f"uid {ids}")
        if not self.stuck:
            self.uid = (ids[0], ids[1], ids[2])

    def getresuid(self) -> tuple[int, int, int]:
        """Current uids."""
        return self.uid

    def getresgid(self) -> tuple[int, int, int]:
        """Current gids."""
        return self.gid


def test_drop_privileges_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """Groups first, then gid, then uid: after setresuid the process could no longer change groups or gid."""
    ids = IdRecorder()
    ids.install(monkeypatch)

    ansible_system.drop_privileges(4242, 100, [100, 27])

    assert ids.calls == ["groups [100, 27]", "gid (100, 100, 100)", "uid (4242, 4242, 4242)"]


def test_drop_privileges_verifies_the_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the ids didn't change, nothing may be read."""
    ids = IdRecorder(stuck=True)
    ids.install(monkeypatch)

    with pytest.raises(PermissionError, match="could not drop"):
        ansible_system.drop_privileges(4242, 100, [100])


# Hardening of the forked read (review 025)


def test_file_is_opened_only_after_the_drop(as_root: tuple[AnsibleSystem, DropRecorder], tmp_path: Path) -> None:
    """The child reads what the file contains after the drop, so it opens the file after dropping."""
    system, drop = as_root
    path = tmp_path / "authorized_keys"
    write(path, "before-drop\n")
    drop.rewrite = path

    assert system.read_user_file(str(path), account()) == "after-drop\n"


def raise_interrupt(_uid: int, _gid: int, _groups: list[int]) -> None:
    """A Ctrl-C (SIGINT from the user) while the child drops privileges."""
    raise KeyboardInterrupt


def test_child_never_returns_into_the_caller(module: FakeModule, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Even a BaseException in the child ends in os._exit: only the parent continues after the call."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getgrouplist", grouplist)
    system = AnsibleSystem(module, raise_interrupt)
    marker = tmp_path / "continued"
    path = tmp_path / "authorized_keys"
    write(path, "k\n")

    with pytest.raises(UnreadableFileError):
        _content = system.read_user_file(str(path), account())
    with marker.open("a") as out:
        _written = out.write(f"{os.getpid()}\n")

    assert marker.read_text().splitlines() == [str(os.getpid())]


def hang(_uid: int, _gid: int, _groups: list[int]) -> None:
    """A child that never answers (stopped, or stuck on a FUSE file)."""
    time.sleep(60)


def test_hanging_child_is_killed_after_the_deadline(module: FakeModule, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The run doesn't hang on one user's file."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getgrouplist", grouplist)
    monkeypatch.setattr(ansible_system, "USER_READ_TIMEOUT", 0.2)
    system = AnsibleSystem(module, hang)
    started = time.monotonic()

    with pytest.raises(UnreadableFileError, match="timed out"):
        _content = system.read_user_file(str(tmp_path / "authorized_keys"), account())

    assert time.monotonic() - started < 5


def write_half_then_die(fd: int, data: bytes) -> None:
    """The child is killed in the middle of writing its answer."""
    _written = os.write(fd, data[: len(data) // 2])
    os.kill(os.getpid(), signal.SIGKILL)


def test_cut_off_answer_is_not_used(as_root: tuple[AnsibleSystem, DropRecorder], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Only a child that exited normally delivered its whole answer."""
    system, _drop = as_root
    monkeypatch.setattr(ansible_system, "_write_all", write_half_then_die)
    path = tmp_path / "authorized_keys"
    write(path, "x" * 300_000)

    with pytest.raises(UnreadableFileError, match="failed"):
        _content = system.read_user_file(str(path), account())


def open_fds() -> int:
    """Number of open file descriptors of this process."""
    return len(list(Path("/proc/self/fd").iterdir()))


def fork_fails() -> int:
    """fork() hitting the process limit."""
    raise BlockingIOError(errno.EAGAIN, "Resource temporarily unavailable")


def test_fork_failure_is_an_unreadable_file(as_root: tuple[AnsibleSystem, DropRecorder], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No crash of the module, and the pipe is closed again."""
    system, _drop = as_root
    monkeypatch.setattr(os, "fork", fork_fails)
    before = open_fds()

    with pytest.raises(UnreadableFileError, match="Resource temporarily unavailable"):
        _content = system.read_user_file(str(tmp_path / "authorized_keys"), account())

    assert open_fds() == before


@pytest.fixture
def second_docker(tmp_path_factory: pytest.TempPathFactory) -> Iterator[FakeDocker]:
    """Another daemon, the one a swapped-in symlink would point at."""
    yield from serve_fake_docker(tmp_path_factory)


def test_socket_swapped_after_the_check_is_not_used(
    system: AnsibleSystem, docker: FakeDocker, second_docker: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Between check and connect the path is replaced by a link to another socket: the checked one is used."""
    real_fstat = os.fstat

    def fstat_then_swap(fd: int) -> os.stat_result:
        info = real_fstat(fd)
        Path(docker.path).unlink()
        Path(docker.path).symlink_to(second_docker.path)
        return info

    monkeypatch.setattr(os, "fstat", fstat_then_swap)

    _answer = system.docker_api(docker.path, "/version", ME, follow_symlinks=False)

    assert (docker.requests, second_docker.requests) == (["/version"], [])


def test_docker_api_deeply_nested_json(system: AnsibleSystem, docker: FakeDocker) -> None:
    """JSON nested deeper than Python's recursion limit is invalid JSON, not a RecursionError crash of the module."""
    with pytest.raises(DockerApiError, match="invalid JSON"):
        _answer = system.docker_api(docker.path, "/deep", ME, follow_symlinks=False)
