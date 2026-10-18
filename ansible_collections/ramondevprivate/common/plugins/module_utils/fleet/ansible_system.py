# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""The System used on real hosts: passwd/group database, files, commands via AnsibleModule, Docker sockets."""

from __future__ import annotations

import errno
import grp
import http.client
import json
import os
import pwd
import resource
import select
import signal
import socket
import stat
import struct
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final, NoReturn, Protocol, cast

from ansible.module_utils.common.locale import (  # pyright: ignore[reportMissingTypeStubs] - no stubs
    get_best_parsable_locale,  # pyright: ignore[reportUnknownVariableType] - untyped ansible-core API
)

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect import (
    Account,
    CommandResult,
    UnreadableFileError,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect_network import DockerApiError

if TYPE_CHECKING:
    from collections.abc import Callable

MAX_FILE_SIZE: Final = 1024 * 1024
SBIN_DIRS: Final = ["/usr/sbin", "/sbin"]
DOCKER_TIMEOUT: Final = 10.0  # seconds per request
MAX_API_RESPONSE: Final = 16 * 1024 * 1024
HTTP_OK: Final = 200
PEERCRED: Final = struct.Struct("iII")  # struct ucred: pid_t pid, uid_t uid, gid_t gid (uid/gid unsigned)
USER_READ_TIMEOUT: Final = 10.0  # seconds for reading one key file as its user (FUSE or a stopped child can hang)
MAX_ANSWER: Final = MAX_FILE_SIZE + 4096  # file content plus the answer's kind byte or an error reason
EXEC_FAILED: Final = 126  # exit code shells use for "found but could not be executed"


def drop_privileges(uid: int, gid: int, groups: list[int]) -> None:
    """Become uid/gid with the given supplementary groups, for good (real, effective and saved ids)."""
    os.setgroups(groups)
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
        message = "could not drop to the account's ids"
        raise PermissionError(message)


class Module(Protocol):
    """The parts of AnsibleModule the system uses."""

    def get_bin_path(self, arg: str, *, opt_dirs: list[str] | None = None) -> str | None:
        """Path of a program, or None."""
        raise NotImplementedError

    def run_command(
        self,
        args: list[str],
        *,
        environ_update: dict[str, str] | None = None,
        expand_user_and_vars: bool = True,
        handle_exceptions: bool = True,
    ) -> tuple[int, str, str]:
        """Run a command; returns rc, stdout, stderr."""
        raise NotImplementedError


class AnsibleSystem:
    """System backed by the host the module runs on."""

    def __init__(self, module: Module, drop: Callable[[int, int, list[int]], None] = drop_privileges) -> None:
        """Remember the module; the parsable locale is determined on first use.

        Args:
            module: The running AnsibleModule.
            drop: How a forked child gives up root before reading a user's file (replaceable in tests).
        """
        self._module: Module = module
        self._locale: str | None = None
        self._drop: Callable[[int, int, list[int]], None] = drop

    def is_root(self) -> bool:
        """Whether the module runs as root (become)."""
        return os.geteuid() == 0

    def accounts(self) -> list[Account]:
        """All passwd entries."""
        return [Account(p.pw_name, p.pw_uid, p.pw_gid, p.pw_dir, p.pw_shell) for p in pwd.getpwall()]

    def group_names(self, account: Account) -> list[str]:
        """All group names of the account (like `id -nG`)."""
        names: list[str] = []
        for gid in os.getgrouplist(account.name, account.gid):
            try:
                names.append(grp.getgrgid(gid).gr_name)
            except KeyError:
                names.append(str(gid))
        return names

    def primary_group(self, account: Account) -> str:
        """Name of the primary group."""
        try:
            return grp.getgrgid(account.gid).gr_name
        except KeyError:
            return str(account.gid)

    def read_file(self, path: str) -> str | None:
        """Read a regular file with the module's own permissions (for root-owned configuration files)."""
        content = _read_regular_file(path)
        return None if content is None else content.decode("utf-8", errors="replace")

    def read_user_file(self, path: str, account: Account) -> str | None:
        """Read a file the way sshd reads authorized_keys: with the account's permissions, following symlinks.

        As root, a forked child drops to the account's uid, gid and groups before it opens the path, so a symlink
        in a user's home only reaches what that user may read, and nothing is opened as root (opening a device
        node can have effects). Without root, or for root's own files, there are no privileges to drop.
        """
        if not self.is_root() or account.uid == 0:
            return self.read_file(path)
        groups = os.getgrouplist(account.name, account.gid)
        answer = _read_in_child(path, lambda: self._drop(account.uid, account.gid, groups))
        kind, payload = answer[:1], answer[1:]
        if kind == b"F":
            return payload.decode("utf-8", errors="replace")
        if kind == b"N":
            return None
        reason = payload.decode("utf-8", errors="replace") if kind == b"E" else "reading as the user failed"
        raise UnreadableFileError(reason)

    def run(self, args: list[str]) -> CommandResult | None:
        """Run a command with a parsable (English) locale; None if the program isn't installed.

        Arguments are passed as they are: no `~` or `$VAR` expansion (`dpkg-query -f=${db:Status-Status}` is a dpkg
        format). A program that can't be executed (OSError) is a failed command (rc 126), not a failed module; any
        other exception from run_command is a bug and fails the module with its traceback.
        """
        path = self._module.get_bin_path(args[0], opt_dirs=SBIN_DIRS)
        if path is None:
            return None
        if self._locale is None:
            self._locale = _parsable_locale(self._module)
        environment: dict[str, str] = dict.fromkeys(("LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE"), self._locale)
        try:
            rc, stdout, stderr = self._module.run_command([path, *args[1:]], environ_update=environment, expand_user_and_vars=False, handle_exceptions=False)
        except OSError as error:
            return CommandResult(EXEC_FAILED, "", f"{args[0]} could not be run: {error.strerror or error}")
        return CommandResult(rc, stdout, stderr)

    def list_dir(self, path: str) -> list[str]:
        """Entry names; empty if the directory doesn't exist or can't be read."""
        try:
            return sorted(entry.name for entry in Path(path).iterdir())
        except OSError:
            return []

    def is_socket(self, path: str, *, follow_symlinks: bool) -> bool:
        """Whether path is a unix socket; with follow_symlinks false a symlink is never one."""
        try:
            return stat.S_ISSOCK(Path(path).stat(follow_symlinks=follow_symlinks).st_mode)
        except OSError:
            return False

    def file_mtime(self, path: str) -> float | None:
        """Modification time; None if the file doesn't exist or can't be read."""
        try:
            return Path(path).stat().st_mtime
        except OSError:
            return None

    def docker_api(self, socket_path: str, api_path: str, owner_uid: int, *, follow_symlinks: bool) -> object:
        """GET a Docker Engine API path over the daemon's unix socket and decode the JSON.

        Talks to the socket directly instead of running the docker CLI: no CLI needed, no `runuser` for rootless
        daemons (root may open their sockets), and no PATH lookup that could hit a wrapper script. The path is
        unversioned, so the daemon answers in its own API version.

        The socket file must belong to owner_uid and so must the process listening on it (SO_PEERCRED), so a user
        can't make root talk to another service's socket. Without follow_symlinks the check and the connect use the
        same file (opened with O_PATH | O_NOFOLLOW), so a symlink swapped in between is never followed.
        """
        connection = http.client.HTTPConnection("localhost", timeout=DOCKER_TIMEOUT)  # host only fills the header
        try:
            # request() uses this socket instead of opening a TCP one
            connection.sock = _connect_unix(socket_path, owner_uid, follow_symlinks=follow_symlinks)
            connection.request("GET", api_path)
            response = connection.getresponse()
            body = response.read(MAX_API_RESPONSE + 1)
        except (OSError, http.client.HTTPException) as error:
            raise DockerApiError(str(error) or type(error).__name__) from error
        finally:
            connection.close()
        if response.status != HTTP_OK:
            message = f"HTTP {response.status} for {api_path}"
            raise DockerApiError(message, response.status)
        if len(body) > MAX_API_RESPONSE:
            message = f"response larger than {MAX_API_RESPONSE} bytes"
            raise DockerApiError(message)
        try:
            return cast("object", json.loads(body))
        except (ValueError, RecursionError) as error:  # RecursionError: JSON nested too deeply to parse
            message = f"invalid JSON for {api_path}"
            raise DockerApiError(message) from error


def _connect_unix(path: str, owner_uid: int, *, follow_symlinks: bool) -> socket.socket:
    """Connect to a unix socket owned by owner_uid whose listener also runs as owner_uid."""
    flags = os.O_PATH | (0 if follow_symlinks else os.O_NOFOLLOW)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISSOCK(info.st_mode):
            message = f"{path} is not a socket"
            raise DockerApiError(message)
        if info.st_uid != owner_uid:
            message = f"{path} belongs to uid {info.st_uid}, expected {owner_uid}"
            raise DockerApiError(message)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(DOCKER_TIMEOUT)
        try:
            sock.connect(f"/proc/self/fd/{fd}")  # the file checked above, not whatever path points to now
            ucred = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, PEERCRED.size)
            peer_uid = cast("tuple[int, int, int]", PEERCRED.unpack(ucred))[1]  # struct.unpack is untyped
        except OSError:
            sock.close()
            raise
    finally:
        os.close(fd)
    if peer_uid != owner_uid:
        sock.close()
        message = f"{path} is served by uid {peer_uid}, expected {owner_uid}"
        raise DockerApiError(message)
    return sock


def _read_regular_file(path: str) -> bytes | None:
    """Content of a regular file of at most MAX_FILE_SIZE; None if missing; raises UnreadableFileError otherwise.

    The non-blocking open keeps a FIFO from hanging the reader. Symlinks are followed with the caller's permissions.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
    except FileNotFoundError:  # includes a dangling symlink
        return None
    except OSError as error:
        reason = "symlink loop" if error.errno == errno.ELOOP else error.strerror
        raise UnreadableFileError(reason) from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            message = "not a regular file"
            raise UnreadableFileError(message)
        if info.st_size > MAX_FILE_SIZE:
            message = f"larger than {MAX_FILE_SIZE} bytes"
            raise UnreadableFileError(message)
        chunks: list[bytes] = []
        remaining = MAX_FILE_SIZE  # also bounds a file that grows while it is read
        while remaining > 0 and (chunk := os.read(fd, remaining)):
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks)


def _read_in_child(path: str, drop: Callable[[], None]) -> bytes:
    """Fork, let the child drop privileges and read path; return its complete answer or raise UnreadableFileError.

    The answer only counts if the child exited normally with 0, i.e. after writing all of it. A child that hangs
    (a file on a FUSE mount the user controls, a SIGSTOP from the user) is killed after USER_READ_TIMEOUT.
    """
    try:
        read_end, write_end = os.pipe()
    except OSError as error:
        message = f"reading as the user failed: {error.strerror}"
        raise UnreadableFileError(message) from error
    try:
        pid = os.fork()
    except OSError as error:
        os.close(read_end)
        os.close(write_end)
        message = f"reading as the user failed: {error.strerror}"
        raise UnreadableFileError(message) from error
    if pid == 0:
        _child_read(path, drop, read_end, write_end)  # never returns
    os.close(write_end)
    try:
        answer = _read_until_eof(read_end, USER_READ_TIMEOUT, MAX_ANSWER)
    except (TimeoutError, OverflowError) as error:
        os.kill(pid, signal.SIGKILL)
        _pid, _status = os.waitpid(pid, 0)
        message = "reading as the user timed out" if isinstance(error, TimeoutError) else "answer too large"
        raise UnreadableFileError(message) from error
    finally:
        os.close(read_end)
    _pid, status = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(status) != 0:  # killed or failed mid-way: the answer may be cut short
        message = "reading as the user failed"
        raise UnreadableFileError(message)
    return answer


def _child_read(path: str, drop: Callable[[], None], read_end: int, write_end: int) -> NoReturn:
    """In the forked child: drop privileges, read, send `F<content>`, `N` (missing) or `E<reason>`, exit.

    Whatever happens, the child ends in os._exit and never unwinds into the module's code; it exits 0 only after
    the whole answer was written.
    """
    status = 1
    try:
        _previous = signal.signal(signal.SIGINT, signal.SIG_DFL)  # no KeyboardInterrupt that could unwind the stack
        os.close(read_end)
        out = _isolate_fds(write_end)
        try:
            drop()
            content = _read_regular_file(path)
            answer = b"N" if content is None else b"F" + content
        except UnreadableFileError as error:
            answer = b"E" + str(error).encode()
        except Exception as error:  # noqa: BLE001 - every failure must become an answer; the outer finally exits
            answer = b"E" + f"reading as the user failed: {error}".encode()
        _write_all(out, answer)
        status = 0
    finally:
        os._exit(status)


def _isolate_fds(write_end: int) -> int:
    """Keep only the answer pipe (moved to fd 3) and /dev/null on 0-2; the user's process sees nothing else."""
    out = 3
    if write_end != out:
        _out = os.dup2(write_end, out)
    null = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        _std = os.dup2(null, fd)
    soft_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    os.closerange(out + 1, soft_limit if soft_limit > 0 else 65536)
    return out


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


def _read_until_eof(fd: int, timeout: float, limit: int) -> bytes:
    """Read until EOF; TimeoutError after timeout seconds in total, OverflowError beyond limit bytes."""
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    deadline = time.monotonic() + timeout
    chunks: list[bytes] = []
    size = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not poller.poll(remaining * 1000):
            raise TimeoutError
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > limit:
            raise OverflowError
        chunks.append(chunk)


def _parsable_locale(module: Module) -> str:
    """Ansible's choice of an English locale for parsing output (C.UTF-8, C, ...); "C" as last resort."""
    locale = cast("object", get_best_parsable_locale(module))  # untyped ansible-core function
    return locale if isinstance(locale, str) else "C"
