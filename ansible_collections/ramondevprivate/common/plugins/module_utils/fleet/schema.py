# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Result schema shared by the fleet_info module and the controller-side plugins."""

from __future__ import annotations

from typing import Final, Literal, NotRequired, TypedDict

SCHEMA_VERSION: Final = 1


SudoLevel = Literal["full", "limited", "none", "unknown"]


class Sudo(TypedDict):
    """What a user may run via sudo."""

    level: SudoLevel
    nopasswd: bool
    rules: list[str]


class AuthorizedKey(TypedDict):
    """One authorized SSH key, without the key material."""

    key_type: str
    comment: str
    fingerprint: str
    allowed_from: str
    forced_command: bool


class User(TypedDict):
    """One login account and its access."""

    name: str
    uid: int
    groups: list[str]
    sudo: Sudo
    authorized_keys: list[AuthorizedKey] | None  # None: key files could not be read
    last_login: str | None  # ISO 8601; "": no record; None: no source available


class Ssh(TypedDict):
    """Where sshd looks for authorized keys."""

    key_files: list[str]
    key_files_source: Literal["sshd", "default"]
    keys_command: bool


Family = Literal["ipv4", "ipv6"]
UfwState = Literal["active", "inactive", "not installed", "unknown"]
DaemonMode = Literal["rootful", "rootless"]
DaemonState = Literal["running", "not running", "unreachable"]


class UfwRule(TypedDict):
    """One rule added with ufw, from the `### tuple ###` lines of user.rules / user6.rules."""

    action: str  # allow, deny, reject, limit
    direction: str  # in, out
    route: bool  # `ufw route ...` (FORWARD chain)
    proto: str  # tcp, udp, any, ...
    to_port: str  # "22", "80,443", "8000:8010" or "any"
    to_address: str  # 0.0.0.0/0, ::/0 or a network
    from_port: str
    from_address: str
    app: str  # application profile on the destination side; ufw already resolved its ports into to_port
    interface_in: str
    interface_out: str
    comment: str
    family: Family


class Ufw(TypedDict):
    """UFW status, default policies and rules."""

    state: UfwState
    logging: str  # e.g. "on (low)", "off"; "" if unknown
    default_incoming: str  # deny, allow, reject, disabled; "" if unknown or inactive
    default_outgoing: str
    default_routed: str
    rules: list[UfwRule] | None  # None: rule files could not be read


class Listener(TypedDict):
    """One listening TCP socket or bound UDP socket (`ss -tulpn`)."""

    proto: str  # tcp, udp
    address: str  # 0.0.0.0, ::, * (both families) or a specific address, without brackets
    interface: str  # from `address%iface`; "" if not bound to an interface
    port: int
    processes: list[str]  # process names; empty without root


class PublishedPort(TypedDict):
    """A container port published on the host."""

    host_ip: str
    host_port: int
    container_port: int
    proto: str


class Container(TypedDict):
    """One container, reduced to the fields the inventory documents (never Env, Cmd or other labels)."""

    name: str
    image: str
    version: str  # org.opencontainers.image.version label, "" if missing
    state: str  # running, exited, ...
    compose_dir: str
    ports: list[PublishedPort]


class DockerDaemon(TypedDict):
    """One Docker daemon on the host and its containers."""

    mode: DaemonMode
    owner: str  # account that runs a rootless daemon; "" for rootful
    socket: str
    state: DaemonState
    version: str
    containers: list[Container]


class Fail2ban(TypedDict):
    """fail2ban service state and its jails."""

    state: str  # systemctl is-active: active, inactive, failed, ...; "not installed"; "unknown"
    jails: list[str] | None  # None: unknown (not running, no root)


class AutoUpdates(TypedDict):
    """How unattended upgrades are configured and when they last ran successfully."""

    installed: bool | None  # unattended-upgrades package; None: unknown
    update_lists: str | None  # APT::Periodic::Update-Package-Lists; "" unset; None: unknown
    unattended_upgrade: str | None  # APT::Periodic::Unattended-Upgrade
    timer: str  # systemctl is-enabled apt-daily-upgrade.timer: enabled, disabled, masked, ...; "" unknown
    last_success: str | None  # ISO 8601 (UTC) mtime of the upgrade stamp; "" no stamp; None: unknown


ExposureState = Literal["public", "internal", "unknown"]


class Exposure(TypedDict):
    """Whether a host answers ping on a public address, as seen from the probe host (set on the controller)."""

    state: ExposureState
    checked_at: str  # collection time of the run that probed; "" if never probed
    answered: list[str]  # public addresses that answered


class FleetInfo(TypedDict):
    """Everything fleet_info reports about one host."""

    schema_version: int
    users: list[User]
    ssh: Ssh
    ufw: Ufw
    listeners: list[Listener] | None  # None: ss not available
    docker: list[DockerDaemon]
    fail2ban: Fail2ban
    auto_updates: AutoUpdates


class Mount(TypedDict):
    """One real filesystem that counts towards a host's disk capacity."""

    mount: str
    device: str
    fstype: str
    size_bytes: int


class Disk(TypedDict):
    """Disk capacity of a host."""

    total_bytes: int
    mounts: list[Mount]


class SystemInfo(TypedDict):
    """OS and hardware capacity of a host."""

    distribution: str
    version: str
    release: str
    kernel: str
    cores: int
    ram_mb: int
    disk: Disk


class Address(TypedDict):
    """One IP address configured on a host interface."""

    interface: str
    address: str
    prefix: int
    family: Literal["ipv4", "ipv6", "unknown"]
    private: bool


class Snapshot(TypedDict):
    """Everything known about one host at one point in time, as stored in fleet_data_dir."""

    schema_version: int
    host: str
    collected_at: str
    system: SystemInfo
    addresses: list[Address]
    users: list[User]
    ssh: Ssh
    ufw: Ufw
    listeners: list[Listener] | None
    docker: list[DockerDaemon]
    fail2ban: Fail2ban
    auto_updates: AutoUpdates
    exposure: NotRequired[Exposure]  # added by the probe step; kept from the stored snapshot when not probed
    unreached_since: NotRequired[str]  # set when a targeted run couldn't collect the host; gone with the next success


DEFAULT_KEY_FILES: Final[tuple[str, ...]] = (".ssh/authorized_keys", ".ssh/authorized_keys2")


def empty_info() -> FleetInfo:
    """Return the result skeleton that the collectors fill in."""
    return {
        "schema_version": SCHEMA_VERSION,
        "users": [],
        "ssh": {
            "key_files": list(DEFAULT_KEY_FILES),
            "key_files_source": "default",
            "keys_command": False,
        },
        "ufw": ufw_without_details("unknown"),
        "listeners": None,
        "docker": [],
        "fail2ban": {"state": "unknown", "jails": None},
        "auto_updates": unknown_auto_updates(),
    }


def unknown_auto_updates() -> AutoUpdates:
    """Auto-update settings that could not be determined."""
    return {"installed": None, "update_lists": None, "unattended_upgrade": None, "timer": "", "last_success": None}


def ufw_without_details(state: UfwState) -> Ufw:
    """UFW whose policies and rules are not known (unknown, not installed)."""
    return {
        "state": state,
        "logging": "",
        "default_incoming": "",
        "default_outgoing": "",
        "default_routed": "",
        "rules": None,
    }
