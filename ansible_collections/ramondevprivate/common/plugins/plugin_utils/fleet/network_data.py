# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Read UFW, listeners and Docker daemons from untyped data (module result or stored JSON), runs on the controller."""

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import (
    Data,
    as_list,
    as_mapping,
    get_int,
    get_list,
    get_str,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    Container,
    DaemonMode,
    DaemonState,
    DockerDaemon,
    Family,
    Listener,
    PublishedPort,
    Ufw,
    UfwRule,
    UfwState,
    ufw_without_details,
)


def parse_ufw(value: object) -> Ufw:
    """UFW from untyped data; unknown values become "unknown"."""
    data = as_mapping(value)
    if not data:
        return ufw_without_details("unknown")
    rules = data.get("rules")
    return {
        "state": _ufw_state(get_str(data, "state")),
        "logging": get_str(data, "logging"),
        "default_incoming": get_str(data, "default_incoming"),
        "default_outgoing": get_str(data, "default_outgoing"),
        "default_routed": get_str(data, "default_routed"),
        "rules": None if rules is None else [_rule(as_mapping(r)) for r in as_list(rules)],
    }


def parse_listeners(value: object) -> list[Listener] | None:
    """Listeners from untyped data; None stays None (ss was not available)."""
    if value is None:
        return None
    return [_listener(as_mapping(item)) for item in as_list(value) if get_int(as_mapping(item), "port")]


def parse_docker(value: object) -> list[DockerDaemon]:
    """Docker daemons from untyped data."""
    return [_daemon(as_mapping(item)) for item in as_list(value)]


def _ufw_state(value: str) -> UfwState:
    if value == "active":
        return "active"
    if value == "inactive":
        return "inactive"
    if value == "not installed":
        return "not installed"
    return "unknown"


def _family(value: str) -> Family:
    return "ipv6" if value == "ipv6" else "ipv4"


def _rule(data: Data) -> UfwRule:
    return {
        "action": get_str(data, "action"),
        "direction": get_str(data, "direction", "in"),
        "route": data.get("route") is True,
        "proto": get_str(data, "proto", "any"),
        "to_port": get_str(data, "to_port", "any"),
        "to_address": get_str(data, "to_address"),
        "from_port": get_str(data, "from_port", "any"),
        "from_address": get_str(data, "from_address"),
        "app": get_str(data, "app"),
        "interface_in": get_str(data, "interface_in"),
        "interface_out": get_str(data, "interface_out"),
        "comment": get_str(data, "comment"),
        "family": _family(get_str(data, "family")),
    }


def _listener(data: Data) -> Listener:
    return {
        "proto": get_str(data, "proto"),
        "address": get_str(data, "address"),
        "interface": get_str(data, "interface"),
        "port": get_int(data, "port"),
        "processes": [p for p in get_list(data, "processes") if isinstance(p, str)],
    }


def _mode(value: str) -> DaemonMode:
    return "rootless" if value == "rootless" else "rootful"


def _daemon_state(value: str) -> DaemonState:
    if value == "running":
        return "running"
    if value == "not running":
        return "not running"
    return "unreachable"


def _daemon(data: Data) -> DockerDaemon:
    return {
        "mode": _mode(get_str(data, "mode")),
        "owner": get_str(data, "owner"),
        "socket": get_str(data, "socket"),
        "state": _daemon_state(get_str(data, "state")),
        "version": get_str(data, "version"),
        "containers": [_container(as_mapping(c)) for c in get_list(data, "containers") if get_str(as_mapping(c), "name")],
    }


def _container(data: Data) -> Container:
    return {
        "name": get_str(data, "name"),
        "image": get_str(data, "image"),
        "version": get_str(data, "version"),
        "state": get_str(data, "state", "unknown"),
        "compose_dir": get_str(data, "compose_dir"),
        "ports": [_port(as_mapping(p)) for p in get_list(data, "ports")],
    }


def _port(data: Data) -> PublishedPort:
    return {
        "host_ip": get_str(data, "host_ip"),
        "host_port": get_int(data, "host_port"),
        "container_port": get_int(data, "container_port"),
        "proto": get_str(data, "proto", "tcp"),
    }
