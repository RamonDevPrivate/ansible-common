# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Reduce Docker Engine API responses to what the inventory documents.

Pure functions on decoded JSON. Only allowlisted fields are copied, so environment variables, commands and
other labels never leave the host.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import (
    as_list,
    as_mapping,
    get_mapping,
    get_str,
    is_number,
)

if TYPE_CHECKING:
    from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import Container, PublishedPort

LABEL_VERSION: Final = "org.opencontainers.image.version"
LABEL_WORKING_DIR: Final = "com.docker.compose.project.working_dir"


def parse_version(data: object) -> str:
    """Engine version from GET /version."""
    return get_str(as_mapping(data), "Version")


def parse_container_ids(data: object) -> list[str]:
    """Container IDs from GET /containers/json."""
    ids = (get_str(as_mapping(item), "Id") for item in as_list(data))
    return [container_id for container_id in ids if container_id]


def parse_container(data: object) -> Container | None:
    """One container from GET /containers/<id>/json (the same JSON as `docker inspect`); None without a name."""
    inspect = as_mapping(data)
    name = get_str(inspect, "Name").lstrip("/")
    if not name:
        return None
    config = get_mapping(inspect, "Config")
    labels = get_mapping(config, "Labels")
    return {
        "name": name,
        "image": get_str(config, "Image"),
        "version": get_str(labels, LABEL_VERSION),
        "state": get_str(get_mapping(inspect, "State"), "Status", "unknown"),
        "compose_dir": get_str(labels, LABEL_WORKING_DIR),
        "ports": published_ports(inspect),
    }


def published_ports(inspect: object) -> list[PublishedPort]:
    """Ports bound on the host; a stopped container binds none."""
    ports = _bindings(get_mapping(get_mapping(as_mapping(inspect), "NetworkSettings"), "Ports"))
    # Docker doesn't guarantee an order; a stable one keeps the snapshot unchanged between runs
    return sorted(ports, key=lambda p: (p["host_port"], p["proto"], p["host_ip"], p["container_port"]))


def _bindings(mapping: object) -> list[PublishedPort]:
    result: list[PublishedPort] = []
    for key, value in as_mapping(mapping).items():
        port, _sep, proto = key.partition("/")
        if not is_number(port):
            continue
        for item in as_list(value):  # null: exposed but not published
            binding = as_mapping(item)
            host_port = get_str(binding, "HostPort")
            if not is_number(host_port):
                continue
            result.append(
                {
                    "host_ip": get_str(binding, "HostIp"),
                    "host_port": int(host_port),
                    "container_port": int(port),
                    "proto": proto or "tcp",
                }
            )
    return result
