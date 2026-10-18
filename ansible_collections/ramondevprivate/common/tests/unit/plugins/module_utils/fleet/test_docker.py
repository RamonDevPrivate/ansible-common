# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for reducing Docker Engine API responses."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import as_list
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.docker import (
    parse_container,
    parse_container_ids,
    parse_version,
    published_ports,
)

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> object:
    """Read a captured (anonymized, reduced) API response."""
    return cast("object", json.loads((FIXTURES / name).read_text()))


def container(fixture: str, name: str) -> object:
    """One container from a captured `docker inspect` list."""
    return next(item for item in as_list(load(fixture)) if f'"/{name}"' in json.dumps(item))


def test_engine_version() -> None:
    """GET /version answers with the server part of `docker version`."""
    assert parse_version(load("rootless_docker_version.json")) == "29.7.1"


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param({}, id="no-version"),
        pytest.param({"Version": 29}, id="not-a-string"),
        pytest.param("29.7.1", id="not-a-mapping"),
    ],
)
def test_engine_version_unknown(answer: object) -> None:
    """An answer without a version string gives an empty version, no error."""
    assert parse_version(answer) == ""


def test_container_ids() -> None:
    """Synthetic GET /containers/json: only the IDs are needed, in the daemon's order."""
    assert parse_container_ids([{"Id": "abc", "Names": ["/x"]}, {"Id": "def"}]) == ["abc", "def"]


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param({"Names": ["/y"]}, id="no-id"),
        pytest.param({"Id": 42}, id="id-not-a-string"),
        pytest.param("junk", id="not-a-mapping"),
    ],
)
def test_container_ids_skip_broken_entries(entry: object) -> None:
    """An entry without a usable ID is skipped; the others still count."""
    assert parse_container_ids([entry, {"Id": "abc"}]) == ["abc"]


@pytest.mark.parametrize("state", ["running", "exited", "created", "paused", "restarting", "dead"])
def test_container_state(state: str) -> None:
    """Synthetic: the state comes from State.Status as Docker reports it (the role decides what to show)."""
    parsed = parse_container({"Name": "/app", "State": {"Status": state}})

    assert parsed is not None
    assert parsed["state"] == state


def test_container_identity_and_compose_dir() -> None:
    """Name without the leading slash, image as configured, compose working directory."""
    parsed = parse_container(container("rootless_docker_inspect.json", "traefik-traefik-1"))

    assert parsed is not None
    assert parsed["name"] == "traefik-traefik-1"
    assert parsed["image"].startswith("traefik:v3.7.13@sha256:")
    assert parsed["version"] == "v3.7.13"
    assert parsed["state"] == "running"
    assert parsed["compose_dir"] == "/services/traefik"


def test_missing_version_label() -> None:
    """Images without the OCI version label have no version."""
    parsed = parse_container(container("rootful_docker_inspect.json", "hedgedoc-database-1"))

    assert parsed is not None
    assert parsed["version"] == ""


def test_published_ports_of_running_container() -> None:
    """The actual bindings, one per host address; exposed-only ports are not published."""
    parsed = parse_container(container("rootful_docker_inspect.json", "traefik-traefik-1"))

    assert parsed is not None
    assert [(p["host_ip"], p["host_port"], p["container_port"], p["proto"]) for p in parsed["ports"]] == [
        ("0.0.0.0", 80, 80, "tcp"),
        ("::", 80, 80, "tcp"),
        ("0.0.0.0", 443, 443, "tcp"),
        ("::", 443, 443, "tcp"),
    ]


def test_exposed_ports_are_not_published() -> None:
    """A container behind a reverse proxy only exposes ports."""
    parsed = parse_container(container("rootless_docker_inspect.json", "ed-miso-client"))

    assert parsed is not None
    assert parsed["ports"] == []


def test_configured_bindings_of_a_stopped_container_are_not_published() -> None:
    """Synthetic: a stopped container binds no port; its configured bindings are not taken for published ones."""
    inspect: dict[str, object] = {
        "NetworkSettings": {"Ports": {}},
        "HostConfig": {"PortBindings": {"8080/tcp": [{"HostIp": "", "HostPort": "8081"}]}},
    }

    assert published_ports(inspect) == []


def test_environment_and_other_labels_never_leave_the_host() -> None:
    """Synthetic: secrets in Env, Cmd or arbitrary labels are not copied."""
    inspect = {
        "Name": "/app",
        "Config": {
            "Image": "app:1",
            "Env": ["DB_PASSWORD=secret-env"],
            "Cmd": ["--token=secret-cmd"],
            "Labels": {"traefik.http.routers.app.rule": "Host(`secret-label`)"},
        },
        "Args": ["--token=secret-args"],
    }

    parsed = parse_container(inspect)

    assert parsed is not None
    assert "secret" not in json.dumps(parsed)


def test_container_without_name_is_skipped() -> None:
    """Without a name there is nothing to document."""
    assert parse_container({"Config": {"Image": "x"}}) is None


def test_unicode_digits_in_port_keys_are_skipped() -> None:
    """Synthetic: "²" passes str.isdigit but not int(); a broken answer must not crash the module."""
    inspect = {"NetworkSettings": {"Ports": {"²/tcp": [{"HostIp": "", "HostPort": "80"}], "80/tcp": [{"HostPort": "²"}]}}}

    assert published_ports(inspect) == []
