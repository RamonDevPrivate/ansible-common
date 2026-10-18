# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the fleet_info module entry point (the collector itself is replaced)."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from ansible.module_utils import basic  # pyright: ignore[reportMissingTypeStubs] - no stubs
from ansible.module_utils.testing import patch_module_args  # pyright: ignore[reportMissingTypeStubs] - no stubs

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect import System, UsersResult
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect_network import (
    HostSystem,
    NetworkResult,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect_security import (
    SecurityResult,
    SecuritySystem,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import as_list, as_mapping
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    SCHEMA_VERSION,
    DockerDaemon,
    FleetInfo,
    Listener,
    Ssh,
    User,
    ufw_without_details,
    unknown_auto_updates,
)
from ansible_collections.ramondevprivate.common.plugins.modules import fleet_info
from ansible_collections.ramondevprivate.common.tests.unit.plugins.doc_schema import doc_mismatches, load_yaml
from ansible_collections.ramondevprivate.common.tests.unit.plugins.modules.utils import AnsibleExitJson, AnsibleFailJson

if TYPE_CHECKING:
    from collections.abc import Iterable

USER: User = {
    "name": "alice",
    "uid": 1000,
    "groups": ["sudo"],
    "sudo": {"level": "full", "nopasswd": False, "rules": ["(ALL : ALL) ALL"]},
    "authorized_keys": [],
    "last_login": "",
}
SSH: Ssh = {
    "key_files": [".ssh/authorized_keys"],
    "key_files_source": "sshd",
    "keys_command": False,
}
LISTENER: Listener = {"proto": "tcp", "address": "0.0.0.0", "interface": "", "port": 22, "processes": ["sshd"]}
DAEMON: DockerDaemon = {
    "mode": "rootful",
    "owner": "",
    "socket": "/var/run/docker.sock",
    "state": "running",
    "version": "29.3.0",
    "containers": [],
}


class Recorder:
    """What the module passed to the collector and to module.warn."""

    def __init__(self) -> None:
        """Start empty."""
        self.group_filters: list[list[str]] = []
        self.user_filters: list[list[str]] = []
        self.warnings: list[str] = []


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    """Replace the collectors and module.warn, pretend to run as root: nothing touches the real system."""
    record = Recorder()

    def fake_collect(_system: System, group_filter: Iterable[str], user_filter: Iterable[str]) -> UsersResult:
        record.group_filters.append(list(group_filter))
        record.user_filters.append(list(user_filter))
        return UsersResult(users=[USER], ssh=SSH, warnings=["sshd -T failed"])

    def fake_network(_system: HostSystem) -> NetworkResult:
        return NetworkResult(
            ufw=ufw_without_details("not installed"),
            listeners=[LISTENER],
            docker=[DAEMON],
            warnings=["ss failed"],
        )

    def fake_security(_system: SecuritySystem) -> SecurityResult:
        return SecurityResult(fail2ban={"state": "active", "jails": ["sshd"]}, auto_updates=unknown_auto_updates())

    def fake_warn(_module: object, warning: str) -> None:
        record.warnings.append(warning)

    def as_root() -> int:
        return 0

    monkeypatch.setattr(fleet_info, "collect_users", fake_collect)
    monkeypatch.setattr(fleet_info, "collect_network", fake_network)
    monkeypatch.setattr(fleet_info, "collect_security", fake_security)
    monkeypatch.setattr(basic.AnsibleModule, "warn", fake_warn)
    monkeypatch.setattr(os, "geteuid", as_root)
    return record


def run_module(args: dict[str, object]) -> dict[str, object]:
    """Run the module with the given arguments and return the result passed to exit_json."""
    with patch_module_args(args), pytest.raises(AnsibleExitJson) as exit_info:
        fleet_info.main()
    return dict(exit_info.value.result)


@pytest.mark.parametrize(
    ("args", "message"),
    [
        pytest.param({"group_filters": ["cdrom"]}, "Unsupported parameters", id="unknown-option"),
        pytest.param({"user_filter": {"root": True}}, "'user_filter' is of type dict", id="wrong-type"),
    ],
)
@pytest.mark.usefixtures("recorder")
def test_invalid_options_fail(args: dict[str, object], message: str) -> None:
    """The argument spec is strict: a typo in an option name or a wrong type fails instead of being ignored."""
    with patch_module_args(args), pytest.raises(AnsibleFailJson) as fail_info:
        fleet_info.main()

    assert message in str(fail_info.value.result["msg"])


@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check-mode"])
@pytest.mark.usefixtures("recorder")
def test_reports_facts_without_changing_anything(*, check_mode: bool) -> None:
    """The module is read-only and runs (not skips) in check mode."""
    result = run_module({"_ansible_check_mode": check_mode})

    assert result["changed"] is False
    assert not result.get("skipped")
    assert as_mapping(result["fleet"])["schema_version"] == SCHEMA_VERSION


@pytest.mark.usefixtures("recorder")
def test_result_contains_users_and_ssh_settings() -> None:
    """What the collector found is returned under fleet."""
    fleet = as_mapping(run_module({})["fleet"])

    assert [as_mapping(u)["name"] for u in as_list(fleet["users"])] == ["alice"]
    assert as_mapping(fleet["ssh"])["key_files_source"] == "sshd"


@pytest.mark.usefixtures("recorder")
def test_result_contains_network_and_docker() -> None:
    """UFW, listeners and Docker daemons are returned under fleet."""
    fleet = as_mapping(run_module({})["fleet"])

    assert as_mapping(fleet["ufw"])["state"] == "not installed"
    assert [as_mapping(item)["port"] for item in as_list(fleet["listeners"])] == [22]
    assert [as_mapping(item)["mode"] for item in as_list(fleet["docker"])] == ["rootful"]


@pytest.mark.usefixtures("recorder")
def test_result_contains_fail2ban_and_auto_updates() -> None:
    """fail2ban and the auto-update settings are returned under fleet."""
    fleet = as_mapping(run_module({})["fleet"])

    assert as_mapping(fleet["fail2ban"])["jails"] == ["sshd"]
    assert "last_success" in as_mapping(fleet["auto_updates"])


def test_default_group_filter(recorder: Recorder) -> None:
    """Without the option, the documented noise groups are filtered."""
    _result = run_module({})

    assert recorder.group_filters == [fleet_info.DEFAULT_GROUP_FILTER]


def test_custom_group_filter(recorder: Recorder) -> None:
    """The role passes its own list through."""
    _result = run_module({"group_filter": ["cdrom", "lpadmin"]})

    assert recorder.group_filters == [["cdrom", "lpadmin"]]


def test_no_users_filtered_by_default(recorder: Recorder) -> None:
    """Every collected account is reported unless the role says otherwise."""
    _result = run_module({})

    assert recorder.user_filters == [[]]


def test_custom_user_filter(recorder: Recorder) -> None:
    """Image default accounts can be left out."""
    _result = run_module({"user_filter": ["debian", "root"]})

    assert recorder.user_filters == [["debian", "root"]]


def test_collector_warnings_reach_ansible(recorder: Recorder) -> None:
    """Warnings of both collectors (e.g. sshd -T or ss failed) are shown in the Ansible output."""
    _result = run_module({})

    assert recorder.warnings == ["sshd -T failed", "ss failed"]


def test_warns_when_not_running_as_root(recorder: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without become, one summary warning replaces the many per-file warnings that follow from it."""

    def as_user() -> int:
        return 1000

    monkeypatch.setattr(os, "geteuid", as_user)

    _result = run_module({})

    assert len(recorder.warnings) == 1
    assert "not running as root" in recorder.warnings[0]


def test_return_doc_matches_schema() -> None:
    """RETURN documents exactly the keys, types and choices of the result schema, at every level."""
    doc = load_yaml(fleet_info.RETURN)
    fleet = as_mapping(as_mapping(doc).get("fleet"))

    assert fleet.get("type") == "dict"
    assert doc_mismatches(fleet.get("contains"), FleetInfo) == []
