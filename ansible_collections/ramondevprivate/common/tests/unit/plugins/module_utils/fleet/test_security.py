# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the fail2ban and APT periodic parsers."""

from __future__ import annotations

from pathlib import Path

import pytest

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.security import (
    parse_apt_periodic,
    parse_fail2ban_jails,
)

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    """Read a captured command output."""
    return (FIXTURES / name).read_text()


def test_jails_from_captured_status() -> None:
    """The jail list is tab-separated after its label."""
    assert parse_fail2ban_jails(fixture("fail2ban_status.txt")) == ["sshd"]


def test_several_jails() -> None:
    """Synthetic: jails are comma-separated."""
    output = "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, recidive\n"

    assert parse_fail2ban_jails(output) == ["sshd", "recidive"]


def test_no_jails() -> None:
    """Synthetic: a running server without jails has an empty list, not an unknown one."""
    assert parse_fail2ban_jails("Status\n|- Number of jail:\t0\n`- Jail list:\t\n") == []


def test_error_output_has_no_jails() -> None:
    """Captured on a host where fail2ban failed: no jail list means unknown."""
    assert parse_fail2ban_jails(fixture("fail2ban_not_running.txt")) is None


def test_apt_periodic_from_captured_dump() -> None:
    """Both settings that make unattended upgrades run."""
    assert parse_apt_periodic(fixture("apt_config_periodic.txt")) == ("1", "1")


def test_apt_periodic_in_full_dump() -> None:
    """Synthetic: other settings are ignored."""
    output = 'APT "";\nAPT::Architecture "amd64";\n' + fixture("apt_config_periodic.txt") + 'Unattended-Upgrade::Origins-Pattern "";\n'

    assert parse_apt_periodic(output) == ("1", "1")


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        pytest.param("", ("", ""), id="nothing-set"),
        pytest.param('APT::Periodic::Update-Package-Lists "0";\n', ("0", ""), id="disabled"),
        pytest.param('APT::Periodic::Unattended-Upgrade "always";\n', ("", "always"), id="interval-keyword"),
    ],
)
def test_apt_periodic_values_are_kept_as_set(output: str, expected: tuple[str, str]) -> None:
    """Synthetic: values are returned as configured; the report decides what counts as enabled."""
    assert parse_apt_periodic(output) == expected
