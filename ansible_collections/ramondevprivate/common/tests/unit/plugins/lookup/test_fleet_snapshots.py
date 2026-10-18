# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the fleet_snapshots lookup (the loader itself is tested in test_stored.py)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest
from ansible.errors import AnsibleLookupError  # pyright: ignore[reportMissingTypeStubs] - no stubs

from ansible_collections.ramondevprivate.common.plugins.lookup.fleet_snapshots import LookupModule

if TYPE_CHECKING:
    from pathlib import Path


def test_returns_the_snapshots_of_the_data_dir(tmp_path: Path) -> None:
    """One term, the data dir: its decoded snapshots."""
    _size = (tmp_path / "host-a.json").write_text('{"host": "host-a"}')

    assert LookupModule().run([str(tmp_path)]) == [{"host": "host-a"}]


def test_damaged_file_is_a_lookup_error_with_its_path(tmp_path: Path) -> None:
    """Ansible shows the message, so it must name the file."""
    path = tmp_path / "host-a.json"
    _size = path.write_text("{")

    with pytest.raises(AnsibleLookupError, match=re.escape(str(path))):
        _snapshots = LookupModule().run([str(tmp_path)])


@pytest.mark.parametrize(
    "terms",
    [pytest.param([], id="none"), pytest.param(["/a", "/b"], id="two"), pytest.param([42], id="not-a-path")],
)
def test_exactly_one_data_dir(terms: list[object]) -> None:
    """Anything but one path is a usage error."""
    with pytest.raises(AnsibleLookupError, match="exactly one data directory"):
        _snapshots = LookupModule().run(terms)
