# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for reading the stored snapshots from the data dir."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.stored import (
    StoredSnapshotError,
    load_snapshots,
)

if TYPE_CHECKING:
    from pathlib import Path


def write(path: Path, text: str) -> None:
    """Create a snapshot file."""
    _size = path.write_text(text, encoding="utf-8")


def test_snapshots_in_file_name_order(tmp_path: Path) -> None:
    """Every JSON file, decoded, sorted by name (stable output, whatever order the filesystem lists them in)."""
    write(tmp_path / "host-a.json", '{"host": "host-a"}')
    write(tmp_path / "host-b.json", '{"host": "host-b"}')

    assert load_snapshots(str(tmp_path)) == [{"host": "host-a"}, {"host": "host-b"}]


def test_other_files_are_ignored(tmp_path: Path) -> None:
    """Only *.json files are snapshots (e.g. an editor's backup file is not)."""
    write(tmp_path / "host-a.json~", "not json")

    assert load_snapshots(str(tmp_path)) == []


def test_missing_data_dir_is_empty(tmp_path: Path) -> None:
    """The first run, also in check mode: nothing stored yet, no error."""
    assert load_snapshots(str(tmp_path / "missing")) == []


def test_tilde_is_expanded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A data dir like ~/.local/share/fleet-inventory (as in the README) is found."""
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "data").mkdir()
    write(tmp_path / "data" / "host-a.json", "{}")

    assert load_snapshots("~/data") == [{}]


def test_snapshot_path_that_is_no_file_names_it(tmp_path: Path) -> None:
    """A directory called host-a.json can't be read: the error names it."""
    (tmp_path / "host-a.json").mkdir()

    with pytest.raises(StoredSnapshotError, match=re.escape(str(tmp_path / "host-a.json"))):
        _snapshots = load_snapshots(str(tmp_path))


def test_unknown_user_in_data_dir_is_an_error() -> None:
    """`~nobody-here/data` can't be expanded: a clear error instead of a traceback."""
    with pytest.raises(StoredSnapshotError, match="can't be resolved"):
        _snapshots = load_snapshots("~fleet-no-such-user/data")


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        pytest.param('{"host": ', "Expecting value", id="invalid-json"),
        pytest.param(b"\xff\xfe", "codec can't decode", id="not-utf-8"),
    ],
)
def test_unreadable_file_names_the_file(tmp_path: Path, content: str | bytes, reason: str) -> None:
    """A damaged file stops the run with its path and the reason."""
    path = tmp_path / "host-a.json"
    _size = path.write_bytes(content.encode() if isinstance(content, str) else content)

    with pytest.raises(StoredSnapshotError, match=f"{re.escape(str(path))}.*{reason}"):
        _snapshots = load_snapshots(str(tmp_path))
