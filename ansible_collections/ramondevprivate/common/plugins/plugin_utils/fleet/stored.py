# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Read the stored snapshots from the data dir (runs on the controller)."""

import json
from pathlib import Path
from typing import cast


class StoredSnapshotError(ValueError):
    """A snapshot file that can't be read or isn't JSON; the message names the file."""


def load_snapshots(data_dir: str) -> list[object]:
    """Every `*.json` in data_dir, decoded, in file name order; [] if the directory doesn't exist yet.

    `~` is expanded (an unknown `~user` is an error). Whether a decoded value is a valid snapshot is decided later
    (parse_snapshot); this only makes sure that a damaged file stops the run with its name instead of an anonymous
    JSON error.
    """
    try:
        directory = Path(data_dir).expanduser()
    except RuntimeError as error:  # ~user without such a user
        message = f"data dir {data_dir} can't be resolved: {error}"
        raise StoredSnapshotError(message) from error
    if not directory.is_dir():
        return []
    snapshots: list[object] = []
    for path in sorted(directory.glob("*.json")):
        try:
            snapshots.append(cast("object", json.loads(path.read_text(encoding="utf-8"))))  # untyped JSON
        except (OSError, UnicodeDecodeError, ValueError) as error:  # JSONDecodeError is a ValueError
            message = f"stored snapshot {path} can't be read: {error}"
            raise StoredSnapshotError(message) from error
    return snapshots
