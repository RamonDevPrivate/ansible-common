# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Typed access to untyped data such as Ansible facts or JSON.

Facts come in as plain dicts and lists of unknown shape. These helpers narrow them to the
expected type and fall back to a default instead of raising, because a missing fact must
never fail a host.
"""

from collections.abc import Mapping, Sequence
from typing import cast

Data = Mapping[str, object]


def as_mapping(value: object) -> Data:
    """Return value as a mapping with string keys, or an empty mapping."""
    if isinstance(value, Mapping):
        return cast("Data", value)
    return {}


def as_list(value: object) -> list[object]:
    """Return value as a list, or an empty list (strings are not lists)."""
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return list(value)
    return []


def get_mapping(data: Data, key: str) -> Data:
    """Return data[key] as a mapping, or an empty mapping."""
    return as_mapping(data.get(key))


def get_list(data: Data, key: str) -> list[object]:
    """Return data[key] as a list, or an empty list."""
    return as_list(data.get(key))


def get_str(data: Data, key: str, default: str = "") -> str:
    """Return data[key] as a string, or the default."""
    value = data.get(key)
    return value if isinstance(value, str) else default


def is_number(text: str) -> bool:
    """Whether text is a plain ASCII number (str.isdigit also accepts "²", which int() rejects)."""
    return text.isascii() and text.isdecimal()


def get_int(data: Data, key: str, default: int = 0) -> int:
    """Return data[key] as an int (numeric strings are converted), or the default."""
    value = data.get(key)
    # bool is a subclass of int: without this check True would pass as an int and end up as `true` in the JSON
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str) and is_number(value.strip()):
        return int(value)
    return default
