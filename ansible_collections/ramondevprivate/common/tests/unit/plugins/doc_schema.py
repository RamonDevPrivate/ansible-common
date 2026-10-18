# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Compare documented return values (RETURN `contains:`) with the TypedDicts they describe."""

from __future__ import annotations

from types import NoneType
from typing import TYPE_CHECKING, Literal, cast, get_args, get_origin, get_type_hints, is_typeddict

import yaml

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import as_mapping

if TYPE_CHECKING:
    from collections.abc import Collection

    from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import Data


def _args(hint: object) -> tuple[object, ...]:
    args: tuple[object, ...] = get_args(hint)
    return args


def without_none(hint: object) -> object:
    """`X | None` -> `X` (None is documented in the description, not in the type)."""
    rest = [arg for arg in _args(hint) if arg is not NoneType]
    if get_origin(hint) is not Literal and len(rest) == 1 < len(_args(hint)):
        return rest[0]
    return hint


def doc_type(hint: object) -> str:
    """The RETURN `type` that documents a type hint."""
    if is_typeddict(hint):
        return "dict"
    if get_origin(hint) is list:
        return "list"
    if get_origin(hint) is Literal:
        return doc_type(type(_args(hint)[0]))
    return getattr(hint, "__name__", repr(hint))


def load_yaml(text: str) -> object:
    """Parse a doc string or doc file."""
    return cast("object", yaml.safe_load(text))


def doc_mismatches(contains: object, typed: object, path: str = "", opaque: Collection[str] = ()) -> list[str]:
    """Differences between a documented `contains:` mapping and a TypedDict, at every level.

    Checks the keys, `type`, `elements` and `choices` (for Literal types). Keys in `opaque` (dotted paths) only have
    their own type checked, not their contents.
    """
    documented = as_mapping(contains)
    hints: dict[str, object] = get_type_hints(typed)
    problems: list[str] = []
    if set(documented) != set(hints):
        problems.append(f"{path or '.'}: documented {sorted(documented)}, schema {sorted(hints)}")
    for key in sorted(set(documented) & set(hints)):
        where = f"{path}.{key}" if path else key
        problems += _entry_mismatches(as_mapping(documented[key]), hints[key], where, opaque)
    return problems


def _entry_mismatches(entry: Data, hint: object, where: str, opaque: Collection[str]) -> list[str]:
    problems: list[str] = []
    hint = without_none(hint)
    if entry.get("type") != doc_type(hint):
        problems.append(f"{where}: documented type {entry.get('type')}, schema {doc_type(hint)}")
    if get_origin(hint) is list:
        hint = without_none(_args(hint)[0])
        if entry.get("elements") != doc_type(hint):
            problems.append(f"{where}: documented elements {entry.get('elements')}, schema {doc_type(hint)}")
    if get_origin(hint) is Literal:
        if entry.get("choices") != list(_args(hint)):
            problems.append(f"{where}: documented choices {entry.get('choices')}, schema {list(_args(hint))}")
    elif "choices" in entry:
        problems.append(f"{where}: documented choices, but the schema allows any value")
    if where in opaque:
        return problems
    if is_typeddict(hint):
        problems += doc_mismatches(entry.get("contains"), hint, where, opaque)
    elif "contains" in entry:
        problems.append(f"{where}: documented contains, but the schema has no keys")
    return problems
