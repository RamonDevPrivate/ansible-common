# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the RETURN-vs-TypedDict comparison the doc drift tests rely on."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, TypedDict

import pytest

from ansible_collections.ramondevprivate.common.tests.unit.plugins.doc_schema import doc_mismatches

if TYPE_CHECKING:
    from collections.abc import Callable

Doc = dict[str, dict[str, object]]


class Item(TypedDict):
    """A nested entry."""

    name: str


class Sample(TypedDict):
    """A schema with every kind of field the docs describe."""

    count: int
    kind: Literal["a", "b"]
    items: list[Item]
    note: str | None


def documented() -> Doc:
    """A `contains:` block that documents Sample correctly."""
    return {
        "count": {"type": "int"},
        "kind": {"type": "str", "choices": ["a", "b"]},
        "items": {"type": "list", "elements": "dict", "contains": {"name": {"type": "str"}}},
        "note": {"type": "str"},
    }


def test_correct_docs_have_no_mismatches() -> None:
    """Keys, types, elements, choices and nested keys as in the schema; None is not a type of its own."""
    assert doc_mismatches(documented(), Sample) == []


def missing_key(doc: Doc) -> None:
    """Drop a documented key."""
    del doc["count"]


def extra_key(doc: Doc) -> None:
    """Document a key the schema doesn't have."""
    doc["gone"] = {"type": "str"}


def wrong_type(doc: Doc) -> None:
    """Document an int as a string."""
    doc["count"]["type"] = "str"


def wrong_elements(doc: Doc) -> None:
    """Document a list of dicts as a list of strings."""
    doc["items"]["elements"] = "str"


def wrong_choices(doc: Doc) -> None:
    """Document other values than the Literal allows."""
    doc["kind"]["choices"] = ["a", "c"]


def choices_without_literal(doc: Doc) -> None:
    """Document choices for a free-text field."""
    doc["note"]["choices"] = ["x"]


def nested_missing_key(doc: Doc) -> None:
    """Drop a key inside a list's elements."""
    doc["items"]["contains"] = {}


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        pytest.param(missing_key, "documented ['items', 'kind', 'note'], schema ['count', 'items', 'kind', 'note']"),
        pytest.param(extra_key, "documented ['count', 'gone', 'items', 'kind', 'note']"),
        pytest.param(wrong_type, "count: documented type str, schema int"),
        pytest.param(wrong_elements, "items: documented elements str, schema dict"),
        pytest.param(wrong_choices, "kind: documented choices ['a', 'c'], schema ['a', 'b']"),
        pytest.param(choices_without_literal, "note: documented choices, but the schema allows any value"),
        pytest.param(nested_missing_key, "items: documented [], schema ['name']"),
    ],
)
def test_each_kind_of_drift_is_reported(change: Callable[[Doc], None], problem: str) -> None:
    """A drift test can only pass silently if the comparison misses something: every kind is named."""
    doc = documented()
    change(doc)

    assert any(problem in mismatch for mismatch in doc_mismatches(doc, Sample))


def test_opaque_keys_only_check_their_own_type() -> None:
    """An opaque key (e.g. the report's per-host view) may leave its contents undocumented."""
    doc = documented()
    doc["items"]["contains"] = {}

    assert doc_mismatches(doc, Sample, opaque=frozenset({"items"})) == []
