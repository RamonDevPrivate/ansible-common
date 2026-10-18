# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for typed access to untyped data."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import (
    as_list,
    as_mapping,
    get_int,
    get_list,
    get_mapping,
    get_str,
    is_number,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import Data

DEFAULT = -1


# as_mapping


def test_as_mapping_accepts_mappings() -> None:
    """A mapping comes back as it is."""
    assert as_mapping({"a": 1}) == {"a": 1}


@pytest.mark.parametrize("value", [pytest.param(["a"], id="list"), pytest.param("a", id="string"), pytest.param(None, id="none")])
def test_as_mapping_rejects_non_mappings(value: object) -> None:
    """Anything that is not a mapping becomes an empty mapping."""
    assert as_mapping(value) == {}


# as_list


@pytest.mark.parametrize(
    ("value", "expected"),
    [pytest.param(["a", "b"], ["a", "b"], id="list"), pytest.param(("a", "b"), ["a", "b"], id="tuple")],
)
def test_as_list_accepts_sequences(value: object, expected: list[object]) -> None:
    """Lists and tuples become lists."""
    assert as_list(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("abc", id="string"),
        pytest.param(b"abc", id="bytes"),
        pytest.param({"a": 1}, id="mapping"),
        pytest.param(None, id="none"),
    ],
)
def test_as_list_rejects_everything_else(value: object) -> None:
    """A string is a sequence, but never a list of facts; mappings and None aren't lists either."""
    assert as_list(value) == []


# get_mapping, get_list, get_str


def test_get_mapping_accepts_a_mapping() -> None:
    """The nested mapping is returned."""
    assert get_mapping({"k": {"a": 1}}, "k") == {"a": 1}


def test_get_mapping_rejects_a_non_mapping() -> None:
    """A list under the key gives an empty mapping."""
    assert get_mapping({"k": ["a"]}, "k") == {}


def test_get_list_accepts_a_list() -> None:
    """The nested list is returned."""
    assert get_list({"k": ["a"]}, "k") == ["a"]


def test_get_list_rejects_a_string() -> None:
    """A string under the key gives an empty list."""
    assert get_list({"k": "a"}, "k") == []


def test_get_str_accepts_a_string() -> None:
    """The string is returned unchanged."""
    assert get_str({"k": " a "}, "k", "default") == " a "


@pytest.mark.parametrize("value", [pytest.param(1, id="int"), pytest.param(None, id="none")])
def test_get_str_rejects_non_strings(value: object) -> None:
    """Only strings are accepted; a number is not turned into text."""
    assert get_str({"k": value}, "k", "default") == "default"


@pytest.mark.parametrize(
    ("getter", "expected"),
    [
        pytest.param(get_int, 0, id="get_int"),
        pytest.param(get_str, "", id="get_str"),
        pytest.param(get_list, [], id="get_list"),
        pytest.param(get_mapping, {}, id="get_mapping"),
    ],
)
def test_missing_key_gives_the_default(getter: Callable[[Data, str], object], expected: object) -> None:
    """A missing fact never raises."""
    assert getter({}, "k") == expected


# get_int and is_number


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(4, 4, id="int"),
        pytest.param("24", 24, id="digit-string"),
        pytest.param(" 8 ", 8, id="spaces"),
        pytest.param("\t8\n", 8, id="tab-and-newline"),
        pytest.param("007", 7, id="leading-zeros"),
    ],
)
def test_get_int_accepts_ints_and_digit_strings(value: object, expected: int) -> None:
    """Ansible facts report some numbers as strings, e.g. an IP prefix; surrounding whitespace doesn't matter."""
    assert get_int({"k": value}, "k", DEFAULT) == expected


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(True, id="true"),
        pytest.param(False, id="false"),
        pytest.param("-1", id="negative-string"),
        pytest.param("+8", id="plus-sign"),
        pytest.param("4.5", id="float-string"),
        pytest.param(4.5, id="float"),
        pytest.param(None, id="none"),
        pytest.param("", id="empty"),
        pytest.param(" ", id="blank"),
        pytest.param("one", id="word"),
        pytest.param("1 2", id="two-numbers"),
        pytest.param("²", id="superscript-digit"),
        pytest.param("٣", id="arabic-indic-digit"),
    ],
)
def test_get_int_rejects_everything_else(value: object) -> None:
    """Anything that is not clearly an int gives the default instead of a guess (a bool is an int in Python)."""
    assert get_int({"k": value}, "k", DEFAULT) == DEFAULT


@pytest.mark.parametrize("text", [pytest.param("0", id="zero"), pytest.param("65535", id="port")])
def test_is_number_accepts_ascii_digits(text: str) -> None:
    """Plain ASCII digits are a number."""
    assert is_number(text)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("", id="empty"),
        pytest.param("²", id="superscript"),
        pytest.param("1a", id="mixed"),
        pytest.param(" 1", id="space"),
    ],
)
def test_is_number_rejects_everything_else(text: str) -> None:
    """`str.isdigit` would accept "²", which int() rejects; whitespace is the caller's business."""
    assert not is_number(text)
