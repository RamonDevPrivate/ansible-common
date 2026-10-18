# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the filter plugin registration and docs."""

import inspect
from collections.abc import Callable
from pathlib import Path
from typing import cast, get_args, get_origin, get_type_hints

import pytest

from ansible_collections.ramondevprivate.common.plugins.filter.fleet import FilterModule
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import as_mapping
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.markdown import md_escape
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.probe import (
    exposures,
    probe_errors,
    probe_targets,
)
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.report import (
    DEFAULT_INACTIVE_DAYS,
    DEFAULT_UPDATE_MAX_AGE_DAYS,
    OPTION_KEYS,
    Report,
    build_report,
)
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.security_view import ATTENTION_RULES
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.snapshot import (
    build_snapshot,
    mark_unreached,
)
from ansible_collections.ramondevprivate.common.tests.unit.plugins.doc_schema import (
    doc_mismatches,
    doc_type,
    load_yaml,
    without_none,
)

FILTER_DOCS = Path(__file__).parents[4] / "plugins" / "filter"
FILTERS = FilterModule().filters()


def test_filter_names_used_by_the_role_are_registered() -> None:
    """The role calls these names; each maps to its function."""
    filters = FilterModule().filters()

    assert filters["fleet_snapshot"] is build_snapshot
    assert filters["fleet_report"] is build_report
    assert filters["fleet_probe_targets"] is probe_targets
    assert filters["fleet_exposure"] is exposures
    assert filters["fleet_probe_errors"] is probe_errors
    assert filters["md_escape"] is md_escape
    assert filters["fleet_unreached"] is mark_unreached
    assert len(filters) == 7, "a new filter needs a line here and a doc file"


def filter_doc(name: str, section: str) -> dict[str, object]:
    """One section (DOCUMENTATION, RETURN) of a filter's doc file."""
    doc = load_yaml((FILTER_DOCS / f"{name}.yml").read_text())
    return dict(as_mapping(as_mapping(doc).get(section)))


def parameters(function: Callable[..., object]) -> list[inspect.Parameter]:
    """The function's parameters; the first one is the filter's input."""
    return list(inspect.signature(function).parameters.values())


@pytest.mark.parametrize("name", sorted(FILTERS))
def test_filter_doc_names_the_filter(name: str) -> None:
    """Every registered filter has its doc file, and the doc names that filter."""
    assert filter_doc(name, "DOCUMENTATION").get("name") == name


@pytest.mark.parametrize("name", sorted(FILTERS))
def test_filter_doc_options_match_the_parameters(name: str) -> None:
    """_input is the first parameter, the other options are the others by name; required means no default."""
    options = as_mapping(filter_doc(name, "DOCUMENTATION").get("options"))
    params = parameters(FILTERS[name])
    expected = {
        "_input" if i == 0 else p.name: cast("object", p.default) is inspect.Parameter.empty  # inspect is untyped here
        for i, p in enumerate(params)
    }

    assert {key: as_mapping(value).get("required") is True for key, value in options.items()} == expected


@pytest.mark.parametrize("name", sorted(FILTERS))
def test_filter_doc_option_types_match_typed_parameters(name: str) -> None:
    """Where a parameter has a concrete type (not `object`, which takes untyped data), the doc names that type."""
    options = as_mapping(filter_doc(name, "DOCUMENTATION").get("options"))
    hints = cast("dict[str, object]", get_type_hints(FILTERS[name]))  # get_type_hints returns Any values
    for index, param in enumerate(parameters(FILTERS[name])):
        hint = without_none(hints.get(param.name, object))
        if hint is object:
            continue
        option = as_mapping(options.get("_input" if index == 0 else param.name))
        assert option.get("type") == doc_type(hint), f"{name}: {param.name}"


@pytest.mark.parametrize("name", sorted(FILTERS))
def test_filter_doc_positional_order_matches_the_parameters(name: str) -> None:
    """`positional` lists the parameters after the input, in the function's order."""
    positional = filter_doc(name, "DOCUMENTATION").get("positional")
    names = [p.name for p in parameters(FILTERS[name])[1:]]

    assert [part.strip() for part in str(positional or "").split(",") if part.strip()] == names


@pytest.mark.parametrize("name", sorted(FILTERS))
def test_filter_doc_return_type_matches_the_annotation(name: str) -> None:
    """RETURN `type` (and `elements` for lists) is what the function is annotated to return."""
    value = as_mapping(filter_doc(name, "RETURN").get("_value"))
    hint = cast("object", get_type_hints(FILTERS[name])["return"])  # get_type_hints returns Any values

    assert value.get("type") == doc_type(hint)
    if get_origin(hint) is list:
        assert value.get("elements") == doc_type(cast("object", get_args(hint)[0]))


def report_doc(section: str) -> dict[str, object]:
    """One section (DOCUMENTATION, RETURN) of fleet_report.yml."""
    doc = load_yaml((FILTER_DOCS / "fleet_report.yml").read_text())
    return dict(as_mapping(as_mapping(doc).get(section)))


def test_report_options_doc_matches_code() -> None:
    """The documented options are the ones parse_options accepts, with the same defaults."""
    documented = as_mapping(report_doc("DOCUMENTATION").get("options"))
    options = as_mapping(as_mapping(documented.get("options")).get("suboptions"))

    assert set(options) == OPTION_KEYS
    assert as_mapping(options["inactive_days"]).get("default") == DEFAULT_INACTIVE_DAYS
    assert as_mapping(options["update_max_age_days"]).get("default") == DEFAULT_UPDATE_MAX_AGE_DAYS
    assert as_mapping(options["stopped_containers"]).get("default") is True


def test_report_return_doc_matches_schema() -> None:
    """RETURN documents every key of the report; the per-host view is internal to the templates."""
    value = as_mapping(report_doc("RETURN").get("_value"))

    assert value.get("type") == "dict"
    assert doc_mismatches(value.get("contains"), Report, opaque=frozenset({"hosts"})) == []


def test_report_documents_every_attention_rule() -> None:
    """The documented rule ids of the attention list are the ones the code produces, in its order."""
    contains = as_mapping(as_mapping(report_doc("RETURN").get("_value")).get("contains"))
    attention = as_mapping(as_mapping(contains.get("attention")).get("contains"))

    assert as_mapping(attention.get("rule")).get("choices") == list(ATTENTION_RULES)
