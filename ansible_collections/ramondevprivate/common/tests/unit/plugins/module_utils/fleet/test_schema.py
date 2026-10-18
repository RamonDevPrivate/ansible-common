# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the fleet result schema."""

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import SCHEMA_VERSION, empty_info


def test_empty_info_carries_schema_version() -> None:
    """The result skeleton always states which result format it uses."""
    assert empty_info()["schema_version"] == SCHEMA_VERSION
