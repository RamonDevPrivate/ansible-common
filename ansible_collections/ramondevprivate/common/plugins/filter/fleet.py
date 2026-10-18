# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Filters of the fleet_inventory role."""

from collections.abc import Callable

from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.markdown import md_escape
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.probe import (
    exposures,
    probe_errors,
    probe_targets,
)
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.report import build_report
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.snapshot import (
    build_snapshot,
    mark_unreached,
)


class FilterModule:
    """Fleet inventory filters."""

    def filters(self) -> dict[str, Callable[..., object]]:
        """Map filter names to functions."""
        return {
            "fleet_snapshot": build_snapshot,
            "fleet_report": build_report,
            "fleet_probe_targets": probe_targets,
            "fleet_exposure": exposures,
            "fleet_probe_errors": probe_errors,
            "md_escape": md_escape,
            "fleet_unreached": mark_unreached,
        }
