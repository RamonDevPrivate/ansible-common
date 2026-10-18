# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Read fail2ban and auto-update settings from untyped data (module result or stored JSON), runs on the controller."""

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import as_list, as_mapping, get_str
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    AutoUpdates,
    Exposure,
    ExposureState,
    Fail2ban,
    unknown_auto_updates,
)


def parse_fail2ban(value: object) -> Fail2ban:
    """fail2ban from untyped data; jails stay None if unknown."""
    data = as_mapping(value)
    jails = data.get("jails")
    return {
        "state": get_str(data, "state", "unknown"),
        "jails": None if jails is None else [j for j in as_list(jails) if isinstance(j, str)],
    }


def parse_auto_updates(value: object) -> AutoUpdates:
    """Auto-update settings from untyped data; missing values stay unknown (None)."""
    data = as_mapping(value)
    if not data:
        return unknown_auto_updates()
    installed = data.get("installed")
    return {
        "installed": installed if isinstance(installed, bool) else None,
        "update_lists": _optional_str(data.get("update_lists")),
        "unattended_upgrade": _optional_str(data.get("unattended_upgrade")),
        "timer": get_str(data, "timer"),
        "last_success": _optional_str(data.get("last_success")),
    }


def parse_exposure(value: object) -> Exposure:
    """Exposure from untyped data; anything unexpected is unknown."""
    data = as_mapping(value)
    return {
        "state": _exposure_state(get_str(data, "state")),
        "checked_at": get_str(data, "checked_at"),
        "answered": [a for a in as_list(data.get("answered")) if isinstance(a, str)],
    }


def _exposure_state(value: str) -> ExposureState:
    if value == "public":
        return "public"
    if value == "internal":
        return "internal"
    return "unknown"


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None
