# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ping targets and exposure from the probe results (runs on the controller).

A host is public if any of its public addresses answers ping from the probe host, internal if none answers or it
has no public address. If a ping could not be sent (probe host unreachable, no IPv6 there, ...) and nothing
answered, the result is not trusted: the host keeps its stored exposure, or is unknown.
"""

from collections.abc import Mapping
from typing import TypedDict

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import (
    as_list,
    as_mapping,
    get_int,
    get_str,
)
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    Exposure,
    ExposureState,
    Snapshot,
)
from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.snapshot import parse_snapshot

PING_ANSWERED = 0
PING_NO_ANSWER = 1  # iputils ping: 1 = no reply, 2 = other error (e.g. network unreachable)


class Target(TypedDict):
    """One address to ping."""

    host: str
    address: str
    family: str  # ipv4, ipv6


def probe_targets(current: object) -> list[Target]:
    """Public addresses of the hosts collected in this run, de-duplicated per host."""
    targets: list[Target] = []
    for snapshot in _snapshots(current):
        for address in snapshot["addresses"]:
            target: Target = {"host": snapshot["host"], "address": address["address"], "family": address["family"]}
            if not address["private"] and target not in targets:
                targets.append(target)
    return targets


def exposures(current: object, results: object, stored: object) -> dict[str, Exposure]:
    """Exposure per host collected in this run.

    Args:
        current: Snapshots collected in this run.
        results: The registered loop results of the ping task (target, rc, unreachable, skipped); empty if no probe
            ran.
        stored: Snapshots read from the data directory, for hosts that could not be probed.
    """
    previous = {s["host"]: s["exposure"] for s in _snapshots(stored) if "exposure" in s}
    outcomes: dict[str, list[tuple[str, str]]] = {}
    for item in as_list(results):
        result = as_mapping(item)
        target = _target(result)
        outcomes.setdefault(get_str(target, "host"), []).append((get_str(target, "address"), _outcome(result)))

    exposure: dict[str, Exposure] = {}
    for snapshot in _snapshots(current):
        host = snapshot["host"]
        has_public = any(t["host"] == host for t in probe_targets([snapshot]))
        pings = outcomes.get(host, [])
        answered = [address for address, outcome in pings if outcome == "answered"]
        if answered:
            exposure[host] = _exposure("public", snapshot, answered)
        elif not has_public or (pings and all(outcome == "no answer" for _address, outcome in pings)):
            exposure[host] = _exposure("internal", snapshot, [])
        else:  # not probed, or a ping could not be sent
            exposure[host] = previous.get(host) or {"state": "unknown", "checked_at": "", "answered": []}
    return exposure


def probe_errors(results: object) -> list[str]:
    """`address (host): reason` for every ping that could not be sent (unreachable probe, missing ping, ...)."""
    errors: list[str] = []
    for item in as_list(results):
        result = as_mapping(item)
        if _outcome(result) != "error" or result.get("skipped") is True:
            continue
        target = _target(result)
        reason = get_str(result, "msg") or get_str(result, "stderr") or f"rc {get_int(result, 'rc', -1)}"
        errors.append(f"{get_str(target, 'address')} ({get_str(target, 'host')}): {reason.strip()}")
    return errors


def _target(result: Mapping[str, object]) -> Mapping[str, object]:
    # with loop_control.loop_var the item is stored under that name, which ansible_loop_var names
    return as_mapping(result.get(get_str(result, "ansible_loop_var", "item")))


def _outcome(result: object) -> str:
    data = as_mapping(result)
    if data.get("unreachable") is True or data.get("skipped") is True:
        return "error"
    rc = get_int(data, "rc", -1)
    if rc == PING_ANSWERED:
        return "answered"
    return "no answer" if rc == PING_NO_ANSWER else "error"


def _exposure(state: ExposureState, snapshot: Snapshot, answered: list[str]) -> Exposure:
    return {"state": state, "checked_at": snapshot["collected_at"], "answered": answered}


def _snapshots(value: object) -> list[Snapshot]:
    return [s for s in (parse_snapshot(item) for item in as_list(value)) if s is not None]
