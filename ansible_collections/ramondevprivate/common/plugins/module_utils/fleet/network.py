# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Parse UFW status and rules and listening sockets.

Pure functions: they get command output or file content and never touch the system. Command output is
expected in a parsable (English) locale; the module sets it for every command.
"""

from __future__ import annotations

import binascii
import re
from typing import Final

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.data import is_number
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import (
    Family,
    Listener,
    Ufw,
    UfwRule,
    ufw_without_details,
)

_STATUS = re.compile(r"^Status:\s*(\S+)", re.MULTILINE)
_LOGGING = re.compile(r"^Logging:\s*(.+?)\s*$", re.MULTILINE)
_DEFAULT = re.compile(r"(\w+) \((incoming|outgoing|routed)\)")
_DEFAULT_LINE = re.compile(r"^Default:\s*(.+)$", re.MULTILINE)
_TUPLE = "### tuple ###"
# ufw writes 7 fields, or 9 with application profiles (backend_iptables.py, _write_rules)
_TUPLE_FIELDS: Final = (7, 9)
_SS_LINE = re.compile(r"^(?P<netid>\S+)\s+\S+\s+\d+\s+\d+\s+(?P<local>\S+)\s+\S+(?:\s+(?P<process>.*))?$")
_SS_PROCESS = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=')


# ufw status verbose


def parse_ufw_status(output: str) -> Ufw:
    """Status, logging and default policies from `ufw status verbose`; the rules come from the rule files."""
    status = _STATUS.search(output)
    if status is None:
        return ufw_without_details("unknown")
    state = status.group(1).lower()
    if state != "active":
        # an inactive ufw prints nothing but its status
        return ufw_without_details("inactive" if state == "inactive" else "unknown")

    ufw = ufw_without_details("active")
    logging = _LOGGING.search(output)
    ufw["logging"] = logging.group(1) if logging else ""
    defaults = _DEFAULT_LINE.search(output)
    for match in _DEFAULT.finditer(defaults.group(1) if defaults else ""):
        policy, chain = match.group(1), match.group(2)
        if chain == "incoming":
            ufw["default_incoming"] = policy
        elif chain == "outgoing":
            ufw["default_outgoing"] = policy
        else:
            ufw["default_routed"] = policy
    return ufw


# /etc/ufw/user.rules, /etc/ufw/user6.rules


def parse_ufw_rules(content: str, family: Family) -> list[UfwRule]:
    """Rules from the `### tuple ###` lines that ufw writes above the iptables rules it generates."""
    rules: list[UfwRule] = []
    for line in content.splitlines():
        if line.startswith(_TUPLE):
            rule = parse_ufw_tuple(line[len(_TUPLE) :], family)
            if rule is not None:
                rules.append(rule)
    return rules


def parse_ufw_tuple(text: str, family: Family) -> UfwRule | None:
    """Parse `action proto dport dst sport src [dapp sapp] direction[_iface] [comment=<hex>]`; None if malformed.

    Format as written by ufw's backend_iptables.py: route rules have the action `route:<action>`, a log option
    is appended as `_log`/`_log-all`, application profile names escape spaces as %20, and comments are hex.
    """
    body, _sep, comment = text.partition(" comment=")
    fields = body.split()
    if len(fields) not in _TUPLE_FIELDS:
        return None
    action, proto, to_port, to_address, from_port, from_address = fields[:6]
    app = fields[6].replace("%20", " ") if len(fields) == max(_TUPLE_FIELDS) and fields[6] != "-" else ""
    route = action.startswith("route:")
    action = action.removeprefix("route:").split("_")[0]
    direction, interface_in, interface_out = _direction(fields[-1])
    return {
        "action": action,
        "direction": direction,
        "route": route,
        "proto": proto,
        "to_port": to_port,
        "to_address": to_address,
        "from_port": from_port,
        "from_address": from_address,
        "app": app,
        "interface_in": interface_in,
        "interface_out": interface_out,
        "comment": _decode_comment(comment.strip()),
        "family": family,
    }


def _direction(field: str) -> tuple[str, str, str]:
    """Direction and interfaces from `in`, `in_eth0`, `out_eth0` or `in_eth0!out_eth1`."""
    interfaces = {"in": "", "out": ""}
    direction = field.split("_", maxsplit=1)[0]
    for part in field.split("!"):
        name, _sep, interface = part.partition("_")
        if name in interfaces:
            interfaces[name] = interface
    return direction, interfaces["in"], interfaces["out"]


def _decode_comment(value: str) -> str:
    if not value:
        return ""
    try:
        return bytes.fromhex(value).decode("utf-8", errors="replace")
    except (ValueError, binascii.Error):
        return value


# ss -H -t -u -l -n -p


def parse_ss(output: str) -> list[Listener]:
    """Listening TCP and bound UDP sockets; duplicates (one per worker process) are merged."""
    listeners: list[Listener] = []
    for line in output.splitlines():
        listener = parse_ss_line(line)
        if listener is not None and listener not in listeners:
            listeners.append(listener)
    return sorted(listeners, key=lambda item: (item["proto"], item["port"], item["address"], item["interface"]))


def parse_ss_line(line: str) -> Listener | None:
    """Parse one `ss` line; None for other socket types and unparsable lines."""
    match = _SS_LINE.match(line.strip())
    if match is None or match.group("netid") not in {"tcp", "udp"}:
        return None
    host, _sep, port = match.group("local").rpartition(":")
    if not is_number(port) or not host:
        return None
    address, interface = _split_host(host)
    return {
        "proto": match.group("netid"),
        "address": address,
        "interface": interface,
        "port": int(port),
        "processes": sorted(set(_SS_PROCESS.findall(match.group("process") or ""))),
    }


def _split_host(host: str) -> tuple[str, str]:
    """`[::]` → `::`; `127.0.0.53%lo` → (`127.0.0.53`, `lo`); `[fe80::1]%eth0` and `[fe80::1%eth0]` alike."""
    address, interface = host, ""
    if address.startswith("["):
        inner, _sep, rest = address[1:].partition("]")
        address, interface = inner, rest.removeprefix("%")
    if "%" in address:
        address, _sep, interface = address.partition("%")
    return address, interface
