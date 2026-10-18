# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Parse fail2ban and APT periodic settings.

Pure functions: they get command output and never touch the system. Command output is expected in a parsable
(English) locale; the module sets it for every command.
"""

from __future__ import annotations

import re

_JAIL_LIST = re.compile(r"^\W*Jail list:\s*(.*)$", re.MULTILINE)
_APT_SETTING = re.compile(r'^(?P<key>[\w:-]+) "(?P<value>[^"]*)";$', re.MULTILINE)

UPDATE_LISTS = "APT::Periodic::Update-Package-Lists"
UNATTENDED_UPGRADE = "APT::Periodic::Unattended-Upgrade"


def parse_fail2ban_jails(output: str) -> list[str] | None:
    """Jail names from `fail2ban-client status`; None if the output has no jail list."""
    match = _JAIL_LIST.search(output)
    if match is None:
        return None
    return [jail.strip() for jail in match.group(1).split(",") if jail.strip()]


def parse_apt_periodic(output: str) -> tuple[str, str]:
    """Update-Package-Lists and Unattended-Upgrade from `apt-config dump`; "" if a setting is missing."""
    settings = {match.group("key"): match.group("value") for match in _APT_SETTING.finditer(output)}
    return settings.get(UPDATE_LISTS, ""), settings.get(UNATTENDED_UPGRADE, "")
