# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Auto-update status and the needs-attention findings (runs on the controller)."""

from collections.abc import Callable
from datetime import datetime
from typing import Final, Literal, TypedDict, get_args

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import AutoUpdates, Snapshot, User

# Rule ids of the needs-attention list, in the order findings are listed. The list is fixed: everything on it needs
# action. Docker ports that bypass UFW are not on it; the ports table on the server page marks them.
AttentionRule = Literal["ufw_off", "fail2ban_public", "auto_updates", "sudo_full_nopasswd", "key_without_comment"]
ATTENTION_RULES: Final[tuple[AttentionRule, ...]] = get_args(AttentionRule)
AddFinding = Callable[[AttentionRule, str, str], None]  # rule, finding, detail
DISABLED_VALUES: Final = frozenset({"", "0"})
ENABLED_TIMER: Final = frozenset({"enabled", "enabled-runtime"})


class Finding(TypedDict):
    """One entry of the needs-attention list."""

    host: str
    rule: AttentionRule
    finding: str
    detail: str


def auto_update_status(auto_updates: AutoUpdates, collected_at: str, max_age_days: int) -> str:
    """`ok`, `not configured`, `no successful run in N days`, `no successful run recorded` or `unknown`.

    Configured means: unattended-upgrades installed, both APT::Periodic settings enabled, apt-daily-upgrade.timer
    enabled. The age of the last success is measured at collection time, so the status doesn't change between runs.
    """
    settings = (auto_updates["installed"], auto_updates["update_lists"], auto_updates["unattended_upgrade"])
    installed, lists, upgrade = settings
    timer = auto_updates["timer"]
    if installed is None or lists is None or upgrade is None or not timer:
        return "unknown"
    if not installed or lists in DISABLED_VALUES or upgrade in DISABLED_VALUES or timer not in ENABLED_TIMER:
        return "not configured"
    last = auto_updates["last_success"]
    if not last:
        return "no successful run recorded"
    try:
        age = datetime.fromisoformat(collected_at) - datetime.fromisoformat(last)
    except (ValueError, TypeError):
        return "unknown"
    return f"no successful run in {max_age_days} days" if age.days >= max_age_days else "ok"


def findings(snapshot: Snapshot, update_status: str) -> list[Finding]:
    """Everything on one host that needs a look.

    Args:
        snapshot: The host's snapshot.
        update_status: Result of auto_update_status.
    """
    host = snapshot["host"]
    result: list[Finding] = []

    def add(rule: AttentionRule, finding: str, detail: str) -> None:
        result.append({"host": host, "rule": rule, "finding": finding, "detail": detail})

    ufw = snapshot["ufw"]
    if ufw["state"] in {"inactive", "not installed"}:
        add("ufw_off", "UFW not active", ufw["state"])
    fail2ban = snapshot["fail2ban"]
    exposure = snapshot.get("exposure")
    if (
        exposure is not None and exposure["state"] == "public" and fail2ban["state"] not in {"active", "unknown"}  # unknown (no root) is no finding
    ):
        add("fail2ban_public", "fail2ban not running on a public host", fail2ban["state"])
    if update_status not in {"ok", "unknown"}:
        add("auto_updates", "Auto-updates", update_status)
    for user in snapshot["users"]:
        _user_findings(user, add)
    return result


def _user_findings(user: User, add: AddFinding) -> None:
    sudo = user["sudo"]
    if sudo["level"] == "full" and sudo["nopasswd"]:
        add("sudo_full_nopasswd", "Full sudo without password", user["name"])
    for key in user["authorized_keys"] or []:
        if not key["comment"]:
            add("key_without_comment", "SSH key without comment", f"{user['name']}: {key['fingerprint']}")
