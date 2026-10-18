# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Checks of what a run wrote, one subcommand per step of runme.sh.

check_pages.py checks that pages are well-formed; this checks that the run put the right data and the right content
on them. Only what the unit tests can't see is checked here: that values reach the JSON and the pages through the
role's tasks and templates. Exits non-zero (AssertionError) at the first failed check.

Usage: python check_run.py COMMAND PATH
"""

import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

import yaml

FILES = Path(__file__).parent / "files"
UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")  # as in check_pages.py: an escaped \| belongs to the cell
HOST_LINK = re.compile(r"\[\[([^\]|#]+)")


def load(path: Path) -> dict[str, object]:
    """A JSON object from a snapshot or fixture file."""
    return cast("dict[str, object]", json.loads(path.read_text()))


def rows(page: Path, first_cell: str) -> list[str]:
    """Table rows of a page whose first cell is first_cell."""
    return [line for line in page.read_text().splitlines() if line.startswith(f"| {first_cell} ")]


def frontmatter(page: Path) -> dict[str, object]:
    """The page's YAML frontmatter."""
    return cast("dict[str, object]", yaml.safe_load(page.read_text().split("---\n")[1]))


def cells(row: str) -> list[str]:
    """The cells of a table row; escaped pipes belong to the cell."""
    return [cell.strip() for cell in UNESCAPED_PIPE.split(row.strip())[1:-1]]


def section(page: list[str], heading: str) -> list[str]:
    """The lines below a `## heading`, up to the next one."""
    start = page.index(f"## {heading}") + 1
    return page[start : next((i for i in range(start, len(page)) if page[i].startswith("## ")), len(page))]


def overview_cells(overview: list[str], column: str) -> dict[str, str]:
    """One column of the overview's Servers table, by host."""
    table = [line for line in section(overview, "Servers") if line.startswith("|")]
    assert table, "Servers table missing"
    header = cells(table[0])
    assert column in header, f"Servers table has no column {column!r}: {header}"
    found: dict[str, str] = {}
    for row in table[2:]:
        link = HOST_LINK.search(row)
        assert link, f"Servers row without host link: {row}"
        found[link.group(1)] = cells(row)[header.index(column)]
    return found


def stored(data: Path) -> None:
    """Step 2: reached hosts are stored as collected (plus exposure), the unreached one is kept and marked."""
    assert load(data / "host-a.json").get("system", {}) == load(FILES / "current/host-a.json")["system"], "replaced"
    host_b = load(data / "host-b.json")
    assert host_b.pop("exposure"), "the probe adds the exposure"
    assert host_b == load(FILES / "current/host-b.json"), "reached host stored as collected"
    host_c = load(data / "host-c.json")
    assert host_c.pop("unreached_since"), "unreached host is marked"
    assert host_c == load(FILES / "stored/host-c.json"), "unreached host keeps its snapshot"


def exposures(data: Path) -> None:
    """Step 2: host-b answered on IPv4, host-a didn't answer, host-c (not reached) has no exposure."""
    found = {host: load(data / f"{host}.json").get("exposure") for host in ("host-a", "host-b", "host-c")}
    assert found["host-b"] == {"state": "public", "checked_at": "2026-10-09T13:09:00Z", "answered": ["198.51.100.42"]}
    assert cast("dict[str, object]", found["host-a"])["state"] == "internal", found
    assert found["host-c"] is None, "a host that was not reached keeps its stored snapshot"


def pages(vault: Path) -> None:
    """Step 2: the templates put each kind of value on the pages."""
    servers = vault / "Servers"
    host_a, host_b = servers / "host-a.md", servers / "host-b.md"
    overview = (vault / "Overview.md").read_text().splitlines()

    assert any("**yes**" in row for row in rows(host_b, "8080/tcp")), "ports table: rootful bypass flagged"
    assert rows(host_b, "old"), "containers table: stopped container listed by default"
    assert any(cells(row)[1].startswith("active") for row in rows(host_a, "fail2ban")), "security section rendered"
    assert overview_cells(overview, "fail2ban")["host-c"] == "active", "unreached host (host-c): stored sections shown"

    tags = cast("list[str]", frontmatter(host_b)["tags"])
    assert frontmatter(host_b)["exposure"] == "public", "probe result in the frontmatter"
    assert {"public", "docker"} <= set(tags), "exposure and Docker as tags"

    attention = [line for line in section(overview, "Needs attention") if line.startswith("| [[")]
    assert any("[[host-b]]" in r and "fail2ban not running on a public host" in r for r in attention), "findings"
    assert any("[[host-b]]" in r and "no successful run in 20 days" in r for r in attention), "role option reached"

    updates = overview_cells(overview, "Auto-updates")
    assert updates["host-a"] == "2026-10-09", "auto-updates ok: date of the last successful run"
    assert updates["host-b"] == "no successful run in 20 days", "auto-update problem stays as text"
    assert overview_cells(overview, "Last fetched"), "collection date column"

    escaped = (
        r'&#37;&#37; hidden &lt;img src\="https://example.invalid/t.png"&gt; \[\[Overview\]\] '
        r"\*\*b\*\* a\_b \~\~c\~\~ \=\=d\=\= \^e &amp;amp; second \| line"
    )
    assert escaped in host_b.read_text(), "key comment printed as text"
    assert "ci@example.org (from 192.0.2.0/24) (forced command)" in host_a.read_text(), "key label"


def tilde(snapshot: Path) -> None:
    """Step 6: with a ~ data dir the stored exposure was found, so a run without probe kept it."""
    exposure = cast("dict[str, object]", load(snapshot)["exposure"])
    assert exposure["state"] == "public", "stored exposure kept with a ~ data dir"


def options(vault: Path) -> None:
    """Step 7: options given as strings with -e reached the report as values."""
    overview = (vault / "Overview.md").read_text()
    assert "```mermaid" not in overview, "charts off"
    assert "no successful run in 21 days" in overview, "age from -e used"
    assert not rows(vault / "Servers" / "host-b.md", "old"), "stopped containers off"


def live(snapshot: Path) -> None:
    """Step 9: every section was collected on a real host (contents depend on the machine running the test)."""
    data = load(snapshot)
    system, ssh = cast("dict[str, int]", data["system"]), cast("dict[str, object]", data["ssh"])
    ufw, fail2ban = cast("dict[str, str]", data["ufw"]), cast("dict[str, str]", data["fail2ban"])
    assert data["schema_version"] == 1, "snapshot format"
    assert system["cores"] > 0, "system facts collected"
    assert isinstance(data["users"], list), "users collected"
    assert data["users"], "at least root collected"
    assert ssh["key_files"], "key file locations known or assumed"
    assert ufw["state"] in {"active", "inactive", "not installed", "unknown"}, "UFW state collected"
    assert data["listeners"] is None or isinstance(data["listeners"], list), "listeners collected or unknown"
    assert isinstance(data["docker"], list), "Docker daemons collected (possibly none)"
    assert fail2ban["state"], "fail2ban state collected (possibly not installed)"
    assert "last_success" in cast("dict[str, object]", data["auto_updates"]), "auto-update settings collected"


COMMANDS: dict[str, Callable[[Path], None]] = {
    "stored": stored,
    "exposures": exposures,
    "pages": pages,
    "tilde": tilde,
    "options": options,
    "live": live,
}


def main() -> None:
    """Run one check."""
    if len(sys.argv) != 3 or sys.argv[1] not in COMMANDS:
        message = f"usage: check_run.py {{{','.join(COMMANDS)}}} PATH"
        raise SystemExit(message)
    COMMANDS[sys.argv[1]](Path(sys.argv[2]))


if __name__ == "__main__":
    main()
