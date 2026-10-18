# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
r"""Make values from the hosts safe to print in Obsidian Markdown (runs on the controller).

Values such as key comments, image labels, UFW comments or process names are set by users or third parties. Printed
as they are, a line break splits a table, `%%` hides the rest of the page (Obsidian comment), `<img src=…>` loads
remote content, `[[…]]` adds links, and `**`, `==` or `~~` change the formatting. md_escape turns every such character
into plain text. The page source then shows backslashes (`zabbix\_agent2`); Obsidian renders the plain characters.
"""

import unicodedata
from typing import Final

REPLACEMENTS: Final = {
    "\\": "\\\\",
    "|": "\\|",  # table cell separator
    "`": "\\`",  # code spans
    "[": "\\[",  # links, wikilinks, embeds
    "]": "\\]",
    "#": "\\#",  # Obsidian tags
    "$": "\\$",  # Obsidian math
    "*": "\\*",  # emphasis
    "_": "\\_",
    "~": "\\~",  # ~~strikethrough~~
    "=": "\\=",  # ==highlight==
    "^": "\\^",  # ^block-id at the end of a line, ^[inline footnote]
    "&": "&amp;",  # entities like &lt; would be rendered instead of printed
    "<": "&lt;",  # raw HTML
    ">": "&gt;",
    "%": "&#37;",  # %% starts an Obsidian comment
}


def md_escape(value: object) -> str:
    """Plain text of value for a Markdown line or table cell: no line breaks, no markup that changes the page."""
    text = "" if value is None else str(value)
    return "".join(REPLACEMENTS.get(char, " " if _is_control(char) else char) for char in text)


def _is_control(char: str) -> bool:
    """Control and format characters (line breaks, tabs, zero-width and bidi overrides) and unassigned code points."""
    return unicodedata.category(char).startswith("C")
