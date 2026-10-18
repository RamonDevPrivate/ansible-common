# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for escaping host values in Markdown."""

import pytest

from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.markdown import md_escape


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("sshd", id="process-name"),
        pytest.param("alice@example.org", id="key-comment"),
        pytest.param("traefik:v3.7.13", id="image"),
        pytest.param("10.0.0.0/8", id="network"),
        pytest.param("full (dockeruser), NOPASSWD", id="sudo-label"),
        pytest.param("Debian 13.7", id="os"),
        pytest.param("443→443/tcp", id="port-label"),
    ],
)
def test_ordinary_values_are_unchanged(value: str) -> None:
    """Escaping must not make normal values unreadable."""
    assert md_escape(value) == value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param("a|b", "a\\|b", id="pipe"),
        pytest.param("a\\b", "a\\\\b", id="backslash"),
        pytest.param("[[Overview]]", "\\[\\[Overview\\]\\]", id="wikilink"),
        pytest.param("![[x.png]]", "!\\[\\[x.png\\]\\]", id="embed"),
        pytest.param("#tag", "\\#tag", id="tag"),
        pytest.param("$x$", "\\$x\\$", id="math"),
        pytest.param("`code`", "\\`code\\`", id="code-span"),
        pytest.param('<img src="https://example.invalid/t.png">', '&lt;img src\\="https://example.invalid/t.png"&gt;', id="html"),
        pytest.param("%% hide", "&#37;&#37; hide", id="obsidian-comment"),
        pytest.param("**allow all**", "\\*\\*allow all\\*\\*", id="bold"),
        pytest.param("zabbix_agent2", "zabbix\\_agent2", id="underscore"),
        pytest.param("~~old~~", "\\~\\~old\\~\\~", id="strikethrough"),
        pytest.param("==x==", "\\=\\=x\\=\\=", id="highlight"),
        pytest.param("note ^abc", "note \\^abc", id="block-id"),
        pytest.param("&lt;b&gt;", "&amp;lt;b&amp;gt;", id="html-entity"),
    ],
)
def test_markup_becomes_text(value: str, expected: str) -> None:
    """Characters that change the page are escaped."""
    assert md_escape(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("a\nb", id="newline"),
        pytest.param("a\r\nb", id="crlf"),
        pytest.param("a\tb", id="tab"),
        pytest.param("a\u2028b", id="line-separator"),
        pytest.param("a\u202eb", id="bidi-override"),
        pytest.param("a\u200bb", id="zero-width-space"),
    ],
)
def test_control_and_format_characters_become_spaces(value: str) -> None:
    """A line break would split a table row; invisible characters could disguise text."""
    escaped = md_escape(value)

    assert escaped.startswith("a")
    assert escaped.endswith("b")
    assert escaped.strip("ab").strip() == ""


@pytest.mark.parametrize(("value", "expected"), [(None, ""), (42, "42")])
def test_non_strings(value: object, expected: str) -> None:
    """None prints as nothing, other values as their text."""
    assert md_escape(value) == expected
