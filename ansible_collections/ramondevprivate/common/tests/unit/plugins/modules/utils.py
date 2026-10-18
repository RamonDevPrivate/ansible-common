# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Helpers for module unit tests.

Ansible's recommended pattern: exit_json and fail_json raise these exceptions instead of printing JSON
and exiting, so a test can inspect the result directly (see conftest.py).
"""

from collections.abc import Mapping
from typing import final


@final
class AnsibleExitJson(Exception):  # noqa: N818 - name follows the Ansible docs and other collections
    """Raised instead of AnsibleModule.exit_json; carries the module result."""

    def __init__(self, result: Mapping[str, object]) -> None:
        """Store the result."""
        super().__init__(result)
        self.result = result


@final
class AnsibleFailJson(Exception):  # noqa: N818 - name follows the Ansible docs and other collections
    """Raised instead of AnsibleModule.fail_json; carries the failure result."""

    def __init__(self, result: Mapping[str, object]) -> None:
        """Store the result."""
        super().__init__(result)
        self.result = result
