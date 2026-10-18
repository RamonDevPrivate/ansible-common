# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Fixtures for module unit tests."""

from typing import NoReturn

import pytest
from ansible.module_utils import basic  # pyright: ignore[reportMissingTypeStubs] - no stubs

from ansible_collections.ramondevprivate.common.tests.unit.plugins.modules.utils import AnsibleExitJson, AnsibleFailJson


@pytest.fixture(autouse=True)
def module_exits_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make exit_json and fail_json raise instead of printing JSON and exiting the process."""

    def exit_json(_module: object, **result: object) -> NoReturn:
        raise AnsibleExitJson(result)

    def fail_json(_module: object, **result: object) -> NoReturn:
        raise AnsibleFailJson(result)

    monkeypatch.setattr(basic.AnsibleModule, "exit_json", exit_json)
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", fail_json)
