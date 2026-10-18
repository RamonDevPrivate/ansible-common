# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Lookup plugin fleet_snapshots: the stored snapshots of the fleet_inventory role."""

DOCUMENTATION = r"""
name: fleet_snapshots
short_description: Read the stored fleet_inventory snapshots
version_added: 1.0.0
author:
  - Ramon (@RamonDevPrivate)
description:
  - Reads every C(*.json) file in the data directory on the controller and returns the decoded snapshots, in file
    name order.
  - A directory that doesn't exist yet gives an empty list (first run, also in check mode).
  - A file that can't be read or isn't valid JSON fails with its path. Whether a decoded value is a valid snapshot
    is decided by the P(ramondevprivate.common.fleet_report#filter) filter, which ignores invalid ones.
options:
  _terms:
    description: The data directory (one path); C(~) is expanded.
    type: list
    elements: path
    required: true
"""

EXAMPLES = r"""
- name: Stored snapshots
  ansible.builtin.set_fact:
    stored: "{{ query('ramondevprivate.common.fleet_snapshots', '~/.local/share/fleet-inventory') }}"
"""

RETURN = r"""
_list:
  description: The decoded content of each snapshot file.
  type: list
  elements: raw
"""

from ansible.errors import AnsibleLookupError  # pyright: ignore[reportMissingTypeStubs] - no stubs
from ansible.plugins.lookup import LookupBase  # pyright: ignore[reportMissingTypeStubs] - no stubs

from ansible_collections.ramondevprivate.common.plugins.plugin_utils.fleet.stored import (
    StoredSnapshotError,
    load_snapshots,
)


class LookupModule(LookupBase):
    """Stored snapshots of one data directory."""

    # base run() is unannotated (inferred None); typing.override is 3.12+ and plugins are type-checked as 3.11
    def run(  # pyright: ignore[reportIncompatibleMethodOverride, reportImplicitOverride]
        self, terms: list[object], variables: object = None, **kwargs: object
    ) -> list[object]:
        """Decoded snapshots of the data directory given as the only term."""
        del variables, kwargs
        if len(terms) != 1 or not isinstance(terms[0], str):
            message = f"fleet_snapshots takes exactly one data directory, got {terms!r}"
            raise AnsibleLookupError(message)
        try:
            return load_snapshots(terms[0])
        except StoredSnapshotError as error:
            raise AnsibleLookupError(str(error)) from error
