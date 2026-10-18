# Copyright: (c) 2026, Ramon
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
"""Read-only collection of server facts for the fleet_inventory role."""

DOCUMENTATION = r"""
---
module: fleet_info
short_description: Collect read-only server facts for the fleet inventory
version_added: 1.0.0
description:
  - Collects how a Debian server is set up, for the C(ramondevprivate.common.fleet_inventory) role. Never changes anything on
    the target; check mode is fully supported.
  - "Collected: login accounts with their groups, sudo level and authorized keys; sshd key settings; UFW status and
    rules; listening sockets; Docker daemons and containers; fail2ban; unattended upgrades."
  - Needs root (C(become)) for sshd settings, other users' key files and sudo rules, UFW, socket processes, Docker
    sockets and fail2ban jails; without root those parts are reported as unknown and one warning is shown.
  - Never returned are key material, the content of forced commands, password hashes, and container environment
    variables, commands or labels other than the image version and compose directory.
  - How each part is read (sources, permission and socket checks) is described in the role README.
author:
  - Ramon (@RamonDevPrivate)
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  platform:
    platforms: debian
options:
  group_filter:
    description:
      - Supplementary groups that are not reported because every desktop-style account has them.
      - Groups like C(sudo), C(docker), C(lxd) and C(adm) grant privileges and should not be listed here.
    type: list
    elements: str
    default: [cdrom, floppy, audio, dip, video, plugdev, users, netdev, bluetooth]
  user_filter:
    description:
      - Accounts that are not collected at all, e.g. provider or image default accounts.
      - Filtering C(root) also hides who can log in as root with a key.
    type: list
    elements: str
    default: []
"""

EXAMPLES = r"""
- name: Collect fleet info
  ramondevprivate.common.fleet_info:
  register: fleet_inventory_info

- name: Collect fleet info, also hiding the lpadmin group and the image's default account
  ramondevprivate.common.fleet_info:
    group_filter: [cdrom, floppy, audio, dip, video, plugdev, users, netdev, bluetooth, lpadmin]
    user_filter: [debian]
"""

RETURN = r"""
fleet:
  description: Facts about the host. Null values mean unknown (not readable, tool missing or no root).
  returned: always
  type: dict
  contains:
    schema_version:
      description: Version of the result format.
      returned: always
      type: int
    users:
      description: Root, accounts with a login shell and C(UID >= UID_MIN), and every account with authorized keys.
      returned: always
      type: list
      elements: dict
      contains:
        name:
          description: Account name.
          type: str
        uid:
          description: Numeric user id.
          type: int
        groups:
          description: Supplementary groups without the primary group and without O(group_filter).
          type: list
          elements: str
        sudo:
          description: What the account may run, from C(sudo -l -U).
          type: dict
          contains:
            level:
              description:
                - V(full) any command as root, V(limited) anything else, V(none) not allowed.
                - V(unknown) without root, without sudo, or output that could not be classified.
              type: str
              choices: [full, limited, none, unknown]
            nopasswd:
              description: Whether a rule that makes up the level (the full ones, if any) has C(NOPASSWD).
              type: bool
            rules:
              description: The rules C(sudo -l) lists, without duplicates.
              type: list
              elements: str
        authorized_keys:
          description: Keys from the files sshd uses, without the key material; null if a key file is not readable.
          type: list
          elements: dict
          contains:
            key_type:
              description: Key type, for example V(ssh-ed25519).
              type: str
            comment:
              description: Key comment; empty if the key has none.
              type: str
            fingerprint:
              description: SHA256 fingerprint as shown by C(ssh-keygen -l).
              type: str
            allowed_from:
              description: The C(from=) option; empty if not set.
              type: str
            forced_command:
              description: Whether the key has a C(command=) option (its content is not returned).
              type: bool
        last_login:
          description: Last login (ISO 8601); empty if there is no record, null if C(lslogins) is not available.
          type: str
    ssh:
      description: Where sshd looks for authorized keys.
      returned: always
      type: dict
      contains:
        key_files:
          description: C(AuthorizedKeysFile) entries, relative ones relative to the home directory.
          type: list
          elements: str
        key_files_source:
          description: V(sshd) from C(sshd -T), V(default) if C(sshd -T) failed and sshd's defaults are assumed.
          type: str
          choices: [sshd, default]
        keys_command:
          description: Whether an C(AuthorizedKeysCommand) is set (its keys are not collected).
          type: bool
    ufw:
      description: UFW status, default policies and rules.
      returned: always
      type: dict
      contains:
        state:
          description: UFW state.
          type: str
          choices: [active, inactive, not installed, unknown]
        logging:
          description: Logging, for example V(on (low)); empty if unknown.
          type: str
        default_incoming:
          description: Incoming default (V(deny), V(allow), V(reject), V(disabled)); empty if unknown or inactive.
          type: str
        default_outgoing:
          description: Default outgoing policy, like RV(fleet.ufw.default_incoming).
          type: str
        default_routed:
          description: Default routed policy, like RV(fleet.ufw.default_incoming).
          type: str
        rules:
          description: Rules added with ufw; null if the rule files are not readable.
          type: list
          elements: dict
          contains:
            action:
              description: V(allow), V(deny), V(reject) or V(limit).
              type: str
            direction:
              description: V(in) or V(out).
              type: str
            route:
              description: Whether it is a C(ufw route) rule (forwarded traffic).
              type: bool
            proto:
              description: V(tcp), V(udp), V(any), ...
              type: str
            to_port:
              description: Destination port, list (V(80,443)), range (V(8000:8010)) or V(any).
              type: str
            to_address:
              description: Destination network, V(0.0.0.0/0) or V(::/0) for any.
              type: str
            from_port:
              description: Source port, like RV(fleet.ufw.rules[].to_port).
              type: str
            from_address:
              description: Source network, like RV(fleet.ufw.rules[].to_address).
              type: str
            app:
              description: Destination-side application profile; its ports are already in RV(fleet.ufw.rules[].to_port).
              type: str
            interface_in:
              description: Incoming interface; empty if not limited to one.
              type: str
            interface_out:
              description: Outgoing interface; empty if not limited to one.
              type: str
            comment:
              description: Rule comment, decoded.
              type: str
            family:
              description: Address family of the rule set the rule comes from.
              type: str
              choices: [ipv4, ipv6]
    listeners:
      description: Listening TCP and bound UDP sockets from C(ss); null if C(ss) is not available.
      returned: always
      type: list
      elements: dict
      contains:
        proto:
          description: V(tcp) or V(udp).
          type: str
        address:
          description: Bind address without brackets; V(*) means both address families.
          type: str
        interface:
          description: Interface from C(address%interface); empty if not bound to one.
          type: str
        port:
          description: Port number.
          type: int
        processes:
          description: Names of the processes holding the socket; empty without root.
          type: list
          elements: str
    docker:
      description: Docker daemons found by their sockets, with their containers.
      returned: always
      type: list
      elements: dict
      contains:
        mode:
          description: V(rootful) (C(/var/run/docker.sock)) or V(rootless) (C(/run/user/<uid>/docker.sock)).
          type: str
          choices: [rootful, rootless]
        owner:
          description: Account that runs a rootless daemon; empty for the rootful one.
          type: str
        socket:
          description: Path of the daemon's socket.
          type: str
        state:
          description:
            - V(running) answered, V(not running) C(docker.service) not active (rootful only, not queried).
            - V(unreachable) the socket failed the owner checks or did not answer.
          type: str
          choices: [running, not running, unreachable]
        version:
          description: Engine version; empty if the daemon was not queried or did not answer.
          type: str
        containers:
          description: All containers of the daemon, running or not.
          type: list
          elements: dict
          contains:
            name:
              description: Container name.
              type: str
            image:
              description: Image reference as configured, for example V(traefik:v3.7.13).
              type: str
            version:
              description: The C(org.opencontainers.image.version) label; empty if missing.
              type: str
            state:
              description: Container state, for example V(running) or V(exited).
              type: str
            compose_dir:
              description: Compose working directory label; empty if not started by compose.
              type: str
            ports:
              description: Published ports; empty for a stopped container.
              type: list
              elements: dict
              contains:
                host_ip:
                  description: Host address.
                  type: str
                host_port:
                  description: Port on the host.
                  type: int
                container_port:
                  description: Port in the container.
                  type: int
                proto:
                  description: V(tcp), V(udp) or V(sctp).
                  type: str
    fail2ban:
      description: fail2ban service state and jails.
      returned: always
      type: dict
      contains:
        state:
          description: C(systemctl is-active) state (V(active), V(failed), ...), V(not installed) or V(unknown).
          type: str
        jails:
          description: Jail names; null if unknown (not running, no root).
          type: list
          elements: str
    auto_updates:
      description: Unattended-upgrades configuration and last successful run; null values are unknown.
      returned: always
      type: dict
      contains:
        installed:
          description: Whether the C(unattended-upgrades) package is installed.
          type: bool
        update_lists:
          description: C(APT::Periodic::Update-Package-Lists); empty if unset.
          type: str
        unattended_upgrade:
          description: C(APT::Periodic::Unattended-Upgrade); empty if unset.
          type: str
        timer:
          description: C(systemctl is-enabled apt-daily-upgrade.timer), for example V(enabled); empty if unknown.
          type: str
        last_success:
          description: Last successful C(unattended-upgrade) run (ISO 8601, UTC); empty if there is none.
          type: str
"""

from typing import cast

from ansible.module_utils.basic import AnsibleModule  # pyright: ignore[reportMissingTypeStubs] - no stubs

from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.ansible_system import AnsibleSystem
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect import collect_users
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect_network import collect_network
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.collect_security import collect_security
from ansible_collections.ramondevprivate.common.plugins.module_utils.fleet.schema import empty_info

DEFAULT_GROUP_FILTER = ["cdrom", "floppy", "audio", "dip", "video", "plugdev", "users", "netdev", "bluetooth"]
NEEDS_ROOT = ("sshd settings", "key files", "sudo rules", "UFW", "socket processes", "fail2ban jails")
ROOT_WARNING = f"not running as root (become: true): {', '.join(NEEDS_ROOT)} and Docker are partly unknown"


def main() -> None:
    """Run the module."""
    argument_spec: dict[str, dict[str, object]] = {
        "group_filter": {"type": "list", "elements": "str", "default": DEFAULT_GROUP_FILTER},
        "user_filter": {"type": "list", "elements": "str", "default": []},
    }
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    params = cast("dict[str, object]", module.params)
    group_filter = cast("list[str]", params["group_filter"])  # validated by argument_spec
    user_filter = cast("list[str]", params["user_filter"])

    system = AnsibleSystem(module)
    collected = collect_users(system, group_filter, user_filter)
    network = collect_network(system)
    security = collect_security(system)
    if not system.is_root():
        # every unreadable file and failing command is a consequence of this; one warning instead of many
        module.warn(ROOT_WARNING)
    else:
        for warning in [*collected.warnings, *network.warnings]:
            module.warn(warning)

    info = empty_info()
    info["users"] = collected.users
    info["ssh"] = collected.ssh
    info["ufw"] = network.ufw
    info["listeners"] = network.listeners
    info["docker"] = network.docker
    info["fail2ban"] = security.fail2ban
    info["auto_updates"] = security.auto_updates
    module.exit_json(changed=False, fleet=info)  # pyright: ignore[reportUnknownMemberType] - untyped ansible-core API


if __name__ == "__main__":
    main()
