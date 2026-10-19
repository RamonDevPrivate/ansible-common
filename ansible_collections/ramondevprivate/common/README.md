# ramondevprivate.common

[![CI](https://github.com/RamonDevPrivate/ansible-common/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/RamonDevPrivate/ansible-common/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/RamonDevPrivate/ansible-common?label=ramondevprivate.common)](https://github.com/RamonDevPrivate/ansible-common/releases/latest)
[![Galaxy](https://img.shields.io/ansible/collection/v/ramondevprivate/common?label=galaxy)](https://galaxy.ansible.com/ui/repo/published/ramondevprivate/common/)
[![Docs](https://img.shields.io/github/deployments/RamonDevPrivate/ansible-common/github-pages?label=docs)](https://ramondevprivate.github.io/ansible-common/)
[![License](https://img.shields.io/github/license/RamonDevPrivate/ansible-common)](https://github.com/RamonDevPrivate/ansible-common/blob/main/COPYING)

Roles, modules and plugins for running my servers: setting them up, managing them, and the deployment-specific
workflows around them.

## Description

`ramondevprivate.common` keeps the automation I use across servers in one place, so playbook repos only install
the collection and call its roles. It is built for my own fleet, not as a general-purpose
collection, but every role documents its assumptions and variables.

| Content | Type | Purpose |
|---|---|---|
| [`fleet_inventory`](https://github.com/RamonDevPrivate/ansible-common/blob/main/ansible_collections/ramondevprivate/common/roles/fleet_inventory/README.md) | role | Documents servers read-only as Markdown pages for Obsidian |
| `fleet_info` | module | Read-only server facts for `fleet_inventory` |
| `fleet_snapshot`, `fleet_report`, `fleet_probe_targets`, `fleet_exposure`, `fleet_probe_errors`, `fleet_unreached` | filter | Building blocks of `fleet_inventory` |
| `md_escape` | filter | Makes a value safe to print in Markdown |
| `fleet_snapshots` | lookup | Reads the stored snapshots of `fleet_inventory` |

Each role has a README with its usage, variables and behaviour. The
[HTML docs](https://ramondevprivate.github.io/ansible-common/) show every module, plugin and role of the latest release;
the same docs are available on the command line:

```bash
ansible-doc ramondevprivate.common.<module>
ansible-doc -t filter ramondevprivate.common.<filter>
ansible-doc -t lookup ramondevprivate.common.<lookup>
ansible-doc -t role ramondevprivate.common.<role>    # the role's variables
```

## Requirements

- Controller: ansible-core 2.21 or newer, on Python 3.12 or newer.
- Managed hosts: Debian 12 or 13 (Python 3.11 or newer).
- No other collections or Python packages.

Roles can have their own requirements, such as `become: true` or an extra host; see the role's README.

## Installation

The collection is on [Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/ramondevprivate/common/):

```bash
ansible-galaxy collection install ramondevprivate.common
```

### Installing from a requirements file

```yaml
collections:
  - name: ramondevprivate.common
    version: 1.0.0
```

```bash
ansible-galaxy collection install -r requirements.yml
```

### Installing from Git

Every release is also tagged in the repository. `ansible-galaxy` needs the path of the collection inside the repo
after the `#`; `version` takes a release tag (`v1.0.0`) or a commit SHA. A tag is easier to read; a SHA can't be
modified later on.

```yaml
collections:
  - name: https://github.com/RamonDevPrivate/ansible-common.git#/ansible_collections/ramondevprivate/common/
    type: git
    version: v1.0.0
```

### Upgrading

Change `version` in `requirements.yml` and run the install command again, or upgrade to the latest release with
`ansible-galaxy collection install --upgrade ramondevprivate.common`.

To work on the collection itself, use a local checkout instead; see the
[repository README](https://github.com/RamonDevPrivate/ansible-common#readme).

## Use cases

- **Document the fleet:** one page per server with its users, SSH keys, sudo rights, firewall, open ports,
  containers and update state, plus an overview of what needs attention.

  ```yaml
  - name: Document the fleet
    hosts: servers
    become: true
    roles:
      - role: ramondevprivate.common.fleet_inventory
        vars:
          fleet_inventory_output_dir: ~/Nextcloud/Vault/Fleet
          fleet_inventory_data_dir: ~/.local/share/fleet-inventory
  ```

## Testing

Tested with ansible-core 2.21 against Debian 12 and 13. Changes are checked with `ansible-test` (sanity, units,
integration), linters and type checks; the commands are in the
[repository README](https://github.com/RamonDevPrivate/ansible-common#checks).

## Release notes

See the [changelog](https://github.com/RamonDevPrivate/ansible-common/blob/main/ansible_collections/ramondevprivate/common/CHANGELOG.md).

## License

GNU General Public License v3.0 or later. The full text is in [COPYING](https://github.com/RamonDevPrivate/ansible-common/blob/main/ansible_collections/ramondevprivate/common/COPYING), which ships with the collection.
