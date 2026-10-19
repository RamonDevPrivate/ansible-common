# ansible-common

[![CI](https://github.com/RamonDevPrivate/ansible-common/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/RamonDevPrivate/ansible-common/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/RamonDevPrivate/ansible-common?label=ramondevprivate.common)](https://github.com/RamonDevPrivate/ansible-common/releases/latest)
[![Galaxy](https://img.shields.io/ansible/collection/v/ramondevprivate/common?label=galaxy)](https://galaxy.ansible.com/ui/repo/published/ramondevprivate/common/)
[![Docs](https://img.shields.io/github/deployments/RamonDevPrivate/ansible-common/github-pages?label=docs)](https://ramondevprivate.github.io/ansible-common/)
[![License](https://img.shields.io/github/license/RamonDevPrivate/ansible-common)](https://github.com/RamonDevPrivate/ansible-common/blob/main/COPYING)

Development repo for the Ansible collection [`ramondevprivate.common`](ansible_collections/ramondevprivate/common/README.md): roles and
modules for my own needs, from managing servers to setting up deployment-specific workflows.

The collection lives in `ansible_collections/ramondevprivate/common/`, so `ansible-test`, basedpyright and pytest resolve
`ansible_collections.ramondevprivate.common...` imports wherever this repo is cloned.

## Setup

Requires [uv](https://docs.astral.sh/uv/).

```sh
uv sync --locked          # creates .venv with ansible-core, ansible-lint, ruff, basedpyright, pytest, yamllint, commitizen
source .venv/bin/activate
git config core.hooksPath .githooks   # commit message check, see CONTRIBUTING.md
uv python install 3.11    # optional: lets ansible-test check the Debian 12 target Python
```

Dependencies only resolve to releases that are at least 7 days old (`exclude-newer` in `pyproject.toml`).
Update them with `uv lock --upgrade`.

Contribution rules (commits, branches, review) are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Checks

From the repo root:

```sh
ruff check . && ruff format --check .
basedpyright
pytest
yamllint .
ansible-lint
shellcheck ansible_collections/ramondevprivate/common/tests/integration/targets/fleet_inventory/{runme.sh,bin/*}
uv sync --locked --group docs     # once, for the docs checks
docs/build.sh                     # HTML docs in docs/build/html
```

From `ansible_collections/ramondevprivate/common/`:

```sh
ansible-test sanity --venv
ansible-test units --venv
ansible-test integration --venv   # the role end to end (tests/integration/targets/fleet_inventory/runme.sh)
ANSIBLE_COLLECTIONS_PATH=../../.. antsibull-docs lint-collection-docs --plugin-docs \
    --validate-collection-refs all --disallow-unknown-collection-refs .   # docs markup and references
```

## Developing against another repo

For development only: to try changes from this checkout in another repo before they are released, add the checkout
to `collections_path` in that repo's `ansible.cfg`. To use a released version, install it as described in the
[collection README](ansible_collections/ramondevprivate/common/README.md#installation).

```ini
[defaults]
collections_path = ~/Dev/ansible-common:~/.ansible/collections
```

Then use the role from a playbook in that repo:

```yaml
- name: Document the fleet
  hosts: servers
  become: true
  roles:
    - role: ramondevprivate.common.fleet_inventory
```

## License

GNU General Public License v3.0 or later, see [COPYING](ansible_collections/ramondevprivate/common/COPYING).
