# Contributing to ramondevprivate.common

## Start the repository

```bash
uv sync --locked
git config core.hooksPath .githooks
```

The [README](README.md) describes the setup and lists the checks. The collection lives in `ansible_collections/ramondevprivate/common/`; everything outside it (tooling, configuration, workflows) stays in the repository and is not part of the built collection.

## Change workflow

1. Define the behavior a playbook should see.
2. Change implementation, documentation (role README, `meta/argument_specs.yml`, module and plugin docs) and tests together.
3. Run the narrowest relevant checks while editing.
4. Run all checks from the README before review.

## Branches and commits

`main` is protected. Every change arrives through a pull request with a passing CI run.

Branch from the latest `main` and write [Conventional Commits](https://www.conventionalcommits.org):

```
fix(fleet_inventory): keep the stored exposure of hosts outside --limit
```

| Type                                                | Appears in the changelog |
| --------------------------------------------------- | ------------------------ |
| `feat`, `fix`, `perf`, `refactor`, `docs`, `revert` | Yes                      |
| `build`, `ci`, `chore`, `style`, `test`             | No                       |

Scopes are the role names (`fleet_inventory`, including its module and plugins) plus `deps` and `release`; a new role adds its scope in `pyproject.toml`. The commit hook and CI check the messages with commitizen (rules in `pyproject.toml`).

Pull requests are squash-merged, so the pull request title becomes the commit message and follows the same convention. CI checks both the branch commits and the title.

## Documentation

Modules, plugins and role variables are documented in the code (`DOCUMENTATION`/`RETURN`, the filter YAML files, `meta/argument_specs.yml`); CI lints them with antsibull-docs. The HTML docs on GitHub Pages are built from them (`uv sync --locked --group docs`, then `docs/build.sh`).

## Dependencies

Dependencies are locked in `uv.lock` and resolve only to releases that are at least seven days old (`exclude-newer` in `pyproject.toml`). Update them with `uv lock --upgrade`.

## Releases

Maintainers release from the Actions tab with the Release workflow. It runs the full check suite, bumps the version from the commits since the last release (`feat` minor; `fix`, `perf` and `refactor` patch; `!` major; other types alone don't bump, a release of them needs `release_as`), writes the changelog, tags, creates the GitHub release with the built collection and its provenance attestation, verifies the release by installing it, and deploys the HTML docs. `dry_run` runs everything without pushing, releasing or deploying. If a run fails after the tag was pushed, running it again releases that tag without a new bump.

The workflow needs the `release` environment (secret `RELEASE_APP_PRIVATE_KEY`, variable `RELEASE_GITHUB_CLIENT_ID` of the release app, which may bypass the `main` ruleset) and GitHub Pages with the source "GitHub Actions" (its `github-pages` environment allows `main`).

## Review checklist

- Explain the problem and the resulting behavior.
- Call out changes to role variables, module options or return values, the snapshot schema, and new dependencies.
- Keep unrelated refactors out of the change.
- Do not commit generated reports, build output, or local configuration.

Contributions are licensed under the repository's GPL-3.0-or-later license.
