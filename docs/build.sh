#!/usr/bin/env bash
# Build the HTML docs of ramondevprivate.common into docs/build/html (run with the docs group: uv sync --group docs).
# Adapted from antsibull-docs sphinx-init.
set -euo pipefail

cd "$(dirname -- "${BASH_SOURCE[0]}")"
# the collection is read from this checkout, whatever is installed elsewhere
export ANSIBLE_COLLECTIONS_PATH="${PWD}/.."

# Plugin and role pages from the docs in the code
mkdir -p rst
chmod og-w rst # antsibull-docs wants that directory only readable by itself
antsibull-docs \
    --config-file antsibull-docs.cfg \
    collection \
    --cleanup everything \
    --fail-on-error \
    --use-current \
    --squash-hierarchy \
    --dest-dir rst \
    ramondevprivate.common

# Sphinx site; warnings fail the build
sphinx-build -M html rst build -c . -W --keep-going
