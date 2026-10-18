#!/usr/bin/env bash
# Integration test for the fleet_inventory role. Checks behaviour and structure, not exact page text.
set -euxo pipefail

work="${OUTPUT_DIR}/fleet"
rm -rf "${work}"
mkdir -p "${work}/data"
cp files/stored/*.json "${work}/data/"

render() { ansible-playbook -i inventory.ini render.yml -e "fleet_test_dir=${work}" "$@"; }

# Fakes for the probe (bin/): ping logs every call to $FLEET_PING_LOG, unreachable-ssh fails like an unknown host
export FLEET_PING_LOG="${work}/ping.log"
export PATH="${PWD}/bin:${PATH}"
# fail if a playbook log (stdout+stderr) warns about a missing data dir ("Unable to find", as fileglob did)
no_missing_dir_warning() { if grep -q 'Unable to find' "$1"; then exit 1; fi; }
# name, size and modification time of every written file; unchanged state = nothing was written
file_state() { find "${work}/vault" "${work}/data" -type f -printf '%p %s %T@\n' | sort; }

# 1. Check mode writes nothing on the controller either
render --check
test ! -e "${work}/vault"
diff -r files/stored "${work}/data"

# 2. Real run: complete, well-formed pages
rm -f "${FLEET_PING_LOG}"
render
python check_pages.py "${work}/vault" --hosts host-a host-b host-c --unreachable host-c --charts

# ...after pinging exactly the public addresses of the reached hosts, each with its family's flag
test "$(sort "${FLEET_PING_LOG}")" = "$(printf '%s\n' '-4 198.51.100.42' '-4 203.0.113.23' '-6 2001:db8:42::42' | sort)"

# ...with snapshots only the owner can read and pages the vault (and its sync) can read
test "$(stat -c %a "${work}/data")" = 700
test "$(stat -c %a "${work}"/data/*.json | sort -u)" = 600
test "$(stat -c %a "${work}/vault" "${work}/vault/Servers" "${work}/vault/Descriptions" | sort -u)" = 755
test "$(stat -c %a "${work}"/vault/*.md "${work}"/vault/Servers/*.md "${work}"/vault/Descriptions/*.md | sort -u)" = 644

# ...the right data behind them, and each kind of value on the pages (check_run.py)
python check_run.py stored "${work}/data"
python check_run.py exposures "${work}/data"
python check_run.py pages "${work}/vault"

# 3. A second run with the same data writes nothing
before="$(file_state)"
render
test "${before}" = "$(file_state)"

# 3a. Descriptions: one note per host of the run, embedded in its page; your text survives runs; empty dir = off
for host in host-a host-b host-c; do
    grep -q ' ^summary$' "${work}/vault/Descriptions/${host} description.md"  # new notes carry the summary marker
    grep -qF "![[${host} description]]" "${work}/vault/Servers/${host}.md"
done
echo "Web server for the team wiki" > "${work}/vault/Descriptions/host-a description.md"
render
grep -qx "Web server for the team wiki" "${work}/vault/Descriptions/host-a description.md"
render -e fleet_inventory_descriptions_dir=
if grep -q "## Description" "${work}/vault/Servers/host-a.md"; then exit 1; fi
if grep -q "#^summary" "${work}/vault/Server List.md"; then exit 1; fi
render

# 3b. --limit: hosts outside the limit are not touched (page and JSON), the overview keeps their state
outside="$(find "${work}/vault/Servers/host-b.md" "${work}/vault/Servers/host-c.md" "${work}/data/host-b.json" \
    "${work}/data/host-c.json" -printf '%p %s %T@\n' | sort)"
render --limit host-a
test "${outside}" = "$(find "${work}/vault/Servers/host-b.md" "${work}/vault/Servers/host-c.md" \
    "${work}/data/host-b.json" "${work}/data/host-c.json" -printf '%p %s %T@\n' | sort)"
grep -q '^Servers: 3 .*1 not updated' "${work}/vault/Overview.md"
grep -q '^| \[\[host-c\]\] .*(not updated) |$' "${work}/vault/Overview.md"

# 4. A broken probe never fails the run: it says which pings were not sent and why, and every host keeps the
#    exposure found before. Both ways a delegated task can fail: the host is unreachable (fake ssh), or the
#    connection fails on the controller (unknown connection plugin; ignore_unreachable doesn't cover that)
probe_fails() {
    local reason="$1" before
    shift
    before="$(file_state)"
    render -e fleet_inventory_probe_user=nobody "$@" 2>&1 | tee "${work}/probe-fails.log"
    test "${before}" = "$(file_state)"
    grep -q "Not probed, the hosts keep their stored exposure: .*${reason}" "${work}/probe-fails.log"
}
# the reasons are ansible-core's messages (2.21): the ssh plugin passes ssh's stderr on; unknown plugin names
probe_fails 'Could not resolve hostname probe.invalid' \
    -e fleet_inventory_probe_host=probe.invalid -e "ansible_ssh_executable=${PWD}/bin/unreachable-ssh"
probe_fails "connection plugin 'does_not_exist' was not found" -e fleet_inventory_probe_host=probe-broken

# 5. No probe host: the probe is skipped cleanly (no ignored errors) and every host keeps its exposure
before="$(file_state)"
render -e fleet_inventory_probe_host= 2>&1 | tee "${work}/no-probe.log"
test "${before}" = "$(file_state)"
if grep -q -e 'ignoring' -e 'Empty hostname' "${work}/no-probe.log"; then exit 1; fi

# 6. Data dir given with ~ (as in the README): stored exposures are found, so a run without probe keeps them.
#    The stored snapshots are read on the controller, which has to expand ~ itself. A unique dir in the real home,
#    removed on exit (overriding HOME would make the copy and file modules disagree about where ~ is).
tilde_dir="$(mktemp -d "${HOME}/.fleet-inventory-test.XXXXXX")"
trap 'rm -rf "${tilde_dir}"' EXIT
# shellcheck disable=SC2088 # a literal ~ on purpose: the role has to expand it
tilde="~/$(basename "${tilde_dir}")"
cp files/stored/*.json "${tilde_dir}/"
ansible-playbook -i inventory.ini render.yml -e "fleet_test_dir=${work}" \
    -e "fleet_inventory_data_dir=${tilde}" -e "fleet_inventory_output_dir=${work}/tilde-vault"
ansible-playbook -i inventory.ini render.yml -e "fleet_test_dir=${work}" -e fleet_inventory_probe_host= \
    -e "fleet_inventory_data_dir=${tilde}" -e "fleet_inventory_output_dir=${work}/tilde-vault"
python check_run.py tilde "${tilde_dir}/host-b.json"

# 7. Options given as strings with -e reach the report as values (not silently replaced by defaults)
strings="${work}/strings"
mkdir -p "${strings}/data"
cp files/stored/*.json "${strings}/data/"
ansible-playbook -i inventory.ini render.yml -e "fleet_test_dir=${work}" \
    -e "fleet_inventory_data_dir=${strings}/data" -e "fleet_inventory_output_dir=${strings}/vault" \
    -e fleet_inventory_mermaid_charts=false -e fleet_inventory_stopped_containers=false \
    -e fleet_inventory_update_max_age_days=21
python check_run.py options "${strings}/vault"

# 7a. Bad input fails before anything is written, with a message that names the problem. validate.yml runs the
#     role's main entry point, so argument validation applies (render.yml's tasks_from skips it)
rejected() {
    local message="$1" before
    shift
    before="$(file_state)"
    if ansible-playbook -i inventory.ini "$@" > "${work}/rejected.log" 2>&1; then
        exit 1
    fi
    grep -q "${message}" "${work}/rejected.log"
    test "${before}" = "$(file_state)"
}
# the validation messages are ansible-core's (2.21: required arguments listed in alphabetical order)
rejected 'Set fleet_inventory_probe_user together with fleet_inventory_probe_host' \
    render.yml -e "fleet_test_dir=${work}" -e fleet_inventory_probe_user=
rejected 'missing required arguments: fleet_inventory_data_dir, fleet_inventory_output_dir' validate.yml
rejected "argument 'fleet_inventory_inactive_days' is of type str" validate.yml \
    -e "fleet_inventory_data_dir=${work}/data" -e "fleet_inventory_output_dir=${work}/vault" \
    -e fleet_inventory_inactive_days=soon
rejected 'fleet_inventory needs all hosts of the play in one batch' serial.yml \
    -e "fleet_inventory_data_dir=${work}/data" -e "fleet_inventory_output_dir=${work}/vault"

# 7b. A damaged snapshot file stops the run before anything is written, and the message names the file
corrupt="${work}/corrupt"
mkdir -p "${corrupt}/data"
cp files/stored/*.json "${corrupt}/data/"
printf '{"host": ' > "${corrupt}/data/host-c.json"
if ansible-playbook -i inventory.ini render.yml -e "fleet_test_dir=${corrupt}" > "${work}/corrupt.log" 2>&1; then
    exit 1
fi
grep -qF "stored snapshot ${corrupt}/data/host-c.json can't be read" "${work}/corrupt.log"
test ! -e "${corrupt}/vault"

# Steps 8 and 9 run against a real host from ansible-test's inventory
if [[ -z "${INVENTORY_PATH:-}" ]]; then
    # Outside ansible-test: the same kind of inventory ansible-test writes
    INVENTORY_PATH="${work}/inventory"
    printf 'testhost ansible_connection=local ansible_python_interpreter=%s\n' "$(command -v python)" > "${INVENTORY_PATH}"
fi

# 8. First run into a new data dir in check mode: nothing written, no warning about the missing dir
ansible-playbook -i "${INVENTORY_PATH}" collect.yml --check -e "fleet_test_dir=${work}/fresh" 2>&1 \
    | tee "${work}/fresh-check.log"
test ! -e "${work}/fresh"
no_missing_dir_warning "${work}/fresh-check.log"

# 9. The whole role (collect + render) against a real host from ansible-test's inventory
ansible-playbook -i "${INVENTORY_PATH}" collect.yml -e "fleet_test_dir=${work}" 2>&1 | tee "${work}/live.log"
# first run into a new data dir: no warning about the missing dir
no_missing_dir_warning "${work}/live.log"
python check_pages.py "${work}/live/vault" --hosts testhost
python check_run.py live "${work}/live/data/testhost.json"
