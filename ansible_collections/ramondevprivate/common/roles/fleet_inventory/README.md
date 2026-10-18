# ramondevprivate.common.fleet_inventory

Documents Debian servers as Markdown for Obsidian: one page per server, an overview with the findings that need
attention, and a server list. It records how a server is set up (users, SSH keys, sudo, firewall, ports, Docker,
fail2ban, updates), not its current load. Nothing is changed on the servers.

## Usage

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

`become: true` is needed for other users' key files and sudo rules, UFW, socket processes, Docker and fail2ban
jails; without it those parts show as unknown. `--check` writes nothing, `--diff` shows the page content.

| Variable | Default | Purpose |
|---|---|---|
| `fleet_inventory_output_dir` | required | Vault folder for `Overview.md`, `Server List.md` and `Servers/` |
| `fleet_inventory_data_dir` | required | JSON snapshots, one per host. Keep it outside the vault |
| `fleet_inventory_mermaid_charts` | `true` | Bar charts for cores, RAM and disk in the overview |
| `fleet_inventory_descriptions_dir` | `Descriptions` | Folder in the output dir for your own note per server. Empty: off |
| `fleet_inventory_group_filter` | `cdrom`, `floppy`, `audio`, … | Supplementary groups not shown. Never list privilege groups (`sudo`, `docker`, `lxd`, `adm`) |
| `fleet_inventory_user_filter` | `root`, `debian` | Accounts not collected at all. Filtering `root` hides who can log in as root |
| `fleet_inventory_inactive_days` | `365` | A last login older than this marks a user inactive |
| `fleet_inventory_stopped_containers` | `true` | List containers that are not running (decided at render time) |
| `fleet_inventory_update_max_age_days` | `7` | Auto-updates without a successful run for this long need attention |
| `fleet_inventory_probe_host` | `""` | Host that pings the public addresses; doesn't have to be in the inventory. Empty: no probe |
| `fleet_inventory_probe_user` | `""` | SSH user on the probe host; required with a probe host |
| `fleet_inventory_probe_key` | `""` | SSH key for the probe host; only this key is offered. Empty: SSH defaults |
| `fleet_inventory_probe_port` | `22` | SSH port of the probe host |

`ansible-doc -t role ramondevprivate.common.fleet_inventory` shows the same variables with their types.

## How it works

1. On each host: gather facts and run `ramondevprivate.common.fleet_info` (read-only).
2. Once, from the probe host: ping every public address of the reached hosts. A host is `public` if any address
   answers, otherwise `internal`; without a usable probe it keeps its stored exposure.
3. Once, on the controller: store a JSON snapshot per reached host, read all snapshots, and render the pages.

A targeted host that can't be collected keeps its last snapshot and shows "not updated" until a run reaches it again.
Hosts outside `--limit` are not touched. To remove a host, delete its JSON file and its page.

## Needs attention

The overview lists these findings per server; the list is fixed.

| Rule | Finding |
|---|---|
| `ufw_off` | UFW inactive or not installed |
| `fail2ban_public` | fail2ban not running on a public host |
| `auto_updates` | Auto-updates not configured, or no successful run in `fleet_inventory_update_max_age_days` |
| `sudo_full_nopasswd` | A user with full sudo and NOPASSWD |
| `key_without_comment` | An authorized key without comment |

Unknown data (no root) never produces a finding. Ports that a rootful Docker daemon publishes past UFW are marked in
the server page's ports table, not listed here.

## How it's read

- Accounts: root, accounts with a login shell and `UID >= UID_MIN`, and every account with authorized keys. The last
  login comes from `lslogins`; only the resulting status is shown.
- Key files are read like sshd reads them: with the account's own permissions (a forked child drops to its uid and
  groups), regular files only, at most 1 MiB, 10 seconds each. Key material and forced commands are never collected.
- UFW from `ufw status verbose` and `/etc/ufw/user*.rules`, ports from `ss`, fail2ban from `systemctl` and
  `fail2ban-client`, auto-updates from `apt-config`, the timer and `/var/lib/apt/periodic/upgrade-stamp`.
- Docker over its Engine API socket, read-only, never through the `docker` CLI. A socket must belong to the daemon's
  owner, and so must the process serving it; rootless sockets are never followed through symlinks. Environment
  variables, commands and labels other than the image version and compose directory never leave the host.
- Commands run with an English locale. Values from the hosts are escaped on the pages (`ramondevprivate.common.md_escape`), so
  they can't break tables, add links or hide content.

## Descriptions

Each server page embeds the note `<host> description` from `fleet_inventory_descriptions_dir`. The role creates a
missing note once and never changes it, so write what you want to know about the server there. `Server List.md`
embeds the line of each note that ends in ` ^summary` (with a space before the `^`).

All generated pages carry the CSS class `fleet-wide`. To show them at full width, enable a snippet
`.obsidian/snippets/fleet-wide.css` in the vault:

```css
.fleet-wide {
  --file-line-width: 100%;
}
```

## Known limitations

- Debian 12 and 13 only.
- `sudo -l` prints several commands of one sudoers entry on one line (`(ALL) NOPASSWD: /usr/bin/apt, ALL`); such a
  line counts as `limited`, so `sudo_full_nopasswd` misses it. The rule is in the JSON snapshot.
- A public host that blocks ICMP shows up as `internal`.
- Edits to ufw's `before.rules` are not read; its defaults (DHCP, mDNS, UPnP) are assumed.
- sshd's StrictModes are not checked, and key files only root may read (e.g. `AuthorizedKeysFile /etc/ssh/keys/%u`)
  show as not readable.
- The role needs the default `linear` strategy. It stops with a message under `serial`; `free` can't be detected.
- Local file changes are counted on the first server of the run in the recap.

## How this was made

This role started as an experiment in building software with AI. The design, the decisions and the reviews are mine;
most of the code, tests and documentation were written by an AI assistant (Claude) under that review, and checked
with the tests and linters described in the repository. Read it with that in mind, and report anything that looks
wrong.
