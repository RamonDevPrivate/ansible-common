# Changelog

## v1.0.0

- New role `fleet_inventory`: documents Debian servers read-only as Markdown pages for Obsidian, one page per server
  with users, SSH keys, sudo, firewall, ports, Docker, fail2ban and updates, plus an overview of what needs attention.
- New module `fleet_info`: collects those facts read-only from a host, for the role.
- New filters for the role: `fleet_snapshot`, `fleet_report`, `fleet_probe_targets`, `fleet_exposure`,
  `fleet_probe_errors` and `fleet_unreached` build the snapshots, the probe and the pages; `md_escape` makes a value
  safe to print in Markdown.
