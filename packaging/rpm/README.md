# RPM package

The `gfe` RPM installs a GFE node the way config management expects to find
it: binaries in `/usr/bin`, a systemd unit, and no configuration.

| Path | Content |
|---|---|
| `/usr/bin/gfe-node` | The proxy |
| `/usr/bin/gfe-trace` | Offline routing tracer and CI assertions |
| `/usr/lib/systemd/system/gfe-node.service` | Hardened unit (not enabled by the package) |
| `/usr/share/gfe/` | Deploy helpers and the Grafana dashboard |
| `/usr/share/doc/gfe/` | README and example configs |

The package creates the `gfe-node` system user. It does **not** ship
`/etc/gfe/gfe.toml` or the dynamic config, and it never enables, starts or
restarts the service: those belong to whoever manages the node. The unit
creates `/var/lib/gfe` (the last-known-good config cache) on start.

## Building

The metadata lives in `crates/gfe-node/Cargo.toml` under
`[package.metadata.generate-rpm]`; the scriptlets are next to this file. The
package is assembled from already-built release binaries by
[`cargo-generate-rpm`](https://github.com/cat-in-136/cargo-generate-rpm), so
no `rpmbuild` is needed:

```bash
cargo install cargo-generate-rpm --locked
cargo build --release --bin gfe-node --bin gfe-trace
cargo generate-rpm -p crates/gfe-node
ls target/generate-rpm/gfe-*.rpm
```

The release workflow does the same for the static `x86_64` and `aarch64`
musl builds and attaches both RPMs to the GitHub release. Those binaries
have no shared-library dependencies, so one RPM per architecture installs on
any RPM-based distribution.

## Managing a node with Puppet

A node needs the package, two files and the service. The dynamic config is
hot-reloaded when the file is replaced, so it must **not** notify the
service. The package and the bootstrap TOML are read once, by a new process,
so they must; and what they trigger is an upgrade in place, not a restart.

```puppet
package { 'gfe': ensure => installed }

file { '/etc/gfe':
  ensure => directory,
}

# Hot-reloaded: no notify. A candidate the node would reject never lands.
file { '/etc/gfe/gfe-dynamic.json':
  content      => to_json_pretty($gfe_dynamic),
  validate_cmd => '/usr/bin/gfe-node --check-config --dynamic-config %',
  require      => Package['gfe'],
}

# Read once at startup: a change replaces the node in place. The check also
# loads the dynamic config the TOML names, hence the ordering.
file { '/etc/gfe/gfe.toml':
  content      => template('gfe/gfe.toml.erb'),
  validate_cmd => '/usr/bin/gfe-node --config % --check-config',
  require      => File['/etc/gfe/gfe-dynamic.json'],
  notify       => Service['gfe-node'],
}

# "Restarting" the service is `systemctl reload`: the node starts the binary
# now on disk, hands it its listening sockets and drains. No connection is
# refused, and a new node that does not start leaves the old one serving.
service { 'gfe-node':
  ensure    => running,
  enable    => true,
  restart   => '/usr/bin/systemctl reload gfe-node',
  subscribe => Package['gfe'],
}
```

Notes:

- Certificate and key files must exist and be readable by `gfe-node` before
  the dynamic config that names them is written, since the check loads them.
  A certificate later replaced in place is picked up within 10 seconds, with
  no change to the dynamic config and no notify.
- The dynamic config is checked on its own, so it can be written before the
  bootstrap TOML exists; that ordering is what lets a fresh node converge in
  one run.
- A node restarted while the dynamic config is missing or broken starts from
  its last-known-good cache (`local_cache`) and reports
  `gfe_config_from_cache = 1`; it does not stay down.
- With `[log] file = "/var/log/gfe/gfe.log"` in the bootstrap TOML, as in the
  example config, the access and connection logs go to that file and the
  journal keeps the node's own log. The unit creates `/var/log/gfe`, owned by
  `gfe-node` and closed to other users. Nothing rotates the file: without a
  collector or logrotate it grows until the disk is full, at roughly 500
  bytes per request and 300 per connection. A minimal logrotate rule, which needs no signal because
  the node finds a renamed file again by itself:

  ```
  /var/log/gfe/gfe.log {
      daily
      rotate 7
      compress
      delaycompress
      missingok
      notifempty
      create 0640 gfe-node gfe-node
  }
  ```

- The kernel TCP statistics (`[ebpf] enabled = true`) need two more
  capabilities than the unit grants. `/usr/share/gfe/gfe-node-ebpf.conf` is a
  drop-in for `/etc/systemd/system/gfe-node.service.d/` that grants them. The
  RPM must also have been built with clang available, or the binary has no
  eBPF program in it and says so when asked to attach.
- Listeners, routes, pools and certificates are all in the dynamic config
  and are reconciled when the file changes, including binding and releasing
  listening sockets. Only the binary and the bootstrap TOML need a new
  process.
- `systemctl reload` does not wait for the upgrade and does not fail when it
  does: Puppet reports the refresh as done either way. A node that could not
  be replaced keeps serving as it was, says why in `systemctl status
  gfe-node`, and raises `GfeUpgradeFailed` through `gfe_upgrade_failures_total`.
- A reload does not apply a change to the unit itself: the new process is
  started by the old one and keeps its capabilities, limits and environment.
  After changing the unit or a drop-in (the eBPF one included), use
  `systemctl restart gfe-node`, which closes the listening sockets while the
  node drains and starts again.
- The first update from a version without upgrades in place must be a
  restart too: that version does not handle the signal a reload sends and is
  killed by it.
