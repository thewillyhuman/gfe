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
service; the bootstrap TOML is read once at startup, so it must.

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

# Read once at startup: a change restarts the node (it drains first). The
# check also loads the dynamic config the TOML names, hence the ordering.
file { '/etc/gfe/gfe.toml':
  content      => template('gfe/gfe.toml.erb'),
  validate_cmd => '/usr/bin/gfe-node --config % --check-config',
  require      => File['/etc/gfe/gfe-dynamic.json'],
  notify       => Service['gfe-node'],
}

service { 'gfe-node':
  ensure => running,
  enable => true,
}
```

Notes:

- Certificate and key files must exist and be readable by `gfe-node` before
  the dynamic config that names them is written, since the check loads them.
  A certificate later replaced in place is picked up within 10 seconds, with
  no change to the dynamic config and no notify.
- The dynamic config is checked on its own, so it can be written before the
  bootstrap TOML exists; that ordering is what lets a fresh node converge in
  one run. The service unit re-checks both files before starting.
- Listeners, routes, pools and certificates are all in the dynamic config
  and are reconciled on reload, including binding and releasing listening
  sockets. Only the bootstrap TOML requires a restart.
