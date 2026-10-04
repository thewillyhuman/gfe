# Create the unprivileged account gfe-node runs as. Idempotent, so it is
# safe on upgrade.
getent group gfe-node >/dev/null || groupadd --system gfe-node
getent passwd gfe-node >/dev/null || useradd --system --gid gfe-node \
    --home-dir /var/lib/gfe --no-create-home --shell /sbin/nologin \
    --comment "General Front End" gfe-node
exit 0
