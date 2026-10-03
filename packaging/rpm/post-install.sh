# Make systemd see the (new or updated) unit. The service is neither enabled
# nor restarted here: when the proxy restarts is the operator's decision.
systemctl daemon-reload >/dev/null 2>&1 || :
