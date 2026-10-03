# $1 is 0 on removal and 1 on upgrade: only stop the service when the
# package is really going away.
if [ "$1" -eq 0 ]; then
    systemctl --no-reload disable --now gfe-node.service >/dev/null 2>&1 || :
fi
