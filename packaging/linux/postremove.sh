#!/bin/sh
#
# deb/rpm postremove — reclaim what the package manager does not.
#
# Config and keys are left in place on an upgrade and only removed on a purge,
# so a reinstall keeps its identity instead of re-enrolling.
set -eu

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl reset-failed hasfy-agent.service 2>/dev/null || true
fi

case "${1:-}" in
    purge|0)
        rm -rf /etc/hasfy /var/log/hasfy
        ;;
esac

exit 0
