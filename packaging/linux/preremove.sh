#!/bin/sh
#
# deb/rpm preremove — stop and disable before the files disappear.
#
# Ordering matters: the audit found that uninstalling used to leave a 6-hourly
# timer firing against a binary that had just been deleted, so every removed
# host accumulated a permanently failing unit.
set -eu

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop hasfy-agent.service || true
    systemctl disable hasfy-agent.service || true
fi

exit 0
