#!/bin/sh
#
# deb/rpm postinstall — runs as root from the package manager's own session.
#
# The single privileged step in the agent's lifecycle. The daemon enrols itself
# on first start (cmd/agent/enroll.go), so nothing here writes a credential and
# nothing afterwards ever asks for elevation.
set -eu

# 0750: holds device.key and, briefly, the one-shot enrolment secret. Group
# readable so an administrator can read the enrolment status file.
install -d -o root -g root -m 0750 /etc/hasfy
install -d -o root -g root -m 0755 /var/log/hasfy

# `depends: osquery` in the package metadata normally guarantees this. It can
# still be missing on a box where the package was force-installed, and the
# agent would then run with an empty CMDB — visible only in its log.
if ! command -v osqueryi >/dev/null 2>&1; then
    echo "warning: osqueryi was not found. Inventory collection will stay" >&2
    echo "         paused until it is installed; the agent re-checks every" >&2
    echo "         15 minutes and needs no restart." >&2
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable hasfy-agent.service || true
    # `restart`, not `start`: on an upgrade the old binary is still running and
    # `start` would be a no-op, leaving the machine on the previous version
    # until the next reboot.
    systemctl restart hasfy-agent.service || true
    echo "hasfy-agent installed. It is waiting to be authorised."
    echo "Enrolment code: sudo cat /etc/hasfy/enrollment-status.json"
else
    echo "hasfy-agent installed, but systemd was not found." >&2
    echo "Start it yourself: /opt/hasfy/hasfy-agent" >&2
fi

exit 0
