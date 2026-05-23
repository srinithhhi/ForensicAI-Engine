#!/bin/bash
# Network connectivity watchdog for the Ubuntu Scope 1 VM.
#
# Why this exists: the VM lives on a bridged adapter on a Mac host. When the
# Mac sleeps, the bridge can lose its link binding to the physical NIC and
# the VM ends up "running" with no network — the Velociraptor agent stops
# checking in, SSH dies, and any in-flight acquisition fails. This watchdog
# pings the gateway every 30 s and runs `netplan apply` after 3 consecutive
# failures to force the bridge to re-attach.
#
# Idempotent: runs forever, never exits on its own. Restart-on-failure is
# handled by the systemd unit.

set -u

GATEWAY="${WATCHDOG_GATEWAY:-192.168.1.1}"
INTERVAL="${WATCHDOG_INTERVAL:-30}"
FAIL_THRESHOLD="${WATCHDOG_FAIL_THRESHOLD:-3}"
PING_TIMEOUT="${WATCHDOG_PING_TIMEOUT:-2}"
RECOVERY_COOLDOWN="${WATCHDOG_RECOVERY_COOLDOWN:-15}"

log() {
    logger -t network-watchdog "$*"
}

log "started — gateway=$GATEWAY interval=${INTERVAL}s threshold=$FAIL_THRESHOLD"

failures=0
while true; do
    if ping -c 1 -W "$PING_TIMEOUT" "$GATEWAY" >/dev/null 2>&1; then
        if [ "$failures" -gt 0 ]; then
            log "gateway $GATEWAY reachable again after $failures failure(s); resetting"
        fi
        failures=0
    else
        failures=$((failures + 1))
        log "gateway $GATEWAY unreachable (failure $failures/$FAIL_THRESHOLD)"
        if [ "$failures" -ge "$FAIL_THRESHOLD" ]; then
            log "running netplan apply to restore network"
            /usr/sbin/netplan apply 2>&1 | logger -t network-watchdog
            failures=0
            sleep "$RECOVERY_COOLDOWN"
        fi
    fi
    sleep "$INTERVAL"
done
