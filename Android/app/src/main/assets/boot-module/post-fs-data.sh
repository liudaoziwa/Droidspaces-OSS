#!/system/bin/sh
# Droidspaces post-fs-data script
# This script starts the Droidspaces daemon as early as possible during boot.

MODDIR=${0%/*}
DROIDSPACE_DIR=/data/local/Droidspaces
LOGS_DIR=${DROIDSPACE_DIR}/Logs
LOGS_FILE=${LOGS_DIR}/boot-module.log
DROIDSPACE_BINARY=${DROIDSPACE_DIR}/bin/droidspaces
BUSYBOX_BINARY=${DROIDSPACE_DIR}/bin/busybox
MAGISKPOLICY_BINARY=${DROIDSPACE_DIR}/bin/magiskpolicy
DROIDSPACES_TE_FILE=${MODDIR}/etc/droidspaces.te

# Create logs directory if it doesn't exist
mkdir -p "${LOGS_DIR}" 2>/dev/null

# Clear log file at boot start
> "${LOGS_FILE}" 2>/dev/null

# Function to log with timestamp
log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$(date +%s)")
    echo "[${timestamp}] [post-fs-data] $*" >> "${LOGS_FILE}"
}

log "Droidspaces post-fs-data script started"

# Daemon mode marker file
DAEMON_MODE_FILE=${DROIDSPACE_DIR}/.daemon_mode

# Live SELinux patching
if [ -f "${MAGISKPOLICY_BINARY}" ] && [ -f "${DROIDSPACES_TE_FILE}" ]; then
    log "Patching SELinux policy..."
    OUTPUT=$("${MAGISKPOLICY_BINARY}" --live --apply "${DROIDSPACES_TE_FILE}" 2>&1)
    RET=$?
    if [ $RET -eq 0 ]; then
        log "SELinux policy patched successfully"
    else
        log "WARNING: magiskpolicy failed (exit $RET)"
        log "Output: ${OUTPUT}"
    fi
else
    log "Skipping live SELinux patch: magiskpolicy or .te file missing"
fi

# Start the Droidspaces daemon if enabled (value 1)
if [ -f "${DAEMON_MODE_FILE}" ] && [ "$(${BUSYBOX_BINARY} cat "${DAEMON_MODE_FILE}" 2>/dev/null)" = "1" ]; then
    log "Daemon mode enabled, starting Droidspaces daemon..."

    if "${DROIDSPACE_BINARY}" daemon >> "${LOGS_FILE}" 2>&1; then
        log "Daemon process launched successfully"
    else
        log "WARNING: Failed to launch daemon"
    fi
else
    log "Daemon mode disabled or not configured, skipping daemon start"
fi
