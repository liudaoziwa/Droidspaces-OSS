#!/system/bin/sh
# Droidspaces post-fs-data script
# This script starts the Droidspaces daemon as early as possible during boot.

MODDIR=${0%/*}
DROIDSPACE_DIR=/data/local/Droidspaces
LOGS_DIR=${DROIDSPACE_DIR}/Logs
LOGS_FILE=${LOGS_DIR}/boot-module.log
DROIDSPACE_BINARY=${DROIDSPACE_DIR}/bin/droidspaces
BUSYBOX_BINARY=${DROIDSPACE_DIR}/bin/busybox

# Create logs directory if it doesn't exist
mkdir -p "${LOGS_DIR}" 2>/dev/null

# Clear log file at boot start
> "${LOGS_FILE}" 2>/dev/null

# Function to log with timestamp
log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$(date +%s)")
    echo "[${timestamp}] [post-fs-data] $*" >> "${LOGS_FILE}"
}

# Function to remove ANSI escape sequences/colors
strip_colors() {
    local ESC=$(printf '\033')
    ${BUSYBOX_BINARY} sed "s/${ESC}\[[0-9;]*[mK]//g"
}

log "Droidspaces post-fs-data script started"

# Daemon mode marker file
DAEMON_MODE_FILE=${DROIDSPACE_DIR}/.daemon_mode

# Start the Droidspaces daemon if enabled (value 1)
if [ -f "${DAEMON_MODE_FILE}" ] && [ "$(${BUSYBOX_BINARY} cat "${DAEMON_MODE_FILE}" 2>/dev/null)" = "1" ]; then
    log "Daemon mode enabled, starting Droidspaces daemon..."
    if "${DROIDSPACE_BINARY}" daemon 2>&1 | strip_colors >> "${LOGS_FILE}" &
    then
        log "Daemon process launched in background"
    else
        log "WARNING: Failed to launch daemon"
    fi
else
    log "Daemon mode disabled or not configured, skipping daemon start"
fi
