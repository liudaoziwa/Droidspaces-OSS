#!/system/bin/sh
set -o pipefail

# Droidspaces Boot Script
# Automatically starts containers with run_at_boot=1 on device boot
MODDIR=${0%/*}
DROIDSPACE_DIR=/data/local/Droidspaces
LOGS_DIR=${DROIDSPACE_DIR}/Logs
LOGS_FILE=${LOGS_DIR}/boot-module.log
CONTAINERS_DIR=${DROIDSPACE_DIR}/Containers
DROIDSPACE_BINARY=${DROIDSPACE_DIR}/bin/droidspaces
BUSYBOX_BINARY=${DROIDSPACE_DIR}/bin/busybox

# Create logs directory if it doesn't exist
mkdir -p "${LOGS_DIR}" 2>/dev/null

# Redirect all output to log file
exec >> "${LOGS_FILE}" 2>&1

# Function to log with timestamp
log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$(date +%s)")
    echo "[${timestamp}] $*"
}

# Function to parse config file and extract a value
get_config_value() {
    local config_file="$1"
    local key="$2"
    ${BUSYBOX_BINARY} grep "^${key}=" "${config_file}" 2>/dev/null | ${BUSYBOX_BINARY} head -1 | ${BUSYBOX_BINARY} sed 's/^[^=]*=//' | ${BUSYBOX_BINARY} tr -d '\r\n'
}

# Function to remove ANSI escape sequences/colors from output
strip_colors() {
    local ESC=$(printf '\033')
    ${BUSYBOX_BINARY} sed "s/${ESC}\[[0-9;]*[mK]//g"
}

log "Droidspaces boot module started"

# Check if droidspaces binary exists
if [ ! -f "${DROIDSPACE_BINARY}" ]; then
    log "ERROR: Droidspaces binary not found at ${DROIDSPACE_BINARY}"
    exit 1
fi

# Check if busybox exists
if [ ! -f "${BUSYBOX_BINARY}" ]; then
    log "ERROR: Busybox binary not found at ${BUSYBOX_BINARY}"
    exit 1
fi

log "All prerequisites checked successfully"

# Apply correct SELinux context to .img files to prevent mount I/O errors
log "Applying SELinux context to rootfs images..."
${BUSYBOX_BINARY} find "${CONTAINERS_DIR}" -name "*.img" -exec chcon u:object_r:vold_data_file:s0 {} + 2>/dev/null

# Wait for boot to complete
log "Waiting for boot to complete..."
while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ]; do
    sleep 1
done

log "Boot completed, waiting 25 seconds for system stability..."
sleep 25
# Daemon mode marker file
DAEMON_MODE_FILE=${DROIDSPACE_DIR}/.daemon_mode
DAEMON_STATUS="⚪ Off"

# Verify the Droidspaces daemon is running (started by post-fs-data.sh)
if [ -f "${DAEMON_MODE_FILE}" ] && [ "$(${BUSYBOX_BINARY} cat "${DAEMON_MODE_FILE}" 2>/dev/null)" = "1" ]; then
    log "Checking Droidspaces daemon status..."
    # Wait up to 5 seconds for daemon to be ready if it's still starting
    count=0
    while [ ${count} -lt 5 ]; do
        if ${BUSYBOX_BINARY} pgrep -f "droidspaces daemon" >/dev/null; then
            DAEMON_PID=$(${BUSYBOX_BINARY} pgrep -f "droidspaces daemon" | ${BUSYBOX_BINARY} head -1)
            log "Daemon verified running (PID ${DAEMON_PID})"
            DAEMON_STATUS="🟢 Running (PID ${DAEMON_PID})"
            break
        fi
        sleep 1
        count=$((count + 1))
    done

    if [ "${DAEMON_STATUS}" = "⚪ Off" ]; then
        log "WARNING: Daemon not found running"
        DAEMON_STATUS="🔴 Not Running"
    fi
else
    log "Daemon mode disabled, skipping status check"
fi

# Find all container.config files
log "Scanning for container configurations..."
CONFIG_FILES=$(${BUSYBOX_BINARY} find "${CONTAINERS_DIR}" -name "container.config" 2>/dev/null)

if [ -z "${CONFIG_FILES}" ]; then
    log "No container configs found, exiting"
    exit 0
fi

log "Found container configs, processing..."

# Process each config file
container_count=0
success_count=0
failed_count=0

for cfg in ${CONFIG_FILES}; do
    if [ ! -f "${cfg}" ]; then
        continue
    fi

    # Parse only mandatory fields for filtering/logging
    name=$(get_config_value "${cfg}" "name")
    run_at_boot=$(get_config_value "${cfg}" "run_at_boot")

    # Skip if run_at_boot is not 1
    if [ "${run_at_boot}" != "1" ]; then
        continue
    fi

    container_count=$((container_count + 1))

    # Use name for log, fall back to dirname if missing
    display_name="${name:-$(basename "$(dirname "${cfg}")")}"

    log "Starting container: ${display_name}"

    # Execute using the new --config flag
    "${DROIDSPACE_BINARY}" --config "${cfg}" start 2>&1 | strip_colors
    exit_code=$?

    if [ ${exit_code} -eq 0 ]; then
        log "SUCCESS: Container '${display_name}' started successfully"
        success_count=$((success_count + 1))
    else
        log "FAILED: Container '${display_name}' failed to start (exit code: ${exit_code})"
        failed_count=$((failed_count + 1))
    fi
done

log "Boot Summary: Daemon: ${DAEMON_STATUS} | Containers: ${success_count} success | ${failed_count} failed"
sed -i "s/^description=.*/description=Daemon: ${DAEMON_STATUS} | Containers: ${success_count} success | ${failed_count} failed/g" $MODDIR/module.prop
log "Update Module description"
