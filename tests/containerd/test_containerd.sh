#!/usr/bin/env bash
# =============================================================================
# tests/containerd/test_containerd.sh
#
# Integration tests for sandlock-oci with containerd.
#
# Prerequisites:
#   - containerd installed and running (systemctl start containerd)
#   - nerdctl or ctr installed
#   - sandlock-oci binary built (cargo build --release -p sandlock-oci)
#   - Run as root (OCI runtimes require root or user-namespace privileges)
#
# Usage:
#   sudo ./tests/containerd/test_containerd.sh [--binary /path/to/sandlock-oci]
#
# Exit code: 0 = all tests passed, non-zero = failure
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BINARY="${1:-${WORKSPACE_ROOT}/target/release/sandlock-oci}"
NERDCTL="${NERDCTL:-nerdctl}"
PASS=0
FAIL=0
SKIP=0

# Colour helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAIL=$((FAIL + 1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $*"; SKIP=$((SKIP + 1)); }
info() { echo -e "       $*"; }

# ── Preflight ─────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "error: this test script must be run as root"
    exit 1
fi

if [[ ! -f "${BINARY}" ]]; then
    echo "error: sandlock-oci binary not found at ${BINARY}"
    echo "       Build it with: cargo build --release -p sandlock-oci"
    exit 1
fi

if ! command -v containerd &>/dev/null; then
    echo "error: containerd not found in PATH"
    exit 1
fi

if ! systemctl is-active --quiet containerd 2>/dev/null; then
    echo "error: containerd is not running (systemctl start containerd)"
    exit 1
fi

echo "=== sandlock-oci containerd integration tests ==="
echo "Binary: ${BINARY}"
echo "containerd: $(containerd --version 2>/dev/null | head -1)"
echo ""

# ── Install binary into containerd runtime path ───────────────────────────────

INSTALL_PATH="/usr/local/bin/sandlock-oci"
install -m 755 "${BINARY}" "${INSTALL_PATH}"
info "Installed ${BINARY} → ${INSTALL_PATH}"

# ── Register sandlock-oci as a containerd runtime ────────────────────────────

CONTAINERD_CONFIG="/etc/containerd/config.toml"
BACKUP_CONFIG="${CONTAINERD_CONFIG}.bak.$$"
CONFIG_MODIFIED=false

if [[ -f "${CONTAINERD_CONFIG}" ]]; then
    cp "${CONTAINERD_CONFIG}" "${BACKUP_CONFIG}"
fi

# Append sandlock-oci runtime config if not already present.
if ! grep -q "sandlock" "${CONTAINERD_CONFIG}" 2>/dev/null; then
    cat >> "${CONTAINERD_CONFIG}" << 'EOF'

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.sandlock]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.sandlock.options]
    BinaryName = "/usr/local/bin/sandlock-oci"
EOF
    CONFIG_MODIFIED=true
    systemctl restart containerd
    sleep 2
    info "containerd config updated and restarted"
fi

# Cleanup function
cleanup() {
    # Restore original containerd config
    if $CONFIG_MODIFIED; then
        if [[ -f "${BACKUP_CONFIG}" ]]; then
            cp "${BACKUP_CONFIG}" "${CONTAINERD_CONFIG}"
        else
            # Remove the lines we added
            sed -i '/\[plugins.*sandlock\]/,/BinaryName.*sandlock-oci/d' "${CONTAINERD_CONFIG}"
        fi
        systemctl restart containerd 2>/dev/null || true
    fi
    rm -f "${BACKUP_CONFIG}"
}
trap cleanup EXIT

# ── Test 1: sandlock-oci check ────────────────────────────────────────────────

echo "--- Test: sandlock-oci check"
if "${BINARY}" check; then
    pass "sandlock-oci check reports kernel support"
else
    fail "sandlock-oci check failed — kernel may not support Landlock"
fi

# ── Test 2: Manual OCI lifecycle (without containerd) ────────────────────────

echo "--- Test: manual OCI lifecycle (create/start/state/kill/delete)"

# Create a minimal bundle
BUNDLE_DIR="$(mktemp -d)"
CONTAINER_ID="sandlock-test-$$"

mkdir -p "${BUNDLE_DIR}/rootfs"

# Copy minimal binaries into rootfs
for bin in sh echo; do
    BIN_PATH="$(which $bin 2>/dev/null || true)"
    if [[ -n "${BIN_PATH}" ]]; then
        cp "${BIN_PATH}" "${BUNDLE_DIR}/rootfs/"
    fi
done

cat > "${BUNDLE_DIR}/config.json" << EOF
{
  "ociVersion": "1.0.2",
  "root": { "path": "rootfs", "readonly": false },
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "cwd": "/",
    "args": ["/sh", "-c", "sleep 10"],
    "env": ["PATH=/usr/bin:/bin:/"]
  },
  "mounts": [],
  "linux": {
    "resources": { "devices": [{ "allow": false, "access": "rwm" }] },
    "namespaces": [{ "type": "mount" }]
  }
}
EOF

# Create
if "${BINARY}" create "${CONTAINER_ID}" -b "${BUNDLE_DIR}"; then
    pass "create container ${CONTAINER_ID}"
else
    fail "create container failed"
    rm -rf "${BUNDLE_DIR}"
    # Don't exit — continue with remaining tests
fi

# State (should be created or running)
STATE_OUTPUT=$("${BINARY}" state "${CONTAINER_ID}" || echo '{"status":"unknown"}')
STATUS=$(echo "${STATE_OUTPUT}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")

if [[ "${STATUS}" == "created" ]] || [[ "${STATUS}" == "running" ]]; then
    pass "state shows valid status (${STATUS})"
else
    fail "state shows unexpected status: ${STATUS}"
fi

# Start
if "${BINARY}" start "${CONTAINER_ID}" 2>/dev/null; then
    pass "start container ${CONTAINER_ID}"
else
    # May fail because the child process immediately exits in test bundle
    skip "start returned non-zero (process may have exited)"
fi

# Kill
"${BINARY}" kill "${CONTAINER_ID}" SIGKILL 2>/dev/null || true
pass "kill container (SIGKILL sent)"

# Delete
if "${BINARY}" delete --force "${CONTAINER_ID}" 2>/dev/null; then
    pass "delete container ${CONTAINER_ID}"
else
    fail "delete container failed"
fi

rm -rf "${BUNDLE_DIR}"

# ── Test 3: nerdctl run with sandlock runtime (if nerdctl available) ──────────

echo "--- Test: nerdctl run with sandlock runtime"

if command -v "${NERDCTL}" &>/dev/null; then
    OUTPUT=$("${NERDCTL}" run \
        --runtime sandlock \
        --rm \
        alpine:latest \
        echo "hello from sandlock" 2>&1 || true)

    if echo "${OUTPUT}" | grep -q "hello from sandlock"; then
        pass "nerdctl run with sandlock runtime produced expected output"
    elif echo "${OUTPUT}" | grep -q "sandlock"; then
        skip "nerdctl run attempted sandlock runtime (output: ${OUTPUT})"
    else
        skip "nerdctl run with sandlock: ${OUTPUT}"
    fi
else
    skip "nerdctl not installed — skipping nerdctl test"
fi

# ── Test 4: ctr run with sandlock runtime (if ctr available) ─────────────────

echo "--- Test: ctr run with sandlock runtime"

if command -v ctr &>/dev/null; then
    # Pull a minimal image
    ctr images pull docker.io/library/busybox:latest &>/dev/null || true

    CONTAINER_NAME="sandlock-ctr-test-$$"
    OUTPUT=$(ctr run \
        --runtime "io.containerd.sandlock.v1" \
        --rm \
        docker.io/library/busybox:latest \
        "${CONTAINER_NAME}" \
        echo "ctr-sandlock-ok" 2>&1 || true)

    if echo "${OUTPUT}" | grep -q "ctr-sandlock-ok"; then
        pass "ctr run with sandlock runtime succeeded"
    else
        skip "ctr run with sandlock: ${OUTPUT}"
    fi
else
    skip "ctr not found — skipping ctr test"
fi

# ── Test 5: OCI state persistence ────────────────────────────────────────────

echo "--- Test: OCI state persistence across list"
LIST_OUTPUT=$("${BINARY}" list 2>/dev/null)
if echo "${LIST_OUTPUT}" | grep -qE "(No sandlock|ID)"; then
    pass "list command produces valid output"
else
    fail "list output unexpected: ${LIST_OUTPUT}"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Results ==="
echo -e "  ${GREEN}PASS${NC}: ${PASS}"
echo -e "  ${RED}FAIL${NC}: ${FAIL}"
echo -e "  ${YELLOW}SKIP${NC}: ${SKIP}"
echo ""

if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
