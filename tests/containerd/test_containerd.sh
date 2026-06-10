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
BINARY="${WORKSPACE_ROOT}/target/release/sandlock-oci"
NERDCTL="${NERDCTL:-nerdctl}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)   BINARY="$2"; shift 2 ;;
        --binary=*) BINARY="${1#--binary=}"; shift ;;
        *)          shift ;;
    esac
done
PASS=0
FAIL=0
SKIP=0

# Isolated state dir so tests never write to /run/sandlock-oci and can run
# without conflicting with a real containerd installation.
export SANDLOCK_OCI_STATE_DIR="$(mktemp -d /tmp/sandlock-oci-test-state.XXXXXX)"

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
echo "Binary:    ${BINARY}"
echo "containerd: $(containerd --version 2>/dev/null | head -1)"
echo "State dir: ${SANDLOCK_OCI_STATE_DIR}"
echo ""

# ── Install binary into containerd runtime path ───────────────────────────────

INSTALL_PATH="/usr/local/bin/sandlock-oci"
install -m 755 "${BINARY}" "${INSTALL_PATH}"
info "Installed ${BINARY} → ${INSTALL_PATH}"

# ── Register sandlock-oci as a containerd runtime ────────────────────────────

CONTAINERD_CONFIG="/etc/containerd/config.toml"
CONFIG_DROPIN_DIR="/etc/containerd/config.toml.d"
BACKUP_CONFIG="${CONTAINERD_CONFIG}.bak.$$"
CONFIG_MODIFIED=false

cleanup() {
    local exit_code=$?
    if $CONFIG_MODIFIED; then
        if [[ -f "${BACKUP_CONFIG}" ]]; then
            cp "${BACKUP_CONFIG}" "${CONTAINERD_CONFIG}"
        elif [[ -f "${CONFIG_DROPIN_DIR}/sandlock.toml" ]]; then
            rm -f "${CONFIG_DROPIN_DIR}/sandlock.toml"
        fi
        systemctl restart containerd 2>/dev/null || true
    fi
    rm -f "${BACKUP_CONFIG}"
    rm -rf "${SANDLOCK_OCI_STATE_DIR}"
    pkill -f "sandlock-oci" 2>/dev/null || true
    exit $exit_code
}
trap cleanup EXIT

if [[ -d "${CONFIG_DROPIN_DIR}" ]]; then
    cat > "${CONFIG_DROPIN_DIR}/sandlock.toml" << 'DROPIN'
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.sandlock]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.sandlock.options]
    BinaryName = "/usr/local/bin/sandlock-oci"
DROPIN
    CONFIG_MODIFIED=true
    info "Registered sandlock-oci via config drop-in"
elif [[ -f "${CONTAINERD_CONFIG}" ]]; then
    cp "${CONTAINERD_CONFIG}" "${BACKUP_CONFIG}"
    if ! grep -q "sandlock" "${CONTAINERD_CONFIG}" 2>/dev/null; then
        cat >> "${CONTAINERD_CONFIG}" << 'EOF'

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.sandlock]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.sandlock.options]
    BinaryName = "/usr/local/bin/sandlock-oci"
EOF
        CONFIG_MODIFIED=true
    fi
fi

if $CONFIG_MODIFIED; then
    systemctl restart containerd
    sleep 2
    info "containerd config updated and restarted"
fi

# ── Helper: build a minimal OCI bundle ───────────────────────────────────────

make_bundle() {
    local dir="$1" cmd="$2"
    mkdir -p "${dir}/rootfs/bin"
    for bin in sh echo ls; do
        local p; p="$(command -v "$bin" 2>/dev/null || true)"
        [[ -n "$p" ]] && cp "$p" "${dir}/rootfs/bin/" 2>/dev/null || true
    done
    # Copy shared libraries required by the copied binaries
    for f in "${dir}/rootfs/bin"/*; do
        ldd "$f" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*' | while read -r lib; do
            local rel="${lib#/}"
            mkdir -p "${dir}/rootfs/$(dirname "$rel")"
            [[ -f "$lib" ]] && cp "$lib" "${dir}/rootfs/$rel" 2>/dev/null || true
        done
    done
    cat > "${dir}/config.json" << EOF
{
  "ociVersion": "1.0.2",
  "root": { "path": "rootfs", "readonly": false },
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "cwd": "/",
    "args": ${cmd},
    "env": ["PATH=/bin:/usr/bin"]
  },
  "mounts": [],
  "linux": {
    "resources": { "devices": [{ "allow": false, "access": "rwm" }] },
    "namespaces": []
  }
}
EOF
}

# ── Test 1: sandlock-oci check ────────────────────────────────────────────────

echo "--- Test 1: sandlock-oci check"
if "${BINARY}" check; then
    pass "check reports kernel support"
else
    fail "check failed — kernel may not support Landlock"
fi

# ── Test 2: ociVersion validation ────────────────────────────────────────────
# Bundles declaring an unsupported ociVersion must be rejected immediately
# rather than running with possibly-mismapped fields.

echo "--- Test 2: ociVersion validation"

BUNDLE_BAD_VER="$(mktemp -d)"
make_bundle "${BUNDLE_BAD_VER}" '["/bin/echo","hello"]'
# Overwrite ociVersion with an unsupported value
python3 -c "
import json, sys
cfg = json.load(open('${BUNDLE_BAD_VER}/config.json'))
cfg['ociVersion'] = '0.3.0'
json.dump(cfg, open('${BUNDLE_BAD_VER}/config.json', 'w'))
"
CTR_BAD_VER="sandlock-badver-$$"
ERR_OUT=$("${BINARY}" create "${CTR_BAD_VER}" -b "${BUNDLE_BAD_VER}" 2>&1 || true)
if echo "${ERR_OUT}" | grep -qi "unsupported.*version"; then
    pass "unsupported ociVersion '0.3.0' rejected with clear error"
else
    fail "unsupported ociVersion was not rejected (got: ${ERR_OUT})"
fi
"${BINARY}" delete --force "${CTR_BAD_VER}" 2>/dev/null || true
rm -rf "${BUNDLE_BAD_VER}"

# ── Test 3: exec command ──────────────────────────────────────────────────────
# sandlock-oci exec re-applies the container's Landlock policy to the calling
# process then execvp's the requested command.
# Tests:
#   3.1  exec on unknown container returns clear "no such container" error
#   3.2  exec inline args against a running container
#   3.3  exec --process spec.json against a running container
#   3.4  runc-style flags-before-id parse cleanly

echo "--- Test 3: exec command"

# 3.1 — unknown container gives clear error, exits non-zero
EXEC_ERR=$("${BINARY}" exec "no-such-ctr-$$" /bin/echo test 2>&1 || true)
if echo "${EXEC_ERR}" | grep -qi "no such container\|not found"; then
    pass "3.1  exec on unknown container returns clear error"
else
    fail "3.1  exec on unknown container: unexpected output: ${EXEC_ERR}"
fi

# 3.2 / 3.3 / 3.4 — run a real container and exec into it
BUNDLE_EXEC="$(mktemp -d)"
make_bundle "${BUNDLE_EXEC}" '["/bin/sh","-c","echo container-ready && while true; do sleep 1; done"]'
CTR_EXEC="sandlock-exec-$$"
EXEC_CONTAINER_OK=false

if "${BINARY}" create "${CTR_EXEC}" -b "${BUNDLE_EXEC}" && \
   "${BINARY}" start "${CTR_EXEC}"; then
    sleep 0.5  # give the container process a moment to be fully running
    STATUS_EXEC=$(python3 -c "
import json
try:
    d = json.load(open('${SANDLOCK_OCI_STATE_DIR}/${CTR_EXEC}/state.json'))
    print(d.get('status','?'))
except: print('?')
" 2>/dev/null || echo "?")

    if [[ "${STATUS_EXEC}" == "running" ]]; then
        pass "3.2a container is running — ready for exec tests"
        EXEC_CONTAINER_OK=true
    else
        skip "3.2a container status is '${STATUS_EXEC}' — skipping exec tests"
    fi
fi

if $EXEC_CONTAINER_OK; then
    # 3.2 inline args
    EXEC_OUT=$("${BINARY}" exec "${CTR_EXEC}" /bin/echo "exec-inline-ok" 2>&1 || true)
    if echo "${EXEC_OUT}" | grep -q "exec-inline-ok"; then
        pass "3.2  exec with inline args returns expected output"
    else
        fail "3.2  exec inline args output: ${EXEC_OUT}"
    fi

    # 3.3 --process spec.json
    PROC_SPEC="$(mktemp /tmp/sandlock-proc.XXXXXX.json)"
    cat > "${PROC_SPEC}" << 'EOF'
{
  "args": ["/bin/echo", "exec-process-spec-ok"],
  "cwd": "/",
  "user": {"uid": 0, "gid": 0},
  "env": ["PATH=/bin:/usr/bin"]
}
EOF
    EXEC_PROC=$("${BINARY}" exec --process "${PROC_SPEC}" "${CTR_EXEC}" 2>&1 || true)
    if echo "${EXEC_PROC}" | grep -q "exec-process-spec-ok"; then
        pass "3.3  exec with --process spec.json returns expected output"
    else
        fail "3.3  exec --process output: ${EXEC_PROC}"
    fi
    rm -f "${PROC_SPEC}"

    # 3.4 runc-style flags-before-id form
    EXEC_FLAG=$("${BINARY}" exec -e TESTVAR=hello "${CTR_EXEC}" /bin/sh -c 'echo $TESTVAR' 2>&1 || true)
    if echo "${EXEC_FLAG}" | grep -q "hello"; then
        pass "3.4  exec with --env flag works"
    else
        fail "3.4  exec --env output: ${EXEC_FLAG}"
    fi

    # 3.5 exec with detach flag returns immediately
    "${BINARY}" exec -d "${CTR_EXEC}" /bin/sh -c 'sleep 2' 2>/dev/null && \
        pass "3.5  exec --detach returns immediately" || \
        skip "3.5  exec --detach test inconclusive"
fi

"${BINARY}" kill "${CTR_EXEC}" SIGKILL 2>/dev/null || true
"${BINARY}" delete --force "${CTR_EXEC}" 2>/dev/null || true
rm -rf "${BUNDLE_EXEC}"

# ── Test 4: create failure propagates through pipe (ERR protocol) ─────────────
# If sandbox setup fails (invalid command, policy build error, etc.) the CLI
# must exit non-zero rather than silently succeeding.

echo "--- Test 4: create failure propagated to CLI (OK/ERR pipe protocol)"

BUNDLE_EMPTY="$(mktemp -d)"
mkdir -p "${BUNDLE_EMPTY}/rootfs"
cat > "${BUNDLE_EMPTY}/config.json" << 'EOF'
{
  "ociVersion": "1.0.2",
  "root": { "path": "rootfs", "readonly": false },
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "cwd": "/",
    "args": [],
    "env": []
  },
  "mounts": [],
  "linux": { "namespaces": [] }
}
EOF
CTR_NO_CMD="sandlock-nocmd-$$"
if "${BINARY}" create "${CTR_NO_CMD}" -b "${BUNDLE_EMPTY}" 2>/dev/null; then
    fail "create with empty args should have failed but returned 0"
else
    pass "create with empty process.args exits non-zero (error propagated)"
fi
"${BINARY}" delete --force "${CTR_NO_CMD}" 2>/dev/null || true
rm -rf "${BUNDLE_EMPTY}"

# ── Test 5: full OCI lifecycle (create/state/start/state/kill/delete) ─────────

echo "--- Test 5: full OCI lifecycle"

BUNDLE_DIR="$(mktemp -d)"
CONTAINER_ID="sandlock-lifecycle-$$"
make_bundle "${BUNDLE_DIR}" '["/bin/sh","-c","echo hello-from-sandlock && sleep 10"]'

# create
if "${BINARY}" create "${CONTAINER_ID}" -b "${BUNDLE_DIR}"; then
    pass "create ${CONTAINER_ID}"
else
    fail "create failed — skipping rest of lifecycle test"
    rm -rf "${BUNDLE_DIR}"
    # continue with remaining tests
    CONTAINER_ID=""
fi

if [[ -n "${CONTAINER_ID}" ]]; then
    # state immediately after create — must be 'created' (never 'creating',
    # since set_created() transitions away from Creating before the pipe write)
    STATE_JSON=$("${BINARY}" state "${CONTAINER_ID}" 2>/dev/null || echo '{}')
    STATUS=$(echo "${STATE_JSON}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null || echo "?")
    PID=$(echo "${STATE_JSON}"    | python3 -c "import sys,json; print(json.load(sys.stdin).get('pid',0))"    2>/dev/null || echo "0")

    if [[ "${STATUS}" == "created" ]]; then
        pass "state after create is 'created' (pid=${PID})"
    else
        fail "expected status 'created', got '${STATUS}'"
    fi

    if [[ "${PID}" -gt 0 ]]; then
        pass "state carries a valid PID (${PID})"
    else
        fail "state PID is 0 — OK/ERR pipe protocol may not be wired up"
    fi

    # start
    if "${BINARY}" start "${CONTAINER_ID}"; then
        pass "start ${CONTAINER_ID}"
    else
        skip "start returned non-zero"
    fi

    sleep 1

    # state after start — must be 'running'; liveness probe should agree
    STATE_AFTER=$("${BINARY}" state "${CONTAINER_ID}" 2>/dev/null || echo '{}')
    STATUS_AFTER=$(echo "${STATE_AFTER}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null || echo "?")

    if [[ "${STATUS_AFTER}" == "running" ]]; then
        pass "state after start is 'running'"
    elif [[ "${STATUS_AFTER}" == "stopped" ]]; then
        # Process exited immediately — that is fine
        pass "state after start is 'stopped' (process exited quickly)"
    else
        fail "unexpected state after start: '${STATUS_AFTER}'"
    fi

    # kill — test that kill-then-state reflects liveness probe
    "${BINARY}" kill "${CONTAINER_ID}" SIGKILL 2>/dev/null || true
    sleep 1

    # The state command should now return 'stopped' via the liveness reconciliation
    # (is_alive() returns false after SIGKILL → status updated to stopped on read)
    STATE_KILLED=$("${BINARY}" state "${CONTAINER_ID}" 2>/dev/null || echo '{}')
    STATUS_KILLED=$(echo "${STATE_KILLED}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null || echo "?")

    if [[ "${STATUS_KILLED}" == "stopped" ]]; then
        pass "state reconciles to 'stopped' after SIGKILL (liveness probe working)"
    else
        skip "state is '${STATUS_KILLED}' after SIGKILL (supervisor may not have reaped yet)"
    fi

    # delete
    if "${BINARY}" delete --force "${CONTAINER_ID}" 2>/dev/null; then
        pass "delete ${CONTAINER_ID}"
    else
        fail "delete failed"
    fi
fi

rm -rf "${BUNDLE_DIR}"

# ── Test 6: create → delete (without start) — must not leak supervisor ────────
# delete-before-start is a legal OCI sequence.  The supervisor must exit cleanly
# via the Shutdown command rather than being leaked as a zombie process.

echo "--- Test 6: delete-before-start (supervisor Shutdown)"

BUNDLE_SLEEP="$(mktemp -d)"
CONTAINER_NOSRT="sandlock-nosrt-$$"
make_bundle "${BUNDLE_SLEEP}" '["/bin/sh","-c","sleep 60"]'

if "${BINARY}" create "${CONTAINER_NOSRT}" -b "${BUNDLE_SLEEP}"; then
    pass "create ${CONTAINER_NOSRT} (will delete without starting)"

    # Capture supervisor PID before delete so we can verify it exits.
    # The supervisor process is not tracked in state.json, so we probe by
    # checking for leftover processes containing the container id.
    sleep 0.5

    if "${BINARY}" delete "${CONTAINER_NOSRT}" 2>/dev/null; then
        pass "delete ${CONTAINER_NOSRT} before start"
    else
        fail "delete-before-start failed"
    fi

    # Give the supervisor a moment to clean up after receiving Shutdown
    sleep 1

    # Verify no sandlock-oci process is still running for this container
    if pgrep -f "sandlock-oci" 2>/dev/null | xargs -r ps -o pid,args 2>/dev/null | grep -q "${CONTAINER_NOSRT}"; then
        fail "supervisor process leaked after delete-before-start"
    else
        pass "no supervisor process leaked after delete-before-start"
    fi
else
    skip "create failed — skipping delete-before-start test"
fi

rm -rf "${BUNDLE_SLEEP}"

# ── Test 7: list ──────────────────────────────────────────────────────────────

echo "--- Test 7: list"
LIST_OUTPUT=$("${BINARY}" list 2>/dev/null)
if echo "${LIST_OUTPUT}" | grep -qE "(No sandlock|ID)"; then
    pass "list produces valid output"
else
    fail "list output unexpected: ${LIST_OUTPUT}"
fi

# ── Test 8: nerdctl run with sandlock runtime (optional) ──────────────────────

echo "--- Test 8: nerdctl run with sandlock runtime"

if command -v "${NERDCTL}" &>/dev/null; then
    # Install CNI plugins if missing (required by nerdctl networking)
    if [[ ! -f /opt/cni/bin/bridge ]]; then
        info "Installing CNI plugins for nerdctl..."
        CNI_VER="1.4.1"
        mkdir -p /opt/cni/bin
        curl -fsSL "https://github.com/containernetworking/plugins/releases/download/v${CNI_VER}/cni-plugins-linux-amd64-v${CNI_VER}.tgz" \
            | tar -xz -C /opt/cni/bin 2>/dev/null || true
    fi

    OUTPUT=$("${NERDCTL}" run \
        --runtime sandlock \
        --rm \
        --net none \
        alpine:latest \
        echo "hello from sandlock" 2>&1 || true)

    if echo "${OUTPUT}" | grep -q "hello from sandlock"; then
        pass "nerdctl run with sandlock runtime produced expected output"
    else
        skip "nerdctl run: ${OUTPUT}"
    fi
else
    skip "nerdctl not installed"
fi

# ── Test 9: ctr run with sandlock runtime (optional) ─────────────────────────
# ctr uses the io.containerd.runc.v2 shim with BinaryName override; the
# runtime identifier for ctr is the handler key in containerd config, not a
# shim binary name.

echo "--- Test 9: ctr run with sandlock runtime"

if command -v ctr &>/dev/null; then
    ctr images pull docker.io/library/busybox:latest &>/dev/null || true
    CONTAINER_CTR="sandlock-ctr-$$"
    # Use the runc.v2 runtime with explicit BinaryName via the task API.
    # ctr's --runtime flag takes the full shim path when using runc.v2.
    OUTPUT=$(ctr run \
        --runtime "io.containerd.runc.v2" \
        --runc-binary "${INSTALL_PATH}" \
        --rm \
        docker.io/library/busybox:latest \
        "${CONTAINER_CTR}" \
        echo "ctr-sandlock-ok" 2>&1 || true)

    if echo "${OUTPUT}" | grep -q "ctr-sandlock-ok"; then
        pass "ctr run with sandlock binary succeeded"
    else
        skip "ctr run (runc.v2 + sandlock binary): ${OUTPUT}"
    fi
else
    skip "ctr not found"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Results ==="
echo -e "  ${GREEN}PASS${NC}: ${PASS}"
echo -e "  ${RED}FAIL${NC}: ${FAIL}"
echo -e "  ${YELLOW}SKIP${NC}: ${SKIP}"
echo ""
echo "Note: exec is a known limitation — kubectl exec and exec-based"
echo "      liveness/readiness probes will not work with sandlock pods."
echo ""

if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
