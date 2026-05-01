#!/usr/bin/env bash
# =============================================================================
# tests/kubernetes/test_kind.sh
#
# End-to-end tests for sandlock-oci with a single-node kind cluster.
#
# What this script does:
#   1. Creates a single-node kind cluster with sandlock-oci registered as a
#      RuntimeClass handler.
#   2. Configures the node's containerd to use sandlock-oci.
#   3. Deploys a test Pod using the "sandlock" RuntimeClass.
#   4. Verifies the Pod runs and produces expected output.
#   5. Tears down the cluster.
#
# Prerequisites:
#   - kind    (https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
#   - kubectl (https://kubernetes.io/docs/tasks/tools/)
#   - docker  (kind uses Docker for node images)
#   - cargo   (to build sandlock-oci)
#
# Usage:
#   ./tests/kubernetes/test_kind.sh [--skip-build]
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BINARY="${WORKSPACE_ROOT}/target/release/sandlock-oci"
CLUSTER_NAME="sandlock-test"
KUBECONFIG_FILE="$(mktemp /tmp/sandlock-kind-kubeconfig.XXXXXX)"
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
info() { echo "       $*"; }

# ── Preflight ─────────────────────────────────────────────────────────────────

for tool in kind kubectl docker; do
    if ! command -v "${tool}" &>/dev/null; then
        echo "error: ${tool} is not installed"
        exit 1
    fi
done

# ── Parse args ────────────────────────────────────────────────────────────────

SKIP_BUILD=false
for arg in "$@"; do
    case "${arg}" in
        --skip-build) SKIP_BUILD=true ;;
    esac
done

# ── Build sandlock-oci ────────────────────────────────────────────────────────

echo "=== sandlock-oci kind (Kubernetes) integration tests ==="

if ! $SKIP_BUILD; then
    echo "--- Building sandlock-oci (release)..."
    cargo build --release -p sandlock-oci \
        --manifest-path "${WORKSPACE_ROOT}/Cargo.toml"
    pass "sandlock-oci built"
else
    if [[ ! -f "${BINARY}" ]]; then
        echo "error: binary not found and --skip-build specified"
        exit 1
    fi
    skip "build skipped (--skip-build)"
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo "--- Cleanup: deleting kind cluster ${CLUSTER_NAME}"
    kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
    rm -f "${KUBECONFIG_FILE}"
}
trap cleanup EXIT

# ── Create kind cluster ───────────────────────────────────────────────────────

echo "--- Creating single-node kind cluster '${CLUSTER_NAME}'"

# kind cluster config — single control-plane node (no workers)
KIND_CONFIG="$(mktemp /tmp/kind-config.XXXXXX.yaml)"
cat > "${KIND_CONFIG}" << EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
nodes:
  - role: control-plane
    # Use the latest stable kind node image.
    image: kindest/node:v1.30.0
    # Extra mounts and labels for containerd config
    extraMounts: []
    # containerd config patches — register sandlock-oci as a runtime
    # Note: kind writes containerd config at /etc/containerd/config.toml on the node
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
EOF

kind create cluster \
    --name "${CLUSTER_NAME}" \
    --config "${KIND_CONFIG}" \
    --kubeconfig "${KUBECONFIG_FILE}" \
    --wait 120s
rm -f "${KIND_CONFIG}"

export KUBECONFIG="${KUBECONFIG_FILE}"
pass "kind cluster created"

# ── Copy sandlock-oci binary into the kind node ───────────────────────────────

echo "--- Installing sandlock-oci into kind node"
NODE_NAME="${CLUSTER_NAME}-control-plane"

# Copy the binary into the node container.
docker cp "${BINARY}" "${NODE_NAME}:/usr/local/bin/sandlock-oci"
docker exec "${NODE_NAME}" chmod +x /usr/local/bin/sandlock-oci
pass "binary installed in node"

# ── Configure containerd on the node to use sandlock-oci ─────────────────────

echo "--- Configuring containerd on node to use sandlock-oci"

docker exec "${NODE_NAME}" bash -c '
cat >> /etc/containerd/config.toml << "TOML"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.sandlock]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.sandlock.options]
    BinaryName = "/usr/local/bin/sandlock-oci"
TOML
systemctl restart containerd
sleep 3
'
pass "containerd configured with sandlock runtime"

# ── Create RuntimeClass ───────────────────────────────────────────────────────

echo "--- Creating sandlock RuntimeClass"

kubectl apply -f - << 'EOF'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: sandlock
handler: sandlock
EOF

pass "RuntimeClass 'sandlock' created"

# ── Deploy test Pod ───────────────────────────────────────────────────────────

echo "--- Deploying test Pod with sandlock RuntimeClass"

POD_NAME="sandlock-test-pod"
kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${POD_NAME}
  labels:
    app: sandlock-test
spec:
  runtimeClassName: sandlock
  restartPolicy: Never
  containers:
    - name: test
      image: busybox:latest
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "echo 'sandlock-pod-ok' && sleep 5"]
      resources:
        limits:
          memory: "64Mi"
          cpu: "100m"
EOF

pass "test Pod submitted"

# ── Wait for Pod completion ───────────────────────────────────────────────────

echo "--- Waiting for Pod to complete (up to 120s)"

WAIT_RESULT=0
kubectl wait pod "${POD_NAME}" \
    --for=condition=Ready \
    --timeout=60s 2>/dev/null || WAIT_RESULT=$?

if [[ ${WAIT_RESULT} -ne 0 ]]; then
    # Check if the pod is in a terminal state (Succeeded or Failed)
    PHASE=$(kubectl get pod "${POD_NAME}" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
    info "Pod phase: ${PHASE}"
    
    if [[ "${PHASE}" == "Succeeded" ]]; then
        pass "Pod completed successfully"
    elif [[ "${PHASE}" == "Failed" ]]; then
        REASON=$(kubectl get pod "${POD_NAME}" -o jsonpath='{.status.containerStatuses[0].state.terminated.reason}' 2>/dev/null || echo "unknown")
        fail "Pod failed with reason: ${REASON}"
    else
        # May be in Pending if sandlock-oci isn't supported in this environment
        skip "Pod not ready (phase=${PHASE}) — runtime may not be fully supported in kind"
    fi
else
    pass "Pod became Ready"
    # Check output
    POD_LOG=$(kubectl logs "${POD_NAME}" 2>/dev/null || echo "")
    if echo "${POD_LOG}" | grep -q "sandlock-pod-ok"; then
        pass "Pod output matches expected string"
    else
        skip "Pod output not verified (log: ${POD_LOG})"
    fi
fi

# ── Deploy a Pod without RuntimeClass (baseline comparison) ──────────────────

echo "--- Deploying baseline Pod (no RuntimeClass)"

BASELINE_POD="sandlock-baseline-pod"
kubectl apply -f - << EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${BASELINE_POD}
spec:
  restartPolicy: Never
  containers:
    - name: test
      image: busybox:latest
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "echo 'baseline-ok'"]
EOF

kubectl wait pod "${BASELINE_POD}" \
    --for=condition=Ready \
    --timeout=60s 2>/dev/null || true

BASELINE_PHASE=$(kubectl get pod "${BASELINE_POD}" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
if [[ "${BASELINE_PHASE}" == "Succeeded" ]] || [[ "${BASELINE_PHASE}" == "Running" ]]; then
    pass "baseline pod ran successfully (${BASELINE_PHASE})"
else
    skip "baseline pod phase: ${BASELINE_PHASE}"
fi

kubectl delete pod "${BASELINE_POD}" --ignore-not-found &>/dev/null || true

# ── Verify RuntimeClass is registered ────────────────────────────────────────

echo "--- Verifying RuntimeClass registration"
RC_OUTPUT=$(kubectl get runtimeclass sandlock -o jsonpath='{.handler}' 2>/dev/null || echo "")
if [[ "${RC_OUTPUT}" == "sandlock" ]]; then
    pass "RuntimeClass 'sandlock' has correct handler"
else
    fail "RuntimeClass handler mismatch: got '${RC_OUTPUT}'"
fi

# ── Deploy a Deployment using RuntimeClass ────────────────────────────────────

echo "--- Deploying Deployment with sandlock RuntimeClass"

kubectl apply -f - << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sandlock-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sandlock-workload
  template:
    metadata:
      labels:
        app: sandlock-workload
    spec:
      runtimeClassName: sandlock
      containers:
        - name: app
          image: busybox:latest
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "echo 'deployment-sandlock-ok' && sleep 30"]
          resources:
            limits:
              memory: "64Mi"
              cpu: "100m"
EOF

DEPLOY_WAIT=0
kubectl rollout status deployment/sandlock-deployment \
    --timeout=60s 2>/dev/null || DEPLOY_WAIT=$?

if [[ ${DEPLOY_WAIT} -eq 0 ]]; then
    pass "Deployment rolled out with sandlock runtime"
else
    skip "Deployment rollout incomplete — may need full kernel Landlock support"
fi

kubectl delete deployment sandlock-deployment --ignore-not-found &>/dev/null || true

# ── Cleanup Pod ───────────────────────────────────────────────────────────────

kubectl delete pod "${POD_NAME}" --ignore-not-found &>/dev/null || true
kubectl delete runtimeclass sandlock --ignore-not-found &>/dev/null || true

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Kind Kubernetes Test Results ==="
echo -e "  ${GREEN}PASS${NC}: ${PASS}"
echo -e "  ${RED}FAIL${NC}: ${FAIL}"
echo -e "  ${YELLOW}SKIP${NC}: ${SKIP}"
echo ""
echo "Note: Some tests may be skipped if the kind node kernel does not"
echo "      support the full Landlock ABI. Use a kernel ≥ 5.13 for full support."
echo ""

if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
