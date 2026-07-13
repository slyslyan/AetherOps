#!/bin/bash
# AetherOps — Multicluster Deployment Script
#
# Usage:
#   kubectl mode (default):
#     bash deploy/aetherops-install.sh
#
#   Helm mode:
#     bash deploy/aetherops-install.sh --helm [--values my-values.yaml]
#
# Prerequisites:
#   - K3s/K8s cluster running
#   - kubectl configured
#   - For Helm mode: helm installed

set -euo pipefail

NAMESPACE="ebpf-system"
HELM_MODE=false
HELM_VALUES=""

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --helm              Deploy via Helm instead of kubectl
  --values FILE       Custom values file (Helm only)
  -h, --help          Show this help
EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --helm)     HELM_MODE=true; shift ;;
        --values)   HELM_VALUES="$2"; shift 2 ;;
        -h|--help)  usage ;;
        *)          echo "Unknown option: $1"; usage ;;
    esac
done

# ── Helm mode ──
if $HELM_MODE; then
    CHART_DIR="$(dirname "$0")/../helm/aetherops"

    if [ ! -f "$CHART_DIR/Chart.yaml" ]; then
        echo "Error: Helm chart not found at $CHART_DIR"
        echo "Run this script from the project root directory."
        exit 1
    fi

    if ! command -v helm &>/dev/null; then
        echo "Error: helm is required for --helm mode"
        echo "Install: https://helm.sh/docs/intro/install/"
        exit 1
    fi

    CMD="helm upgrade --install aetherops $CHART_DIR --namespace $NAMESPACE --create-namespace"
    if [ -n "$HELM_VALUES" ]; then
        CMD="$CMD --values $HELM_VALUES"
    fi

    echo "=== AetherOps Helm Deployment ==="
    echo "Chart:      $CHART_DIR"
    echo "Namespace:  $NAMESPACE"
    echo "Values:     ${HELM_VALUES:-defaults}"
    echo ""
    echo "Running: $CMD"
    echo ""
    eval "$CMD"

    echo ""
    echo "=== Deployment Complete ==="
    echo "Check status: kubectl -n $NAMESPACE get pods"
    exit 0
fi

# ── kubectl mode (original) ──
echo "=== AetherOps Deployment (kubectl) ==="
echo ""

# Step 1: Ensure namespace exists
kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$NAMESPACE"

# Step 2: Deploy eBPF tracer (DaemonSet + RBAC)
echo "[1/3] Deploying eBPF Tracer..."
kubectl apply -f deploy/ebpf-tracer.yaml

# Step 3: Deploy AetherOps Python Core (if image is available)
echo "[2/3] Deploying AetherOps Core..."
if docker image inspect aetherops-core:latest >/dev/null 2>&1; then
    if command -v minikube &>/dev/null; then
        echo "  Loading image into minikube..."
        minikube image load aetherops-core:latest
    fi
    kubectl apply -f deploy/aetherops-core.yaml
    echo "  Waiting for AetherOps Core to be ready..."
    kubectl -n "$NAMESPACE" wait --for=condition=available --timeout=120s deployment/aetherops-core || true
else
    echo "  [SKIP] aetherops-core:latest image not found. Build it with:"
    echo "    docker build -t aetherops-core:latest -f aetherops/Dockerfile aetherops/"
fi

echo ""
echo "=== AetherOps Deployment Complete ==="
echo ""
echo "Services:"
echo "  Prometheus:      kubectl port-forward -n $NAMESPACE svc/prometheus 9090:9090"
echo ""
echo "Check status:"
echo "  kubectl -n $NAMESPACE get pods"
