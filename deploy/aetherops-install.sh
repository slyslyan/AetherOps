#!/bin/bash
# AetherOps — K3s Deployment Script
# Usage: bash deploy/aetherops-install.sh
#
# Prerequisites:
#   - K3s cluster running
#   - kubectl configured
#   - ebpf-autoheal DaemonSet already deployed (or deploy it first)

set -euo pipefail

NAMESPACE="ebpf-system"

echo "=== AetherOps Deployment ==="
echo ""

# Step 1: Ensure namespace exists
kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$NAMESPACE"

# Step 2: Deploy Neo4j (dependency graph)
echo "[1/4] Deploying Neo4j..."
kubectl apply -f deploy/aetherops-neo4j.yaml
echo "  Waiting for Neo4j to be ready..."
kubectl -n "$NAMESPACE" wait --for=condition=available --timeout=120s deployment/neo4j || true

# Step 3: Deploy Milvus (vector store)
echo "[2/4] Deploying Milvus + etcd + minio..."
kubectl apply -f deploy/aetherops-milvus.yaml
echo "  Waiting for Milvus to be ready..."
kubectl -n "$NAMESPACE" wait --for=condition=available --timeout=180s deployment/milvus || true

# Step 4: Deploy AetherOps Python Core (if image is available)
echo "[3/4] Deploying AetherOps Core..."
if docker image inspect aetherops-core:latest >/dev/null 2>&1; then
    # If using minikube, load the image
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
    echo "    minikube image load aetherops-core:latest"
fi

# Step 5: Update ConfigMap for gRPC address
echo "[4/4] Updating configuration..."
kubectl -n "$NAMESPACE" create configmap aetherops-config \
    --from-literal=grpc-addr=":50051" \
    --from-literal=analysis-interval="15" \
    --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo "=== AetherOps Deployment Complete ==="
echo ""
echo "Services:"
echo "  Neo4j Browser:   kubectl port-forward -n $NAMESPACE svc/neo4j 7474:7474"
echo "  Milvus:          kubectl port-forward -n $NAMESPACE svc/milvus 19530:19530"
echo "  Prometheus:      kubectl port-forward -n $NAMESPACE svc/prometheus 9090:9090"
echo ""
echo "Check status:"
echo "  kubectl -n $NAMESPACE get pods -l 'app in (aetherops-core,neo4j,milvus,etcd,minio)'"
