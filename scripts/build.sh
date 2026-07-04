#!/usr/bin/env bash
#
# AetherOps — Build script
#
# Usage:
#   ./scripts/build.sh              — Generate + build release binary
#   ./scripts/build.sh debug        — Build with debug flags
#   ./scripts/build.sh clean        — Clean artifacts
#
set -euo pipefail

APP_NAME="ebpf-local"
CMD_DIR="./cmd/tracer/"

__clean() {
    echo "✦ Cleaning..."
    rm -f "$APP_NAME" tracer tracer-mcp
    rm -f "$CMD_DIR"*.o
    echo "✓ Done"
}

__build() {
    echo "✦ Running go:generate..."
    go generate "$CMD_DIR"...

    local ldflags="-s -w"
    if [ "${1:-}" = "debug" ]; then
        ldflags=""
        echo "✦ Building debug: $APP_NAME"
    else
        echo "✦ Building release: $APP_NAME"
    fi

    CGO_ENABLED=0 go build -ldflags="$ldflags" -o "$APP_NAME" "$CMD_DIR"
    echo "✓ Build complete: $(ls -lh "$APP_NAME" | awk '{print $5}')"
}

case "${1:-}" in
    clean) __clean ;;
    debug) __build debug ;;
    *)     __build ;;
esac
