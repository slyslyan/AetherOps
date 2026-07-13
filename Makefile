# AetherOps — Build Automation
#
# Usage:
#   make generate    — Run go:generate (eBPF bindings)
#   make build       — Generate + build Go binary
#   make run         — Local run with simulated latency
#   make test        — Run Go tests
#   make clean       — Remove build artifacts
#   make help        — Show this help

APP_NAME   := ebpf-local
CMD_DIR    := ./cmd/tracer/
OUTPUT     := ./$(APP_NAME)

.PHONY: generate build run test clean fmt lint help

help:
	@echo "AetherOps Build Targets:"
	@echo "  make generate   — Run go:generate (eBPF bindings)"
	@echo "  make build      — Generate + build Go binary"
	@echo "  make run        — Local run (SIMULATE_LATENCY=1, needs sudo)"
	@echo "  make test       — Run Go tests"
	@echo "  make fmt        — Format Go source code"
	@echo "  make lint       — Run Go vet + staticcheck (if installed)"
	@echo "  make clean      — Remove build artifacts"
	@echo "  make help       — Show this help"

generate:
	@echo "✦ Running go:generate (eBPF bindings)..."
	go generate $(CMD_DIR)...

build: generate
	@echo "✦ Building $(APP_NAME)..."
	go build -o $(OUTPUT) $(CMD_DIR)
	@echo "✓ Build complete: $(OUTPUT)"

run: build
	@echo "✦ Starting tracer with simulated latency..."
	sudo SIMULATE_LATENCY=1 ./$(APP_NAME)

test:
	@echo "✦ Running tests..."
	go test -v ./internal/...

fmt:
	@echo "✦ Formatting Go source..."
	go fmt ./...

lint:
	@echo "✦ Running go vet..."
	go vet ./...
	@echo "✦ Running staticcheck (if installed)..."
	command -v staticcheck >/dev/null && staticcheck ./... || echo "(staticcheck not installed, skipping)"

clean:
	@echo "✦ Cleaning build artifacts..."
	rm -f $(OUTPUT)
	rm -f cmd/tracer/*.o
	@echo "✓ Clean complete"
