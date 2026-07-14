//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -cflags "-O2 -g -Wall -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu -I../../bpf" tracer ../../bpf/net_trace.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -cflags "-O2 -g -Wall -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu -I../../bpf" tc_drop ../../bpf/tc_drop.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -cflags "-O2 -g -Wall -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu -I../../bpf" http_probe ../../bpf/http_probe.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -cflags "-O2 -g -Wall -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu -I../../bpf" tcp_conntrack ../../bpf/tcp_conntrack.c

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	app, err := NewApp()
	if err != nil {
		slog.Error("init failed", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err = app.Start(ctx); err != nil {
		slog.Error("start failed", "error", err)
		os.Exit(1)
	}

	go func() {
		if err := app.RunMainLoop(ctx); err != nil {
			slog.Info("main loop exited", "error", err)
		}
		stop()
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	app.Shutdown(shutdownCtx)
}
