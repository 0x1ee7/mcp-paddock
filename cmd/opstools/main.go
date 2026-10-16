// Command opstools runs the demo MCP tool server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0x1ee7/mcp-paddock/internal/opstools"
	"github.com/0x1ee7/mcp-paddock/internal/telemetry"
)

func main() {
	listen := flag.String("listen", ":8081", "listen address")
	sse := flag.Bool("sse", false, "answer POSTs with SSE streams instead of JSON bodies")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log, shutdown, err := telemetry.Setup(ctx, "opstools", "v0.1.0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "opstools:", err)
		os.Exit(1)
	}
	defer shutdown(context.Background())

	mux := http.NewServeMux()
	mux.Handle("/mcp", opstools.Handler(opstools.NewFleet(), !*sse))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("opstools listening", "addr", *listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "error", err)
		os.Exit(1)
	}
}
