// Command gateway runs the MCP gateway.
//
//	gateway -config policy.yaml -listen :8080
//	gateway hash-token <token>     print the token_sha256 for a policy file
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

	"github.com/0x1ee7/mcp-paddock/internal/gateway"
	"github.com/0x1ee7/mcp-paddock/internal/policy"
	"github.com/0x1ee7/mcp-paddock/internal/ratelimit"
	"github.com/0x1ee7/mcp-paddock/internal/telemetry"
)

var version = "dev"

func main() {
	if len(os.Args) == 3 && os.Args[1] == "hash-token" {
		fmt.Println(policy.HashToken(os.Args[2]))
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gateway:", err)
		os.Exit(1)
	}
}

func run() error {
	config := flag.String("config", "config/policy.yaml", "policy file")
	listen := flag.String("listen", ":8080", "listen address")
	reload := flag.Duration("reload-interval", 5*time.Second, "how often to check the policy file for changes")
	timeout := flag.Duration("call-timeout", 60*time.Second, "upstream timeout for one MCP request")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log, shutdown, err := telemetry.Setup(ctx, "mcp-gateway", version)
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdown(ctx)
	}()

	pol, err := policy.Load(*config)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	store := policy.NewStore(pol)
	go store.Watch(ctx, *config, *reload, log)

	gw, err := gateway.New(gateway.Options{
		Policy:      store,
		Limiter:     ratelimit.New(),
		Logger:      log,
		CallTimeout: *timeout,
	})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("gateway listening", "addr", *listen, "policy_version", pol.Version, "version", version)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
