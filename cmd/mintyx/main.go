// Command mintyx runs the panel and supervises Xray.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/ysuhao/mintyx-next/internal/app"
	"github.com/ysuhao/mintyx-next/internal/engine"
	"github.com/ysuhao/mintyx-next/internal/panel"
	"github.com/ysuhao/mintyx-next/internal/probe"
	"github.com/ysuhao/mintyx-next/internal/store"
	"github.com/ysuhao/mintyx-next/web"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mintyx:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dataDir    = flag.String("data", "data", "directory for the database and the generated Xray config")
		listen     = flag.String("listen", "127.0.0.1:8088", "address the panel listens on")
		xrayBin    = flag.String("xray", "xray", "path to the Xray binary")
		apiPort    = flag.Int("xray-api-port", 10085, "loopback port for Xray's stats API")
		trustProxy = flag.Bool("trust-proxy", false, "trust X-Forwarded-* headers from a reverse proxy in front of the panel; required when the proxy terminates TLS, or browser requests fail the same-origin check")
		tick       = flag.Duration("tick", 30*time.Second, "how often traffic is collected and quotas are enforced")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(*dataDir, "mintyx.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	_, portText, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("-listen: %w", err)
	}
	panelPort, err := strconv.Atoi(portText)
	if err != nil {
		return fmt.Errorf("-listen: %w", err)
	}

	opt := engine.Options{APIPort: *apiPort}
	sup := engine.NewSupervisor(*xrayBin, filepath.Join(*dataDir, "xray.json"), engine.SupervisorOptions{})
	eng := app.NewEngine(st, sup, *xrayBin, opt, logger)
	defer eng.Stop()

	prober := &probe.Prober{}
	// The panel rejects unknown regions before probing, so an error here only means no suggestion.
	coverSite := func(ctx context.Context, region string) string {
		site, _ := prober.CoverSite(ctx, region)
		return site
	}
	srv, err := panel.New(panel.Config{
		Store:         st,
		Engine:        eng,
		Keys:          app.Keys{},
		Static:        web.Dist(),
		TrustProxy:    *trustProxy,
		ReservedPorts: []int{panelPort, *apiPort},
		CoverSite:     coverSite,
		Logger:        logger,
	})
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// The panel must come up even when Xray cannot, so the admin can see why.
	if err := srv.Sync(ctx); err != nil {
		logger.Error("Xray did not start; the panel is running without it and will retry", "error", err)
	}
	runner := srv.NewRunner(eng.Traffic, *tick)
	runner.Start(ctx)
	defer runner.Stop()
	reachRunner := srv.NewReachRunner(time.Minute)
	reachRunner.Start(ctx)
	defer reachRunner.Stop()

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.ListenAndServe() }()
	logger.Info("panel listening", "address", *listen, "frontendBuilt", web.Built())

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	srv.Close()
	shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
