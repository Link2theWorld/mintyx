// Command mintyx runs the panel and supervises Xray.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	// Monthly quota days are read in an IANA zone; minimal server images may have no zoneinfo.
	_ "time/tzdata"

	"github.com/ysuhao/mintyx-next/internal/app"
	"github.com/ysuhao/mintyx-next/internal/attack"
	"github.com/ysuhao/mintyx-next/internal/engine"
	"github.com/ysuhao/mintyx-next/internal/panel"
	"github.com/ysuhao/mintyx-next/internal/probe"
	"github.com/ysuhao/mintyx-next/internal/store"
	"github.com/ysuhao/mintyx-next/web"
)

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "reset-password" {
		err = resetPassword(os.Args[2:])
	} else {
		err = run()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mintyx:", err)
		os.Exit(1)
	}
}

// resetPassword is `mintyx reset-password`: a new admin password for whoever has root on the
// server and lost the old one. The password goes to stdout and nowhere else.
func resetPassword(args []string) error {
	set := flag.NewFlagSet("reset-password", flag.ExitOnError)
	dataDir := set.String("data", "data", "the panel's data directory (the deployer uses /var/lib/mintyx)")
	set.Usage = func() {
		fmt.Fprintln(set.Output(), "Usage: mintyx reset-password [-data DIR]")
		fmt.Fprintln(set.Output(), "Gives the admin account a new random password and signs out every session that used the old one.")
		set.PrintDefaults()
	}
	_ = set.Parse(args)
	if set.NArg() > 0 {
		return fmt.Errorf("reset-password: unexpected argument %q", set.Arg(0))
	}
	path := filepath.Join(*dataDir, "mintyx.db")
	// Opening a missing file would create an empty database, so look first.
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("there is no panel database at %s; pass -data with the panel's data directory", path)
	} else if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w; run it as root, for example with sudo", err)
	} else if err != nil {
		return err
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	user, password, err := panel.ResetAdminPassword(context.Background(), st)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "The admin password was reset. Everyone signed in with the old one is signed out.")
	fmt.Printf("username: %s\npassword: %s\n", user, password)
	return nil
}

func run() error {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  mintyx [flags]                       run the panel")
		fmt.Fprintln(out, "  mintyx reset-password [-data DIR]    give the admin account a new password")
		fmt.Fprintln(out, "\nFlags:")
		flag.PrintDefaults()
	}
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

	// Xray reports a connection that fails a line's handshake only at info level, so it runs at
	// info and XrayTap keeps the extra lines out of the log the panel shows.
	attacks := attack.NewCollector()
	opt := engine.Options{APIPort: *apiPort, LogLevel: "info"}
	sup := engine.NewSupervisor(*xrayBin, filepath.Join(*dataDir, "xray.json"),
		engine.SupervisorOptions{OnLine: app.XrayTap(attacks, time.Now)})
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
		Attacks:       attacks,
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
	attackRunner := srv.NewAttackRunner(*tick)
	attackRunner.Start(ctx)
	defer attackRunner.Stop()

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
