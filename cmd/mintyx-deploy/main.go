// Command mintyx-deploy runs on the user's own computer: it serves a local page that
// installs Mintyx on a server over SSH and tunnels to the panel afterwards.
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
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/ysuhao/mintyx-next/internal/deploy"
	"github.com/ysuhao/mintyx-next/internal/deploy/localui"
	"github.com/ysuhao/mintyx-next/internal/deploy/payload"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mintyx-deploy:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		panelBinary = flag.String("panel-binary", "", "upload this Linux build of the panel instead of the one built into this program")
		noBrowser   = flag.Bool("no-browser", false, "print the address but do not open a browser")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	binary, archs := payload.Embedded, payload.Available()
	if *panelBinary != "" {
		file, err := payload.Open(*panelBinary)
		if err != nil {
			return fmt.Errorf("-panel-binary: %w", err)
		}
		binary, archs = file.Binary, []string{file.Arch}
	}
	if len(archs) == 0 {
		fmt.Fprintln(os.Stderr, "mintyx-deploy: this build has no panel program inside, so it cannot deploy.\n"+
			"  Build a release with scripts/build-deployer.sh, or pass -panel-binary <path to a Linux mintyx build>.")
	}

	knownHostsPath, err := deploy.DefaultKnownHostsPath()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Port 0 on the literal loopback address: nothing on the network can connect, and the
	// page's origin is unguessable until the address below is printed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	ui, err := localui.New(localui.Config{
		KnownHosts:   deploy.OpenKnownHosts(knownHostsPath),
		KeyDir:       filepath.Join(home, ".ssh"),
		PanelBinary:  binary,
		PayloadArchs: archs,
		Logger:       logger,
	}, ln.Addr().String())
	if err != nil {
		return err
	}
	defer ui.Close()

	httpServer := &http.Server{Handler: ui, ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.Serve(ln) }()

	fmt.Printf("\nMintyx deployer is running. Open this address in your browser:\n\n  %s\n\nKeep this window open; press Ctrl+C to quit.\n\n", ui.URL())
	if !*noBrowser {
		if err := openBrowser(ui.URL()); err != nil {
			fmt.Fprintln(os.Stderr, "mintyx-deploy: could not open a browser, copy the address above instead:", err)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
