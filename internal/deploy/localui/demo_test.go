package localui

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"testing"

	"github.com/ysuhao/mintyx-next/internal/deploy"
	"github.com/ysuhao/mintyx-next/internal/deploy/deploytest"
)

// TestDemo serves the page against a pretend server, so every screen of it can be looked at
// in a browser without a real VPS. It only runs when asked, and keeps running until Ctrl+C:
//
//	MINTYX_DEPLOY_DEMO=1 go test -v -run TestDemo -timeout 0 ./internal/deploy/localui
//
// Then open the page address it prints and connect to the SSH address it prints.
func TestDemo(t *testing.T) {
	if os.Getenv("MINTYX_DEPLOY_DEMO") == "" {
		t.Skip("set MINTYX_DEPLOY_DEMO=1 to serve the page against a pretend server")
	}
	vps := deploytest.New(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		KnownHosts:   deploy.OpenKnownHosts(filepath.Join(t.TempDir(), "known_hosts.json")),
		KeyDir:       filepath.Join(t.TempDir(), ".ssh"),
		PanelBinary:  func(string) ([]byte, error) { return []byte("pretend panel"), nil },
		PayloadArchs: []string{"amd64", "arm64"},
	}, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close(); srv.Close() })

	t.Logf("page: %s", srv.URL())
	t.Logf("pretend server: IP 127.0.0.1, SSH port %d, user %s, password %s", vps.SSH.Port(), deploytest.User, deploytest.Password)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	<-ctx.Done()
}
