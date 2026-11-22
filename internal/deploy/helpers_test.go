package deploy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ysuhao/mintyx-next/internal/deploy/deploytest"
)

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func testKnownHosts(t *testing.T) *KnownHosts {
	t.Helper()
	return OpenKnownHosts(filepath.Join(t.TempDir(), "cfg", "known_hosts.json"))
}

func vpsTarget(v *deploytest.VPS) Target {
	return Target{Host: "127.0.0.1", Port: v.SSH.Port(), User: deploytest.User, Password: deploytest.Password}
}

func dialVPS(t *testing.T, v *deploytest.VPS, kh *KnownHosts) *Client {
	t.Helper()
	c, err := Dial(testContext(t), vpsTarget(v), Options{KnownHosts: kh})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
