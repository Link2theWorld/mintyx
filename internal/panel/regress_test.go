package panel

import (
	"context"
	"errors"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
	"net/http"
	"testing"

	"github.com/Link2theWorld/mintyx/internal/engine"
)

type realKeys struct{ fakeKeys }

func (*realKeys) NewRealityKeyPair() (string, string, error) { return engine.NewRealityKeyPair() }

// A short ID the panel accepts must also be one the config builder accepts,
// otherwise the saved line makes every later engine sync fail.
func TestUppercaseShortIDStillBuildsConfig(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.Keys = &realKeys{} })
	c := f.setup()
	body := realityLine("tokyo", 443)
	body["reality"].(map[string]any)["shortId"] = "ABCDEF12"
	w := f.do("POST", "/api/lines", body, withCookie(c))
	expectStatus(t, w, http.StatusCreated)
	if got := decodeBody[lineDTO](t, w).Reality.ShortID; got != "abcdef12" {
		t.Errorf("stored short ID = %q, want abcdef12", got)
	}
	lines, err := f.st.ListLines(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.BuildConfig(lines, nil, nil, engine.Options{APIPort: 10085}); err != nil {
		t.Fatalf("BuildConfig rejects a line the panel saved: %v", err)
	}
}

// A sync that fails while the panel starts (Xray missing, port still held) must be
// retried by the quota runner, like any other failed sync.
func TestFailedStartupSyncIsRetried(t *testing.T) {
	f := newFixture(t, nil)
	f.eng.failSync(errors.New("xray not ready"))
	if err := f.srv.Sync(t.Context()); err == nil {
		t.Fatal("Sync returned nil for a failing engine")
	}
	f.eng.failSync(nil)
	r := f.srv.NewRunner(func(context.Context) (map[string]model.Traffic, error) { return nil, nil }, time.Hour)
	if err := r.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := f.eng.syncCount(); n != 2 {
		t.Fatalf("engine synced %d times, want 2 (startup + retry)", n)
	}
}
