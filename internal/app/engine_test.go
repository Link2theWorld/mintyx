package app

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ysuhao/mintyx-next/internal/engine"
	"github.com/ysuhao/mintyx-next/internal/model"
	"github.com/ysuhao/mintyx-next/internal/store"
)

type fakeProc struct {
	applies int
	starts  int
	stops   int
	// usedDownAtApply records client 1's stored usage at the moment each config was applied.
	usedDownAtApply []int64
	st              *store.Store
}

func (f *fakeProc) Start() error { f.starts++; return nil }
func (f *fakeProc) Stop()        { f.stops++ }
func (f *fakeProc) Apply([]byte) error {
	f.applies++
	if c, err := f.st.GetClient(context.Background(), 1); err == nil {
		f.usedDownAtApply = append(f.usedDownAtApply, c.UsedDown)
	}
	return nil
}
func (f *fakeProc) Status() engine.Status { return engine.Status{Running: f.starts > f.stops} }
func (f *fakeProc) Logs() []string        { return nil }

func newTestEngine(t *testing.T) (*Engine, *fakeProc, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "mintyx.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	priv, pub, err := engine.NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	line := &model.Line{
		Name: "tokyo", Protocol: model.VLESSReality, Port: 8443, Enabled: true,
		Reality: &model.RealityParams{
			PrivateKey: priv, PublicKey: pub, ShortID: "0123456789abcdef",
			ServerName: "www.example.com", Target: "www.example.com:443",
		},
	}
	if err := st.CreateLine(context.Background(), line); err != nil {
		t.Fatal(err)
	}
	addClient(t, st, "phone")

	proc := &fakeProc{st: st}
	e := &Engine{
		Store:    st,
		Proc:     proc,
		Options:  engine.Options{APIPort: 10085},
		validate: func(context.Context, []byte) error { return nil },
		query:    func(context.Context) (map[string]model.Traffic, error) { return nil, nil },
	}
	return e, proc, st
}

func addClient(t *testing.T, st *store.Store, name string) {
	t.Helper()
	c := &model.Client{Name: name, Secret: engine.NewUUID(), SubToken: engine.NewUUID()}
	if err := st.CreateClient(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func TestSyncDoesNotRestartWhenConfigIsUnchanged(t *testing.T) {
	e, proc, st := newTestEngine(t)
	ctx := context.Background()

	if err := e.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// A rename leaves the Xray config byte-identical; restarting would drop every live connection.
	c, _ := st.GetClient(ctx, 1)
	c.Name = "my phone"
	if err := st.UpdateClient(ctx, &c); err != nil {
		t.Fatal(err)
	}
	if err := e.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if proc.applies != 1 || proc.starts != 1 {
		t.Fatalf("applies=%d starts=%d, want 1 and 1", proc.applies, proc.starts)
	}

	addClient(t, st, "laptop")
	if err := e.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if proc.applies != 2 || proc.starts != 1 {
		t.Fatalf("after a real change applies=%d starts=%d, want 2 and 1", proc.applies, proc.starts)
	}
}

func TestSyncSavesTrafficBeforeRestartingXray(t *testing.T) {
	e, proc, st := newTestEngine(t)
	ctx := context.Background()
	if err := e.Sync(ctx); err != nil {
		t.Fatal(err)
	}

	// Xray's counters die with the process, so they must be stored before the restart.
	e.query = func(context.Context) (map[string]model.Traffic, error) {
		return map[string]model.Traffic{"c1": {Up: 5, Down: 700}}, nil
	}
	addClient(t, st, "laptop")
	if err := e.Sync(ctx); err != nil {
		t.Fatal(err)
	}

	if len(proc.usedDownAtApply) != 2 || proc.usedDownAtApply[1] != 700 {
		t.Fatalf("usage seen at each apply = %v, want the second apply to already see 700", proc.usedDownAtApply)
	}
}

func TestRestartSavesTrafficAndStartsAgain(t *testing.T) {
	e, proc, st := newTestEngine(t)
	ctx := context.Background()
	if err := e.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	e.query = func(context.Context) (map[string]model.Traffic, error) {
		return map[string]model.Traffic{"c1": {Up: 9}}, nil
	}
	if err := e.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	c, _ := st.GetClient(ctx, 1)
	if c.UsedUp != 9 || proc.stops != 1 || proc.starts != 2 {
		t.Fatalf("usedUp=%d stops=%d starts=%d, want 9, 1, 2", c.UsedUp, proc.stops, proc.starts)
	}
}
