// Package app connects the store, the Xray supervisor and the panel.
package app

import (
	"bytes"
	"context"
	"log/slog"
	"os/exec"
	"sync"

	"github.com/ysuhao/mintyx-next/internal/engine"
	"github.com/ysuhao/mintyx-next/internal/model"
	"github.com/ysuhao/mintyx-next/internal/panel"
	"github.com/ysuhao/mintyx-next/internal/quota"
	"github.com/ysuhao/mintyx-next/internal/store"
)

type Process interface {
	Start() error
	Stop()
	Apply(config []byte) error
	Status() engine.Status
	Logs() []string
}

// Engine keeps Xray's running config equal to what the store describes.
type Engine struct {
	Store   *store.Store
	Proc    Process
	Bin     string
	Options engine.Options
	Logger  *slog.Logger

	validate func(ctx context.Context, config []byte) error
	query    func(ctx context.Context) (map[string]model.Traffic, error)

	mu      sync.Mutex
	applied []byte
	started bool
	version string
}

func NewEngine(st *store.Store, proc Process, bin string, opt engine.Options, logger *slog.Logger) *Engine {
	e := &Engine{Store: st, Proc: proc, Bin: bin, Options: opt, Logger: logger}
	e.validate = func(ctx context.Context, config []byte) error { return engine.Validate(ctx, bin, config) }
	e.query = func(ctx context.Context) (map[string]model.Traffic, error) {
		return engine.QueryTraffic(ctx, bin, opt.APIAddr())
	}
	return e
}

// Sync rebuilds the config and restarts Xray only when the bytes differ from what is running.
func (e *Engine) Sync(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	lines, err := e.Store.ListLines(ctx)
	if err != nil {
		return err
	}
	clients, err := e.Store.ListClients(ctx)
	if err != nil {
		return err
	}
	config, err := engine.BuildConfig(lines, clients, e.Options)
	if err != nil {
		return err
	}
	if e.started && bytes.Equal(config, e.applied) {
		return nil
	}
	// A config Xray rejects would crash-loop it; keep the running one instead.
	if err := e.validate(ctx, config); err != nil {
		return err
	}
	if e.started {
		e.saveTraffic(ctx)
	}
	if err := e.Proc.Apply(config); err != nil {
		return err
	}
	e.applied = config
	if !e.started {
		if err := e.Proc.Start(); err != nil {
			return err
		}
		e.started = true
	}
	return nil
}

func (e *Engine) Restart(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.started {
		e.saveTraffic(ctx)
		e.Proc.Stop()
		e.started = false
	}
	if err := e.Proc.Start(); err != nil {
		return err
	}
	e.started = true
	return nil
}

func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.started {
		e.saveTraffic(context.Background())
		e.Proc.Stop()
		e.started = false
	}
}

// saveTraffic stores Xray's counters, which are lost when the process exits. Callers hold e.mu.
func (e *Engine) saveTraffic(ctx context.Context) {
	traffic, err := e.query(ctx)
	if err == nil {
		err = e.Store.AddTraffic(ctx, quota.ByClientID(traffic))
	}
	if err != nil && e.Logger != nil {
		e.Logger.Warn("traffic since the last tick was not saved before the restart", "error", err)
	}
}

// Traffic is the quota runner's source. It reports nothing while Xray is not running.
func (e *Engine) Traffic(ctx context.Context) (map[string]model.Traffic, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.started || !e.Proc.Status().Running {
		return nil, nil
	}
	return e.query(ctx)
}

func (e *Engine) Status(ctx context.Context) panel.EngineStatus {
	_, lookErr := exec.LookPath(e.Bin)
	st := e.Proc.Status()

	e.mu.Lock()
	if e.version == "" && lookErr == nil {
		if v, err := engine.Version(ctx, e.Bin); err == nil {
			e.version = v
		}
	}
	version := e.version
	e.mu.Unlock()

	return panel.EngineStatus{
		Running:     st.Running,
		PID:         st.PID,
		StartedAt:   st.StartedAt,
		LastExit:    st.LastExit,
		Restarts:    st.Restarts,
		Version:     version,
		BinaryFound: lookErr == nil,
	}
}

func (e *Engine) Logs() []string { return e.Proc.Logs() }

// Keys adapts the engine package's generators to panel.KeyGen.
type Keys struct{}

func (Keys) NewUUID() string                            { return engine.NewUUID() }
func (Keys) NewRealityKeyPair() (string, string, error) { return engine.NewRealityKeyPair() }
func (Keys) NewShortID() string                         { return engine.NewShortID() }
func (Keys) NewPassword() string                        { return engine.NewPassword() }
