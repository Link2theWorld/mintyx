// Package app connects the store, the Xray supervisor and the panel.
package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"

	"github.com/Link2theWorld/mintyx/internal/engine"
	"github.com/Link2theWorld/mintyx/internal/model"
	"github.com/Link2theWorld/mintyx/internal/panel"
	"github.com/Link2theWorld/mintyx/internal/quota"
	"github.com/Link2theWorld/mintyx/internal/store"
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
	// trafficDebt is traffic drained from Xray whose store write failed. The next quota
	// read hands it to the runner, which then owns retrying it.
	trafficDebt map[string]model.Traffic
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

	config, exits, err := e.build(ctx)
	if err != nil {
		return err
	}
	if e.started && bytes.Equal(config, e.applied) {
		return nil
	}
	// A config Xray rejects would crash-loop it; keep the running one instead.
	if err := e.check(ctx, config, exits); err != nil {
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

// Check asks Xray whether it would take the config the store describes now, also when that is
// the config already running, which Sync does not ask about again: a certificate may have gone
// from disk, or Xray been upgraded, since it started. Nothing is applied.
func (e *Engine) Check(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	config, exits, err := e.build(ctx)
	if err != nil {
		return err
	}
	return e.check(ctx, config, exits)
}

// build makes the config from the store; callers hold e.mu.
func (e *Engine) build(ctx context.Context) ([]byte, []model.Exit, error) {
	lines, err := e.Store.ListLines(ctx)
	if err != nil {
		return nil, nil, err
	}
	clients, err := e.Store.ListClients(ctx)
	if err != nil {
		return nil, nil, err
	}
	exits, err := e.Store.ListExits(ctx)
	if err != nil {
		return nil, nil, err
	}
	config, err := engine.BuildConfig(lines, clients, exits, e.Options)
	return config, exits, err
}

// check runs `xray run -test` on config. Only Xray's own refusal is marked ErrConfigRejected.
func (e *Engine) check(ctx context.Context, config []byte, exits []model.Exit) error {
	if err := e.validate(ctx, config); err != nil {
		var cte *engine.ConfigTestError
		if !errors.As(err, &cte) {
			// Xray could not be asked at all (missing binary, no temp dir): not a refusal.
			return err
		}
		return fmt.Errorf("%w: %w", panel.ErrConfigRejected, redactExitSecrets(err, exits))
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
		if err = e.Store.AddTraffic(ctx, quota.ByClientID(traffic)); err != nil {
			// The counters are already drained, so keep the batch in memory for the next quota read.
			e.trafficDebt = mergeTraffic(e.trafficDebt, traffic)
		}
	}
	if err != nil && e.Logger != nil {
		e.Logger.Warn("traffic since the last tick was not saved before the restart", "error", err)
	}
}

func mergeTraffic(dst, src map[string]model.Traffic) map[string]model.Traffic {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]model.Traffic, len(src))
	}
	for tag, tr := range src {
		total := dst[tag]
		total.Up += tr.Up
		total.Down += tr.Down
		dst[tag] = total
	}
	return dst
}

// Traffic is the quota runner's source. It reports nothing new while Xray is not running,
// but still hands over a batch an earlier restart could not store.
func (e *Engine) Traffic(ctx context.Context) (map[string]model.Traffic, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.trafficDebt
	e.trafficDebt = nil
	if !e.started || !e.Proc.Status().Running {
		return out, nil
	}
	traffic, err := e.query(ctx)
	return mergeTraffic(out, traffic), err
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

// redactExitSecrets hides exit credentials that Xray may echo in its error text, such as a
// Shadowsocks key it could not decode, before the error reaches the API response and the log.
func redactExitSecrets(err error, exits []model.Exit) error {
	var cte *engine.ConfigTestError
	if !errors.As(err, &cte) {
		return err
	}
	out := cte.Output
	for _, x := range exits {
		for _, secret := range []string{x.Params.Secret, x.Params.ObfsPassword, x.Params.Encryption} {
			if len(secret) >= 4 && secret != "none" {
				out = strings.ReplaceAll(out, secret, "[redacted]")
			}
		}
	}
	return &engine.ConfigTestError{ExitErr: cte.ExitErr, Output: out}
}
