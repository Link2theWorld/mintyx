package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ysuhao/mintyx-next/internal/model"
)

// ConfigTestError carries Xray's own output when `xray run -test` rejects a config.
type ConfigTestError struct {
	ExitErr string
	Output  string
}

func (e *ConfigTestError) Error() string {
	return fmt.Sprintf("xray rejected the config (%s): %s", e.ExitErr, e.Output)
}

// Validate runs `xray run -test` on config and returns a *ConfigTestError with Xray's text if it is rejected.
func Validate(ctx context.Context, binPath string, config []byte) error {
	dir, err := os.MkdirTemp("", "mintyx-xray-test-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, config, 0o600); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, binPath, "run", "-test", "-c", path).CombinedOutput()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && ctx.Err() == nil {
		return &ConfigTestError{ExitErr: exitErr.Error(), Output: strings.TrimSpace(string(out))}
	}
	return fmt.Errorf("run %s -test: %w", binPath, err)
}

// Version runs `xray version` and returns the version number, e.g. "26.3.27".
func Version(ctx context.Context, binPath string) (string, error) {
	out, err := exec.CommandContext(ctx, binPath, "version").Output()
	if err != nil {
		return "", fmt.Errorf("run %s version: %w", binPath, err)
	}
	return ParseVersion(out)
}

// ParseVersion extracts the version from the first line of `xray version`, "Xray 26.3.27 (Xray, ...) ...".
func ParseVersion(out []byte) (string, error) {
	first, _, _ := strings.Cut(string(out), "\n")
	fields := strings.Fields(first)
	if len(fields) < 2 || fields[0] != "Xray" {
		return "", fmt.Errorf("unrecognised xray version output %q", first)
	}
	return strings.TrimPrefix(fields[1], "v"), nil
}

// QueryTraffic reads and resets every per-user counter through `xray api statsquery`, keyed by stats tag.
func QueryTraffic(ctx context.Context, binPath, apiAddr string) (map[string]model.Traffic, error) {
	cmd := exec.CommandContext(ctx, binPath, "api", "statsquery", "--server="+apiAddr, "-pattern", "user>>>", "-reset")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("xray api statsquery: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return ParseStatsQuery(out)
}

// ParseStatsQuery parses `xray api statsquery` JSON, {"stat":[{"name":"user>>>c1>>>traffic>>>uplink","value":5}]}.
// Xray omits zero values and empty lists, and protojson-style output would quote int64, so both forms are accepted.
func ParseStatsQuery(out []byte) (map[string]model.Traffic, error) {
	var resp struct {
		Stat []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	result := map[string]model.Traffic{}
	if len(bytes.TrimSpace(out)) == 0 {
		return result, nil
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("parse statsquery output: %w", err)
	}
	for _, s := range resp.Stat {
		parts := strings.Split(s.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
			continue
		}
		v, err := parseStatValue(s.Value)
		if err != nil {
			return nil, fmt.Errorf("parse statsquery value of %q: %w", s.Name, err)
		}
		t := result[parts[1]]
		switch parts[3] {
		case "uplink":
			t.Up += v
		case "downlink":
			t.Down += v
		default:
			continue
		}
		result[parts[1]] = t
	}
	return result, nil
}

func parseStatValue(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strconv.ParseInt(s, 10, 64)
	}
	var n int64
	err := json.Unmarshal(raw, &n)
	return n, err
}
