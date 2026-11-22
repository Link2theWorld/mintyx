package engine

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/ysuhao/mintyx-next/internal/model"
)

func TestParseStatsQuery(t *testing.T) {
	// Shape printed by `xray api statsquery`: four-space indent, zero values and empty lists omitted.
	out := []byte(`{
    "stat": [
        {
            "name": "user>>>c1>>>traffic>>>uplink",
            "value": 1024
        },
        {
            "name": "user>>>c1>>>traffic>>>downlink",
            "value": 8796093022208
        },
        {
            "name": "user>>>c12>>>traffic>>>downlink",
            "value": "77"
        },
        {
            "name": "user>>>c12>>>traffic>>>uplink"
        },
        {
            "name": "inbound>>>line-1>>>traffic>>>uplink",
            "value": 5
        },
        {
            "name": "user>>>c3>>>online",
            "value": 2
        }
    ]
}
`)
	got, err := ParseStatsQuery(out)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]model.Traffic{
		"c1":  {Up: 1024, Down: 8796093022208},
		"c12": {Up: 0, Down: 77},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseStatsQuery = %+v, want %+v", got, want)
	}
}

func TestParseStatsQueryEmptyAndInvalid(t *testing.T) {
	for _, empty := range []string{"", "{}\n"} {
		got, err := ParseStatsQuery([]byte(empty))
		if err != nil || len(got) != 0 {
			t.Errorf("ParseStatsQuery(%q) = %v, %v; want empty map", empty, got, err)
		}
	}
	if _, err := ParseStatsQuery([]byte("rpc error: code = Unavailable")); err == nil {
		t.Error("non-JSON output was accepted")
	}
	if _, err := ParseStatsQuery([]byte(`{"stat":[{"name":"user>>>c1>>>traffic>>>uplink","value":"x"}]}`)); err == nil {
		t.Error("non-numeric value was accepted")
	}
}

func TestParseVersion(t *testing.T) {
	got, err := ParseVersion([]byte("Xray 26.3.27 (Xray, Penetrates Everything.) 1c2b3a4 (go1.26.1 linux/amd64)\nA unified platform for anti-censorship.\n"))
	if err != nil || got != "26.3.27" {
		t.Errorf("ParseVersion = %q, %v; want 26.3.27", got, err)
	}
	if _, err := ParseVersion([]byte("V2Ray 5.1.0\n")); err == nil {
		t.Error("non-Xray output accepted")
	}
}

func fakeBinEnv(t *testing.T) {
	t.Helper()
	t.Setenv(fakeModeEnv, "serve")
}

func TestVersionRunsBinary(t *testing.T) {
	fakeBinEnv(t)
	got, err := Version(context.Background(), os.Args[0])
	if err != nil || got != "26.3.27" {
		t.Errorf("Version = %q, %v", got, err)
	}
}

func TestValidateReturnsXrayText(t *testing.T) {
	fakeBinEnv(t)
	if err := Validate(context.Background(), os.Args[0], []byte(`{"ok":true}`)); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	err := Validate(context.Background(), os.Args[0], []byte(`{"bad":true}`))
	var ce *ConfigTestError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *ConfigTestError", err)
	}
	want := ConfigTestError{ExitErr: "exit status 23", Output: "Failed to start: main: failed to load config files > unknown field bad"}
	if *ce != want {
		t.Errorf("err = %+v, want %+v", *ce, want)
	}
}

func TestQueryTrafficRunsStatsQueryWithReset(t *testing.T) {
	fakeBinEnv(t)
	got, err := QueryTraffic(context.Background(), os.Args[0], "127.0.0.1:10085")
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]model.Traffic{"c1": {Up: 100, Down: 2000}}; !reflect.DeepEqual(got, want) {
		t.Errorf("QueryTraffic = %+v, want %+v", got, want)
	}
	if _, err := QueryTraffic(context.Background(), os.Args[0], "127.0.0.1:1"); err == nil {
		t.Error("failing statsquery returned no error")
	}
}
