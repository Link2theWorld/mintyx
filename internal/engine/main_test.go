package engine

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeModeEnv makes the test binary act as a fake xray; the value selects the behaviour.
const (
	fakeModeEnv   = "MINTYX_FAKE_XRAY"
	fakeMarkerEnv = "MINTYX_FAKE_XRAY_MARKER"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeModeEnv); mode != "" {
		os.Exit(fakeXray(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeXray(mode string, args []string) int {
	switch {
	case len(args) >= 1 && args[0] == "version":
		fmt.Println("Xray 26.3.27 (Xray, Penetrates Everything.) abc1234 (go1.26.1 linux/amd64)")
		fmt.Println("A unified platform for anti-censorship.")
		return 0
	case len(args) >= 2 && args[0] == "api" && args[1] == "statsquery":
		if strings.Join(args[2:], " ") != "--server=127.0.0.1:10085 -pattern user>>> -reset" {
			fmt.Fprintf(os.Stderr, "unexpected args %q\n", args[2:])
			return 2
		}
		fmt.Println(`{
    "stat": [
        {"name": "user>>>c1>>>traffic>>>uplink", "value": 100},
        {"name": "user>>>c1>>>traffic>>>downlink", "value": 2000}
    ]
}`)
		return 0
	case len(args) == 4 && args[0] == "run" && args[1] == "-test" && args[2] == "-c":
		data, err := os.ReadFile(args[3])
		if err != nil {
			fmt.Println(err)
			return 1
		}
		if strings.Contains(string(data), "bad") {
			fmt.Println("Failed to start: main: failed to load config files > unknown field bad")
			return 23
		}
		fmt.Println("Configuration OK.")
		return 0
	case len(args) == 3 && args[0] == "run" && args[1] == "-c":
		return fakeRun(mode, args[2])
	}
	fmt.Fprintf(os.Stderr, "fake xray: unexpected args %q\n", args)
	return 2
}

func fakeRun(mode, configPath string) int {
	term := make(chan os.Signal, 1)
	if mode == "ignore-term" {
		signal.Ignore(syscall.SIGTERM)
	} else {
		signal.Notify(term, syscall.SIGTERM)
	}
	data, _ := os.ReadFile(configPath)
	fmt.Printf("config: %s\n", data)
	fmt.Fprintf(os.Stderr, "fake stderr pid %d\n", os.Getpid())
	switch mode {
	case "crash-once":
		marker := os.Getenv(fakeMarkerEnv)
		if _, err := os.Stat(marker); err != nil {
			_ = os.WriteFile(marker, nil, 0o600)
			return 3
		}
	case "always-crash":
		return 4
	case "ignore-term":
		time.Sleep(30 * time.Second) // bounded so an aborted test run leaves no long-lived orphan
	}
	<-term
	return 0
}
