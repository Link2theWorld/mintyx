package payload

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/Link2theWorld/mintyx/internal/deploy"
)

func TestReadTellsAMissingPayloadApart(t *testing.T) {
	fsys := fstest.MapFS{
		"bin/placeholder.txt":    {Data: []byte("placeholder")},
		"bin/mintyx-linux-amd64": {Data: []byte("amd64 build")},
	}
	got, err := read(fsys, "amd64")
	if err != nil || string(got) != "amd64 build" {
		t.Fatalf("amd64 = %q, %v; want the embedded build", got, err)
	}
	if _, err := read(fsys, "arm64"); !errors.Is(err, deploy.ErrNoPayload) {
		t.Fatalf("arm64 err = %v, want ErrNoPayload", err)
	}
}

// The override must not let an x86 build be uploaded to an ARM server, where it would only fail at start.
func TestOpenReadsTheArchitectureFromTheBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-compiles a small program")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	build := func(goos, goarch string) string {
		out := filepath.Join(dir, goos+"-"+goarch)
		cmd := exec.Command("go", "build", "-o", out, src)
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
		if msg, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s/%s: %v\n%s", goos, goarch, err, msg)
		}
		return out
	}

	armPath := build("linux", "arm64")
	want, _ := os.ReadFile(armPath)
	f, err := Open(armPath)
	if err != nil {
		t.Fatal(err)
	}
	if f.Arch != "arm64" {
		t.Fatalf("Arch = %q, want arm64", f.Arch)
	}
	if _, err := f.Binary("amd64"); !errors.Is(err, deploy.ErrNoPayload) {
		t.Fatalf("Binary(amd64) err = %v, want ErrNoPayload", err)
	}
	if data, err := f.Binary("arm64"); err != nil || !bytes.Equal(data, want) {
		t.Fatalf("Binary(arm64) = %d bytes, %v; want the file's %d bytes", len(data), err, len(want))
	}

	if _, err := Open(build("darwin", "arm64")); err == nil {
		t.Fatal("a macOS executable was accepted as a panel binary")
	}
}
