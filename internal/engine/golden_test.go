package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ysuhao/mintyx-next/internal/model"
)

// goldenLines is a mix of every line kind; its config was captured before exits existed.
func goldenLines() []model.Line {
	return []model.Line{realityLine(1, 443), xhttpLine(2, 8443, model.XHTTPTLS), xhttpLine(3, 8080, model.XHTTPPlain), hy2Line(4, 443, "obfs-pass")}
}

// TestNoExitsConfigIsUnchanged pins the config of a panel that uses no exits, byte for byte, so
// adding exits never restarts Xray for anyone who does not use them.
// UPDATE_GOLDEN=1 go test ./internal/engine -run TestNoExitsConfigIsUnchanged rewrites the file.
func TestNoExitsConfigIsUnchanged(t *testing.T) {
	got, err := buildGolden()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "no-exits.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("config without exits changed:\n%s", got)
	}
}
