package web

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestWithIndexFallback(t *testing.T) {
	tests := []struct {
		name  string
		files fstest.MapFS
		want  string
	}{
		{
			name: "unbuilt checkout serves placeholder as index",
			files: fstest.MapFS{
				"unbuilt.html": {Data: []byte("placeholder")},
			},
			want: "placeholder",
		},
		{
			name: "real build wins over placeholder",
			files: fstest.MapFS{
				"unbuilt.html": {Data: []byte("placeholder")},
				"index.html":   {Data: []byte("app")},
			},
			want: "app",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fs.ReadFile(withIndexFallback(tc.files), "index.html")
			if err != nil {
				t.Fatalf("read index.html: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("index.html = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDistServesIndex(t *testing.T) {
	if _, err := fs.ReadFile(Dist(), "index.html"); err != nil {
		t.Fatalf("Dist() has no index.html: %v", err)
	}
}
