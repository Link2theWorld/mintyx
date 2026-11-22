// Package web embeds the built single-page frontend.
//
// A fresh checkout only contains dist/unbuilt.html (tracked in git), so the
// embed always has something to match and `go build` works before any npm
// build. Once `npm run build` has written dist/index.html, Dist serves it;
// until then index.html resolves to the placeholder page.
package web

import (
	"embed"
	"errors"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

const (
	indexName       = "index.html"
	placeholderName = "unbuilt.html"
)

// Dist returns the frontend files rooted at the dist directory.
func Dist() fs.FS {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		panic(err) // the embed pattern guarantees dist exists
	}
	return withIndexFallback(sub)
}

// Built reports whether the embedded frontend is a real build rather than the placeholder.
func Built() bool {
	_, err := fs.Stat(embedded, "dist/"+indexName)
	return err == nil
}

func withIndexFallback(fsys fs.FS) fs.FS {
	if _, err := fs.Stat(fsys, indexName); err == nil {
		return fsys
	}
	return placeholderFS{fsys}
}

type placeholderFS struct{ fs.FS }

func (p placeholderFS) Open(name string) (fs.File, error) {
	if name == indexName {
		f, err := p.FS.Open(placeholderName)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
		return f, err
	}
	return p.FS.Open(name)
}
