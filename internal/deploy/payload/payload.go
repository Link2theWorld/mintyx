// Package payload carries the Linux builds of the panel that the deployer uploads.
//
// A fresh checkout has only bin/placeholder.txt, so the embed always matches and the
// repository builds; scripts/build-deployer.sh fills bin/ before a release build.
package payload

import (
	"bytes"
	"debug/elf"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/ysuhao/mintyx-next/internal/deploy"
)

//go:embed all:bin
var embedded embed.FS

// Archs are the server CPUs a release build carries a panel for.
var Archs = []string{"amd64", "arm64"}

func fileName(arch string) string { return "bin/mintyx-linux-" + arch }

// Embedded returns the panel built into this program for arch, or deploy.ErrNoPayload.
func Embedded(arch string) ([]byte, error) { return read(embedded, arch) }

func read(fsys fs.FS, arch string) ([]byte, error) {
	data, err := fs.ReadFile(fsys, fileName(arch))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w (linux/%s)", deploy.ErrNoPayload, arch)
	}
	return data, err
}

// Available lists the architectures this program can deploy to.
func Available() []string {
	var have []string
	for _, arch := range Archs {
		if _, err := fs.Stat(embedded, fileName(arch)); err == nil {
			have = append(have, arch)
		}
	}
	return have
}

// File is a panel binary given with -panel-binary; its CPU is read from the ELF header.
type File struct {
	Arch string
	data []byte
}

func Open(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s is not a Linux executable: %w", path, err)
	}
	defer f.Close()
	switch f.Machine {
	case elf.EM_X86_64:
		return &File{Arch: "amd64", data: data}, nil
	case elf.EM_AARCH64:
		return &File{Arch: "arm64", data: data}, nil
	}
	return nil, fmt.Errorf("%s is built for %s; only x86-64 and arm64 are supported", path, f.Machine)
}

// Binary refuses to hand an amd64 build to an arm64 server and the other way round.
func (f *File) Binary(arch string) ([]byte, error) {
	if arch != f.Arch {
		return nil, fmt.Errorf("%w: the given panel binary is for linux/%s, the server is linux/%s", deploy.ErrNoPayload, f.Arch, arch)
	}
	return f.data, nil
}
