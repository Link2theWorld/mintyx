package deploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// KnownHost is the host key remembered from the first connection to an address.
type KnownHost struct {
	KeyType     string    `json:"keyType"`
	Fingerprint string    `json:"fingerprint"`
	AddedAt     time.Time `json:"addedAt"`
}

// KnownHosts is the trust-on-first-use store, one JSON file keyed by "host:port".
type KnownHosts struct {
	path string
	mu   sync.Mutex
}

type knownHostsFile struct {
	Hosts map[string]KnownHost `json:"hosts"`
}

// DefaultKnownHostsPath is mintyx/known_hosts.json under the user's config directory.
func DefaultKnownHostsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "mintyx", "known_hosts.json"), nil
}

func OpenKnownHosts(path string) *KnownHosts { return &KnownHosts{path: path} }

func (k *KnownHosts) load() (knownHostsFile, error) {
	f := knownHostsFile{Hosts: map[string]KnownHost{}}
	data, err := os.ReadFile(k.path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return f, fmt.Errorf("known hosts file %s is damaged: %w", k.path, err)
	}
	if f.Hosts == nil {
		f.Hosts = map[string]KnownHost{}
	}
	return f, nil
}

// save replaces the file through a rename so a crash never leaves half a file behind.
func (k *KnownHosts) save(f knownHostsFile) error {
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(k.path), ".known_hosts-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), k.path)
}

func (k *KnownHosts) Lookup(addr string) (KnownHost, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, err := k.load()
	if err != nil {
		return KnownHost{}, false, err
	}
	h, ok := f.Hosts[addr]
	return h, ok, nil
}

func (k *KnownHosts) Remember(addr string, h KnownHost) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, err := k.load()
	if err != nil {
		return err
	}
	f.Hosts[addr] = h
	return k.save(f)
}

// Forget drops the remembered key so the next connection trusts whatever the host presents.
func (k *KnownHosts) Forget(addr string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, err := k.load()
	if err != nil {
		return err
	}
	if _, ok := f.Hosts[addr]; !ok {
		return nil
	}
	delete(f.Hosts, addr)
	return k.save(f)
}
