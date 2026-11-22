// Package deploytest is a pretend VPS for tests: a loopback SSH server that reacts to the
// deployer's scripts the way a Linux host would, with a real panel behind its "loopback".
package deploytest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ysuhao/mintyx-next/internal/app"
	"github.com/ysuhao/mintyx-next/internal/deploy/sshtest"
	"github.com/ysuhao/mintyx-next/internal/panel"
	"github.com/ysuhao/mintyx-next/internal/store"
)

const (
	User     = "deployer"
	Password = "vps-login-password"
)

// Ran is one script the VPS executed, with the variables it was given.
type Ran struct {
	Name   string
	AsRoot bool
	Vars   map[string]string
}

// VPS holds the knobs a test turns. Change them only through the methods or before connecting.
type VPS struct {
	SSH *sshtest.Server

	mu sync.Mutex
	// Root makes the login user uid 0; otherwise sudo decides.
	Root           bool
	SudoNoPassword bool
	// SudoPassword is what `sudo -S` accepts; "" means the user may not use sudo at all.
	SudoPassword string
	OS           string
	Machine      string
	Systemd      bool
	// Firewall is "ufw", "firewalld" or "" for none active.
	Firewall string
	// CorruptUploads flips a byte of every upload in transit.
	CorruptUploads bool
	// CoverSite is what the panel's draft suggests; "" makes it suggest nothing.
	CoverSite string

	// IgnoreAuthorizedKeys emulates an sshd that does not honour the user's authorized_keys.
	IgnoreAuthorizedKeys bool
	// BreakKeysWithPasswords emulates a server where turning passwords off also kills key login.
	BreakKeysWithPasswords bool
	// OtherConfigKeepsPasswords emulates another sshd config file that wins over the drop-in.
	OtherConfigKeepsPasswords bool

	files        map[string][]byte
	xrayVersion  string
	panelRunning bool
	// runningPanel is the binary the panel process was started from; replacing the file does not change it.
	runningPanel []byte
	openedPorts  []string
	ran          []Ran
	uploads      int
	panelAddr    string
}

// New starts the VPS with a non-root login that may sudo with its password.
func New(t testing.TB) *VPS {
	t.Helper()
	v := &VPS{
		SSH:          sshtest.New(t),
		SudoPassword: Password,
		OS:           "Linux",
		Machine:      "x86_64",
		Systemd:      true,
		CoverSite:    "www.campus.example",
		files:        map[string][]byte{},
	}
	v.SSH.SetPassword(User, Password)
	v.SSH.Handle(v.exec)

	st, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	srv, err := panel.New(panel.Config{
		Store: st, Engine: idleEngine{}, Keys: app.Keys{}, ReservedPorts: []int{8088, 10085},
		CoverSite: func(context.Context, string) string {
			v.mu.Lock()
			defer v.mu.Unlock()
			return v.CoverSite
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	v.panelAddr = hs.Listener.Addr().String()

	// The panel is only reachable the way the deployer must reach it: the server's own loopback.
	v.SSH.Forward(func(addr string) (net.Conn, error) {
		v.mu.Lock()
		running := v.panelRunning
		v.mu.Unlock()
		if addr != "127.0.0.1:8088" || !running {
			return nil, errors.New("connection refused")
		}
		return net.Dial("tcp", v.panelAddr)
	})
	return v
}

type idleEngine struct{}

func (idleEngine) Sync(context.Context) error    { return nil }
func (idleEngine) Restart(context.Context) error { return nil }
func (idleEngine) Status(context.Context) panel.EngineStatus {
	return panel.EngineStatus{Running: true, BinaryFound: true}
}
func (idleEngine) Logs() []string { return nil }

// Set changes knobs under the lock, for tests that flip behaviour while connected.
func (v *VPS) Set(change func(*VPS)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	change(v)
}

func (v *VPS) File(path string) ([]byte, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, ok := v.files[path]
	return b, ok
}

// TempUploads lists the temporary upload files still on the server.
func (v *VPS) TempUploads() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []string
	for path := range v.files {
		if strings.HasPrefix(path, "/tmp/mintyx-upload.") {
			out = append(out, path)
		}
	}
	return out
}

// Ran returns the scripts executed so far, oldest first.
func (v *VPS) Ran() []Ran {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]Ran(nil), v.ran...)
}

// RanNames is Ran reduced to script names.
func (v *VPS) RanNames() []string {
	var names []string
	for _, r := range v.Ran() {
		names = append(names, r.Name)
	}
	return names
}

func (v *VPS) OpenedPorts() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.openedPorts...)
}

// RunningPanel is the binary the panel process is executing, nil while it is stopped.
func (v *VPS) RunningPanel() []byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.runningPanel
}

func (v *VPS) Uploads() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.uploads
}

func (v *VPS) XrayVersion() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.xrayVersion
}

func (v *VPS) exec(e *sshtest.Exec) int {
	v.mu.Lock()
	root, noPass, sudoPass := v.Root, v.SudoNoPassword, v.SudoPassword
	v.mu.Unlock()
	in := bufio.NewReader(e.Stdin)

	const sudoPrefix = "sudo -k -S -p '' "
	switch cmd := e.Command; {
	case cmd == "id -u":
		if root {
			fmt.Fprintln(e.Stdout, "0")
		} else {
			fmt.Fprintln(e.Stdout, "1000")
		}
		return 0
	case cmd == "sudo -k -n true":
		if root || noPass {
			return 0
		}
		fmt.Fprintln(e.Stderr, "sudo: a password is required")
		return 1
	case cmd == "sudo -n sh -s":
		if !root && !noPass {
			fmt.Fprintln(e.Stderr, "sudo: a password is required")
			return 1
		}
		return v.script(e, in, true)
	case strings.HasPrefix(cmd, sudoPrefix):
		// Like sudo, take exactly one line as the password and leave the rest for the command.
		line, _ := in.ReadString('\n')
		if sudoPass == "" || strings.TrimSuffix(line, "\n") != sudoPass {
			fmt.Fprintln(e.Stderr, "Sorry, try again.")
			return 1
		}
		switch strings.TrimPrefix(cmd, sudoPrefix) {
		case "true":
			return 0
		case "sh -c 'IFS= read -r _; exec sh -s'":
			if _, err := in.ReadString('\n'); err != nil {
				return 1
			}
			return v.script(e, in, true)
		}
	case cmd == "sh -s":
		return v.script(e, in, root)
	case strings.HasPrefix(cmd, "rm -f '/tmp/mintyx-upload."):
		v.mu.Lock()
		delete(v.files, strings.Trim(strings.TrimPrefix(cmd, "rm -f "), "'"))
		v.mu.Unlock()
		return 0
	case strings.Contains(cmd, "mktemp /tmp/mintyx-upload."):
		data, _ := io.ReadAll(in)
		v.mu.Lock()
		v.uploads++
		if v.CorruptUploads && len(data) > 0 {
			data[len(data)/2] ^= 0xff
		}
		path := fmt.Sprintf("/tmp/mintyx-upload.%06d", v.uploads)
		v.files[path] = data
		v.mu.Unlock()
		fmt.Fprintln(e.Stdout, path)
		return 0
	}
	fmt.Fprintf(e.Stderr, "sh: command not understood by the fake VPS: %s\n", e.Command)
	return 127
}

// parseScript reads the `# mintyx:name` header and the quoted NAME='value' assignments after it.
func parseScript(text string) (name string, vars map[string]string, ok bool) {
	rest, found := strings.CutPrefix(text, "# mintyx:")
	if !found {
		return "", nil, false
	}
	name, rest, _ = strings.Cut(rest, "\n")
	rest = strings.TrimPrefix(rest, "set -eu\n")
	vars = map[string]string{}
	for {
		eq := strings.Index(rest, "='")
		if eq <= 0 || strings.ContainsAny(rest[:eq], " \n\t$(") {
			return name, vars, true
		}
		key := rest[:eq]
		rest = rest[eq+2:]
		var val strings.Builder
		for {
			end := strings.IndexByte(rest, '\'')
			if end < 0 {
				return name, vars, false
			}
			val.WriteString(rest[:end])
			rest = rest[end+1:]
			if strings.HasPrefix(rest, `\''`) {
				val.WriteByte('\'')
				rest = rest[3:]
				continue
			}
			break
		}
		vars[key] = val.String()
		rest = strings.TrimPrefix(rest, "\n")
	}
}

var rootOnly = map[string]bool{
	"install-file": true, "xray-install": true, "service": true, "firewall": true,
	"keylogin-apply": true, "keylogin-rollback": true,
}

func (v *VPS) script(e *sshtest.Exec, in io.Reader, asRoot bool) int {
	text, _ := io.ReadAll(in)
	name, vars, ok := parseScript(string(text))
	if !ok {
		fmt.Fprintln(e.Stderr, "sh: not a mintyx script")
		return 2
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.ran = append(v.ran, Ran{Name: name, AsRoot: asRoot, Vars: vars})
	if rootOnly[name] && !asRoot {
		fmt.Fprintln(e.Stderr, "Permission denied")
		return 1
	}
	say := func(format string, a ...any) { fmt.Fprintf(e.Stdout, format+"\n", a...) }

	switch name {
	case "inspect":
		say("os=%s", v.OS)
		say("arch=%s", v.Machine)
		if v.Systemd {
			say("systemd=1")
		} else {
			say("systemd=0")
		}
	case "file-sha256":
		if data, ok := v.files[vars["FILE"]]; ok {
			sum := sha256.Sum256(data)
			say("sha256=%s", hex.EncodeToString(sum[:]))
		} else {
			say("sha256=")
		}
	case "install-file":
		data := v.files[vars["SRC"]]
		delete(v.files, vars["SRC"])
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != vars["SHA256"] {
			say("checksum=mismatch")
			return 3
		}
		v.files[vars["DEST"]] = data
		say("checksum=ok")
	case "xray-install":
		if v.xrayVersion == vars["VERSION"] {
			say("xray=present")
		} else {
			v.xrayVersion = vars["VERSION"]
			say("xray=installed")
		}
	case "service":
		if _, ok := v.files["/usr/local/bin/mintyx"]; !ok {
			fmt.Fprintln(e.Stderr, "Job for mintyx.service failed: executable not found")
			return 1
		}
		changed := string(v.files[vars["UNIT_PATH"]]) != vars["UNIT"]
		v.files[vars["UNIT_PATH"]] = []byte(vars["UNIT"])
		stale := v.panelRunning && !bytes.Equal(v.runningPanel, v.files[vars["BIN"]])
		restart := changed || vars["RESTART"] == "1" || stale
		if restart || !v.panelRunning {
			v.runningPanel = v.files[vars["BIN"]]
		}
		v.panelRunning = true
		if restart {
			say("service=restarted")
		} else {
			say("service=started")
		}
	case "service-log":
		say("mintyx.service: (fake journal)")
	case "firewall":
		if v.Firewall == "" {
			say("firewall=none")
		} else {
			v.openedPorts = append(v.openedPorts, vars["PORT"]+"/tcp")
			say("firewall=%s", v.Firewall)
		}
	case "authorized-keys-add":
		if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(vars["KEY"])); err == nil && !v.IgnoreAuthorizedKeys {
			v.SSH.AuthorizeKey(e.User, key)
		}
		v.files["~/.ssh/authorized_keys"] = append(v.files["~/.ssh/authorized_keys"], vars["KEY"]+"\n"...)
		say("key=added")
	case "authorized-keys-remove":
		if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(vars["KEY"])); err == nil {
			v.SSH.RevokeKey(e.User, key)
		}
		kept := strings.ReplaceAll(string(v.files["~/.ssh/authorized_keys"]), vars["KEY"]+"\n", "")
		v.files["~/.ssh/authorized_keys"] = []byte(kept)
		say("key=removed")
	case "keylogin-apply":
		if v.OtherConfigKeepsPasswords {
			say("result=still-on")
			say("files=/etc/ssh/sshd_config.d/50-cloud-init.conf ")
			break
		}
		v.files[vars["DROPIN"]] = []byte("PasswordAuthentication no\n")
		v.SSH.DisablePassword()
		if v.BreakKeysWithPasswords {
			v.SSH.RevokeAllKeys(e.User)
		}
		say("result=applied")
	case "keylogin-rollback":
		delete(v.files, vars["DROPIN"])
		v.SSH.EnablePassword()
		say("result=rolled-back")
	default:
		fmt.Fprintf(e.Stderr, "sh: unknown mintyx script %q\n", name)
		return 127
	}
	return 0
}
