package deploy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Link2theWorld/mintyx/internal/deploy/deploytest"
	"github.com/Link2theWorld/mintyx/internal/deploy/sshtest"
)

func TestDialTellsFailuresApart(t *testing.T) {
	v := deploytest.New(t)
	kh := testKnownHosts(t)

	t.Run("wrong password is an auth error", func(t *testing.T) {
		target := vpsTarget(v)
		target.Password = "not-the-password"
		_, err := Dial(testContext(t), target, Options{KnownHosts: kh})
		if !errors.Is(err, ErrAuth) {
			t.Fatalf("err = %v, want ErrAuth", err)
		}
	})

	t.Run("closed port is unreachable", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		target := vpsTarget(v)
		target.Port = port
		_, err = Dial(testContext(t), target, Options{KnownHosts: kh})
		var unreachable *UnreachableError
		if !errors.As(err, &unreachable) {
			t.Fatalf("err = %v, want *UnreachableError", err)
		}
	})

	t.Run("a port that is not SSH is unreachable, not an auth error", func(t *testing.T) {
		hs := httptest.NewServer(http.NotFoundHandler())
		defer hs.Close()
		target := vpsTarget(v)
		target.Port = hs.Listener.Addr().(*net.TCPAddr).Port
		_, err := Dial(testContext(t), target, Options{KnownHosts: kh, Timeout: 3 * time.Second})
		var unreachable *UnreachableError
		if !errors.As(err, &unreachable) {
			t.Fatalf("err = %v, want *UnreachableError", err)
		}
	})

	t.Run("a reinstalled host is refused until forgotten", func(t *testing.T) {
		kh := testKnownHosts(t)
		first := dialVPS(t, v, kh)
		if !first.FirstSeen() || first.Fingerprint() != v.SSH.HostKeyFingerprint() {
			t.Fatalf("first connection: FirstSeen=%v fingerprint=%q, want true and %q", first.FirstSeen(), first.Fingerprint(), v.SSH.HostKeyFingerprint())
		}
		if again := dialVPS(t, v, kh); again.FirstSeen() {
			t.Fatal("second connection to a remembered host reported FirstSeen")
		}

		old := v.SSH.HostKeyFingerprint()
		v.SSH.RotateHostKey()
		_, err := Dial(testContext(t), vpsTarget(v), Options{KnownHosts: kh})
		var changed *HostKeyChangedError
		if !errors.As(err, &changed) {
			t.Fatalf("err = %v, want *HostKeyChangedError", err)
		}
		if changed.Known != old || changed.Presented != v.SSH.HostKeyFingerprint() {
			t.Fatalf("changed = {known %q, presented %q}, want {%q, %q}", changed.Known, changed.Presented, old, v.SSH.HostKeyFingerprint())
		}

		if err := kh.Forget(vpsTarget(v).Addr()); err != nil {
			t.Fatal(err)
		}
		if c := dialVPS(t, v, kh); !c.FirstSeen() {
			t.Fatal("after Forget the host should be trusted as new")
		}
	})
}

func TestKnownHostsFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no permission bits")
	}
	v := deploytest.New(t)
	kh := testKnownHosts(t)
	dialVPS(t, v, kh)
	fi, err := os.Stat(kh.path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("known_hosts.json mode = %o, want 600", got)
	}
}

func encryptedKey(t *testing.T, passphrase string) (pemBytes []byte, pub ssh.PublicKey) {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(edPriv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(edPriv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	pub, err = ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), pub
}

func TestDialWithPrivateKey(t *testing.T) {
	v := deploytest.New(t)
	kh := testKnownHosts(t)
	keyPEM, pub := encryptedKey(t, "open sesame")
	v.SSH.AuthorizeKey(deploytest.User, pub)
	v.SSH.DisablePassword()

	target := Target{Host: "127.0.0.1", Port: v.SSH.Port(), User: deploytest.User, PrivateKey: keyPEM}
	tests := []struct {
		name       string
		passphrase string
		want       error
	}{
		{"no passphrase", "", ErrPassphraseRequired},
		{"wrong passphrase", "open barley", ErrPassphraseWrong},
		{"right passphrase", "open sesame", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target.Passphrase = tt.passphrase
			c, err := Dial(testContext(t), target, Options{KnownHosts: kh})
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if c != nil {
				c.Close()
			}
		})
	}

	t.Run("a key the server does not know is an auth error", func(t *testing.T) {
		other, _ := encryptedKey(t, "")
		_, err := Dial(testContext(t), Target{Host: "127.0.0.1", Port: v.SSH.Port(), User: deploytest.User, PrivateKey: other}, Options{KnownHosts: kh})
		if !errors.Is(err, ErrAuth) {
			t.Fatalf("err = %v, want ErrAuth", err)
		}
	})
}

func TestRunRootPicksTheRightWayToBecomeRoot(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*deploytest.VPS)
		wantCommand string
		wantErr     bool
	}{
		{"root runs the shell directly", func(v *deploytest.VPS) { v.Root = true }, "sh -s", false},
		{"passwordless sudo", func(v *deploytest.VPS) { v.SudoNoPassword = true }, "sudo -n sh -s", false},
		{"sudo with the login password", func(v *deploytest.VPS) {}, cmdSudoPasswordSh, false},
		{"no sudo rights", func(v *deploytest.VPS) { v.SudoPassword = "" }, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := deploytest.New(t)
			tt.setup(v)
			c := dialVPS(t, v, testKnownHosts(t))
			out, err := c.RunRoot(testContext(t), Script{Name: "inspect", Body: inspectBody})
			if tt.wantErr {
				var needs *NeedsRootError
				if !errors.As(err, &needs) {
					t.Fatalf("err = %v, want *NeedsRootError", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := out.Values()["os"]; got != "Linux" {
				t.Fatalf("script output os = %q, want Linux (stdout %q)", got, out.Stdout)
			}
			ran := v.Ran()
			if len(ran) != 1 || !ran[0].AsRoot {
				t.Fatalf("ran = %+v, want exactly one script as root", ran)
			}
			records := v.SSH.Records()
			if last := records[len(records)-1].Command; last != tt.wantCommand {
				t.Fatalf("command = %q, want %q", last, tt.wantCommand)
			}
		})
	}
}

// The sudo password may only ever travel as the first line of stdin.
func TestSudoPasswordStaysOffTheCommandLine(t *testing.T) {
	v := deploytest.New(t)
	c := dialVPS(t, v, testKnownHosts(t))
	if _, err := c.RunRoot(testContext(t), Script{Name: "inspect", Body: inspectBody}); err != nil {
		t.Fatal(err)
	}
	fed := 0
	for _, r := range v.SSH.Records() {
		if strings.Contains(r.Command, deploytest.Password) {
			t.Fatalf("password appears in command %q", r.Command)
		}
		if strings.HasPrefix(r.Command, "sudo -k -S") {
			fed++
			if first, _, _ := strings.Cut(string(r.Stdin), "\n"); first != deploytest.Password {
				t.Fatalf("first stdin line of %q is %q, want the password", r.Command, first)
			}
		}
	}
	if fed != 2 {
		t.Fatalf("sudo -S ran %d times, want 2 (the check and the script)", fed)
	}
}

func TestRunReportsExitStatusAndStderr(t *testing.T) {
	s := sshtest.New(t)
	s.SetPassword("root", "pw")
	s.Handle(func(e *sshtest.Exec) int {
		if e.Command == "id -u" {
			io.WriteString(e.Stdout, "0\n")
			return 0
		}
		io.Copy(io.Discard, e.Stdin)
		io.WriteString(e.Stderr, "disk full\n")
		return 7
	})
	c, err := Dial(testContext(t), Target{Host: "127.0.0.1", Port: s.Port(), User: "root", Password: "pw"}, Options{KnownHosts: testKnownHosts(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.RunRoot(testContext(t), Script{Name: "inspect", Body: inspectBody})
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 7 || exit.Stderr != "disk full\n" {
		t.Fatalf("err = %#v, want ExitError{Code: 7, Stderr: \"disk full\\n\"}", err)
	}
}

func TestScriptRenderQuotesValues(t *testing.T) {
	got := Script{Name: "x", Vars: []Var{{"A", "it's $HOME; rm -rf /"}}, Body: "echo \"$A\"\n"}.render()
	want := "# mintyx:x\nset -eu\nA='it'\\''s $HOME; rm -rf /'\necho \"$A\"\n"
	if got != want {
		t.Fatalf("render =\n%q\nwant\n%q", got, want)
	}
}

func TestUpload(t *testing.T) {
	payload := bytes.Repeat([]byte("mintyx panel binary\x00\xff"), 40_000)

	t.Run("the file arrives intact and the temporary copy is gone", func(t *testing.T) {
		v := deploytest.New(t)
		c := dialVPS(t, v, testKnownHosts(t))
		if err := c.Upload(testContext(t), bytes.NewReader(payload), "/usr/local/bin/mintyx", "0755"); err != nil {
			t.Fatal(err)
		}
		got, ok := v.File("/usr/local/bin/mintyx")
		if !ok || !bytes.Equal(got, payload) {
			t.Fatalf("installed file: present=%v, %d bytes, want the %d bytes sent", ok, len(got), len(payload))
		}
		if _, left := v.File("/tmp/mintyx-upload.000001"); left {
			t.Fatal("temporary upload was left behind")
		}
	})

	t.Run("damage in transit is detected and nothing is installed", func(t *testing.T) {
		v := deploytest.New(t)
		v.CorruptUploads = true
		c := dialVPS(t, v, testKnownHosts(t))
		err := c.Upload(testContext(t), bytes.NewReader(payload), "/usr/local/bin/mintyx", "0755")
		if !errors.Is(err, ErrUploadCorrupt) {
			t.Fatalf("err = %v, want ErrUploadCorrupt", err)
		}
		if _, ok := v.File("/usr/local/bin/mintyx"); ok {
			t.Fatal("a damaged upload was installed")
		}
	})

	t.Run("the temporary copy is removed when sudo fails before the install script runs", func(t *testing.T) {
		v := deploytest.New(t)
		c := dialVPS(t, v, testKnownHosts(t))
		if err := c.EnsureRoot(testContext(t)); err != nil {
			t.Fatal(err)
		}
		v.Set(func(v *deploytest.VPS) { v.SudoPassword = "changed meanwhile" })
		if err := c.Upload(testContext(t), bytes.NewReader(payload), "/usr/local/bin/mintyx", "0755"); err == nil {
			t.Fatal("upload succeeded although sudo refused the install")
		}
		if v.Uploads() != 1 {
			t.Fatalf("uploads = %d, want the copy to have reached the server", v.Uploads())
		}
		if left := v.TempUploads(); len(left) != 0 {
			t.Fatalf("temporary uploads left behind: %v", left)
		}
	})

	t.Run("the temporary copy is removed when the data source fails", func(t *testing.T) {
		v := deploytest.New(t)
		c := dialVPS(t, v, testKnownHosts(t))
		broken := io.MultiReader(bytes.NewReader(payload[:1000]), iotest.ErrReader(errors.New("disk read error")))
		if err := c.Upload(testContext(t), broken, "/usr/local/bin/mintyx", "0755"); err == nil {
			t.Fatal("upload of a failing reader succeeded")
		}
		if left := v.TempUploads(); len(left) != 0 {
			t.Fatalf("temporary uploads left behind: %v", left)
		}
		if _, ok := v.File("/usr/local/bin/mintyx"); ok {
			t.Fatal("a truncated upload was installed")
		}
	})
}

// The forwarder is what lets the user's browser reach a panel that only listens on the server's loopback.
func TestForwarderReachesTheRemoteLoopback(t *testing.T) {
	v := deploytest.New(t)
	c := dialVPS(t, v, testKnownHosts(t))
	if err := c.Upload(testContext(t), strings.NewReader("bin"), PanelBinaryPath, "0755"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RunRoot(testContext(t), Script{Name: "service", Body: serviceBody, Vars: []Var{{"UNIT_PATH", UnitPath}, {"UNIT", unitFile}, {"RESTART", "0"}}}); err != nil {
		t.Fatal(err)
	}
	f, err := c.Forward(PanelAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 10 * time.Second}
	resp, err := client.Get("http://" + f.Addr() + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if want := `{"needsSetup":true,"username":null}`; strings.TrimSpace(string(body)) != want {
		t.Fatalf("GET /api/session through the forwarder = %q, want %q", body, want)
	}
}
