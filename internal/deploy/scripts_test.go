package deploy

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These tests run the real script text through the local sh, with stand-ins on PATH for the
// commands that would touch the system. They catch shell mistakes the fake VPS cannot see.

func requireSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX sh")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on this machine")
	}
}

type localRun struct {
	stdout string
	stderr string
	code   int
}

func runLocally(t *testing.T, s Script, stubDir string, env ...string) localRun {
	t.Helper()
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(s.render())
	cmd.Env = append(os.Environ(), env...)
	if stubDir != "" {
		cmd.Env = append(cmd.Env, "PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"), "STUB="+stubDir)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	r := localRun{stdout: stdout.String(), stderr: stderr.String()}
	if exit, ok := err.(*exec.ExitError); ok {
		r.code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return r
}

func (r localRun) value(key string) string { return Output{Stdout: r.stdout}.Values()[key] }

func writeStub(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestEveryScriptParses(t *testing.T) {
	requireSh(t)
	bodies := map[string]string{
		"inspect": inspectBody, "install-file": installFileBody, "file-sha256": fileSHA256Body,
		"xray-install": xrayInstallBody, "service": serviceBody, "service-log": serviceLogBody,
		"firewall": firewallBody, "authorized-keys-add": authorizedKeysAddBody,
		"authorized-keys-remove": authorizedKeysRemoveBody, "keylogin-apply": keyLoginApplyBody,
		"keylogin-rollback": keyLoginRollbackBody,
	}
	for name, body := range bodies {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(Script{Name: name, Body: body}.render())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %v\n%s", name, err, out)
		}
	}
	for _, cmdline := range []string{cmdUpload} {
		if out, err := exec.Command("sh", "-n", "-c", cmdline).CombinedOutput(); err != nil {
			t.Errorf("%q does not parse: %v\n%s", cmdline, err, out)
		}
	}
}

// xrayFixture builds a release as GitHub would serve it: the zip and a .dgst in the real file's layout.
func xrayFixture(t *testing.T, dir, asset string) (sha string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{
		"xray":        "#!/bin/sh\necho \"Xray " + XrayVersion + " (Xray, Penetrates Everything.) abc1234 (go1.26 linux/amd64)\"\n",
		"geoip.dat":   "geoip",
		"geosite.dat": "geosite",
		"README.md":   "readme",
	}
	for name, content := range files {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0o755)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	sha = hex.EncodeToString(sum[:])
	dgst := "MD5= 17349769d85d6d0c5043b25c30da9673\nSHA1= 4b9d50003e0ba1b67b375bfd0a51019c50a26f57\nSHA2-256= " + sha +
		"\nSHA2-512= 9eb4e81887342a1a01de651bf31e8496817640c7e70c9f1b899a2c99432a305b\n"
	if err := os.WriteFile(filepath.Join(dir, asset), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, asset+".dgst"), []byte(dgst), 0o644); err != nil {
		t.Fatal(err)
	}
	return sha
}

func TestXrayInstallScript(t *testing.T) {
	requireSh(t)
	if _, err := exec.LookPath("unzip"); err != nil {
		t.Skip("no unzip on this machine")
	}
	const asset = "Xray-linux-64.zip"
	// The stand-in curl serves files from $STUB/release by the last path element of the URL.
	const curlStub = `
while [ $# -gt 0 ]; do
  case "$1" in
    -o) dest=$2; shift ;;
    http*) url=$1 ;;
  esac
  shift
done
echo "$url" >> "$STUB/requests"
cp "$STUB/release/${url##*/}" "$dest"
`
	setup := func(t *testing.T) (stub, dir, sha string) {
		stub, dir = t.TempDir(), filepath.Join(t.TempDir(), "lib", "mintyx")
		writeStub(t, stub, "curl", curlStub)
		if err := os.Mkdir(filepath.Join(stub, "release"), 0o755); err != nil {
			t.Fatal(err)
		}
		return stub, dir, xrayFixture(t, filepath.Join(stub, "release"), asset)
	}
	script := func(dir, pinned string) Script {
		return Script{Name: "xray-install", Body: xrayInstallBody, Vars: []Var{
			{"DIR", dir}, {"VERSION", XrayVersion}, {"BASE", xrayReleaseBase}, {"ASSET", asset}, {"PINNED", pinned},
		}}
	}

	t.Run("installs a verified download, then leaves it alone", func(t *testing.T) {
		stub, dir, sha := setup(t)
		r := runLocally(t, script(dir, sha), stub)
		if r.code != 0 || r.value("xray") != "installed" {
			t.Fatalf("exit %d, stdout %q, stderr %q; want xray=installed", r.code, r.stdout, r.stderr)
		}
		for _, f := range []string{"xray", "geoip.dat", "geosite.dat"} {
			if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
				t.Errorf("%s was not installed: %v", f, err)
			}
		}
		requests, _ := os.ReadFile(filepath.Join(stub, "requests"))
		want := xrayReleaseBase + "/v" + XrayVersion + "/" + asset + "\n" + xrayReleaseBase + "/v" + XrayVersion + "/" + asset + ".dgst\n"
		if string(requests) != want {
			t.Fatalf("downloaded\n%s\nwant\n%s", requests, want)
		}

		again := runLocally(t, script(dir, sha), stub)
		if again.code != 0 || again.value("xray") != "present" {
			t.Fatalf("second run: exit %d, stdout %q; want xray=present", again.code, again.stdout)
		}
		if after, _ := os.ReadFile(filepath.Join(stub, "requests")); string(after) != want {
			t.Fatal("the second run downloaded again")
		}
	})

	t.Run("refuses a zip that differs from the published digest", func(t *testing.T) {
		stub, dir, sha := setup(t)
		zipPath := filepath.Join(stub, "release", asset)
		data, _ := os.ReadFile(zipPath)
		if err := os.WriteFile(zipPath, append(data, 0), 0o644); err != nil {
			t.Fatal(err)
		}
		tampered := sha256.Sum256(append(data, 0))
		// Pinning the tampered digest isolates the comparison with the .dgst file.
		r := runLocally(t, script(dir, hex.EncodeToString(tampered[:])), stub)
		if r.code != 12 || r.value("problem") != "digest" {
			t.Fatalf("exit %d, stdout %q; want exit 12 with problem=digest (published was %s)", r.code, r.stdout, sha)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("install dir exists after a refused download (err %v)", err)
		}
	})

	t.Run("refuses a release that differs from the pinned digest", func(t *testing.T) {
		stub, dir, _ := setup(t)
		r := runLocally(t, script(dir, strings.Repeat("0", 64)), stub)
		if r.code != 12 || r.value("problem") != "digest" {
			t.Fatalf("exit %d, stdout %q; want exit 12 with problem=digest", r.code, r.stdout)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("install dir exists after a refused download (err %v)", err)
		}
	})
}

func TestInstallFileScript(t *testing.T) {
	requireSh(t)
	dir := t.TempDir()
	src, dest := filepath.Join(dir, "upload"), filepath.Join(dir, "bin", "mintyx")
	content := []byte("panel")
	sum := sha256.Sum256(content)
	script := func(sha string) Script {
		return Script{Name: "install-file", Body: installFileBody, Vars: []Var{{"SRC", src}, {"DEST", dest}, {"SHA256", sha}, {"MODE", "0755"}}}
	}

	os.WriteFile(src, content, 0o600)
	if r := runLocally(t, script(strings.Repeat("0", 64)), ""); r.code != uploadMismatchExit || r.value("checksum") != "mismatch" {
		t.Fatalf("wrong digest: exit %d stdout %q, want exit %d checksum=mismatch", r.code, r.stdout, uploadMismatchExit)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("a file with the wrong digest was installed")
	}

	os.WriteFile(src, content, 0o600)
	if r := runLocally(t, script(hex.EncodeToString(sum[:])), ""); r.code != 0 || r.value("checksum") != "ok" {
		t.Fatalf("right digest: exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}
	fi, err := os.Stat(dest)
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("installed file: %v, mode %v; want mode 755", err, fi)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("the temporary upload was not removed")
	}
}

func TestAuthorizedKeysScripts(t *testing.T) {
	requireSh(t)
	home := t.TempDir()
	file := filepath.Join(home, ".ssh", "authorized_keys")
	os.Mkdir(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(file, []byte("ssh-ed25519 AAAAexisting someone@laptop\n"), 0o600)
	const key = "ssh-ed25519 AAAAnew mintyx-deploy"
	add := Script{Name: "authorized-keys-add", Body: authorizedKeysAddBody, Vars: []Var{{"KEY", key}}}
	remove := Script{Name: "authorized-keys-remove", Body: authorizedKeysRemoveBody, Vars: []Var{{"KEY", key}}}

	for range 2 {
		if r := runLocally(t, add, "", "HOME="+home); r.code != 0 {
			t.Fatalf("add: exit %d, %s", r.code, r.stderr)
		}
	}
	got, _ := os.ReadFile(file)
	if want := "ssh-ed25519 AAAAexisting someone@laptop\n" + key + "\n"; string(got) != want {
		t.Fatalf("after adding twice:\n%q\nwant\n%q", got, want)
	}
	if r := runLocally(t, remove, "", "HOME="+home); r.code != 0 {
		t.Fatalf("remove: exit %d, %s", r.code, r.stderr)
	}
	got, _ = os.ReadFile(file)
	if want := "ssh-ed25519 AAAAexisting someone@laptop\n"; string(got) != want {
		t.Fatalf("after removing:\n%q\nwant\n%q", got, want)
	}
}

func TestKeyLoginScripts(t *testing.T) {
	requireSh(t)
	// The stand-in sshd rejects a config containing the word in $STUB/reject, and reports
	// passwords off only when the drop-in exists and no "other file" overrides it.
	const sshdStub = `
case "$1" in
-t)
  if [ -f "$STUB/reject" ] && grep -q "$(cat "$STUB/reject")" "$STUB/dropin.conf" 2>/dev/null; then
    echo "Bad configuration option" >&2
    exit 255
  fi ;;
-T)
  if [ -f "$STUB/dropin.conf" ] && [ ! -f "$STUB/other-wins" ]; then
    echo "passwordauthentication no"
  else
    echo "passwordauthentication yes"
  fi ;;
esac
`
	tests := []struct {
		name       string
		reject     string
		otherWins  bool
		wantResult string
		wantDropIn string
		wantReload bool
	}{
		{name: "current sshd", wantResult: "applied", wantDropIn: "KbdInteractiveAuthentication no", wantReload: true},
		{name: "sshd too old for KbdInteractiveAuthentication", reject: "KbdInteractive", wantResult: "applied",
			wantDropIn: "ChallengeResponseAuthentication no", wantReload: true},
		{name: "sshd rejects the file", reject: "PasswordAuthentication", wantResult: "invalid"},
		{name: "another file keeps passwords on", otherWins: true, wantResult: "still-on"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := t.TempDir()
			writeStub(t, stub, "sshd", sshdStub)
			writeStub(t, stub, "systemctl", `echo "$*" >> "$STUB/systemctl.log"`+"\n")
			if tt.reject != "" {
				os.WriteFile(filepath.Join(stub, "reject"), []byte(tt.reject), 0o644)
			}
			if tt.otherWins {
				os.WriteFile(filepath.Join(stub, "other-wins"), nil, 0o644)
			}
			dropIn := filepath.Join(stub, "dropin.conf")
			vars := []Var{{"DROPIN", dropIn}}

			r := runLocally(t, Script{Name: "keylogin-apply", Body: keyLoginApplyBody, Vars: vars}, stub)
			if r.code != 0 || r.value("result") != tt.wantResult {
				t.Fatalf("exit %d, stdout %q, stderr %q; want result=%s", r.code, r.stdout, r.stderr, tt.wantResult)
			}
			content, err := os.ReadFile(dropIn)
			if tt.wantDropIn == "" {
				if !os.IsNotExist(err) {
					t.Fatalf("drop-in left behind after %s: %q", tt.wantResult, content)
				}
			} else if !strings.Contains(string(content), "\nPasswordAuthentication no\n"+tt.wantDropIn+"\n") {
				t.Fatalf("drop-in = %q, want PasswordAuthentication no and %s", content, tt.wantDropIn)
			}
			log, _ := os.ReadFile(filepath.Join(stub, "systemctl.log"))
			if reloaded := string(log) == "reload ssh.service\n"; reloaded != tt.wantReload {
				t.Fatalf("systemctl calls = %q, want reload: %v", log, tt.wantReload)
			}
			if tt.wantResult != "applied" {
				return
			}

			back := runLocally(t, Script{Name: "keylogin-rollback", Body: keyLoginRollbackBody, Vars: vars}, stub)
			if back.code != 0 || back.value("result") != "rolled-back" {
				t.Fatalf("rollback: exit %d, stdout %q, stderr %q", back.code, back.stdout, back.stderr)
			}
			if _, err := os.Stat(dropIn); !os.IsNotExist(err) {
				t.Fatal("rollback left the drop-in in place")
			}
			log, _ = os.ReadFile(filepath.Join(stub, "systemctl.log"))
			if string(log) != "reload ssh.service\nreload ssh.service\n" {
				t.Fatalf("systemctl calls after rollback = %q, want a second reload", log)
			}
		})
	}
}
