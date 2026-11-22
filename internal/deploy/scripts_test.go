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
		"keylogin-rollback": keyLoginRollbackBody, "reset-password": resetPasswordBody,
		"sshd-settings": sshdSettingsBody,
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
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys mode %v after removing, want 600", fi.Mode().Perm())
	}

	// Removing the only line leaves grep nothing to print (exit 1), which is not an error.
	os.WriteFile(file, []byte(key+"\n"), 0o600)
	if r := runLocally(t, remove, "", "HOME="+home); r.code != 0 || r.value("key") != "removed" {
		t.Fatalf("remove the only key: exit %d, %s", r.code, r.stderr)
	}
	if got, _ := os.ReadFile(file); len(got) != 0 {
		t.Fatalf("after removing the only key: %q", got)
	}

	// A read error must fail the script and leave the file as it was, not empty it.
	if os.Geteuid() == 0 {
		return
	}
	const keep = "ssh-ed25519 AAAAexisting someone@laptop\n" + key + "\n"
	os.WriteFile(file, []byte(keep), 0o600)
	os.Chmod(file, 0o200)
	r := runLocally(t, remove, "", "HOME="+home)
	os.Chmod(file, 0o600)
	if r.code == 0 || r.value("key") == "removed" {
		t.Fatalf("unreadable authorized_keys: exit %d stdout %q, want a failure", r.code, r.stdout)
	}
	if got, _ := os.ReadFile(file); string(got) != keep {
		t.Fatalf("unreadable authorized_keys was changed to %q", got)
	}
	if left, _ := filepath.Glob(file + ".mintyx*"); len(left) != 0 {
		t.Errorf("temporary copies left behind: %v", left)
	}

	// A symlinked authorized_keys stays a link, and the key comes out of the file it points to.
	real := filepath.Join(t.TempDir(), "managed_keys")
	os.WriteFile(real, []byte(keep), 0o640)
	os.Remove(file)
	if err := os.Symlink(real, file); err != nil {
		t.Fatal(err)
	}
	if r := runLocally(t, remove, "", "HOME="+home); r.code != 0 {
		t.Fatalf("remove through a symlink: exit %d, %s", r.code, r.stderr)
	}
	if fi, err := os.Lstat(file); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("authorized_keys is no longer a symlink: %v %v", fi, err)
	}
	if got, _ := os.ReadFile(real); string(got) != "ssh-ed25519 AAAAexisting someone@laptop\n" {
		t.Fatalf("linked file after removing: %q", got)
	}
	if fi, _ := os.Stat(real); fi.Mode().Perm() != 0o640 {
		t.Errorf("linked file mode %v, want its own 640 kept", fi.Mode().Perm())
	}
	if left, _ := filepath.Glob(file + ".mintyx*"); len(left) != 0 {
		t.Errorf("temporary copies left behind: %v", left)
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

// A stand-in for the panel program's reset-password command, run through the real script.
func TestResetPasswordScript(t *testing.T) {
	requireSh(t)
	run := func(t *testing.T, panel string, withDB bool) localRun {
		t.Helper()
		dir := t.TempDir()
		bin := filepath.Join(dir, "mintyx")
		data := filepath.Join(dir, "data")
		if panel != "" {
			if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+panel), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.MkdirAll(data, 0o700); err != nil {
			t.Fatal(err)
		}
		if withDB {
			if err := os.WriteFile(filepath.Join(data, "mintyx.db"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return runLocally(t, Script{Name: "reset-password", Body: resetPasswordBody, Vars: []Var{{"BIN", bin}, {"DATA", data}}}, "")
	}

	t.Run("reports the new password", func(t *testing.T) {
		r := run(t, `[ "$1" = reset-password ] && [ "$2" = -data ] || exit 9
echo "The admin password was reset." >&2
printf 'username: admin\npassword: K7ZQ4M2XWQ3B6ZQ5RTEN4S7Y2A\n'
`, true)
		if r.code != 0 || r.value("user") != "admin" || r.value("password") != "K7ZQ4M2XWQ3B6ZQ5RTEN4S7Y2A" {
			t.Fatalf("got code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
		}
	})
	t.Run("a missing panel is not an error of the panel", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			panel  string
			withDB bool
		}{{"no program", "", true}, {"no database", "exit 0\n", false}} {
			if r := run(t, tc.panel, tc.withDB); r.code != 0 || r.value("problem") != "not-installed" {
				t.Errorf("%s: code %d, stdout %q", tc.name, r.code, r.stdout)
			}
		}
	})
	t.Run("a failing panel program fails the script with its message", func(t *testing.T) {
		r := run(t, "echo 'mintyx: the panel has no admin account yet' >&2\nexit 1\n", true)
		if r.code == 0 || r.value("password") != "" || !strings.Contains(r.stderr, "no admin account") {
			t.Fatalf("got code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
		}
	})
}

// A file whose last line has no newline is common (hand-edited, or written by a provider's
// console); appending straight onto it would glue both keys into one unusable line.
func TestAuthorizedKeysAddAfterAnUnterminatedLine(t *testing.T) {
	requireSh(t)
	const existing = "ssh-ed25519 AAAAexisting"
	const key = "ssh-ed25519 AAAAnew mintyx-deploy"
	add := Script{Name: "authorized-keys-add", Body: authorizedKeysAddBody, Vars: []Var{{"KEY", key}}}
	remove := Script{Name: "authorized-keys-remove", Body: authorizedKeysRemoveBody, Vars: []Var{{"KEY", key}}}
	for _, tc := range []struct{ name, before, added, removed string }{
		{"no trailing newline", existing, existing + "\n" + key + "\n", existing + "\n"},
		{"empty file", "", key + "\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			file := filepath.Join(home, ".ssh", "authorized_keys")
			os.Mkdir(filepath.Join(home, ".ssh"), 0o700)
			os.WriteFile(file, []byte(tc.before), 0o600)
			if r := runLocally(t, add, "", "HOME="+home); r.code != 0 {
				t.Fatalf("add: exit %d, %s", r.code, r.stderr)
			}
			if got, _ := os.ReadFile(file); string(got) != tc.added {
				t.Fatalf("after adding:\n%q\nwant\n%q", got, tc.added)
			}
			if r := runLocally(t, remove, "", "HOME="+home); r.code != 0 {
				t.Fatalf("remove: exit %d, %s", r.code, r.stderr)
			}
			if got, _ := os.ReadFile(file); string(got) != tc.removed {
				t.Fatalf("after removing:\n%q\nwant\n%q", got, tc.removed)
			}
		})
	}
}

func TestServiceScriptRestartsAProcessRunningAReplacedBinary(t *testing.T) {
	requireSh(t)
	const bin = "/usr/local/bin/mintyx"
	for _, tc := range []struct{ name, pid, exe, want string }{
		{"not running", "0", "", "started"},
		{"running the installed file", "4242", bin, "started"},
		// What Linux reports once the file a process was started from has been renamed over.
		{"running a replaced file", "4242", bin + " (deleted)", "restarted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stubs, proc := filepath.Join(dir, "bin"), filepath.Join(dir, "proc")
			os.MkdirAll(stubs, 0o755)
			os.MkdirAll(filepath.Join(proc, "4242"), 0o755)
			if tc.exe != "" {
				if err := os.Symlink(tc.exe, filepath.Join(proc, "4242", "exe")); err != nil {
					t.Skip("no symlinks here")
				}
			}
			writeStub(t, stubs, "systemctl", `if [ "$1" = show ]; then echo "MainPID=$STUB_PID"; else echo "$1" >> "$STUB/calls"; fi`+"\n")
			unitPath := filepath.Join(dir, "mintyx.service")
			os.WriteFile(unitPath, []byte(unitFile+"\n"), 0o644)
			s := Script{Name: "service", Body: serviceBody, Vars: []Var{
				{"DATA", filepath.Join(dir, "data")}, {"UNIT_PATH", unitPath}, {"UNIT", unitFile}, {"RESTART", "0"},
				{"BIN", bin}, {"PROC", proc},
			}}
			r := runLocally(t, s, stubs, "STUB_PID="+tc.pid)
			if r.code != 0 || r.value("service") != tc.want {
				t.Fatalf("exit %d, service=%q, want %q\n%s", r.code, r.value("service"), tc.want, r.stderr)
			}
			calls, _ := os.ReadFile(filepath.Join(stubs, "calls"))
			if want := "enable\n" + strings.TrimSuffix(tc.want, "ed") + "\n"; string(calls) != want {
				t.Fatalf("systemctl calls = %q, want %q", calls, want)
			}
		})
	}
}
