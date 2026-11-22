package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ErrUploadCorrupt means the bytes that arrived on the server are not the bytes that were sent.
var ErrUploadCorrupt = errors.New("the uploaded file arrived damaged")

const (
	uploadTmpPrefix = "/tmp/mintyx-upload."
	// The file is written by the login user; a root script then checks and installs it.
	// A failed or interrupted write removes the file, since its name never reaches the deployer.
	cmdUpload = `umask 077; t=$(mktemp ` + uploadTmpPrefix + `XXXXXX) || exit 1; ` +
		`trap 'rm -f "$t"; exit 1' HUP INT TERM PIPE; ` +
		`if cat >"$t"; then echo "$t"; else rm -f "$t"; exit 1; fi`

	uploadMismatchExit = 3
)

// shSHA256 defines sha256_of for scripts; minimal images may lack one tool or another.
const shSHA256 = `
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else openssl dgst -sha256 -r "$1" | cut -d' ' -f1
  fi
}
`

const installFileBody = shSHA256 + `
trap 'rm -f "$SRC" "$DEST.new"' EXIT
if [ "$(sha256_of "$SRC")" != "$SHA256" ]; then
  echo "checksum=mismatch"
  exit 3
fi
mkdir -p "$(dirname "$DEST")"
# cp, not mv: the copy is created by root, so it is root-owned whoever uploaded it.
cp "$SRC" "$DEST.new"
chmod "$MODE" "$DEST.new"
# A rename swaps the file in one step and works while the old binary is running.
mv -f "$DEST.new" "$DEST"
echo "checksum=ok"
`

const fileSHA256Body = shSHA256 + `
if [ -f "$FILE" ]; then echo "sha256=$(sha256_of "$FILE")"; else echo "sha256="; fi
`

// Upload streams data to a temporary file, has the server verify its SHA-256, and only then
// moves it to dest (owned by root, with the given octal mode such as "0755").
func (c *Client) Upload(ctx context.Context, data io.Reader, dest, mode string) (err error) {
	if err := c.EnsureRoot(ctx); err != nil {
		return err
	}
	sum := sha256.New()
	out, err := c.run(ctx, "upload", cmdUpload, io.TeeReader(data, sum))
	tmp := strings.TrimSpace(out.Stdout)
	valid := strings.HasPrefix(tmp, uploadTmpPrefix) && !strings.ContainsAny(tmp, " \n'\"")
	if valid {
		// The install script removes the file once it runs; this covers every failure before
		// that, such as sudo refusing or the data source failing after the server saved a copy.
		defer func() {
			if err != nil {
				c.removeUpload(ctx, tmp)
			}
		}()
	}
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("upload: unexpected temporary file name %q", tmp)
	}
	_, err = c.RunRoot(ctx, Script{Name: "install-file", Body: installFileBody, Vars: []Var{
		{"SRC", tmp}, {"DEST", dest}, {"SHA256", hex.EncodeToString(sum.Sum(nil))}, {"MODE", mode},
	}})
	var exit *ExitError
	if errors.As(err, &exit) && exit.Code == uploadMismatchExit {
		return ErrUploadCorrupt
	}
	return err
}

// removeUpload deletes a temporary upload as the login user who wrote it. It is best effort:
// on a dead connection there is nothing more to do, and /tmp is cleared eventually anyway.
func (c *Client) removeUpload(ctx context.Context, tmp string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_, _ = c.run(ctx, "upload cleanup", "rm -f '"+tmp+"'", nil)
}

// remoteSHA256 returns the hex digest of a file on the server, or "" when it does not exist.
func (c *Client) remoteSHA256(ctx context.Context, path string) (string, error) {
	out, err := c.RunRoot(ctx, Script{Name: "file-sha256", Body: fileSHA256Body, Vars: []Var{{"FILE", path}}})
	if err != nil {
		return "", err
	}
	return out.Values()["sha256"], nil
}
