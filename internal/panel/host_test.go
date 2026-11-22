package panel

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ysuhao/mintyx-next/internal/hostcheck"
)

func TestHostSSH(t *testing.T) {
	const dump = "usepam yes\npermitrootlogin yes\npasswordauthentication yes\nkbdinteractiveauthentication no\n"
	for _, tc := range []struct {
		name string
		out  string
		err  error
		want string
	}{
		{"password login accepted", dump, nil, `{"passwordLogin":"on"}`},
		{"key only", strings.Replace(dump, "passwordauthentication yes", "passwordauthentication no", 1), nil, `{"passwordLogin":"off"}`},
		// sshd's own output must never reach the browser, even when it is all we have.
		{"sshd cannot run", "sshd: no hostkeys available -- exiting.", errors.New("exit status 1"), `{"passwordLogin":"unknown"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, func(c *Config) {
				c.HostCheck = hostcheck.New(func(context.Context) (string, error) { return tc.out, tc.err })
			})
			c := f.setup()
			w := f.do("GET", "/api/host/ssh", nil, withCookie(c))
			expectStatus(t, w, http.StatusOK)
			if got := strings.TrimSpace(w.Body.String()); got != tc.want {
				t.Errorf("body = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestHostSSHNeedsLogin(t *testing.T) {
	ran := false
	f := newFixture(t, func(c *Config) {
		c.HostCheck = hostcheck.New(func(context.Context) (string, error) { ran = true; return "", nil })
	})
	f.setup()
	expectError(t, f.do("GET", "/api/host/ssh", nil), http.StatusUnauthorized, codeUnauthorized, "")
	if ran {
		t.Error("sshd was inspected for an anonymous request")
	}
}
