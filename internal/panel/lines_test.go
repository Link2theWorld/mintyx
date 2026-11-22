package panel

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestLineValidation(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	with := func(mod func(m map[string]any)) map[string]any {
		m := realityLine("tokyo", 443)
		mod(m)
		return m
	}
	params := func(m map[string]any) map[string]any { return m["reality"].(map[string]any) }
	for _, tc := range []struct {
		name  string
		body  map[string]any
		field string
	}{
		{"empty name", with(func(m map[string]any) { m["name"] = "  " }), "name"},
		{"port zero", with(func(m map[string]any) { m["port"] = 0 }), "port"},
		{"port too high", with(func(m map[string]any) { m["port"] = 65536 }), "port"},
		{"reserved port", with(func(m map[string]any) { m["port"] = 2096 }), "port"},
		{"port not a number", with(func(m map[string]any) { m["port"] = "443" }), "port"},
		{"unknown protocol", with(func(m map[string]any) { m["protocol"] = "vmess" }), "protocol"},
		{"missing params block", with(func(m map[string]any) { delete(m, "reality") }), "reality"},
		{"reality without server name", with(func(m map[string]any) { params(m)["serverName"] = "" }), "reality.serverName"},
		{"reality target without port", with(func(m map[string]any) { params(m)["target"] = "www.example.com" }), "reality.target"},
		{"reality bad short id", with(func(m map[string]any) { params(m)["shortId"] = "xyz" }), "reality.shortId"},
		{"reality public key without private", with(func(m map[string]any) { params(m)["publicKey"] = "abc" }), "reality.publicKey"},
		{"bad host", with(func(m map[string]any) { m["host"] = "a b" }), "host"},
		{"xhttp tls without cert", map[string]any{"name": "x", "protocol": "vless-xhttp", "port": 8443,
			"xhttp": map[string]any{"path": "/p", "domain": "cdn.example.com", "security": "tls", "keyFile": "/k"}}, "xhttp.certFile"},
		{"xhttp without domain", map[string]any{"name": "x", "protocol": "vless-xhttp", "port": 8443,
			"xhttp": map[string]any{"path": "/p", "security": "none"}}, "xhttp.domain"},
		{"xhttp bad security", map[string]any{"name": "x", "protocol": "vless-xhttp", "port": 8443,
			"xhttp": map[string]any{"path": "/p", "domain": "cdn.example.com", "security": "ssl"}}, "xhttp.security"},
		{"hysteria2 without key file", map[string]any{"name": "h", "protocol": "hysteria2", "port": 8443,
			"hysteria2": map[string]any{"domain": "h.example.com", "certFile": "/c"}}, "hysteria2.keyFile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.do("POST", "/api/lines", tc.body, withCookie(c))
			expectError(t, w, http.StatusBadRequest, codeInvalid, tc.field)
		})
	}
	if lines, _ := f.st.ListLines(t.Context()); len(lines) != 0 {
		t.Fatalf("invalid requests stored %d lines", len(lines))
	}
	if n := f.eng.syncCount(); n != 0 {
		t.Fatalf("invalid requests synced %d times", n)
	}
}

func TestLineDuplicatePortConflict(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	expectStatus(t, f.do("POST", "/api/lines", realityLine("a", 443), withCookie(c)), http.StatusCreated)
	w := f.do("POST", "/api/lines", realityLine("b", 443), withCookie(c))
	expectError(t, w, http.StatusConflict, codeConflict, "port")
}

func TestRealityPrivateKeyHiddenAndPreserved(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	w := f.do("POST", "/api/lines", realityLine("tokyo", 443), withCookie(c))
	expectStatus(t, w, http.StatusCreated)
	if strings.Contains(w.Body.String(), "PRIVATEKEY") {
		t.Fatalf("create response leaks the private key: %s", w.Body)
	}
	created := decodeBody[lineDTO](t, w)
	if created.Reality == nil || created.Reality.PublicKey != "pub1" {
		t.Fatalf("created reality = %+v, want generated public key pub1", created.Reality)
	}
	if created.XHTTP != nil || created.Hysteria2 != nil {
		t.Fatal("response carries params blocks for other protocols")
	}

	w = f.do("GET", "/api/lines", nil, withCookie(c))
	if strings.Contains(w.Body.String(), "PRIVATEKEY") || strings.Contains(w.Body.String(), "rivate") {
		t.Fatalf("list leaks the private key: %s", w.Body)
	}

	upd := realityLine("tokyo renamed", 443)
	upd["reality"].(map[string]any)["publicKey"] = "pub1"
	path := "/api/lines/" + itoa(created.ID)
	w = f.do("PUT", path, upd, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), "PRIVATEKEY") {
		t.Fatalf("update response leaks the private key: %s", w.Body)
	}
	stored, err := f.st.GetLine(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Name != "tokyo renamed" || stored.Reality.PrivateKey != "PRIVATEKEY1" || stored.Reality.PublicKey != "pub1" {
		t.Fatalf("after update stored = %q %+v, want renamed with key pair 1 kept", stored.Name, *stored.Reality)
	}

	upd["reality"].(map[string]any)["publicKey"] = "someone-elses-key"
	expectError(t, f.do("PUT", path, upd, withCookie(c)), http.StatusBadRequest, codeInvalid, "reality.publicKey")

	upd["reality"].(map[string]any)["publicKey"] = ""
	expectStatus(t, f.do("PUT", path, upd, withCookie(c)), http.StatusOK)
	stored, _ = f.st.GetLine(t.Context(), created.ID)
	if stored.Reality.PrivateKey != "PRIVATEKEY2" || stored.Reality.PublicKey != "pub2" {
		t.Fatalf("empty public key should regenerate the pair, got %+v", *stored.Reality)
	}
}

func TestLineUpdateCannotChangeProtocol(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	created := decodeBody[lineDTO](t, f.do("POST", "/api/lines", realityLine("a", 443), withCookie(c)))
	w := f.do("PUT", "/api/lines/"+itoa(created.ID), map[string]any{"name": "a", "protocol": "hysteria2", "port": 443,
		"hysteria2": map[string]any{"certFile": "/c", "keyFile": "/k"}}, withCookie(c))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "protocol")
}

func TestLineUpdateKeepsEnabledWhenOmitted(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	body := realityLine("a", 443)
	body["enabled"] = false
	created := decodeBody[lineDTO](t, f.do("POST", "/api/lines", body, withCookie(c)))
	delete(body, "enabled")
	body["reality"].(map[string]any)["publicKey"] = created.Reality.PublicKey
	expectStatus(t, f.do("PUT", "/api/lines/"+itoa(created.ID), body, withCookie(c)), http.StatusOK)
	if l, _ := f.st.GetLine(t.Context(), created.ID); l.Enabled {
		t.Fatal("PUT without enabled re-enabled the line")
	}
}

func TestLineDraftSuggestsFreePort(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	expectStatus(t, f.do("POST", "/api/lines", realityLine("a", 443), withCookie(c)), http.StatusCreated)

	w := f.do("POST", "/api/lines/draft", map[string]string{"protocol": "vless-reality"}, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	d := decodeBody[map[string]any](t, w)
	if _, has := d["id"]; has {
		t.Fatalf("draft has an id: %s", w.Body)
	}
	if d["port"] != float64(8443) {
		t.Fatalf("draft port = %v, want 8443 (443 is taken)", d["port"])
	}
	r := d["reality"].(map[string]any)
	if r["publicKey"] != "" || r["shortId"] == "" {
		t.Fatalf("draft reality = %v, want empty publicKey and a generated short id", r)
	}
	if r["serverName"] != "www.campus.example" || r["target"] != "www.campus.example:443" {
		t.Fatalf("draft cover site = %v / %v, want the picked site and its port 443", r["serverName"], r["target"])
	}
	// The draft must save as-is.
	expectStatus(t, f.do("POST", "/api/lines", d, withCookie(c)), http.StatusCreated)

	expectError(t, f.do("POST", "/api/lines/draft", map[string]string{"protocol": "trojan"}, withCookie(c)),
		http.StatusBadRequest, codeInvalid, "protocol")
}

func TestLineDraftLeavesCoverSiteEmptyWhenNoneIsReachable(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.CoverSite = func(context.Context) string { return "" } })
	c := f.setup()
	w := f.do("POST", "/api/lines/draft", map[string]string{"protocol": "vless-reality"}, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	r := decodeBody[map[string]any](t, w)["reality"].(map[string]any)
	// A guessed site would be saved unchecked; an empty field makes the admin choose.
	if r["serverName"] != "" || r["target"] != "" {
		t.Fatalf("draft cover site = %v / %v, want both empty", r["serverName"], r["target"])
	}
}

func TestLineDeleteSyncsAndAudits(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	created := decodeBody[lineDTO](t, f.do("POST", "/api/lines", realityLine("gone", 443), withCookie(c)))
	expectStatus(t, f.do("DELETE", "/api/lines/"+itoa(created.ID), nil, withCookie(c)), http.StatusNoContent)
	if n := f.eng.syncCount(); n != 2 {
		t.Fatalf("syncs = %d, want 2 (create + delete)", n)
	}
	e, _ := f.st.ListAudit(t.Context(), 1, 0)
	if e[0].Action != "line.delete" || e[0].Target != "gone" {
		t.Fatalf("audit = %+v", e[0])
	}
	expectError(t, f.do("DELETE", "/api/lines/"+itoa(created.ID), nil, withCookie(c)), http.StatusNotFound, codeNotFound, "")
}
