package panel

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Link2theWorld/mintyx/internal/hostport"
	"github.com/Link2theWorld/mintyx/internal/model"
)

func TestValidHostnameShape(t *testing.T) {
	for _, h := range []string{
		"example.com",
		"a-b.example",
		"localhost",
		"xn--nxasmq6b.example",
		"1.example.com",
		strings.Repeat("a", 63) + ".example",
	} {
		if !validHostname(h) {
			t.Errorf("validHostname(%q) = false, want true", h)
		}
	}
	for _, h := range []string{
		"",
		".",
		".example.com",
		"example..com",
		"-bad.example",
		"bad-.example",
		"example.com.",
		"123",
		"123.456",
		"a.123",
		strings.Repeat("a", 64) + ".example",
	} {
		if validHostname(h) {
			t.Errorf("validHostname(%q) = true, want false", h)
		}
	}
	if validDialHost("123.456") {
		t.Error(`validDialHost("123.456") = true, want false`)
	}
	if !validDialHost("203.0.113.7") {
		t.Error(`validDialHost("203.0.113.7") = false, want true`)
	}
}

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
		{"reality malformed server name", with(func(m map[string]any) { params(m)["serverName"] = "-bad.example" }), "reality.serverName"},
		{"reality target without port", with(func(m map[string]any) { params(m)["target"] = "www.example.com" }), "reality.target"},
		{"reality bad short id", with(func(m map[string]any) { params(m)["shortId"] = "xyz" }), "reality.shortId"},
		{"reality public key without private", with(func(m map[string]any) { params(m)["publicKey"] = "abc" }), "reality.publicKey"},
		{"bad host", with(func(m map[string]any) { m["host"] = "a b" }), "host"},
		{"malformed numeric host", with(func(m map[string]any) { m["host"] = "123.456" }), "host"},
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
	expectStatus(t, f.do("POST", "/api/lines", xhttpLine("c", 8443), withCookie(c)), http.StatusCreated)
	expectError(t, f.do("POST", "/api/lines", xhttpLine("d", 8443), withCookie(c)), http.StatusConflict, codeConflict, "port")
}

func TestRealityLineIsOn443(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	expectError(t, f.do("POST", "/api/lines", realityLine("a", 8443), withCookie(c)), http.StatusBadRequest, codeInvalid, "port")
	created := decodeBody[lineDTO](t, f.do("POST", "/api/lines", realityLine("a", 443), withCookie(c)))
	if created.Port != 443 {
		t.Fatalf("created port = %d", created.Port)
	}
	body := realityLine("a", 2053)
	body["reality"].(map[string]any)["publicKey"] = created.Reality.PublicKey
	expectError(t, f.do("PUT", "/api/lines/"+itoa(created.ID), body, withCookie(c)), http.StatusBadRequest, codeInvalid, "port")

	// A line saved on another port before REALITY was pinned to 443 keeps working and may move to 443.
	old := model.Line{Name: "old", Protocol: model.VLESSReality, Port: 8443, Enabled: true,
		Reality: &model.RealityParams{PrivateKey: "K", PublicKey: "P", ShortID: "ab", ServerName: "www.example.com", Target: "www.example.com:443"}}
	if err := f.st.CreateLine(t.Context(), &old); err != nil {
		t.Fatal(err)
	}
	body = realityLine("old renamed", 8443)
	body["reality"].(map[string]any)["publicKey"] = "P"
	expectStatus(t, f.do("PUT", "/api/lines/"+itoa(old.ID), body, withCookie(c)), http.StatusOK)
	body["port"] = 9443
	expectError(t, f.do("PUT", "/api/lines/"+itoa(old.ID), body, withCookie(c)), http.StatusBadRequest, codeInvalid, "port")
}

func TestRealityLineFreesPort443(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	f.ports.stopped = []hostport.Stopped{{Unit: "nginx.service", Name: "nginx"}, {PID: 812, Name: "python3"}}

	syncs := f.eng.syncCount()
	w := f.do("POST", "/api/lines", realityLine("tokyo", 443), withCookie(c))
	expectStatus(t, w, http.StatusCreated)
	calls := f.ports.callsMade()
	if len(calls) != 1 || calls[0].port != 443 {
		t.Fatalf("FreeTCP calls = %+v, want one for 443", calls)
	}
	// The panel's own Xray (pid 42 in the fake engine) is never stopped, and the port is
	// freed before Xray is given the new line, so it can bind.
	if !slices.Equal(calls[0].keep, []int{42}) || calls[0].syncs != syncs {
		t.Fatalf("FreeTCP call = %+v, want keep [42] before the sync", calls[0])
	}
	if f.eng.syncCount() != syncs+1 {
		t.Fatalf("syncs = %d, want one after freeing the port", f.eng.syncCount()-syncs)
	}
	e, _ := f.st.ListAudit(t.Context(), 2, 0)
	if e[1].Action != "port.free" || e[1].Target != "443/tcp" || e[1].Detail != "nginx.service, python3 (pid 812)" {
		t.Fatalf("audit = %+v, want what was stopped on 443/tcp", e[1])
	}
	if e[0].Action != "line.create" {
		t.Fatalf("latest audit = %+v, want the line", e[0])
	}

	// Nothing to free for another protocol or a disabled REALITY line.
	first := decodeBody[lineDTO](t, w)
	expectStatus(t, f.do("POST", "/api/lines", xhttpLine("cdn", 8443), withCookie(c)), http.StatusCreated)
	expectStatus(t, f.do("DELETE", "/api/lines/"+itoa(first.ID), nil, withCookie(c)), http.StatusNoContent)
	body := realityLine("later", 443)
	body["enabled"] = false
	later := decodeBody[lineDTO](t, f.do("POST", "/api/lines", body, withCookie(c)))
	if n := len(f.ports.callsMade()); n != 1 {
		t.Fatalf("FreeTCP calls = %d, want none for an XHTTP or a disabled REALITY line", n)
	}
	// Switching it on is when 443 is needed.
	body["enabled"] = true
	body["reality"].(map[string]any)["publicKey"] = later.Reality.PublicKey
	expectStatus(t, f.do("PUT", "/api/lines/"+itoa(later.ID), body, withCookie(c)), http.StatusOK)
	if n := len(f.ports.callsMade()); n != 2 {
		t.Fatalf("FreeTCP calls = %d, want one more when the line is switched on", n)
	}
}

func TestRealityLineRefusedWhen443CannotBeFreed(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	f.ports.err = &hostport.RefusedError{Port: 443, Holder: hostport.Process{PID: 700, Name: "sshd", Unit: "ssh.service"}, Reason: "stopping SSH would lock you out of the server"}

	syncs := f.eng.syncCount()
	w := f.do("POST", "/api/lines", realityLine("tokyo", 443), withCookie(c))
	expectError(t, w, http.StatusConflict, codeConflict, "port")
	if !strings.Contains(w.Body.String(), "ssh.service") {
		t.Fatalf("error does not name the holder: %s", w.Body)
	}
	if lines, _ := f.st.ListLines(t.Context()); len(lines) != 0 {
		t.Fatalf("a line whose port is held was kept: %+v", lines)
	}
	if f.eng.syncCount() != syncs {
		t.Fatal("a line whose port is held was given to Xray")
	}

	// Switching an existing line on is taken back the same way.
	f.ports.err = nil
	body := realityLine("tokyo", 443)
	body["enabled"] = false
	created := decodeBody[lineDTO](t, f.do("POST", "/api/lines", body, withCookie(c)))
	f.ports.err = hostport.ErrStillHeld
	body["enabled"] = true
	body["reality"].(map[string]any)["publicKey"] = created.Reality.PublicKey
	expectError(t, f.do("PUT", "/api/lines/"+itoa(created.ID), body, withCookie(c)), http.StatusConflict, codeConflict, "port")
	if l, _ := f.st.GetLine(t.Context(), created.ID); l.Enabled {
		t.Fatal("the line stayed on although 443 is still held")
	}
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

func TestLineDraftSuggestsPortByProtocol(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	draftPort := func(protocol string) float64 {
		t.Helper()
		w := f.do("POST", "/api/lines/draft", map[string]string{"protocol": protocol}, withCookie(c))
		expectStatus(t, w, http.StatusOK)
		return decodeBody[map[string]any](t, w)["port"].(float64)
	}
	if p := draftPort("vless-reality"); p != 443 {
		t.Fatalf("REALITY draft port = %v, want 443", p)
	}
	// XHTTP never gets 443, which belongs to REALITY; it walks the CDN-friendly ports instead.
	if p := draftPort("vless-xhttp"); p != 8443 {
		t.Fatalf("first XHTTP draft port = %v, want 8443", p)
	}
	expectStatus(t, f.do("POST", "/api/lines", xhttpLine("cdn", 8443), withCookie(c)), http.StatusCreated)
	if p := draftPort("vless-xhttp"); p != 2053 {
		t.Fatalf("second XHTTP draft port = %v, want 2053", p)
	}
	expectStatus(t, f.do("POST", "/api/lines", realityLine("a", 443), withCookie(c)), http.StatusCreated)
	// Even with 443 taken, REALITY is drafted on 443; saving a second one is what fails.
	if p := draftPort("vless-reality"); p != 443 {
		t.Fatalf("REALITY draft port with 443 taken = %v, want 443", p)
	}
	if p := draftPort("hysteria2"); p == 443 || p == 8443 || p == 2053 || p == 2083 || p == 2087 || p == 2096 {
		t.Fatalf("Hysteria2 draft port = %v, want neither a taken port nor one kept for XHTTP", p)
	}
}

func TestLineDraftSuggestsFreePort(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()

	w := f.do("POST", "/api/lines/draft", map[string]string{"protocol": "vless-reality"}, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	d := decodeBody[map[string]any](t, w)
	if _, has := d["id"]; has {
		t.Fatalf("draft has an id: %s", w.Body)
	}
	if d["port"] != float64(443) {
		t.Fatalf("draft port = %v, want 443", d["port"])
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

func TestLineDraftPicksCoverSiteForRegion(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	w := f.do("POST", "/api/lines/draft", map[string]string{"protocol": "vless-reality", "region": "jp"}, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	r := decodeBody[map[string]any](t, w)["reality"].(map[string]any)
	if r["serverName"] != "www.jp.example" || r["target"] != "www.jp.example:443" {
		t.Fatalf("draft cover site = %v / %v, want the site picked for region jp", r["serverName"], r["target"])
	}

	for _, protocol := range []string{"vless-reality", "hysteria2"} {
		w = f.do("POST", "/api/lines/draft", map[string]string{"protocol": protocol, "region": "mars"}, withCookie(c))
		expectError(t, w, http.StatusBadRequest, codeInvalid, "region")
	}
}

func TestLineDraftLeavesCoverSiteEmptyWhenNoneIsReachable(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.CoverSite = func(context.Context, string) string { return "" } })
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
