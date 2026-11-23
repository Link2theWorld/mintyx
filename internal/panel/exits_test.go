package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testPubKey is RFC 7748 §6.1 Alice's public key in base64url.
const testPubKey = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"

const exitSecret = "b831381d-6324-4d53-ad4f-8cda48b30811"

func realityLink(host string, port int, name string) string {
	return fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=%s&sid=0123abcd&type=tcp#%s",
		exitSecret, host, port, testPubKey, name)
}

const ssLink = "ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA==@203.0.113.9:8388#Osaka"
const hy2Link = "hysteria2://hy-auth-secret@198.51.100.9:443/?sni=hy.example.com#Seoul"

func (f *fixture) createExit(c *http.Cookie, name, link string) exitDTO {
	f.t.Helper()
	w := f.do("POST", "/api/exits", map[string]any{"name": name, "region": "jp", "link": link}, withCookie(c))
	expectStatus(f.t, w, http.StatusCreated)
	return decodeBody[exitDTO](f.t, w)
}

func (f *fixture) createLineAt(c *http.Cookie, name string, port int) lineDTO {
	f.t.Helper()
	w := f.do("POST", "/api/lines", realityLine(name, port), withCookie(c))
	expectStatus(f.t, w, http.StatusCreated)
	return decodeBody[lineDTO](f.t, w)
}

func TestExitCreateParsesAndHidesSecrets(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()

	w := f.do("POST", "/api/exits/parse", map[string]any{"link": realityLink("203.0.113.7", 443, "Tokyo")}, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	if body := w.Body.String(); !strings.Contains(body, `"name":"Tokyo"`) || !strings.Contains(body, `"security":"reality"`) || strings.Contains(body, exitSecret) {
		t.Fatalf("parse preview = %s", body)
	}

	syncs := f.eng.syncCount()
	w = f.do("POST", "/api/exits", map[string]any{"name": "", "region": "jp", "link": realityLink("203.0.113.7", 443, "Tokyo")}, withCookie(c))
	expectStatus(t, w, http.StatusCreated)
	if body := w.Body.String(); strings.Contains(body, exitSecret) || strings.Contains(body, testPubKey) {
		t.Fatalf("create response leaks a credential: %s", body)
	}
	e := decodeBody[exitDTO](t, w)
	if e.Name != "Tokyo" || e.Region != "jp" || e.NextID != nil || e.Summary.Host != "203.0.113.7" || e.Summary.Flow != "xtls-rprx-vision" {
		t.Fatalf("created exit = %+v", e)
	}
	if f.eng.syncCount() != syncs {
		t.Error("creating an unwired exit restarted the engine")
	}
	list := f.do("GET", "/api/exits", nil, withCookie(c)).Body.String()
	if strings.Contains(list, exitSecret) || !strings.Contains(list, `"Tokyo"`) {
		t.Fatalf("list = %s", list)
	}

	for _, tc := range []struct {
		body  map[string]any
		field string
	}{
		{map[string]any{"name": "x", "link": ""}, "link"},
		{map[string]any{"name": "x", "region": "mars", "link": ssLink}, "region"},
		{map[string]any{"name": "x", "link": "vmess://abc"}, "link.scheme"},
		{map[string]any{"name": "x", "link": strings.Replace(realityLink("203.0.113.7", 443, "x"), "pbk="+testPubKey, "pbk=short", 1)}, "link.pbk"},
	} {
		expectError(t, f.do("POST", "/api/exits", tc.body, withCookie(c)), http.StatusBadRequest, codeInvalid, tc.field)
	}
	expectError(t, f.do("POST", "/api/exits", map[string]any{"name": "Tokyo", "link": ssLink}, withCookie(c)), http.StatusConflict, codeConflict, "name")
}

func TestExitLinkToOwnLineIsRefused(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	f.createLineAt(c, "own", 443)
	// The fixture's requests arrive for panel.test, the host share links use when publicHost is empty.
	w := f.do("POST", "/api/exits", map[string]any{"name": "loop", "link": realityLink(testHost, 443, "loop")}, withCookie(c))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "link")
	client := f.createClient(c, "friend", 0)
	got, _ := f.st.GetClient(t.Context(), client.ID)
	w = f.do("POST", "/api/exits", map[string]any{"name": "secret", "link": strings.Replace(realityLink("203.0.113.7", 443, "x"), exitSecret, got.Secret, 1)}, withCookie(c))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "link")
}

// The self-loop check must recognise the same IP however it is spelt: share-link parsing
// canonicalises the exit's address, while a line or publicHost keeps the spelling the admin typed.
func TestExitLinkToOwnLineIsRefusedAcrossIPSpellings(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()

	v6 := realityLine("own-v6", 443)
	v6["host"] = "2001:0DB8:0000:0000:0000:0000:0000:0001"
	expectStatus(t, f.do("POST", "/api/lines", v6, withCookie(c)), http.StatusCreated)
	w := f.do("POST", "/api/exits", map[string]any{"name": "loop-v6", "link": realityLink("[2001:db8::1]", 443, "loop-v6")}, withCookie(c))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "link")

	v4 := realityLine("own-v4", 8443)
	v4["host"] = "203.0.113.7"
	expectStatus(t, f.do("POST", "/api/lines", v4, withCookie(c)), http.StatusCreated)
	w = f.do("POST", "/api/exits", map[string]any{"name": "loop-mapped", "link": realityLink("[::ffff:203.0.113.7]", 8443, "loop-mapped")}, withCookie(c))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "link")

	expectStatus(t, f.do("PUT", "/api/settings", map[string]any{"publicHost": "[2001:0DB8::a]", "subscriptionBaseUrl": ""}, withCookie(c)), http.StatusOK)
	f.createLineAt(c, "own-pub", 2053)
	w = f.do("POST", "/api/exits", map[string]any{"name": "loop-pub", "link": realityLink("[2001:db8::a]", 2053, "loop-pub")}, withCookie(c))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "link")

	// A different IP on the same port is not a self-loop.
	w = f.do("POST", "/api/exits", map[string]any{"name": "other-v6", "link": realityLink("[2001:db8::2]", 443, "other-v6")}, withCookie(c))
	expectStatus(t, w, http.StatusCreated)
}

func TestRoutingWiresLinesThroughExitsWithOneSync(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	line := f.createLineAt(c, "entry", 443)
	a := f.createExit(c, "A", realityLink("203.0.113.7", 443, "A"))
	b := f.createExit(c, "B", ssLink)

	syncs := f.eng.syncCount()
	w := f.do("PUT", "/api/routing", map[string]any{
		"lines": []any{map[string]any{"id": line.ID, "exitId": a.ID}},
		"exits": []any{map[string]any{"id": a.ID, "nextId": b.ID}},
	}, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	if got := f.eng.syncCount() - syncs; got != 1 {
		t.Fatalf("PUT /api/routing synced %d times, want 1", got)
	}
	routing := decodeBody[routingDTO](t, w)
	if derefID(routing.Lines[0].ExitID) != a.ID || derefID(routing.Exits[0].NextID) != b.ID || routing.Exits[1].NextID != nil {
		t.Fatalf("routing = %+v", routing)
	}

	// Editing the line through its own endpoint keeps the wiring.
	body := realityLine("renamed", 443)
	expectStatus(t, f.do("PUT", fmt.Sprintf("/api/lines/%d", line.ID), body, withCookie(c)), http.StatusOK)
	lines := decodeBody[struct{ Lines []lineDTO }](t, f.do("GET", "/api/lines", nil, withCookie(c)))
	if derefID(lines.Lines[0].ExitID) != a.ID {
		t.Fatalf("line exit after an edit = %v, want %d", lines.Lines[0].ExitID, a.ID)
	}

	w = f.do("PUT", "/api/routing", map[string]any{"exits": []any{map[string]any{"id": b.ID, "nextId": a.ID}}}, withCookie(c))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "exits[0].nextId")
	if !strings.Contains(w.Body.String(), "loop") {
		t.Fatalf("loop error = %s", w.Body.String())
	}
	for _, bad := range []map[string]any{
		{"lines": []any{map[string]any{"id": 999, "exitId": nil}}},
		{"lines": []any{map[string]any{"id": line.ID, "exitId": 999}}},
		{"exits": []any{map[string]any{"id": a.ID, "nextId": nil}, map[string]any{"id": a.ID, "nextId": nil}}},
	} {
		expectStatus(t, f.do("PUT", "/api/routing", bad, withCookie(c)), http.StatusBadRequest)
	}

	w = f.do("PUT", "/api/routing", map[string]any{"lines": []any{map[string]any{"id": line.ID, "exitId": nil}}}, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	if decodeBody[routingDTO](t, w).Lines[0].ExitID != nil {
		t.Fatal("null did not send the line straight out")
	}
	entries, _ := f.st.ListAudit(t.Context(), 20, 0)
	routingAudits := 0
	for _, e := range entries {
		if e.Action == "routing.update" {
			routingAudits++
			if strings.Contains(e.Detail, exitSecret) {
				t.Fatalf("audit leaks a secret: %+v", e)
			}
		}
	}
	if routingAudits != 2 {
		t.Fatalf("routing audits = %d, want 2", routingAudits)
	}
}

func TestDeleteExitInUseNeedsUnlink(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	line := f.createLineAt(c, "entry", 443)
	a := f.createExit(c, "A", ssLink)
	expectStatus(t, f.do("PUT", "/api/routing", map[string]any{"lines": []any{map[string]any{"id": line.ID, "exitId": a.ID}}}, withCookie(c)), http.StatusOK)

	w := f.do("DELETE", fmt.Sprintf("/api/exits/%d", a.ID), nil, withCookie(c))
	expectError(t, w, http.StatusConflict, codeConflict, "exit")
	if !strings.Contains(w.Body.String(), "line entry") {
		t.Fatalf("409 body = %s, want it to name the line", w.Body.String())
	}
	expectStatus(t, f.do("DELETE", fmt.Sprintf("/api/exits/%d?unlink=1", a.ID), nil, withCookie(c)), http.StatusNoContent)
	if l, _ := f.st.GetLine(t.Context(), line.ID); l.ExitID != 0 {
		t.Fatalf("line still points at the deleted exit: %d", l.ExitID)
	}
}

func TestExitLatency(t *testing.T) {
	var mu sync.Mutex
	dialled := map[string]int{}
	f := newFixture(t, func(cfg *Config) {
		cfg.ExitRTT = func(_ context.Context, host string, _ int) (time.Duration, error) {
			mu.Lock()
			defer mu.Unlock()
			dialled[host]++
			if host == "203.0.113.9" {
				return 0, errors.New("connection refused")
			}
			return 42 * time.Millisecond, nil
		}
	})
	c := f.setup()
	line := f.createLineAt(c, "entry", 443)
	a := f.createExit(c, "A", realityLink("203.0.113.7", 443, "A"))
	b := f.createExit(c, "B", ssLink)
	h := f.createExit(c, "H", hy2Link)
	inner := f.createExit(c, "Inner", realityLink("203.0.113.50", 443, "Inner"))
	expectStatus(t, f.do("PUT", "/api/routing", map[string]any{
		"lines": []any{map[string]any{"id": line.ID, "exitId": a.ID}},
		"exits": []any{map[string]any{"id": a.ID, "nextId": inner.ID}},
	}, withCookie(c)), http.StatusOK)

	type latency struct {
		Refreshing bool             `json:"refreshing"`
		Exits      []exitLatencyDTO `json:"exits"`
	}
	var got latency
	deadline := time.Now().Add(5 * time.Second)
	for {
		got = decodeBody[latency](t, f.do("GET", "/api/exits/latency", nil, withCookie(c)))
		if !got.Refreshing && got.Exits[0].MeasuredAt != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("latency never settled: %+v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	byID := map[int64]exitLatencyDTO{}
	for _, e := range got.Exits {
		byID[e.ID] = e
	}
	if e := byID[a.ID]; e.RTTMs == nil || *e.RTTMs != 42 {
		t.Errorf("A = %+v, want 42 ms", e)
	}
	if e := byID[b.ID]; e.RTTMs != nil || !strings.Contains(e.Error, "refused") {
		t.Errorf("B = %+v, want the dial error", e)
	}
	if e := byID[h.ID]; e.Unmeasured != "udp" {
		t.Errorf("Hysteria2 = %+v, want unmeasured udp", e)
	}
	if e := byID[inner.ID]; e.Unmeasured != "inner" {
		t.Errorf("inner hop = %+v, want unmeasured inner", e)
	}
	mu.Lock()
	if dialled["198.51.100.9"] != 0 || dialled["203.0.113.50"] != 0 {
		t.Errorf("dialled exits that must not be: %v", dialled)
	}
	mu.Unlock()

	expectStatus(t, f.do("POST", "/api/exits/latency", nil, withCookie(c)), http.StatusOK)
	expectError(t, f.do("POST", "/api/exits/latency", nil, withCookie(c)), http.StatusTooManyRequests, codeRateLimited, "")
}

func TestGraphLayoutAndServerRegion(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	w := f.do("PUT", "/api/graph/layout", map[string]any{"positions": map[string]any{"line-1": map[string]any{"x": 10.5, "y": -3}}}, withCookie(c))
	expectStatus(t, w, http.StatusNoContent)
	if body := f.do("GET", "/api/graph/layout", nil, withCookie(c)).Body.String(); !strings.Contains(body, `"line-1":{"x":10.5,"y":-3}`) {
		t.Fatalf("layout = %s", body)
	}

	if got := decodeBody[settingsDTO](t, f.do("GET", "/api/settings", nil, withCookie(c))); got.ServerRegion != "" {
		t.Fatalf("default server region = %q", got.ServerRegion)
	}
	expectError(t, f.do("PUT", "/api/settings", map[string]any{"publicHost": "", "subscriptionBaseUrl": "", "serverRegion": "mars"}, withCookie(c)),
		http.StatusBadRequest, codeInvalid, "serverRegion")
	expectStatus(t, f.do("PUT", "/api/settings", map[string]any{"publicHost": "", "subscriptionBaseUrl": "", "serverRegion": "kr"}, withCookie(c)), http.StatusOK)
	w = f.do("POST", "/api/lines/draft", map[string]any{"protocol": "vless-reality"}, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "www.kr.example") {
		t.Fatalf("draft without a region = %s, want the server region's cover site", w.Body.String())
	}
}

func TestCopyExitKeepsCredentialsAndStartsUnwired(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	a := f.createExit(c, "A", realityLink("203.0.113.7", 443, "A"))
	w := f.do("POST", fmt.Sprintf("/api/exits/%d/copy", a.ID), nil, withCookie(c))
	expectStatus(t, w, http.StatusCreated)
	cp := decodeBody[exitDTO](t, w)
	if cp.Name != "A (2)" || cp.ID == a.ID || cp.NextID != nil || cp.Summary != a.Summary {
		t.Fatalf("copy = %+v, want an unwired A (2) with the same summary", cp)
	}
	orig, _ := f.st.GetExit(t.Context(), a.ID)
	got, _ := f.st.GetExit(t.Context(), cp.ID)
	if got.Params.Secret != orig.Params.Secret || got.Params.Reality.PublicKey != orig.Params.Reality.PublicKey {
		t.Fatal("the copy lost the credentials")
	}
	if again := decodeBody[exitDTO](t, f.do("POST", fmt.Sprintf("/api/exits/%d/copy", a.ID), nil, withCookie(c))); again.Name != "A (3)" {
		t.Fatalf("second copy = %q, want A (3)", again.Name)
	}
}

// A name already at the length limit must still get a free copy name, not a loop that holds s.mu.
func TestCopyExitWithAMaxLengthName(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	long := strings.Repeat("长", maxNameRunes)
	a := f.createExit(c, long, ssLink)
	for i, want := range []string{strings.Repeat("长", maxNameRunes-4) + " (2)", strings.Repeat("长", maxNameRunes-4) + " (3)"} {
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- f.do("POST", fmt.Sprintf("/api/exits/%d/copy", a.ID), nil, withCookie(c)) }()
		select {
		case w := <-done:
			expectStatus(t, w, http.StatusCreated)
			if got := decodeBody[exitDTO](t, w).Name; got != want {
				t.Fatalf("copy %d name = %q, want %q", i+1, got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("copying an exit with a 64-character name never returned")
		}
	}
}

func TestGraphLayoutNullIsEmpty(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	expectStatus(t, f.do("PUT", "/api/graph/layout", map[string]any{"positions": nil}, withCookie(c)), http.StatusNoContent)
	if body := strings.TrimSpace(f.do("GET", "/api/graph/layout", nil, withCookie(c)).Body.String()); body != `{"positions":{}}` {
		t.Fatalf("layout after a null PUT = %s, want an empty object", body)
	}
}

// Wiring or a link Xray refuses must not stay in the store: at the next start it would stop
// every line, not just the one being changed.
func TestXrayRefusalRollsBackWiringAndLinks(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	line := f.createLineAt(c, "entry", 443)
	a := f.createExit(c, "A", realityLink("203.0.113.7", 443, "A"))
	b := f.createExit(c, "B", ssLink)

	f.eng.refuseWhen(func(ctx context.Context) (string, bool) {
		e, _ := f.st.GetExit(ctx, a.ID)
		return "invalid key", e.NextID != 0
	})
	w := f.do("PUT", "/api/routing", map[string]any{
		"lines": []any{map[string]any{"id": line.ID, "exitId": a.ID}},
		"exits": []any{map[string]any{"id": a.ID, "nextId": b.ID}},
	}, withCookie(c))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "routing")
	if l, _ := f.st.GetLine(t.Context(), line.ID); l.ExitID != 0 {
		t.Fatalf("refused wiring stayed: line exit %d", l.ExitID)
	}
	if e, _ := f.st.GetExit(t.Context(), a.ID); e.NextID != 0 {
		t.Fatalf("refused wiring stayed: A next %d", e.NextID)
	}

	expectStatus(t, f.do("PUT", "/api/routing", map[string]any{"lines": []any{map[string]any{"id": line.ID, "exitId": a.ID}}}, withCookie(c)), http.StatusOK)
	f.eng.refuseWhen(func(ctx context.Context) (string, bool) {
		e, _ := f.st.GetExit(ctx, a.ID)
		return "invalid encryption", e.Params.Host == "198.51.100.77"
	})
	w = f.do("PUT", fmt.Sprintf("/api/exits/%d", a.ID), map[string]any{"name": "A", "region": "jp", "link": realityLink("198.51.100.77", 443, "A")}, withCookie(c))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "link")
	if e, _ := f.st.GetExit(t.Context(), a.ID); e.Params.Host != "203.0.113.7" {
		t.Fatalf("refused link stayed: host %s", e.Params.Host)
	}

	// Other engine failures (Xray missing, failing to start) keep the saved change and say 502.
	f.eng.refuseWhen(nil)
	f.eng.failSync(errors.New("xray binary not found"))
	w = f.do("PUT", "/api/routing", map[string]any{"lines": []any{map[string]any{"id": line.ID, "exitId": nil}}}, withCookie(c))
	expectError(t, w, http.StatusBadGateway, codeEngine, "")
	if l, _ := f.st.GetLine(t.Context(), line.ID); l.ExitID != 0 {
		t.Fatal("a non-refusal engine failure rolled the wiring back")
	}
}

// When a link replacement is refused by Xray, the whole edit — link, name and region — is rolled
// back so the 400 "nothing was changed" response stays truthful, including when the name came from
// the refused link itself. A name/region-only edit (empty link) is kept; see TestEnablingALineXrayRefusesIsRolledBack.
func TestRefusedExitLinkRollbackUndoesWholeEdit(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	line := f.createLineAt(c, "entry", 443)
	a := f.createExit(c, "A", realityLink("203.0.113.7", 443, "A"))
	expectStatus(t, f.do("PUT", "/api/routing", map[string]any{"lines": []any{map[string]any{"id": line.ID, "exitId": a.ID}}}, withCookie(c)), http.StatusOK)

	f.eng.refuseWhen(func(ctx context.Context) (string, bool) {
		e, _ := f.st.GetExit(ctx, a.ID)
		return "invalid encryption", e.Params.Host == "198.51.100.77"
	})
	for _, body := range []map[string]any{
		{"name": "A renamed", "region": "kr", "link": realityLink("198.51.100.77", 443, "A renamed")},
		{"name": "", "region": "kr", "link": realityLink("198.51.100.77", 443, "FromBadLink")},
	} {
		w := f.do("PUT", fmt.Sprintf("/api/exits/%d", a.ID), body, withCookie(c))
		expectError(t, w, http.StatusBadRequest, codeInvalid, "link")
		e, err := f.st.GetExit(t.Context(), a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if e.Params.Host != "203.0.113.7" || e.Name != "A" || e.Region != "jp" {
			t.Fatalf("refused link replacement left partial changes: %+v; want host 203.0.113.7, name A, region jp", e)
		}
	}
}

// A disabled line may be wired to an exit without Xray seeing it; enabling the line later is
// where Xray refuses, and that change must not be kept either. A rename alone is kept.
func TestEnablingALineXrayRefusesIsRolledBack(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	body := realityLine("off", 443)
	body["enabled"] = false
	w := f.do("POST", "/api/lines", body, withCookie(c))
	expectStatus(t, w, http.StatusCreated)
	line := decodeBody[lineDTO](t, w)
	a := f.createExit(c, "A", ssLink)
	expectStatus(t, f.do("PUT", "/api/routing", map[string]any{"lines": []any{map[string]any{"id": line.ID, "exitId": a.ID}}}, withCookie(c)), http.StatusOK)

	f.eng.refuseWhen(func(ctx context.Context) (string, bool) {
		lines, _ := f.st.ListLines(ctx)
		for _, l := range lines {
			if (l.Enabled && l.ExitID != 0) || l.Name == "new" {
				return "invalid key", true
			}
		}
		return "", false
	})
	body["enabled"] = true
	w = f.do("PUT", fmt.Sprintf("/api/lines/%d", line.ID), body, withCookie(c))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "line")
	if l, _ := f.st.GetLine(t.Context(), line.ID); l.Enabled || l.ExitID != a.ID {
		t.Fatalf("after a refused enable: enabled %v, exit %d; want still off and still wired", l.Enabled, l.ExitID)
	}
	w = f.do("POST", "/api/lines", realityLine("new", 8443), withCookie(c))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "line")
	if lines, _ := f.st.ListLines(t.Context()); len(lines) != 1 {
		t.Fatalf("a refused new line was kept: %d lines", len(lines))
	}

	f.eng.refuseWhen(nil)
	f.eng.failSync(fmt.Errorf("%w: invalid key", ErrConfigRejected))
	w = f.do("PUT", fmt.Sprintf("/api/exits/%d", a.ID), map[string]any{"name": "A renamed", "region": "kr", "link": ""}, withCookie(c))
	expectError(t, w, http.StatusBadGateway, codeEngine, "")
	if e, _ := f.st.GetExit(t.Context(), a.ID); e.Name != "A renamed" {
		t.Fatalf("a rename was rolled back: %q", e.Name)
	}
}

// When the store already holds a config Xray refuses because of something else (a certificate
// gone from disk, an Xray upgrade), no change can be told apart as the cause. Undoing each one
// would lock the admin out of the fix, so changes are kept with a 502 until the fix lands.
func TestRefusedStoreStillTakesTheFix(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	broken := f.createLineAt(c, "broken", 443)
	other := f.createLineAt(c, "other", 8443)
	a := f.createExit(c, "A", ssLink)
	f.eng.refuseWhen(func(ctx context.Context) (string, bool) {
		l, _ := f.st.GetLine(ctx, broken.ID)
		return "certificate not found", l.Enabled
	})

	// Xray still runs the old config and the panel has not synced since the certificate went:
	// it finds out by asking Xray about the old state, which Sync alone would not re-check.
	w := f.do("PUT", fmt.Sprintf("/api/lines/%d", other.ID), realityLine("other", 8444), withCookie(c))
	expectError(t, w, http.StatusBadGateway, codeEngine, "")
	if l, _ := f.st.GetLine(t.Context(), other.ID); l.Port != 8444 {
		t.Fatalf("a change made while the store was refused anyway was undone: port %d", l.Port)
	}
	// Now it knows, and does not try undoing at all.
	syncs, checks := f.eng.syncCount(), f.eng.checkCount()
	w = f.do("PUT", "/api/routing", map[string]any{"lines": []any{map[string]any{"id": other.ID, "exitId": a.ID}}}, withCookie(c))
	expectError(t, w, http.StatusBadGateway, codeEngine, "")
	if l, _ := f.st.GetLine(t.Context(), other.ID); l.ExitID != a.ID {
		t.Fatal("wiring made while the store was refused anyway was undone")
	}
	if s, c := f.eng.syncCount()-syncs, f.eng.checkCount()-checks; s != 1 || c != 0 {
		t.Fatalf("a change on a store known to be refused synced %d and checked %d times, want 1 and 0", s, c)
	}
	w = f.do("POST", "/api/lines", realityLine("third", 9443), withCookie(c))
	expectError(t, w, http.StatusBadGateway, codeEngine, "")

	// Switching the broken line off is the way out, and it works.
	off := realityLine("broken", 443)
	off["enabled"] = false
	expectStatus(t, f.do("PUT", fmt.Sprintf("/api/lines/%d", broken.ID), off, withCookie(c)), http.StatusOK)
	if l, _ := f.st.GetLine(t.Context(), broken.ID); l.Enabled {
		t.Fatal("switching the broken line off did not stick")
	}
	if lines, _ := f.st.ListLines(t.Context()); len(lines) != 3 {
		t.Fatalf("lines after the fix = %d, want 3", len(lines))
	}
	e, _ := f.st.ListAudit(t.Context(), 10, 0)
	if e[0].Action != "line.update" || e[0].Target != "broken" {
		t.Fatalf("latest audit = %+v, want the fix", e[0])
	}
}
