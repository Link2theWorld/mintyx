package panel

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const remoteHy2Link = "hysteria2://hk-auth-secret@hk.example.net:8443/?sni=hk.example.net#HK"

type remoteLinesResp struct {
	RemoteLines []remoteLineDTO `json:"remoteLines"`
}

func TestRemoteLinesMergeIntoTheSubscription(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	expectStatus(t, f.do("PUT", "/api/settings", map[string]string{"publicHost": "vpn.example.com"}, withCookie(c)), http.StatusOK)
	f.createLineAt(c, "tokyo", 443)
	cl := f.createClient(c, "phone", 0)
	other := f.createClient(c, "tablet", 0)
	base := "/api/clients/" + itoa(cl.ID) + "/remote-lines"
	syncs := f.eng.syncCount()

	w := f.do("POST", base, map[string]any{"name": "", "link": realityLink("198.51.100.8", 443, "Seoul")}, withCookie(c))
	expectStatus(t, w, http.StatusCreated)
	seoul := decodeBody[remoteLineDTO](t, w)
	if seoul.Name != "Seoul" || seoul.Summary.Protocol != "vless" || seoul.Summary.Security != "reality" || seoul.Summary.Host != "198.51.100.8" {
		t.Fatalf("created = %+v", seoul)
	}
	if strings.Contains(w.Body.String(), exitSecret) {
		t.Fatalf("response leaks the credential: %s", w.Body)
	}
	hk := decodeBody[remoteLineDTO](t, f.do("POST", base, map[string]any{"name": "Hong Kong", "link": remoteHy2Link}, withCookie(c)))
	if hk.Name != "Hong Kong" || !hk.Summary.UDP {
		t.Fatalf("hk = %+v", hk)
	}

	list := decodeBody[remoteLinesResp](t, f.do("GET", base, nil, withCookie(c)))
	if len(list.RemoteLines) != 2 || list.RemoteLines[0].ID != seoul.ID || list.RemoteLines[1].ID != hk.ID {
		t.Fatalf("list = %+v", list)
	}
	if l := decodeBody[remoteLinesResp](t, f.do("GET", "/api/clients/"+itoa(other.ID)+"/remote-lines", nil, withCookie(c))); len(l.RemoteLines) != 0 {
		t.Fatalf("another client sees %+v", l)
	}
	if n := f.eng.syncCount(); n != syncs {
		t.Fatalf("syncs = %d, want %d: remote lines never touch Xray", n, syncs)
	}

	stored, _ := f.st.GetClient(t.Context(), cl.ID)
	sub := "/sub/" + stored.SubToken
	w = f.do("GET", sub+"?format=mihomo", nil)
	expectStatus(t, w, http.StatusOK)
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
		Groups  []map[string]any `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("yaml: %v\n%s", err, w.Body)
	}
	if len(doc.Proxies) != 3 || len(doc.Groups) != 2 || doc.Groups[1]["type"] != "load-balance" ||
		doc.Groups[1]["strategy"] != "consistent-hashing" {
		t.Fatalf("mihomo subscription:\n%s", w.Body)
	}
	if members := doc.Groups[0]["proxies"].([]any); members[0] != doc.Groups[1]["name"] {
		t.Fatalf("select group does not default to the load-balance group: %v", members)
	}
	raw, _ := base64.StdEncoding.DecodeString(f.do("GET", sub, nil).Body.String())
	if uris := strings.Split(string(raw), "\n"); len(uris) != 3 || !strings.HasSuffix(uris[2], "#Hong%20Kong") {
		t.Fatalf("links subscription = %q", uris)
	}

	// The other client's subscription is unchanged: one line, no balancing.
	storedOther, _ := f.st.GetClient(t.Context(), other.ID)
	if body := f.do("GET", "/sub/"+storedOther.SubToken+"?format=mihomo", nil).Body.String(); strings.Contains(body, "load-balance") {
		t.Fatalf("tablet got a load-balance group:\n%s", body)
	}

	// Rename keeps the link; another client's id cannot reach the line.
	w = f.do("PUT", base+"/"+itoa(seoul.ID), map[string]any{"name": "Seoul 2", "link": ""}, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	if got := decodeBody[remoteLineDTO](t, w); got.Name != "Seoul 2" || got.Summary.Host != "198.51.100.8" {
		t.Fatalf("renamed = %+v", got)
	}
	expectError(t, f.do("PUT", "/api/clients/"+itoa(other.ID)+"/remote-lines/"+itoa(seoul.ID),
		map[string]any{"name": "x"}, withCookie(c)), http.StatusNotFound, codeNotFound, "")
	expectError(t, f.do("DELETE", "/api/clients/"+itoa(other.ID)+"/remote-lines/"+itoa(seoul.ID), nil, withCookie(c)),
		http.StatusNotFound, codeNotFound, "")

	expectStatus(t, f.do("DELETE", base+"/"+itoa(hk.ID), nil, withCookie(c)), http.StatusNoContent)
	// Two endpoints remain (tokyo and Seoul 2), so the group stays; only HK is gone.
	if body := f.do("GET", sub+"?format=mihomo", nil).Body.String(); strings.Contains(body, "hk-auth-secret") ||
		!strings.Contains(body, "load-balance") || !strings.Contains(body, "Seoul 2") {
		t.Fatalf("after deleting HK:\n%s", body)
	}

	entries, err := f.st.ListAudit(t.Context(), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		if strings.HasPrefix(e.Action, "client.remote-line.") {
			actions = append(actions, e.Action)
			if e.Target != "phone" || strings.Contains(e.Detail, "hk-auth-secret") || strings.Contains(e.Detail, exitSecret) {
				t.Errorf("audit entry %+v", e)
			}
		}
	}
	if want := "client.remote-line.delete client.remote-line.update client.remote-line.create client.remote-line.create"; strings.Join(actions, " ") != want {
		t.Fatalf("audit actions = %v", actions)
	}
}

func TestRemoteLineLinkErrors(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	expectStatus(t, f.do("PUT", "/api/settings", map[string]string{"publicHost": "vpn.example.com"}, withCookie(c)), http.StatusOK)
	f.createLineAt(c, "tokyo", 443)
	cl := f.createClient(c, "phone", 0)
	base := "/api/clients/" + itoa(cl.ID) + "/remote-lines"
	for _, tc := range []struct{ name, link, field string }{
		{"empty", " ", "link"},
		{"unparsable", "vless://nope", "link.userinfo"},
		{"cannot go into a subscription", ssLink, "link.scheme"},
		{"this panel's own line", realityLink("vpn.example.com", 443, "me"), "link"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectError(t, f.do("POST", base, map[string]any{"link": tc.link}, withCookie(c)), http.StatusBadRequest, codeInvalid, tc.field)
		})
	}
	expectError(t, f.do("POST", "/api/clients/999/remote-lines", map[string]any{"link": remoteHy2Link}, withCookie(c)),
		http.StatusNotFound, codeNotFound, "")
	expectError(t, f.do("GET", "/api/clients/999/remote-lines", nil, withCookie(c)), http.StatusNotFound, codeNotFound, "")

	// Deleting the client deletes its remote lines.
	expectStatus(t, f.do("POST", base, map[string]any{"link": remoteHy2Link}, withCookie(c)), http.StatusCreated)
	expectStatus(t, f.do("DELETE", "/api/clients/"+itoa(cl.ID), nil, withCookie(c)), http.StatusNoContent)
	if left, err := f.st.ListRemoteLines(t.Context(), cl.ID); err != nil || len(left) != 0 {
		t.Fatalf("remote lines after client delete: %+v, %v", left, err)
	}
}
