package panel

import (
	"encoding/base64"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/ysuhao/mintyx-next/internal/model"
	"github.com/ysuhao/mintyx-next/internal/share"
)

type shareResp struct {
	Subscriptions []subscriptionDTO `json:"subscriptions"`
	Links         []linkDTO         `json:"links"`
}

func subPath(t *testing.T, url string) string {
	t.Helper()
	i := strings.Index(url, "/sub/")
	if i < 0 {
		t.Fatalf("no /sub/ in %q", url)
	}
	return url[i:]
}

func TestShareMatchesLinkOutput(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	expectStatus(t, f.do("PUT", "/api/settings", map[string]string{"publicHost": "vpn.example.com"}, withCookie(c)), http.StatusOK)
	line := decodeBody[lineDTO](t, f.do("POST", "/api/lines", realityLine("tokyo", 443), withCookie(c)))
	expectStatus(t, f.do("POST", "/api/lines", map[string]any{"name": "cdn", "protocol": "vless-xhttp", "port": 8080,
		"xhttp": map[string]any{"path": "/x", "domain": "cdn.example.com", "security": "none"}}, withCookie(c)), http.StatusCreated)
	cl := f.createClient(c, "phone", 0)

	w := f.do("GET", "/api/clients/"+itoa(cl.ID)+"/share", nil, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	got := decodeBody[shareResp](t, w)

	storedLine, _ := f.st.GetLine(t.Context(), line.ID)
	storedClient, _ := f.st.GetClient(t.Context(), cl.ID)
	want, err := share.Link(storedLine, storedClient, "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Links) != 2 || got.Links[0].URI != want || got.Links[0].LineID != line.ID || got.Links[0].LineName != "tokyo" {
		t.Fatalf("links = %+v, want first %q", got.Links, want)
	}

	base := "http://panel.test/sub/" + storedClient.SubToken
	wantSubs := []subscriptionDTO{
		{Format: share.FormatLinks, URL: base, Omitted: []omissionDTO{}},
		{Format: share.FormatMihomo, URL: base + "?format=mihomo", Omitted: []omissionDTO{}},
	}
	if !reflect.DeepEqual(got.Subscriptions, wantSubs) {
		t.Fatalf("subscriptions = %+v, want %+v", got.Subscriptions, wantSubs)
	}
	if !strings.Contains(w.Body.String(), `"omitted":[]`) {
		t.Fatalf("an empty omitted list must be [], not null: %s", w.Body)
	}

	// A stored line the API would no longer accept (its key pair is gone) is reported, not linked.
	broken := storedLine
	broken.Name, broken.Port = "broken", 444
	broken.Reality = &model.RealityParams{ServerName: "www.example.com", Target: "www.example.com:443"}
	if err := f.st.CreateLine(t.Context(), &broken); err != nil {
		t.Fatal(err)
	}
	got = decodeBody[shareResp](t, f.do("GET", "/api/clients/"+itoa(cl.ID)+"/share", nil, withCookie(c)))
	wantOm := []omissionDTO{{LineID: broken.ID, LineName: "broken", Reason: "reality public key is empty"}}
	for _, s := range got.Subscriptions {
		if !reflect.DeepEqual(s.Omitted, wantOm) {
			t.Errorf("%s omitted = %+v, want %+v", s.Format, s.Omitted, wantOm)
		}
	}
	if len(got.Links) != 2 || got.Links[0].LineName != "tokyo" || got.Links[1].LineName != "cdn" {
		t.Fatalf("links = %+v, want tokyo and cdn only", got.Links)
	}

	expectStatus(t, f.do("PUT", "/api/settings", map[string]string{"publicHost": "vpn.example.com",
		"subscriptionBaseUrl": "https://sub.example.com/m/"}, withCookie(c)), http.StatusOK)
	got = decodeBody[shareResp](t, f.do("GET", "/api/clients/"+itoa(cl.ID)+"/share", nil, withCookie(c)))
	if u := got.Subscriptions[0].URL; u != "https://sub.example.com/m/sub/"+storedClient.SubToken {
		t.Fatalf("with base setting url = %q", u)
	}
}

func TestSubscriptionEndpoint(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	expectStatus(t, f.do("PUT", "/api/settings", map[string]string{"publicHost": "vpn.example.com"}, withCookie(c)), http.StatusOK)
	expectStatus(t, f.do("POST", "/api/lines", realityLine("tokyo", 443), withCookie(c)), http.StatusCreated)
	w := f.do("POST", "/api/clients", map[string]any{"name": "phone", "quotaBytes": 5000}, withCookie(c))
	cl := decodeBody[clientDTO](t, w)
	got := decodeBody[shareResp](t, f.do("GET", "/api/clients/"+itoa(cl.ID)+"/share", nil, withCookie(c)))
	path := subPath(t, got.Subscriptions[0].URL)

	w = f.do("GET", path, nil)
	expectStatus(t, w, http.StatusOK)
	raw, err := base64.StdEncoding.DecodeString(w.Body.String())
	if err != nil || string(raw) != got.Links[0].URI {
		t.Fatalf("links body decodes to %q (%v), want %q", raw, err, got.Links[0].URI)
	}
	if h := w.Header().Get("Subscription-Userinfo"); h != "upload=0; download=0; total=5000" {
		t.Fatalf("Subscription-Userinfo = %q", h)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("subscription response sets a cookie")
	}

	w = f.do("GET", path+"?format=mihomo", nil)
	expectStatus(t, w, http.StatusOK)
	if ct := w.Header().Get("Content-Type"); ct != "text/yaml; charset=utf-8" || !strings.Contains(w.Body.String(), "reality-opts") {
		t.Fatalf("mihomo: content-type %q body %s", ct, w.Body)
	}
	for _, format := range []string{"clash", "v2rayng"} {
		w = f.do("GET", path+"?format="+format, nil)
		if w.Code != http.StatusBadRequest || w.Body.String() != "unknown format\n" {
			t.Fatalf("format %s: %d %q, want 400 \"unknown format\"", format, w.Code, w.Body)
		}
	}

	// A disabled client still gets a valid, empty subscription.
	expectStatus(t, f.do("POST", "/api/clients/"+itoa(cl.ID)+"/disable", nil, withCookie(c)), http.StatusNoContent)
	w = f.do("GET", path, nil)
	expectStatus(t, w, http.StatusOK)
	if w.Body.String() != "" {
		t.Fatalf("disabled client body = %q, want empty base64", w.Body)
	}

	w = f.do("GET", "/sub/not-a-token", nil)
	if w.Code != http.StatusNotFound || w.Body.Len() != 0 {
		t.Fatalf("unknown token: %d %q, want 404 empty", w.Code, w.Body)
	}
}

func TestRotateInvalidatesOldSubscription(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	cl := f.createClient(c, "phone", 0)
	before, _ := f.st.GetClient(t.Context(), cl.ID)
	old := "/sub/" + before.SubToken
	expectStatus(t, f.do("GET", old, nil), http.StatusOK)

	expectStatus(t, f.do("POST", "/api/clients/"+itoa(cl.ID)+"/rotate", nil, withCookie(c)), http.StatusNoContent)
	after, _ := f.st.GetClient(t.Context(), cl.ID)
	if after.SubToken == before.SubToken || after.Secret == before.Secret {
		t.Fatal("rotate kept the token or secret")
	}
	if w := f.do("GET", old, nil); w.Code != http.StatusNotFound || w.Body.Len() != 0 {
		t.Fatalf("old url: %d %q, want 404 empty", w.Code, w.Body)
	}
	expectStatus(t, f.do("GET", "/sub/"+after.SubToken, nil), http.StatusOK)
	if n := f.eng.syncCount(); n != 2 {
		t.Fatalf("syncs = %d, want 2 (create + rotate)", n)
	}
}
