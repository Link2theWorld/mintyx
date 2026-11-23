package panel

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
	"github.com/Link2theWorld/mintyx/internal/reach"
)

type recheckFixture struct {
	*fixture
	picker *fakePicker
	cc     *fakeCoverCheck
	runner *CoverRunner
	cookie *http.Cookie
	// managed has the panel's usual target; handSet forwards to a server of its own.
	managed, handSet model.Line
}

func newRecheckFixture(t *testing.T) *recheckFixture {
	t.Helper()
	f, picker, cc, c := newCoverFixture(t, "old.example", "new.example", "spare.example")
	rf := &recheckFixture{fixture: f, picker: picker, cc: cc, runner: f.srv.NewCoverRunner(time.Minute), cookie: c}
	rf.managed = model.Line{Name: "tokyo", Protocol: model.VLESSReality, Port: 443, Enabled: true, Reality: &model.RealityParams{
		PrivateKey: "priv", PublicKey: "pub", ShortID: "abcd", ServerName: "old.example", Target: "old.example:443"}}
	rf.handSet = model.Line{Name: "self", Protocol: model.VLESSReality, Port: 8443, Enabled: true, Reality: &model.RealityParams{
		PrivateKey: "priv2", PublicKey: "pub2", ShortID: "ef01", ServerName: "old.example", Target: "127.0.0.1:8001"}}
	for _, l := range []*model.Line{&rf.managed, &rf.handSet} {
		if err := f.st.CreateLine(t.Context(), l); err != nil {
			t.Fatal(err)
		}
	}
	return rf
}

func (f *recheckFixture) tick() bool {
	f.t.Helper()
	ran, err := f.runner.Tick(f.t.Context())
	if err != nil {
		f.t.Fatalf("Tick: %v", err)
	}
	return ran
}

func (f *recheckFixture) line(l model.Line) model.Line {
	f.t.Helper()
	got, err := f.st.GetLine(f.t.Context(), l.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return got
}

func (f *recheckFixture) switches() []model.AuditEntry {
	f.t.Helper()
	all, err := f.st.ListAudit(f.t.Context(), 100, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []model.AuditEntry
	for _, e := range all {
		if e.Action == "line.cover-switch" {
			out = append(out, e)
		}
	}
	return out
}

func TestCoverRecheckSwitchesAFailingSiteAfterConfirmation(t *testing.T) {
	f := newRecheckFixture(t)
	expectStatus(t, f.do("PUT", "/api/settings", map[string]string{"publicHost": "vpn.example.com"}, withCookie(f.cookie)), http.StatusOK)
	cl := f.createClient(f.cookie, "phone", 0)
	syncs := f.eng.syncCount()

	if !f.tick() {
		t.Fatal("first Tick did not recheck")
	}
	if f.tick() {
		t.Fatal("rechecked again within coverRecheckEvery")
	}

	f.picker.setBad("old.example", "homepage redirects (301 to https://elsewhere.example/)")
	*f.clock = f.clock.Add(coverRecheckEvery)
	f.tick()
	if got := f.line(f.managed).Reality.ServerName; got != "old.example" || len(f.switches()) != 0 {
		t.Fatalf("after one failed check the cover is %q; want it kept until the failure repeats", got)
	}

	*f.clock = f.clock.Add(coverRecheckEvery)
	f.tick()
	got := f.line(f.managed)
	want := model.RealityParams{PrivateKey: "priv", PublicKey: "pub", ShortID: "abcd", ServerName: "new.example", Target: "new.example:443"}
	if *got.Reality != want {
		t.Fatalf("reality after the switch = %+v, want %+v: only the cover may change", *got.Reality, want)
	}
	if f.eng.syncCount() <= syncs {
		t.Fatal("Xray was not synced after the switch")
	}
	sw := f.switches()
	if len(sw) != 1 || sw[0].Target != "tokyo" || !strings.Contains(sw[0].Detail, "old.example → new.example") ||
		!strings.Contains(sw[0].Detail, "redirects") || sw[0].RemoteIP != "" {
		t.Fatalf("audit = %+v, want one line.cover-switch for tokyo naming both sites and why", sw)
	}
	if hand := f.line(f.handSet); *hand.Reality != *f.handSet.Reality {
		t.Fatalf("hand-set line = %+v, want it untouched", *hand.Reality)
	}

	// Subscriptions are rendered from the store, so the next refresh carries the new site.
	share := decodeBody[shareResp](t, f.do("GET", "/api/clients/"+itoa(cl.ID)+"/share", nil, withCookie(f.cookie)))
	links := ""
	for _, l := range share.Links {
		if l.LineID == f.managed.ID {
			links = l.URI
		}
	}
	if !strings.Contains(links, "sni=new.example") {
		t.Fatalf("share link = %q, want it to present new.example", links)
	}
	w := f.do("GET", subPath(t, share.Subscriptions[1].URL), nil)
	if !strings.Contains(w.Body.String(), "servername: new.example") {
		t.Fatalf("mihomo subscription does not carry the new site:\n%s", w.Body)
	}
}

func TestCoverRecheckForgivesASiteThatRecovers(t *testing.T) {
	f := newRecheckFixture(t)
	for _, bad := range []bool{true, false, true} {
		problem := ""
		if bad {
			problem = "dial tcp: i/o timeout"
		}
		f.picker.setBad("old.example", problem)
		*f.clock = f.clock.Add(coverRecheckEvery)
		f.tick()
	}
	if got := f.line(f.managed).Reality.ServerName; got != "old.example" || len(f.switches()) != 0 {
		t.Fatalf("cover = %q after fail, pass, fail; want it kept", got)
	}
}

func TestCoverRecheckKeepsTheSiteWhenNothingElseQualifies(t *testing.T) {
	f := newRecheckFixture(t)
	for _, s := range []string{"old.example", "new.example", "spare.example"} {
		f.picker.setBad(s, "dial tcp: i/o timeout")
	}
	*f.clock = f.clock.Add(coverRecheckEvery)
	f.tick() // the first failure only counts
	for range 2 {
		*f.clock = f.clock.Add(coverRecheckEvery)
		if _, err := f.runner.Tick(t.Context()); err == nil {
			t.Fatal("Tick reported nothing though the failing cover could not be replaced")
		}
	}
	if got := f.line(f.managed).Reality.ServerName; got != "old.example" || len(f.switches()) != 0 {
		t.Fatalf("cover = %q; want it kept: a server whose network is down must not move its lines", got)
	}
}

func TestCoverRecheckHearsMainlandProbesOnlyWhileReachIsOn(t *testing.T) {
	f := newRecheckFixture(t)
	f.cc.verdicts["old.example"] = reach.CoverVerdict{Problem: "resolves to 223.5.5.5, a mainland China address"}
	f.cc.verdicts["new.example"] = reach.CoverVerdict{Problem: "cannot be loaded from mainland China"}
	f.cc.verdicts["spare.example"] = reach.CoverVerdict{OK: true}

	for range 2 {
		*f.clock = f.clock.Add(coverRecheckEvery)
		f.tick()
	}
	if f.cc.count() != 0 || len(f.switches()) != 0 {
		t.Fatalf("%d mainland checks and %d switches with the reachability check off; want none", f.cc.count(), len(f.switches()))
	}

	f.enableReach(true)
	for range 2 {
		*f.clock = f.clock.Add(coverRecheckEvery)
		f.tick()
	}
	if got := f.line(f.managed).Reality.ServerName; got != "spare.example" {
		t.Fatalf("cover = %q, want spare.example: the only site mainland probes accept", got)
	}
	if sw := f.switches(); len(sw) != 1 || !strings.Contains(sw[0].Detail, "mainland") {
		t.Fatalf("audit = %+v, want the mainland verdict as the reason", sw)
	}
}

func TestCoverRecheckLeavesALineTheAdminJustChanged(t *testing.T) {
	f := newRecheckFixture(t)
	f.picker.setBad("old.example", "does not support HTTP/2")
	*f.clock = f.clock.Add(coverRecheckEvery)
	f.tick()

	// The admin points the line at a site of their own between two rechecks.
	l := f.line(f.managed)
	l.Reality.ServerName, l.Reality.Target = "mine.example", "mine.example:443"
	if err := f.st.UpdateLine(t.Context(), &l); err != nil {
		t.Fatal(err)
	}
	*f.clock = f.clock.Add(coverRecheckEvery)
	f.tick()
	if got := f.line(f.managed).Reality.ServerName; got != "mine.example" || len(f.switches()) != 0 {
		t.Fatalf("cover = %q; want the admin's mine.example, with its failure count starting over", got)
	}
}

func TestCoverRunnerStartStop(t *testing.T) {
	f := newRecheckFixture(t)
	f.runner.Start(t.Context())
	f.runner.Start(t.Context())
	f.runner.Stop()
	f.runner.Stop()
}
