package app

import (
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/attack"
)

func TestXrayTapFeedsTheCollectorAndHidesInfoLines(t *testing.T) {
	c := attack.NewCollector()
	tap := XrayTap(c, func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) })
	keep := map[string]bool{
		"2026/11/21 22:25:25.568501 [Info] transport/internet/tcp: REALITY: processed invalid connection from 203.0.113.5:64998: failed to read client hello": false,
		"2026/11/21 22:25:31.080490 [Info] [2253650119] proxy/vless/inbound: firstLen = 209":                                                                  false,
		"2026/11/21 22:25:09.156995 [Warning] core: Xray 26.11.9 started":                                                                                     true,
		"2026/11/21 22:25:17.451132 from 203.0.113.6:64860 rejected  proxy/vless/encoding: invalid request user id: 2222":                                     true,
	}
	for line, want := range keep {
		if got := tap(line); got != want {
			t.Errorf("keep = %v, want %v for %q", got, want, line)
		}
	}
	if hits, _ := c.Drain(); len(hits) != 2 {
		t.Errorf("collector got %+v, want the probe and the rejected login", hits)
	}
}
