package store

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Link2theWorld/mintyx/internal/model"
)

func vlessExit(name string) *model.Exit {
	return &model.Exit{Name: name, Region: "jp", Params: model.ExitParams{
		Protocol: model.ExitVLESS, Host: "203.0.113.7", Port: 443, Secret: "b831381d-6324-4d53-ad4f-8cda48b30811",
		Flow: "xtls-rprx-vision", Encryption: "none", Transport: model.ExitTransport{Network: model.ExitRaw},
		Reality: &model.ExitReality{ServerName: "www.example.com", Fingerprint: "chrome", PublicKey: "pbk", ShortID: "0a1b"},
	}}
}

func TestExitParamsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	cases := []*model.Exit{
		vlessExit("reality"),
		{Name: "trojan ws", Params: model.ExitParams{Protocol: model.ExitTrojan, Host: "t.example.com", Port: 443, Secret: "pw",
			Transport: model.ExitTransport{Network: model.ExitWS, Path: "/ws", Host: "cdn.example.com"},
			TLS:       &model.ExitTLS{ServerName: "t.example.com", Fingerprint: "chrome", ALPN: []string{"h2", "http/1.1"}, PinSHA256: "ab"}}},
		{Name: "ss", Params: model.ExitParams{Protocol: model.ExitShadowsocks, Host: "10.0.0.2", Port: 8388, Method: "aes-128-gcm", Secret: "k"}},
		{Name: "socks", Params: model.ExitParams{Protocol: model.ExitSOCKS, Host: "10.0.0.3", Port: 1080, Username: "u", Secret: "p"}},
		{Name: "hy2", Params: model.ExitParams{Protocol: model.ExitHysteria2, Host: "hy.example.com", Port: 443, Secret: "auth",
			ObfsPassword: "o", TLS: &model.ExitTLS{ServerName: "hy.example.com", ALPN: []string{"h3"}}}},
		{Name: "grpc", Params: model.ExitParams{Protocol: model.ExitVLESS, Host: "g.example.com", Port: 443, Secret: "id", Encryption: "none",
			Transport: model.ExitTransport{Network: model.ExitGRPC, ServiceName: "svc", Authority: "a.example.com", MultiMode: true},
			TLS:       &model.ExitTLS{ServerName: "g.example.com"}}},
	}
	for _, e := range cases {
		if err := s.CreateExit(ctx, e); err != nil {
			t.Fatalf("CreateExit %s: %v", e.Name, err)
		}
		got, err := s.GetExit(ctx, e.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, *e) {
			t.Errorf("round trip of %s:\n got  %+v\n want %+v", e.Name, got, *e)
		}
	}
	if err := s.CreateExit(ctx, vlessExit("reality")); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name err = %v, want ErrConflict", err)
	}
	if list, err := s.ListExits(ctx); err != nil || len(list) != len(cases) {
		t.Fatalf("ListExits = %d exits, %v", len(list), err)
	}
}

func TestSetRoutingAndDeleteUnlinks(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	line := realityLine(443)
	if err := s.CreateLine(ctx, line); err != nil {
		t.Fatal(err)
	}
	a, b := vlessExit("a"), vlessExit("b")
	for _, e := range []*model.Exit{a, b} {
		if err := s.CreateExit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetRouting(ctx, map[int64]int64{line.ID: a.ID}, map[int64]int64{a.ID: b.ID}); err != nil {
		t.Fatal(err)
	}
	gotLine, _ := s.GetLine(ctx, line.ID)
	gotA, _ := s.GetExit(ctx, a.ID)
	if gotLine.ExitID != a.ID || gotA.NextID != b.ID {
		t.Fatalf("after routing: line exit %d, a next %d; want %d, %d", gotLine.ExitID, gotA.NextID, a.ID, b.ID)
	}

	// Editing the line or the exit keeps the wiring.
	gotLine.Name = "renamed"
	if err := s.UpdateLine(ctx, &gotLine); err != nil {
		t.Fatal(err)
	}
	gotA.Name = "a2"
	if err := s.UpdateExit(ctx, &gotA); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.GetLine(ctx, line.ID); l.ExitID != a.ID {
		t.Fatalf("UpdateLine dropped the exit: %d", l.ExitID)
	}
	if e, _ := s.GetExit(ctx, a.ID); e.NextID != b.ID {
		t.Fatalf("UpdateExit dropped the next hop: %d", e.NextID)
	}

	// One bad id fails the whole change.
	if err := s.SetRouting(ctx, map[int64]int64{line.ID: 0}, map[int64]int64{9999: 0}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown exit err = %v, want ErrNotFound", err)
	}
	if l, _ := s.GetLine(ctx, line.ID); l.ExitID != a.ID {
		t.Fatal("a failed SetRouting still changed the line")
	}
	if err := s.SetRouting(ctx, map[int64]int64{line.ID: 9999}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pointing at a missing exit err = %v, want ErrInvalid", err)
	}
	if err := s.SetRouting(ctx, nil, map[int64]int64{a.ID: a.ID}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("self loop err = %v, want ErrInvalid", err)
	}

	if err := s.DeleteExit(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.GetLine(ctx, line.ID); l.ExitID != 0 {
		t.Fatalf("line still points at the deleted exit: %d", l.ExitID)
	}
	if err := s.DeleteExit(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete err = %v, want ErrNotFound", err)
	}
}
