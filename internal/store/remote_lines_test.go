package store

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Link2theWorld/mintyx/internal/model"
)

func TestRemoteLinesBelongToTheirClient(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	a := &model.Client{Name: "a", Secret: "sa", SubToken: "ta"}
	b := &model.Client{Name: "b", Secret: "sb", SubToken: "tb"}
	for _, c := range []*model.Client{a, b} {
		if err := s.CreateClient(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	r1 := &model.RemoteLine{ClientID: a.ID, Name: "Seoul", Params: vlessExit("x").Params}
	r2 := &model.RemoteLine{ClientID: a.ID, Name: "HK", Params: model.ExitParams{Protocol: model.ExitHysteria2,
		Host: "hk.example.com", Port: 443, Secret: "auth", TLS: &model.ExitTLS{ServerName: "hk.example.com", ALPN: []string{"h3"}}}}
	for _, r := range []*model.RemoteLine{r1, r2} {
		if err := s.CreateRemoteLine(ctx, r); err != nil {
			t.Fatalf("CreateRemoteLine %s: %v", r.Name, err)
		}
	}
	got, err := s.ListRemoteLines(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []model.RemoteLine{*r1, *r2}) {
		t.Fatalf("ListRemoteLines =\n%+v\nwant\n%+v", got, []model.RemoteLine{*r1, *r2})
	}
	if other, err := s.ListRemoteLines(ctx, b.ID); err != nil || len(other) != 0 {
		t.Fatalf("client b sees %+v, %v", other, err)
	}

	// Another client's id cannot reach the line.
	if _, err := s.GetRemoteLine(ctx, b.ID, r1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetRemoteLine as b: %v, want ErrNotFound", err)
	}
	if err := s.DeleteRemoteLine(ctx, b.ID, r1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteRemoteLine as b: %v, want ErrNotFound", err)
	}
	moved := *r1
	moved.ClientID, moved.Name = b.ID, "stolen"
	if err := s.UpdateRemoteLine(ctx, &moved); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateRemoteLine as b: %v, want ErrNotFound", err)
	}

	r1.Name = "Seoul 2"
	if err := s.UpdateRemoteLine(ctx, r1); err != nil {
		t.Fatal(err)
	}
	if g, err := s.GetRemoteLine(ctx, a.ID, r1.ID); err != nil || g.Name != "Seoul 2" {
		t.Fatalf("after update: %+v, %v", g, err)
	}

	if err := s.CreateRemoteLine(ctx, &model.RemoteLine{ClientID: 999, Name: "x", Params: r1.Params}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown client err = %v, want ErrInvalid", err)
	}

	// Deleting the client takes its remote lines with it.
	if err := s.DeleteClient(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if left, err := s.ListRemoteLines(ctx, a.ID); err != nil || len(left) != 0 {
		t.Fatalf("after client delete: %+v, %v", left, err)
	}
}
