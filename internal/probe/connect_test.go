package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestConnectTime(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	if d, err := ConnectTime(context.Background(), "127.0.0.1", port, time.Second); err != nil || d <= 0 {
		t.Fatalf("ConnectTime to a listener = %v, %v", d, err)
	}
	if d, err := ConnectTime(context.Background(), "localhost", port, time.Second); err != nil || d <= 0 {
		t.Fatalf("ConnectTime by name = %v, %v", d, err)
	}
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()
	if _, err := ConnectTime(context.Background(), "127.0.0.1", closed, time.Second); err == nil {
		t.Fatal("ConnectTime to a closed port succeeded")
	}
}
