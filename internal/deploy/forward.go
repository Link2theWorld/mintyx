package deploy

import (
	"context"
	"io"
	"net"
	"sync"
)

// Forwarder is a local loopback listener whose connections come out on the server's side.
type Forwarder struct {
	ln     net.Listener
	client *Client
	remote string

	mu     sync.Mutex
	conns  map[net.Conn]bool
	closed bool
	wg     sync.WaitGroup
}

// Forward listens on 127.0.0.1 at a free port and relays every connection to remote.
func (c *Client) Forward(remote string) (*Forwarder, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f := &Forwarder{ln: ln, client: c, remote: remote, conns: map[net.Conn]bool{}}
	f.wg.Go(f.accept)
	return f, nil
}

func (f *Forwarder) Addr() string { return f.ln.Addr().String() }

func (f *Forwarder) Close() {
	f.mu.Lock()
	f.closed = true
	for c := range f.conns {
		c.Close()
	}
	f.mu.Unlock()
	f.ln.Close()
	f.wg.Wait()
}

func (f *Forwarder) track(c net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.conns[c] = true
	return true
}

func (f *Forwarder) untrack(c net.Conn) {
	f.mu.Lock()
	delete(f.conns, c)
	f.mu.Unlock()
}

func (f *Forwarder) accept() {
	for {
		local, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.wg.Go(func() { f.relay(local) })
	}
}

func (f *Forwarder) relay(local net.Conn) {
	defer local.Close()
	if !f.track(local) {
		return
	}
	defer f.untrack(local)
	remote, err := f.client.DialRemote(context.Background(), f.remote)
	if err != nil {
		return
	}
	defer remote.Close()
	if !f.track(remote) {
		return
	}
	defer f.untrack(remote)

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(remote, local); closeWrite(remote); done <- struct{}{} }()
	go func() { _, _ = io.Copy(local, remote); closeWrite(local); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
