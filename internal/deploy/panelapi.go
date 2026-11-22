package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// PanelError is an error response from the panel's own API.
type PanelError struct {
	Status  int
	Code    string
	Message string
	Field   string
}

func (e *PanelError) Error() string {
	msg := fmt.Sprintf("the panel answered %d %s: %s", e.Status, e.Code, e.Message)
	if e.Field != "" {
		msg += " (" + e.Field + ")"
	}
	return msg
}

// panelClient talks to the panel on the server's loopback, every connection riding the SSH link.
type panelClient struct {
	http *http.Client
}

func (c *Client) panel() *panelClient {
	jar, _ := cookiejar.New(nil)
	return &panelClient{http: &http.Client{
		Jar:     jar,
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			// Proxy stays nil: a proxy from the environment must never see panel traffic.
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return c.DialRemote(ctx, PanelAddr)
			},
		},
	}}
}

func (p *panelClient) close() { p.http.CloseIdleConnections() }

func (p *panelClient) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+PanelAddr+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("X-Mintyx", "1")
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		pe := &PanelError{Status: resp.StatusCode}
		var envelope struct {
			Error struct{ Code, Message, Field string } `json:"error"`
		}
		if json.Unmarshal(data, &envelope) == nil {
			pe.Code, pe.Message, pe.Field = envelope.Error.Code, envelope.Error.Message, envelope.Error.Field
		}
		return pe
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}
