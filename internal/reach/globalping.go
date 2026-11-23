package reach

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	globalpingURL = "https://api.globalping.io"
	// userAgent names the app only: every panel sends it, so it must not point at the author.
	userAgent = "mintyx/1"

	// ChinaProbes and ControlCountries decide what one measurement costs: one test per probe.
	ChinaProbes = 5
	mainland    = "CN"
	pingPackets = 3
	maxBody     = 4 << 20
)

// ControlCountries are outside China and far apart, so one regional outage cannot fake a verdict.
var ControlCountries = []string{"JP", "US", "DE"}

// ProbesPerMeasurement is the rate-limit cost of one measurement.
func ProbesPerMeasurement() int { return ChinaProbes + len(ControlCountries) }

// RateLimitError means the hourly allowance for this server's address is spent.
type RateLimitError struct {
	// Reset is how long until the allowance refills; 0 when the API did not say.
	Reset time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("globalping: rate limit reached, resets in %s", e.Reset)
}

// APIError is any other refusal from Globalping, e.g. no probes available or a private target.
type APIError struct {
	Status  int
	Type    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("globalping: %d %s: %s", e.Status, e.Type, e.Message)
}

// PingRequest asks for a TCP ping to Port, or an ICMP ping when Port is 0.
type PingRequest struct {
	Host string
	Port int
	// Reuse is an earlier measurement ID whose probes should run this one too.
	Reuse string
}

type ProbeResult struct {
	// China is true for a probe located in mainland China.
	China   bool
	Outcome Outcome
}

type PingResult struct {
	ID     string
	Probes []ProbeResult
}

// Client talks to the public Globalping API without a token.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	// PollEvery is the pause after each status response; the API asks for at least 500ms.
	PollEvery time.Duration
	// Deadline bounds one measurement; probes still running then count as no data.
	Deadline time.Duration
}

func NewClient() *Client {
	return &Client{
		BaseURL:   globalpingURL,
		HTTP:      &http.Client{Timeout: 20 * time.Second},
		PollEvery: time.Second,
		Deadline:  50 * time.Second,
	}
}

type location struct {
	Country string `json:"country"`
	Limit   int    `json:"limit"`
}

type pingOptions struct {
	Packets  int    `json:"packets"`
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port,omitempty"`
}

type createRequest struct {
	Type      string `json:"type"`
	Target    string `json:"target"`
	Locations any    `json:"locations"`
	Options   any    `json:"measurementOptions"`
}

type measurement struct {
	Status  string `json:"status"`
	Results []struct {
		Probe struct {
			Country string `json:"country"`
		} `json:"probe"`
		Result struct {
			Status        string `json:"status"`
			FailureSource string `json:"failureSource"`
			Stats         struct {
				Rcv int `json:"rcv"`
			} `json:"stats"`
		} `json:"result"`
	} `json:"results"`
}

const statusInProgress = "in-progress"

func (c *Client) Ping(ctx context.Context, req PingRequest) (PingResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Deadline)
	defer cancel()
	id, err := c.create(ctx, req)
	if err != nil {
		return PingResult{}, err
	}
	var m measurement
	if err := c.await(ctx, id, &m); err != nil {
		return PingResult{}, err
	}
	out := PingResult{ID: id}
	for _, r := range m.Results {
		p := ProbeResult{China: r.Probe.Country == mainland}
		switch r.Result.Status {
		case "finished":
			p.Outcome = Unreached
			if r.Result.Stats.Rcv > 0 {
				p.Outcome = Reached
			}
		case "failed":
			// Only a failure the API pins on the target counts; a broken probe says nothing.
			if r.Result.FailureSource == "target" {
				p.Outcome = Unreached
			}
		}
		out.Probes = append(out.Probes, p)
	}
	return out, nil
}

// await polls measurement id until it is no longer in progress or ctx ends, and decodes the
// last answer into into. Probes still running at the end count as no data. It fails only when
// no answer arrived at all.
func (c *Client) await(ctx context.Context, id string, into any) error {
	var last json.RawMessage
	for ctx.Err() == nil {
		var got json.RawMessage
		err := c.do(ctx, http.MethodGet, "/v1/measurements/"+id, nil, http.StatusOK, &got)
		var throttled *RateLimitError
		switch {
		case err == nil:
			last = got
		case errors.As(err, &throttled):
			// Polling has its own per-measurement limit; it clears in seconds, so keep waiting.
		case ctx.Err() == nil:
			return err
		}
		if err == nil {
			var head struct {
				Status string `json:"status"`
			}
			if err := json.Unmarshal(got, &head); err != nil {
				return fmt.Errorf("globalping: unreadable response: %w", err)
			}
			if head.Status != statusInProgress {
				break
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(c.PollEvery):
		}
	}
	if last == nil {
		return fmt.Errorf("globalping: measurement %s gave no results in %s", id, c.Deadline)
	}
	if err := json.Unmarshal(last, into); err != nil {
		return fmt.Errorf("globalping: unreadable response: %w", err)
	}
	return nil
}

func (c *Client) create(ctx context.Context, req PingRequest) (string, error) {
	opts := pingOptions{Packets: pingPackets}
	if req.Port != 0 {
		opts.Protocol, opts.Port = "TCP", req.Port
	}
	var locs any = req.Reuse
	if req.Reuse == "" {
		all := []location{{Country: mainland, Limit: ChinaProbes}}
		for _, cc := range ControlCountries {
			all = append(all, location{Country: cc, Limit: 1})
		}
		locs = all
	}
	return c.start(ctx, createRequest{Type: "ping", Target: strings.Trim(req.Host, "[]"), Locations: locs, Options: opts})
}

// start creates a measurement and returns its id.
func (c *Client) start(ctx context.Context, body createRequest) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/measurements", raw, http.StatusAccepted, &created); err != nil {
		return "", err
	}
	if created.ID == "" {
		return "", errors.New("globalping: response has no measurement id")
	}
	return created.ID, nil
}

// do sends one request. A GET whose connection dies before any answer is tried once more: idle
// connections and middleboxes drop often enough that one failure should not void a round. A POST
// is not, since the server may have created the measurement before the answer was lost, and a
// second one would spend the rate-limited allowance twice. (net/http still retries a request it
// knows never left this machine.)
func (c *Client) do(ctx context.Context, method, path string, body []byte, want int, into any) error {
	var resp *http.Response
	for attempt := 0; ; attempt++ {
		hr, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		hr.Header.Set("User-Agent", userAgent)
		hr.Header.Set("Accept", "application/json")
		if body != nil {
			hr.Header.Set("Content-Type", "application/json")
		}
		if resp, err = c.HTTP.Do(hr); err == nil {
			break
		}
		if attempt == 1 || method != http.MethodGet || ctx.Err() != nil {
			return fmt.Errorf("globalping: %w", err)
		}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("globalping: %w", err)
	}
	if resp.StatusCode == want {
		if err := json.Unmarshal(raw, into); err != nil {
			return fmt.Errorf("globalping: unreadable response: %w", err)
		}
		return nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		secs, _ := strconv.Atoi(resp.Header.Get("X-RateLimit-Reset"))
		return &RateLimitError{Reset: time.Duration(secs) * time.Second}
	}
	var fail struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &fail)
	return &APIError{Status: resp.StatusCode, Type: fail.Error.Type, Message: fail.Error.Message}
}
