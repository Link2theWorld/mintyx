package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// ConnectTime measures how long a TCP handshake with host:port takes from this server: the
// best of three attempts, each bounded by timeout (3s when zero). The name is resolved first,
// so DNS time is not counted and a lookup failure is reported as such. IPv4 addresses are
// tried before IPv6, and the first address that answers is the one measured.
func ConnectTime(ctx context.Context, host string, port int, timeout time.Duration) (time.Duration, error) {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	ips, err := resolve(ctx, host, timeout)
	if err != nil {
		return 0, err
	}
	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		var best time.Duration
		for range 3 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			took, err := dialOnce(ctx, addr, timeout)
			if err != nil {
				lastErr = err
				if best == 0 {
					break // this address does not answer; try the next one
				}
				continue
			}
			if best == 0 || took < best {
				best = took
			}
		}
		if best > 0 {
			return best, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no attempt finished")
	}
	return 0, lastErr
}

func resolve(ctx context.Context, host string, timeout time.Duration) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil {
		return nil, fmt.Errorf("look up %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("look up %s: no addresses", host)
	}
	var v4, v6 []net.IP
	for _, a := range addrs {
		if a.IP.To4() != nil {
			v4 = append(v4, a.IP)
		} else {
			v6 = append(v6, a.IP)
		}
	}
	return append(v4, v6...), nil
}

func dialOnce(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	took := time.Since(start)
	_ = conn.Close()
	return took, nil
}
