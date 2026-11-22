package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ExitProtocol is the protocol of another proxy server that lines can leave through.
type ExitProtocol string

const (
	ExitVLESS       ExitProtocol = "vless"
	ExitTrojan      ExitProtocol = "trojan"
	ExitShadowsocks ExitProtocol = "shadowsocks"
	ExitSOCKS       ExitProtocol = "socks"
	ExitHysteria2   ExitProtocol = "hysteria2"
)

func (p ExitProtocol) Valid() bool {
	switch p {
	case ExitVLESS, ExitTrojan, ExitShadowsocks, ExitSOCKS, ExitHysteria2:
		return true
	}
	return false
}

// Exit is another proxy server, given to the panel as a share link, that a line's traffic can
// leave through instead of going straight out. Exits chain: NextID is the exit this one's
// traffic continues through, so line → A → B means the line's ExitID is A and A's NextID is B.
type Exit struct {
	ID   int64
	Name string
	// Region is "" or one of the region codes the panel knows (jp, kr, ...); for display only.
	Region string
	// NextID is 0 when traffic leaves this exit for the internet.
	NextID    int64
	Params    ExitParams
	CreatedAt time.Time
}

// ExitParams is everything needed to dial an exit, parsed from its share link.
// Security is none exactly when both TLS and Reality are nil.
type ExitParams struct {
	Protocol ExitProtocol
	Host     string
	Port     int
	// Secret is the VLESS id, the Trojan, Shadowsocks or SOCKS password, or the Hysteria2 auth.
	// It never leaves the server.
	Secret string
	// Username is the SOCKS user name; empty means no authentication.
	Username string
	// Method is the Shadowsocks cipher.
	Method string
	// Flow is the VLESS flow ("" or xtls-rprx-vision).
	Flow string
	// Encryption is the VLESS encryption: "none" or a VLESS Encryption string.
	Encryption string

	Transport ExitTransport
	TLS       *ExitTLS
	Reality   *ExitReality

	// ObfsPassword turns on Hysteria2 salamander obfuscation.
	ObfsPassword string
}

type ExitNetwork string

const (
	ExitRaw   ExitNetwork = "raw"
	ExitXHTTP ExitNetwork = "xhttp"
	ExitWS    ExitNetwork = "ws"
	ExitGRPC  ExitNetwork = "grpc"
)

// ExitTransport applies to VLESS and Trojan; other protocols leave it zero.
type ExitTransport struct {
	// Network "" means raw.
	Network ExitNetwork
	// Path and Host are for xhttp and ws; Mode is the xhttp mode.
	Path string
	Host string
	Mode string
	// ServiceName, Authority and MultiMode are for grpc.
	ServiceName string
	Authority   string
	MultiMode   bool
}

type ExitTLS struct {
	ServerName  string
	Fingerprint string
	ALPN        []string
	// PinSHA256 is a comma-separated list of certificate SHA-256 fingerprints in hex.
	PinSHA256 string
	// VerifyName is a comma-separated list of names to verify the certificate against.
	VerifyName string
}

type ExitReality struct {
	ServerName    string
	Fingerprint   string
	PublicKey     string
	ShortID       string
	SpiderX       string
	MLDSA65Verify string
}

// MaxExitHops is the longest chain a line may leave through.
const MaxExitHops = 4

type ChainProblem string

const (
	ChainMissing ChainProblem = "missing"
	ChainLoop    ChainProblem = "loop"
	ChainTooLong ChainProblem = "too-long"
)

// ChainError explains why a line's exits do not form a usable chain.
type ChainError struct {
	// ExitID is the exit where the walk stopped: the missing one, the one seen twice, or the first.
	ExitID  int64
	Problem ChainProblem
	// Path is the walk up to the problem, first exit first.
	Path []int64
}

func (e *ChainError) Error() string {
	ids := make([]string, len(e.Path))
	for i, id := range e.Path {
		ids[i] = strconv.FormatInt(id, 10)
	}
	path := strings.Join(ids, " -> ")
	switch e.Problem {
	case ChainMissing:
		return fmt.Sprintf("exit %d does not exist (chain %s)", e.ExitID, path)
	case ChainLoop:
		return fmt.Sprintf("exits loop: %s -> %d", path, e.ExitID)
	default:
		return fmt.Sprintf("chain %s has more than %d exits", path, MaxExitHops)
	}
}

// ExitChain follows NextID from first and returns the exits in the order traffic passes them.
func ExitChain(byID map[int64]Exit, first int64) ([]Exit, error) {
	var chain []Exit
	var path []int64
	seen := map[int64]bool{}
	for id := first; id != 0; {
		if seen[id] {
			return nil, &ChainError{ExitID: id, Problem: ChainLoop, Path: path}
		}
		e, ok := byID[id]
		if !ok {
			return nil, &ChainError{ExitID: id, Problem: ChainMissing, Path: append(path, id)}
		}
		seen[id] = true
		path = append(path, id)
		chain = append(chain, e)
		if len(chain) > MaxExitHops {
			return nil, &ChainError{ExitID: first, Problem: ChainTooLong, Path: path}
		}
		id = e.NextID
	}
	return chain, nil
}
