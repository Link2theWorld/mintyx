package share

import "github.com/Link2theWorld/mintyx/internal/model"

// DialAddress is the host and port a client's share link points at for this line, e.g. the
// CDN edge on 443 for a plain XHTTP line. It fails for a line no link can be built for.
func DialAddress(line model.Line, defaultHost string) (host string, port int, err error) {
	// The address does not depend on the client; resolve only insists that one has a secret.
	ep, err := resolve(line, model.Client{Secret: "-"}, defaultHost)
	if err != nil {
		return "", 0, err
	}
	return ep.host, ep.port, nil
}
