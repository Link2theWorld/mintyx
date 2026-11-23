package probe

import (
	"crypto/x509"
	"strings"
)

// popularDests are the cover sites REALITY guides and one-click scripts name most often. So many
// servers borrow them that a server claiming to be one of them, from an address that plainly is
// not theirs, stands out; a candidate that matches is never suggested.
//
// A name matches a brand when one of its labels is a brand label (apple matches www.apple.com.cn
// but not www.applebees.com), or when it is one of the brand's other domains or a name under one.
var popularDests = []struct {
	brand   string
	labels  []string
	domains []string
}{
	{"Microsoft", []string{"microsoft"}, []string{"live.com", "bing.com", "office.com", "msn.com", "azure.com", "xbox.com", "windows.com"}},
	{"Apple", []string{"apple"}, []string{"icloud.com", "cdn-apple.com", "mzstatic.com", "itunes.com"}},
	{"Cloudflare", []string{"cloudflare"}, []string{"cloudflaressl.com", "cloudflare-dns.com", "one.one.one.one", "workers.dev", "pages.dev"}},
	{"lovelive-anime.jp", nil, []string{"lovelive-anime.jp"}},
	{"Speedtest", []string{"speedtest"}, []string{"ookla.com"}},
	{"Discord", []string{"discord", "discordapp"}, []string{"discord.gg", "discord.media"}},
}

// PopularDest names the brand when host is one of popularDests, and returns "" otherwise.
// A leading "*." (a wildcard certificate name) is ignored.
func PopularDest(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	host = strings.TrimPrefix(host, "*.")
	if host == "" {
		return ""
	}
	labels := strings.Split(host, ".")
	for _, p := range popularDests {
		for _, d := range p.domains {
			if host == d || strings.HasSuffix(host, "."+d) {
				return p.brand
			}
		}
		for _, want := range p.labels {
			for _, l := range labels {
				if l == want {
					return p.brand
				}
			}
		}
	}
	return ""
}

// popularCert names the brand when the certificate a candidate presents gives it away as one
// of popularDests: a name on it is one, or Cloudflare issued it, which it does only for sites
// it fronts. The handshake shows this for free; a site behind Cloudflare is caught too, since
// its addresses are Cloudflare's and the cover would not match them.
func popularCert(cert *x509.Certificate) string {
	for _, name := range append([]string{cert.Subject.CommonName}, cert.DNSNames...) {
		if brand := PopularDest(name); brand != "" {
			return brand
		}
	}
	for _, org := range cert.Issuer.Organization {
		if strings.Contains(strings.ToLower(org), "cloudflare") {
			return "Cloudflare"
		}
	}
	return ""
}
