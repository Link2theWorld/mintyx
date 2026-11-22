package attack

import (
	"fmt"
	"strings"

	"github.com/ysuhao/mintyx-next/internal/model"
)

// kindPhrase names each kind the way an abuse desk would expect to read it.
var kindPhrase = map[Kind]string{
	SSHLogin:       "SSH login attempts (password guessing)",
	SSHInvalidUser: "SSH login attempts with user names that do not exist",
	SSHScan:        "SSH port scanning",
	LineProbe:      "unsolicited connections probing a TLS service",
	LineBadAuth:    "connection attempts with invalid credentials",
}

const reportTime = "2006-01-02 15:04:05"

// Report drafts the complaint the owner sends to the network's abuse contact. It is in English,
// the working language of abuse desks. target is the attacked server's address, "" when not known.
func Report(a model.Attacker, target string) (subject, body string) {
	what := "unsolicited connection attempts"
	if len(a.Kinds) == 1 {
		if p, ok := kindPhrase[Kind(a.Kinds[0].Kind)]; ok {
			what = p
		}
	} else if len(a.Kinds) > 1 && strings.HasPrefix(a.Kinds[0].Kind, "ssh_") {
		what = "SSH brute-force attempts"
	}
	subject = fmt.Sprintf("Abuse report: %s from %s", what, a.IP)

	var b strings.Builder
	b.WriteString("Hello,\n\n")
	b.WriteString("A server I operate has been receiving unsolicited connection attempts from an IP address ")
	if a.Network != "" {
		fmt.Fprintf(&b, "registered to your network (%s). ", a.Network)
	} else {
		b.WriteString("in your network. ")
	}
	b.WriteString("Please investigate and take appropriate action.\n\n")

	fmt.Fprintf(&b, "Source IP:   %s\n", a.IP)
	if a.NetRange != "" {
		fmt.Fprintf(&b, "Network:     %s\n", a.NetRange)
	}
	if target == "" {
		target = "[your server's IP address]"
	}
	fmt.Fprintf(&b, "Destination: %s\n", target)
	fmt.Fprintf(&b, "First seen:  %s UTC\n", a.FirstAt.UTC().Format(reportTime))
	fmt.Fprintf(&b, "Last seen:   %s UTC\n", a.LastAt.UTC().Format(reportTime))
	b.WriteString("\nActivity (all times are UTC):\n")
	for _, k := range a.Kinds {
		phrase, ok := kindPhrase[Kind(k.Kind)]
		if !ok {
			phrase = k.Kind
		}
		fmt.Fprintf(&b, "- %s: %d, between %s and %s\n", phrase, k.Hits, k.FirstAt.UTC().Format(reportTime), k.LastAt.UTC().Format(reportTime))
	}
	b.WriteString("\nLog excerpts:\n")
	for _, k := range a.Kinds {
		for _, s := range k.Samples {
			fmt.Fprintf(&b, "%s UTC  %s\n", s.At.UTC().Format(reportTime), s.Line)
		}
	}
	b.WriteString("\nThank you for your help.\n")
	return subject, b.String()
}
