package app

import (
	"strings"
	"time"

	"github.com/ysuhao/mintyx-next/internal/attack"
)

// XrayTap is the supervisor's OnLine hook: every line goes to the attack collector, and the
// info and debug chatter is kept out of the log the panel shows, which stays what it was at
// Xray's default level.
func XrayTap(c *attack.Collector, now func() time.Time) func(line string) bool {
	return func(line string) bool {
		c.Xray(now(), line)
		return !strings.Contains(line, " [Info] ") && !strings.Contains(line, " [Debug] ")
	}
}
