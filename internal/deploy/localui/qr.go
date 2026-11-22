package localui

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

const qrQuietZone = 4

// qrSVG draws text as a QR code. It is always black on white, whatever the page theme:
// phone cameras read inverted codes poorly.
func qrSVG(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	side := code.Size + 2*qrQuietZone
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`, side, side)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, side, side)
	for y := range code.Size {
		for x := range code.Size {
			if code.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+qrQuietZone, y+qrQuietZone)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}
