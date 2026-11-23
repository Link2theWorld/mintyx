package model

import "time"

// RemoteLine is a line on another server, given to the panel as the share link that server made
// for one client. The client's subscription then lists it next to this server's own lines, so one
// subscription covers several machines. The panel never connects to it.
type RemoteLine struct {
	ID       int64
	ClientID int64
	Name     string
	// Params is the parsed link; Secret is the client's credential on the other server.
	Params    ExitParams
	CreatedAt time.Time
}
