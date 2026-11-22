// Package hostapps installs and runs a short, fixed list of extra software on the server the
// panel lives on, through the distribution's own package manager and systemd.
package hostapps

// App is one entry of the catalog. Its name and description live in the frontend's translations.
type App struct {
	ID       string
	Category string
	// Packages are the Debian/Ubuntu package names; the first one decides whether the app is installed.
	Packages []string
	// Units are the systemd units that make up the service, main one first. Empty for a plain tool.
	Units []string
	// Ports are the TCP ports the service binds as soon as it is installed.
	Ports []int
}

const (
	CategoryWeb       = "web"
	CategoryContainer = "container"
	CategoryTools     = "tools"
)

// Catalog is deliberately closed: every command the panel runs as root is built from these
// literals, never from request data.
var Catalog = []App{
	{ID: "nginx", Category: CategoryWeb, Packages: []string{"nginx"}, Units: []string{"nginx.service"}, Ports: []int{80}},
	{ID: "caddy", Category: CategoryWeb, Packages: []string{"caddy"}, Units: []string{"caddy.service"}, Ports: []int{80}},
	// Stopping docker.service alone leaves the socket unit to start it again on the next client call.
	{ID: "docker", Category: CategoryContainer, Packages: []string{"docker.io"}, Units: []string{"docker.service", "docker.socket"}},
	{ID: "vnstat", Category: CategoryTools, Packages: []string{"vnstat"}, Units: []string{"vnstat.service"}},
	{ID: "iperf3", Category: CategoryTools, Packages: []string{"iperf3"}},
	{ID: "htop", Category: CategoryTools, Packages: []string{"htop"}},
}

func find(id string) (App, bool) {
	for _, a := range Catalog {
		if a.ID == id {
			return a, true
		}
	}
	return App{}, false
}
