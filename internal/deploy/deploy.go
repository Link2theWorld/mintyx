package deploy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AdminUser is the panel account the deployer creates on a fresh server.
const AdminUser = "admin"

type StepID string

const (
	StepInspect  StepID = "inspect"
	StepPanel    StepID = "panel"
	StepXray     StepID = "xray"
	StepService  StepID = "service"
	StepSetup    StepID = "setup"
	StepLine     StepID = "line"
	StepFirewall StepID = "firewall"
)

// Steps lists every step in the order Deploy runs them.
var Steps = []StepID{StepInspect, StepPanel, StepXray, StepService, StepSetup, StepLine, StepFirewall}

type StepStatus string

const (
	StatusRunning StepStatus = "running"
	StatusDone    StepStatus = "done"
	StatusSkipped StepStatus = "skipped"
	StatusFailed  StepStatus = "failed"
)

// Regions are the codes the panel's draft endpoint understands; "" means "not sure".
var Regions = []string{"jp", "kr", "hk", "tw", "sg", "us", "eu", "other"}

var (
	// ErrNoPayload means this build of the deployer carries no panel binary for the server's CPU.
	ErrNoPayload = errors.New("this build does not include the panel program for the server")
	// ErrNoCoverSite means the panel found no website it could use as the REALITY cover site.
	ErrNoCoverSite = errors.New("the panel found no reachable cover site for REALITY")
	// ErrPanelNotAnswering means the service was started but its API never came up.
	ErrPanelNotAnswering = errors.New("the panel was started but does not answer")
)

// UnsupportedError means the server is not something the deployer can set up.
type UnsupportedError struct{ Reason string }

func (e *UnsupportedError) Error() string { return "unsupported server: " + e.Reason }

type Request struct {
	// Region is one of Regions or "".
	Region string
	// ClientName names the first client; empty means "Device 1".
	ClientName string
	// PanelBinary returns the Linux panel executable for "amd64" or "arm64", or ErrNoPayload.
	PanelBinary func(arch string) ([]byte, error)
	// Report is called as each step starts and ends; nil is allowed.
	Report func(step StepID, status StepStatus, detail string)
	// PanelWait bounds how long the freshly started panel may take to answer; zero means 45s.
	PanelWait time.Duration
	// AdminPassword is the password an earlier, unfinished run set for AdminUser. With it a retry
	// logs in and finishes the line and firewall steps instead of treating the panel as someone else's.
	AdminPassword string
}

// Result is filled in as far as the deploy got, also when Deploy returns an error:
// an admin password that was already set on the server must still reach the user.
type Result struct {
	Arch            string
	AlreadyDeployed bool
	AdminUser       string
	AdminPassword   string
	Link            string
	LineName        string
	Port            int
	// Firewall is "ufw", "firewalld" or "none".
	Firewall string
}

type deployRun struct {
	c   *Client
	req Request
	res *Result
	cur StepID
}

func (d *deployRun) report(step StepID, status StepStatus, detail string) {
	if d.req.Report != nil {
		d.req.Report(step, status, detail)
	}
}

// step runs fn between a "running" and a "done"/"failed" report; fn returns the detail shown when done.
func (d *deployRun) step(id StepID, fn func() (string, error)) error {
	d.cur = id
	d.report(id, StatusRunning, "")
	detail, err := fn()
	if err != nil {
		d.report(id, StatusFailed, err.Error())
		return err
	}
	d.report(id, StatusDone, detail)
	return nil
}

func goArch(uname string) (string, bool) {
	switch uname {
	case "x86_64", "amd64":
		return "amd64", true
	case "aarch64", "arm64":
		return "arm64", true
	}
	return "", false
}

// Deploy prepares the server and creates the first line. Every step is safe to repeat.
func (c *Client) Deploy(ctx context.Context, req Request) (*Result, error) {
	if req.Region != "" && !contains(Regions, req.Region) {
		return nil, fmt.Errorf("unknown region %q", req.Region)
	}
	if req.PanelBinary == nil {
		return nil, ErrNoPayload
	}
	d := &deployRun{c: c, req: req, res: &Result{}}
	return d.res, d.run(ctx)
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func (d *deployRun) run(ctx context.Context) error {
	var binary []byte
	if err := d.step(StepInspect, func() (string, error) {
		out, err := d.c.RunRoot(ctx, Script{Name: "inspect", Body: inspectBody})
		if err != nil {
			return "", err
		}
		v := out.Values()
		if v["os"] != "Linux" {
			return "", &UnsupportedError{Reason: "it runs " + v["os"] + ", not Linux"}
		}
		arch, ok := goArch(v["arch"])
		if !ok {
			return "", &UnsupportedError{Reason: "its CPU is " + v["arch"] + "; only x86_64 and arm64 are supported"}
		}
		if v["systemd"] != "1" {
			return "", &UnsupportedError{Reason: "it does not use systemd"}
		}
		d.res.Arch = arch
		// Asked for here so a build without the payload stops before anything is changed.
		if binary, err = d.req.PanelBinary(arch); err != nil {
			return "", err
		}
		return "linux/" + arch, nil
	}); err != nil {
		return err
	}

	binaryChanged := false
	if err := d.step(StepPanel, func() (string, error) {
		sum := sha256.Sum256(binary)
		have, err := d.c.remoteSHA256(ctx, PanelBinaryPath)
		if err != nil {
			return "", err
		}
		if have == hex.EncodeToString(sum[:]) {
			return "unchanged", nil
		}
		binaryChanged = true
		return "uploaded", d.c.Upload(ctx, bytes.NewReader(binary), PanelBinaryPath, "0755")
	}); err != nil {
		return err
	}

	if err := d.step(StepXray, func() (string, error) {
		asset := xrayAssets[d.res.Arch]
		out, err := d.c.RunRoot(ctx, Script{Name: "xray-install", Body: xrayInstallBody, Vars: []Var{
			{"DIR", XrayDir}, {"VERSION", XrayVersion}, {"BASE", xrayReleaseBase},
			{"ASSET", asset.name}, {"PINNED", asset.sha256},
		}})
		if err != nil {
			return "", xrayProblem(out, err)
		}
		return XrayVersion + " " + out.Values()["xray"], nil
	}); err != nil {
		return err
	}

	p := d.c.panel()
	defer p.close()
	var session struct {
		NeedsSetup bool `json:"needsSetup"`
	}
	if err := d.step(StepService, func() (string, error) {
		restart := "0"
		if binaryChanged {
			restart = "1"
		}
		out, err := d.c.RunRoot(ctx, Script{Name: "service", Body: serviceBody, Vars: []Var{
			{"DATA", DataDir}, {"UNIT_PATH", UnitPath}, {"UNIT", unitFile}, {"RESTART", restart},
		}})
		if err != nil {
			return "", err
		}
		if err := d.waitForPanel(ctx, p, &session); err != nil {
			return "", err
		}
		return out.Values()["service"], nil
	}); err != nil {
		return err
	}

	if !session.NeedsSetup && d.req.AdminPassword == "" {
		// Someone already chose this panel's password; the deployer has no business guessing it.
		d.res.AlreadyDeployed = true
		for _, id := range []StepID{StepSetup, StepLine, StepFirewall} {
			d.report(id, StatusSkipped, "")
		}
		return nil
	}

	if err := d.step(StepSetup, func() (string, error) {
		detail := ""
		if session.NeedsSetup {
			password, err := newPassword()
			if err != nil {
				return "", err
			}
			creds := map[string]string{"username": AdminUser, "password": password}
			if err := p.do(ctx, http.MethodPost, "/api/setup", creds, nil); err != nil {
				return "", err
			}
			d.res.AdminUser, d.res.AdminPassword = AdminUser, password
		} else {
			// An earlier run set the password and stopped later on; pick up where it left off.
			d.res.AdminUser, d.res.AdminPassword = AdminUser, d.req.AdminPassword
			creds := map[string]string{"username": AdminUser, "password": d.req.AdminPassword}
			if err := p.do(ctx, http.MethodPost, "/api/login", creds, nil); err != nil {
				return "", err
			}
			detail = "resumed"
		}
		settings := map[string]string{"publicHost": d.c.target.Host, "subscriptionBaseUrl": ""}
		return detail, p.do(ctx, http.MethodPut, "/api/settings", settings, nil)
	}); err != nil {
		return err
	}

	if err := d.step(StepLine, func() (string, error) { return d.createLine(ctx, p) }); err != nil {
		return err
	}

	return d.step(StepFirewall, func() (string, error) {
		out, err := d.c.RunRoot(ctx, Script{Name: "firewall", Body: firewallBody, Vars: []Var{{"PORT", strconv.Itoa(d.res.Port)}}})
		if err != nil {
			return "", err
		}
		d.res.Firewall = out.Values()["firewall"]
		return d.res.Firewall, nil
	})
}

func xrayProblem(out Output, err error) error {
	switch out.Values()["problem"] {
	case "no-downloader":
		return fmt.Errorf("the server has neither curl nor wget and none could be installed: %w", err)
	case "download":
		return fmt.Errorf("the server could not download Xray from GitHub: %w", err)
	case "digest":
		return fmt.Errorf("the Xray download does not match its published checksum, nothing was installed: %w", err)
	case "unpack":
		return fmt.Errorf("the server could not unpack the Xray archive: %w", err)
	case "not-runnable":
		return fmt.Errorf("Xray was installed but does not run on this server: %w", err)
	}
	return err
}

func (d *deployRun) waitForPanel(ctx context.Context, p *panelClient, session any) error {
	wait := d.req.PanelWait
	if wait == 0 {
		wait = 45 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		err := p.do(ctx, http.MethodGet, "/api/session", nil, session)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			msg := err.Error()
			if out, logErr := d.c.RunRoot(ctx, Script{Name: "service-log", Body: serviceLogBody}); logErr == nil {
				if tail := lastLines(out.Stdout, 8); tail != "" {
					msg += "\n" + tail
				}
			}
			return fmt.Errorf("%w: %s", ErrPanelNotAnswering, msg)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

type panelLine struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// createLine is safe to repeat: a retry reuses the line and client an earlier run already made.
func (d *deployRun) createLine(ctx context.Context, p *panelClient) (string, error) {
	var line panelLine
	var lines struct {
		Lines []panelLine `json:"lines"`
	}
	if err := p.do(ctx, http.MethodGet, "/api/lines", nil, &lines); err != nil {
		return "", err
	}
	for _, l := range lines.Lines {
		if l.Protocol == "vless-reality" {
			line = l
			break
		}
	}
	if line.ID == 0 {
		if err := d.draftAndCreateLine(ctx, p, &line); err != nil {
			return "", err
		}
	}
	d.res.LineName, d.res.Port = line.Name, line.Port

	name := d.req.ClientName
	if name == "" {
		name = "Device 1"
	}
	var clients struct {
		Clients []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"clients"`
	}
	if err := p.do(ctx, http.MethodGet, "/api/clients", nil, &clients); err != nil {
		return "", err
	}
	var clientID int64
	for _, c := range clients.Clients {
		if c.Name == name {
			clientID = c.ID
			break
		}
	}
	if clientID == 0 {
		var client struct {
			ID int64 `json:"id"`
		}
		newClient := map[string]any{"name": name, "quotaBytes": 0, "expiresAt": nil}
		if err := p.do(ctx, http.MethodPost, "/api/clients", newClient, &client); err != nil {
			return "", err
		}
		clientID = client.ID
	}
	var share struct {
		Links []struct {
			LineID int64  `json:"lineId"`
			URI    string `json:"uri"`
		} `json:"links"`
	}
	if err := p.do(ctx, http.MethodGet, "/api/clients/"+strconv.FormatInt(clientID, 10)+"/share", nil, &share); err != nil {
		return "", err
	}
	for _, l := range share.Links {
		if l.LineID == line.ID && strings.HasPrefix(l.URI, "vless://") {
			d.res.Link = l.URI
			return "port " + strconv.Itoa(line.Port), nil
		}
	}
	return "", errors.New("the panel created the line but returned no share link for it")
}

func (d *deployRun) draftAndCreateLine(ctx context.Context, p *panelClient, line *panelLine) error {
	draftReq := map[string]string{"protocol": "vless-reality"}
	if d.req.Region != "" {
		draftReq["region"] = d.req.Region
	}
	// The draft is passed back as it came, so fields this program does not know survive.
	var draft map[string]any
	if err := p.do(ctx, http.MethodPost, "/api/lines/draft", draftReq, &draft); err != nil {
		return err
	}
	reality, _ := draft["reality"].(map[string]any)
	if site, _ := reality["serverName"].(string); site == "" {
		return ErrNoCoverSite
	}
	return p.do(ctx, http.MethodPost, "/api/lines", draft, line)
}

// newPassword returns 144 random bits as 24 URL-safe characters.
func newPassword() (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
