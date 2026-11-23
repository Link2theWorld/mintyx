package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Link2theWorld/mintyx/internal/exitlink"
	"github.com/Link2theWorld/mintyx/internal/model"
	"github.com/Link2theWorld/mintyx/internal/probe"
)

// exitSummary describes an exit without any of its credentials.
type exitSummary struct {
	Protocol   model.ExitProtocol `json:"protocol"`
	Host       string             `json:"host"`
	Port       int                `json:"port"`
	Network    string             `json:"network"`
	Security   string             `json:"security"`
	ServerName string             `json:"serverName"`
	Flow       string             `json:"flow"`
	Method     string             `json:"method"`
	// Auth: a SOCKS exit with a user name. Obfs: Hysteria2 salamander. Pinned: a certificate pin.
	Auth   bool `json:"auth"`
	Obfs   bool `json:"obfs"`
	Pinned bool `json:"pinned"`
	// Plaintext: traffic to this exit is not encrypted (SOCKS, or VLESS/Trojan on a private address).
	Plaintext bool `json:"plaintext"`
	// UDP: the exit is reached over UDP (Hysteria2), which a TCP latency check cannot measure.
	UDP bool `json:"udp"`
}

func summarize(p model.ExitParams) exitSummary {
	s := exitSummary{Protocol: p.Protocol, Host: p.Host, Port: p.Port, Network: string(p.Transport.Network), Flow: p.Flow,
		Method: p.Method, Auth: p.Username != "", Obfs: p.ObfsPassword != ""}
	switch {
	case p.Reality != nil:
		s.Security, s.ServerName = "reality", p.Reality.ServerName
	case p.TLS != nil:
		s.Security, s.ServerName, s.Pinned = "tls", p.TLS.ServerName, p.TLS.PinSHA256 != ""
	default:
		s.Security = "none"
	}
	switch p.Protocol {
	case model.ExitSOCKS:
		s.Plaintext = true
	case model.ExitVLESS:
		s.Plaintext = s.Security == "none" && (p.Encryption == "" || p.Encryption == "none")
	case model.ExitTrojan:
		s.Plaintext = s.Security == "none"
	case model.ExitHysteria2:
		s.UDP = true
	}
	return s
}

type exitDTO struct {
	ID        int64       `json:"id"`
	Name      string      `json:"name"`
	Region    string      `json:"region"`
	NextID    *int64      `json:"nextId"`
	CreatedAt time.Time   `json:"createdAt"`
	Summary   exitSummary `json:"summary"`
}

func optionalID(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
}

func exitToDTO(e model.Exit) exitDTO {
	return exitDTO{ID: e.ID, Name: e.Name, Region: e.Region, NextID: optionalID(e.NextID), CreatedAt: e.CreatedAt, Summary: summarize(e.Params)}
}

type exitInput struct {
	Name   string `json:"name"`
	Region string `json:"region"`
	// Link is required on create; on update an empty link keeps the stored parameters.
	Link string `json:"link"`
}

// parseLink maps the parser's error onto the API's field convention: link.<part>.
func parseLink(link string) (model.ExitParams, string, error) {
	p, name, err := exitlink.Parse(link)
	var le *exitlink.Error
	if errors.As(err, &le) {
		return p, name, invalid("link."+le.Part, le.Problem)
	}
	return p, name, err
}

// pointsAtSelf reports whether an exit would dial one of this panel's own lines, which would
// loop traffic through the server until it runs out of connections.
func (s *Server) pointsAtSelf(ctx context.Context, r *http.Request, p model.ExitParams) (bool, error) {
	clients, err := s.st.ListClients(ctx)
	if err != nil {
		return false, err
	}
	for _, c := range clients {
		if p.Secret != "" && p.Secret == c.Secret {
			return true, nil
		}
	}
	lines, err := s.st.ListLines(ctx)
	if err != nil {
		return false, err
	}
	public, err := s.dialHost(ctx, r)
	if err != nil {
		return false, err
	}
	for _, l := range lines {
		if !l.Enabled || l.Port != p.Port || l.Protocol.Network() != p.Protocol.Network() {
			continue
		}
		host := l.Host
		if host == "" {
			host = public
		}
		if sameDialHost(host, p.Host) {
			return true, nil
		}
	}
	return false, nil
}

// sameDialHost compares two dial hosts as endpoints, not strings: share-link parsing writes
// IP literals in canonical form while a line or publicHost keeps the spelling the admin typed.
func sameDialHost(a, b string) bool {
	a, b = unbracketHost(a), unbracketHost(b)
	if ip, err := netip.ParseAddr(a); err == nil {
		other, err := netip.ParseAddr(b)
		return err == nil && ip.Unmap() == other.Unmap()
	}
	return strings.EqualFold(a, b)
}

func unbracketHost(h string) string {
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		return h[1 : len(h)-1]
	}
	return h
}

func validRegion(region string) bool { return region == "" || probe.KnownRegion(region) }

func (s *Server) listExits(w http.ResponseWriter, r *http.Request) {
	exits, err := s.st.ListExits(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	out := make([]exitDTO, 0, len(exits))
	for _, e := range exits {
		out = append(out, exitToDTO(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"exits": out})
}

// parseExit previews a link: what the panel understood, nothing saved.
func (s *Server) parseExit(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Link string `json:"link"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	p, name, err := parseLink(in.Link)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "summary": summarize(p)})
}

// exitName picks the name to store: the admin's, else the link's #fragment, else "PROTOCOL host".
func exitName(given, fromLink string, p model.ExitParams) string {
	for _, n := range []string{given, fromLink} {
		if n = strings.TrimSpace(n); n != "" {
			return truncateRunes(n, maxNameRunes)
		}
	}
	return truncateRunes(strings.ToUpper(string(p.Protocol))+" "+p.Host, maxNameRunes)
}

func (s *Server) createExit(w http.ResponseWriter, r *http.Request) {
	var in exitInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if !validRegion(in.Region) {
		s.writeFail(w, invalid("region", "unknown region"))
		return
	}
	if strings.TrimSpace(in.Link) == "" {
		s.writeFail(w, invalid("link", "paste the exit server's share link"))
		return
	}
	p, linkName, err := parseLink(in.Link)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	e := model.Exit{Name: exitName(in.Name, linkName, p), Region: in.Region, Params: p}
	if err := validateName("name", e.Name); err != nil {
		s.writeFail(w, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if self, err := s.pointsAtSelf(r.Context(), r, p); err != nil {
		s.writeFail(w, err)
		return
	} else if self {
		s.writeFail(w, invalid("link", "this link points at one of this panel's own lines"))
		return
	}
	if err := s.st.CreateExit(r.Context(), &e); err != nil {
		s.writeFail(w, err)
		return
	}
	sum := summarize(p)
	s.audit(r, "exit.create", e.Name, fmt.Sprintf("%s %s %s", sum.Protocol, sum.Security, net.JoinHostPort(sum.Host, strconv.Itoa(sum.Port))))
	// A new exit is not wired to anything yet, so the config does not change and Xray keeps running.
	writeJSON(w, http.StatusCreated, exitToDTO(e))
}

func (s *Server) updateExit(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in exitInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if !validRegion(in.Region) {
		s.writeFail(w, invalid("region", "unknown region"))
		return
	}
	var params *model.ExitParams
	linkName := ""
	if strings.TrimSpace(in.Link) != "" {
		p, n, err := parseLink(in.Link)
		if err != nil {
			s.writeFail(w, err)
			return
		}
		params, linkName = &p, n
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	wasRefused := s.configRefused
	e, err := s.st.GetExit(r.Context(), id)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	before := e
	detail := ""
	if params != nil {
		if self, err := s.pointsAtSelf(r.Context(), r, *params); err != nil {
			s.writeFail(w, err)
			return
		} else if self {
			s.writeFail(w, invalid("link", "this link points at one of this panel's own lines"))
			return
		}
		e.Params, detail = *params, "link replaced"
	}
	e.Name, e.Region = exitName(in.Name, linkName, e.Params), in.Region
	if err := validateName("name", e.Name); err != nil {
		s.writeFail(w, err)
		return
	}
	if err := s.st.UpdateExit(r.Context(), &e); err != nil {
		s.writeFail(w, err)
		return
	}
	ctx := context.WithoutCancel(r.Context())
	syncErr := s.syncLocked(ctx)
	// A name/region-only edit cannot be what Xray refused (neither is in the config), so only
	// link replacements roll back. When one does, the whole edit is undone so the 400 "nothing
	// was changed" response stays truthful and the old link is not left with the refused link's
	// name or region.
	if params != nil && errors.Is(syncErr, ErrConfigRejected) {
		undone, err := s.undoRefused(ctx, wasRefused,
			func(ctx context.Context) error { return s.st.UpdateExit(ctx, &before) },
			func(ctx context.Context) error { return s.st.UpdateExit(ctx, &e) })
		if err != nil {
			s.writeFail(w, errors.Join(syncErr, err))
			return
		}
		if undone {
			s.writeFail(w, invalid("link", "Xray refused this exit, so nothing was changed: "+syncErr.Error()))
			return
		}
	}
	s.forgetLatency(id)
	s.audit(r, "exit.update", e.Name, detail)
	respondSynced(w, syncErr, http.StatusOK, exitToDTO(e))
}

// copyExit duplicates an exit, credentials and all, without them passing through the browser.
// The copy is unwired: one server can then be both a last hop and a middle hop, which a single
// exit cannot, since its next hop is fixed.
func (s *Server) copyExit(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	src, err := s.st.GetExit(r.Context(), id)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	exits, err := s.st.ListExits(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	taken := map[string]bool{}
	for _, e := range exits {
		taken[e.Name] = true
	}
	// The base is shortened so " (n)" always fits: truncating the whole name could cut the
	// suffix off and hand back a name that is already taken, forever.
	name := ""
	for n := 2; name == "" || taken[name]; n++ {
		if n > len(exits)+2 {
			s.writeFail(w, invalid("name", "no free name for the copy"))
			return
		}
		suffix := fmt.Sprintf(" (%d)", n)
		name = truncateRunes(src.Name, maxNameRunes-utf8.RuneCountInString(suffix)) + suffix
	}
	cp := model.Exit{Name: name, Region: src.Region, Params: src.Params}
	if err := s.st.CreateExit(r.Context(), &cp); err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "exit.create", cp.Name, "copy of "+src.Name)
	writeJSON(w, http.StatusCreated, exitToDTO(cp))
}

// deleteExit refuses to silently change where traffic goes: when lines or exits still send
// traffic through this exit it answers 409 unless the request says ?unlink=1.
func (s *Server) deleteExit(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.st.GetExit(r.Context(), id)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	refs, err := s.exitReferrers(r.Context(), id)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	if len(refs) > 0 && r.URL.Query().Get("unlink") != "1" {
		writeErr(w, http.StatusConflict, codeConflict, "still used by "+strings.Join(refs, ", "), "exit")
		return
	}
	if err := s.st.DeleteExit(r.Context(), id); err != nil {
		s.writeFail(w, err)
		return
	}
	s.forgetLatency(id)
	detail := ""
	if len(refs) > 0 {
		detail = "unlinked: " + strings.Join(refs, ", ")
	}
	s.audit(r, "exit.delete", e.Name, detail)
	s.applyAndRespond(w, r, http.StatusNoContent, nil)
}

func (s *Server) exitReferrers(ctx context.Context, id int64) ([]string, error) {
	lines, err := s.st.ListLines(ctx)
	if err != nil {
		return nil, err
	}
	exits, err := s.st.ListExits(ctx)
	if err != nil {
		return nil, err
	}
	var refs []string
	for _, l := range lines {
		if l.ExitID == id {
			refs = append(refs, "line "+l.Name)
		}
	}
	for _, e := range exits {
		if e.NextID == id {
			refs = append(refs, "exit "+e.Name)
		}
	}
	return refs, nil
}

type routingDTO struct {
	Lines []lineRoute `json:"lines"`
	Exits []exitRoute `json:"exits"`
}

type lineRoute struct {
	ID int64 `json:"id"`
	// ExitID null sends the line straight to the internet.
	ExitID *int64 `json:"exitId"`
}

type exitRoute struct {
	ID     int64  `json:"id"`
	NextID *int64 `json:"nextId"`
}

func (s *Server) loadRouting(ctx context.Context) (routingDTO, error) {
	lines, err := s.st.ListLines(ctx)
	if err != nil {
		return routingDTO{}, err
	}
	exits, err := s.st.ListExits(ctx)
	if err != nil {
		return routingDTO{}, err
	}
	out := routingDTO{Lines: []lineRoute{}, Exits: []exitRoute{}}
	for _, l := range lines {
		out.Lines = append(out.Lines, lineRoute{ID: l.ID, ExitID: optionalID(l.ExitID)})
	}
	for _, e := range exits {
		out.Exits = append(out.Exits, exitRoute{ID: e.ID, NextID: optionalID(e.NextID)})
	}
	return out, nil
}

func (s *Server) getRouting(w http.ResponseWriter, r *http.Request) {
	d, err := s.loadRouting(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func derefID(id *int64) int64 {
	if id == nil {
		return 0
	}
	return *id
}

// putRouting applies several wiring changes at once, so the graph page's edits cost one
// Xray restart instead of one per edge. Entries not mentioned keep their wiring.
func (s *Server) putRouting(w http.ResponseWriter, r *http.Request) {
	var in routingDTO
	if !decodeJSON(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	wasRefused := s.configRefused
	lines, err := s.st.ListLines(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	exits, err := s.st.ListExits(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	lineByID := map[int64]model.Line{}
	lineByIDBefore := map[int64]int64{}
	for _, l := range lines {
		lineByID[l.ID] = l
		lineByIDBefore[l.ID] = l.ExitID
	}
	exitByID := map[int64]model.Exit{}
	exitNextBefore := map[int64]int64{}
	for _, e := range exits {
		exitByID[e.ID] = e
		exitNextBefore[e.ID] = e.NextID
	}

	lineExit, exitNext := map[int64]int64{}, map[int64]int64{}
	var changes []string
	for i, lr := range in.Lines {
		field := fmt.Sprintf("lines[%d]", i)
		l, ok := lineByID[lr.ID]
		if !ok {
			s.writeFail(w, invalid(field+".id", "no such line"))
			return
		}
		if _, dup := lineExit[lr.ID]; dup {
			s.writeFail(w, invalid(field+".id", "line listed twice"))
			return
		}
		target := derefID(lr.ExitID)
		if _, ok := exitByID[target]; target != 0 && !ok {
			s.writeFail(w, invalid(field+".exitId", "no such exit"))
			return
		}
		lineExit[lr.ID] = target
		if l.ExitID != target {
			changes = append(changes, "line "+l.Name+" → "+s.routeName(exitByID, target))
			l.ExitID = target
			lineByID[l.ID] = l
		}
	}
	for i, er := range in.Exits {
		field := fmt.Sprintf("exits[%d]", i)
		e, ok := exitByID[er.ID]
		if !ok {
			s.writeFail(w, invalid(field+".id", "no such exit"))
			return
		}
		if _, dup := exitNext[er.ID]; dup {
			s.writeFail(w, invalid(field+".id", "exit listed twice"))
			return
		}
		target := derefID(er.NextID)
		if _, ok := exitByID[target]; target != 0 && !ok {
			s.writeFail(w, invalid(field+".nextId", "no such exit"))
			return
		}
		exitNext[er.ID] = target
		if e.NextID != target {
			changes = append(changes, "exit "+e.Name+" → "+s.routeName(exitByID, target))
			e.NextID = target
			exitByID[e.ID] = e
		}
	}
	// Every exit's onward chain must be finite and short, wired or not, so any line can use it.
	for _, e := range exits {
		if _, err := model.ExitChain(exitByID, e.ID); err != nil {
			s.writeFail(w, routingError(in, exitByID, e.ID, err))
			return
		}
	}
	// What every entry pointed at before, to put back if Xray refuses the new wiring.
	prevLines, prevExits := map[int64]int64{}, map[int64]int64{}
	for id := range lineExit {
		prevLines[id] = lineByIDBefore[id]
	}
	for id := range exitNext {
		prevExits[id] = exitNextBefore[id]
	}
	if err := s.st.SetRouting(r.Context(), lineExit, exitNext); err != nil {
		s.writeFail(w, err)
		return
	}
	ctx := context.WithoutCancel(r.Context())
	syncErr := s.syncLocked(ctx)
	if errors.Is(syncErr, ErrConfigRejected) {
		undone, err := s.undoRefused(ctx, wasRefused,
			func(ctx context.Context) error { return s.st.SetRouting(ctx, prevLines, prevExits) },
			func(ctx context.Context) error { return s.st.SetRouting(ctx, lineExit, exitNext) })
		if err != nil {
			s.writeFail(w, errors.Join(syncErr, err))
			return
		}
		if undone {
			s.writeFail(w, invalid("routing", "Xray refused this wiring, so nothing was changed: "+syncErr.Error()))
			return
		}
	}
	if len(changes) > 0 {
		s.audit(r, "routing.update", "routing", strings.Join(changes, "; "))
	}
	out, err := s.loadRouting(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	respondSynced(w, syncErr, http.StatusOK, out)
}

func (s *Server) routeName(exits map[int64]model.Exit, id int64) string {
	if id == 0 {
		return "internet"
	}
	return "exit " + exits[id].Name
}

// routingError names the request entry that closed a loop or made a chain too long.
func routingError(in routingDTO, exits map[int64]model.Exit, start int64, err error) error {
	var ce *model.ChainError
	if !errors.As(err, &ce) {
		return err
	}
	names := make([]string, 0, len(ce.Path)+1)
	for _, id := range ce.Path {
		names = append(names, exits[id].Name)
	}
	field := "exits"
	for i, er := range in.Exits {
		if slices.Contains(ce.Path, er.ID) {
			field = fmt.Sprintf("exits[%d].nextId", i)
		}
	}
	switch ce.Problem {
	case model.ChainLoop:
		names = append(names, exits[ce.ExitID].Name)
		return invalid(field, strings.Join(names, " → ")+" forms a loop")
	case model.ChainTooLong:
		return invalid(field, fmt.Sprintf("the chain from %s has more than %d exits", exits[start].Name, model.MaxExitHops))
	}
	return invalid(field, ce.Error())
}

// latencyEntry is a cached measurement from this server to one exit.
type latencyEntry struct {
	addr string
	rtt  time.Duration
	err  string
	at   time.Time
}

const (
	latencyTTL      = time.Minute
	latencyMinForce = 30 * time.Second
	latencyRound    = 10 * time.Second
	latencyParallel = 8
)

type latencyState struct {
	mu         sync.Mutex
	cache      map[int64]latencyEntry
	refreshing bool
	lastForced time.Time
}

func (s *Server) forgetLatency(id int64) {
	s.latency.mu.Lock()
	delete(s.latency.cache, id)
	s.latency.mu.Unlock()
}

type exitLatencyDTO struct {
	ID         int64      `json:"id"`
	RTTMs      *int64     `json:"rttMs"`
	MeasuredAt *time.Time `json:"measuredAt"`
	// Unmeasured explains a missing value: "udp" (Hysteria2) or "inner" (only reached through another exit).
	Unmeasured string `json:"unmeasured,omitempty"`
	Error      string `json:"error,omitempty"`
}

// measurable tells which exits a TCP check from this server says something true about.
// An exit used only behind another exit is never dialled from here, so dialling it directly
// would measure a path the traffic does not take, and opens the very link the chain avoids.
func measurable(lines []model.Line, exits []model.Exit) map[int64]string {
	why := map[int64]string{}
	first := map[int64]bool{}
	for _, l := range lines {
		if l.ExitID != 0 {
			first[l.ExitID] = true
		}
	}
	inner := map[int64]bool{}
	for _, e := range exits {
		if e.NextID != 0 {
			inner[e.NextID] = true
		}
	}
	for _, e := range exits {
		switch {
		case e.Params.Protocol == model.ExitHysteria2:
			why[e.ID] = "udp"
		case inner[e.ID] && !first[e.ID]:
			why[e.ID] = "inner"
		}
	}
	return why
}

func (s *Server) exitLatency(w http.ResponseWriter, r *http.Request) {
	force := r.Method == http.MethodPost
	lines, err := s.st.ListLines(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	exits, err := s.st.ListExits(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	skip := measurable(lines, exits)
	now := s.now()

	st := &s.latency
	st.mu.Lock()
	if force {
		if wait := latencyMinForce - now.Sub(st.lastForced); wait > 0 {
			st.mu.Unlock()
			s.writeRateLimited(w, wait)
			return
		}
		st.lastForced = now
	}
	out := make([]exitLatencyDTO, 0, len(exits))
	var stale []model.Exit
	for _, e := range exits {
		d := exitLatencyDTO{ID: e.ID, Unmeasured: skip[e.ID]}
		if d.Unmeasured == "" {
			addr := net.JoinHostPort(e.Params.Host, strconv.Itoa(e.Params.Port))
			c, ok := st.cache[e.ID]
			if ok && c.addr == addr {
				at := c.at
				d.MeasuredAt, d.Error = &at, c.err
				if c.err == "" {
					ms := c.rtt.Milliseconds()
					d.RTTMs = &ms
				}
			}
			if force || !ok || c.addr != addr || now.Sub(c.at) >= latencyTTL {
				stale = append(stale, e)
			}
		}
		out = append(out, d)
	}
	if len(stale) > 0 && !st.refreshing {
		st.refreshing = true
		go s.refreshLatency(stale)
	}
	refreshing := st.refreshing
	st.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"refreshing": refreshing, "exits": out})
}

// refreshLatency measures the given exits a few at a time, without holding s.mu.
func (s *Server) refreshLatency(exits []model.Exit) {
	ctx, cancel := context.WithTimeout(context.Background(), latencyRound)
	defer cancel()
	sem := make(chan struct{}, latencyParallel)
	var wg sync.WaitGroup
	for _, e := range exits {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			entry := latencyEntry{addr: net.JoinHostPort(e.Params.Host, strconv.Itoa(e.Params.Port))}
			rtt, err := s.exitRTT(ctx, e.Params.Host, e.Params.Port)
			entry.rtt, entry.at = rtt, s.now()
			if err != nil {
				entry.err = err.Error()
			}
			s.latency.mu.Lock()
			s.latency.cache[e.ID] = entry
			s.latency.mu.Unlock()
		}()
	}
	wg.Wait()
	s.latency.mu.Lock()
	s.latency.refreshing = false
	s.latency.mu.Unlock()
}

const settingGraphLayout = "graph.layout"

type nodePosition struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// getGraphLayout returns where the admin last placed each node on the route graph.
func (s *Server) getGraphLayout(w http.ResponseWriter, r *http.Request) {
	raw, found, err := s.st.GetSetting(r.Context(), settingGraphLayout)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	layout := map[string]nodePosition{}
	if found {
		_ = json.Unmarshal([]byte(raw), &layout)
	}
	if layout == nil {
		layout = map[string]nodePosition{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"positions": layout})
}

func (s *Server) putGraphLayout(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Positions map[string]nodePosition `json:"positions"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Positions == nil {
		in.Positions = map[string]nodePosition{}
	}
	if len(in.Positions) > 2000 {
		s.writeFail(w, invalid("positions", "too many nodes"))
		return
	}
	for id, p := range in.Positions {
		if len(id) > 64 || p.X != p.X || p.Y != p.Y || p.X > 1e7 || p.X < -1e7 || p.Y > 1e7 || p.Y < -1e7 {
			s.writeFail(w, invalid("positions", "node positions must be finite numbers"))
			return
		}
	}
	raw, err := json.Marshal(in.Positions)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	if err := s.st.SetSetting(r.Context(), settingGraphLayout, string(raw)); err != nil {
		s.writeFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
