package panel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Link2theWorld/mintyx/internal/model"
	"github.com/Link2theWorld/mintyx/internal/share"
	"github.com/Link2theWorld/mintyx/internal/store"
)

const (
	settingPublicHost = "publicHost"
	settingSubBaseURL = "subscriptionBaseUrl"
)

var subFormats = []share.Format{share.FormatLinks, share.FormatMihomo}

// dialHost is the panel-wide host clients connect to: the publicHost setting, else the host the admin browsed to.
func (s *Server) dialHost(ctx context.Context, r *http.Request) (string, error) {
	h, _, err := s.st.GetSetting(ctx, settingPublicHost)
	if err != nil || h != "" {
		return h, err
	}
	if host, _, err := net.SplitHostPort(r.Host); err == nil {
		return host, nil
	}
	return r.Host, nil
}

func (s *Server) subBase(ctx context.Context, r *http.Request) (string, error) {
	b, _, err := s.st.GetSetting(ctx, settingSubBaseURL)
	if err != nil {
		return "", err
	}
	if b != "" {
		return strings.TrimRight(b, "/"), nil
	}
	scheme := "http"
	if s.isHTTPS(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host, nil
}

type omissionDTO struct {
	LineID   int64  `json:"lineId"`
	LineName string `json:"lineName"`
	Reason   string `json:"reason"`
}

type subscriptionDTO struct {
	Format  share.Format  `json:"format"`
	URL     string        `json:"url"`
	Omitted []omissionDTO `json:"omitted"`
}

type linkDTO struct {
	LineID   int64  `json:"lineId"`
	LineName string `json:"lineName"`
	URI      string `json:"uri"`
}

func (s *Server) shareClient(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	c, err := s.st.GetClient(ctx, id)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	lines, err := s.st.ListLines(ctx)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	host, err := s.dialHost(ctx, r)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	base, err := s.subBase(ctx, r)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	subURL := base + "/sub/" + url.PathEscape(c.SubToken)
	om := []omissionDTO{}
	for _, o := range share.Omitted(lines, host) {
		om = append(om, omissionDTO{LineID: o.LineID, LineName: o.LineName, Reason: o.Reason})
	}
	subs := make([]subscriptionDTO, 0, len(subFormats))
	for _, f := range subFormats {
		u := subURL
		if f != share.FormatLinks {
			u += "?format=" + string(f)
		}
		subs = append(subs, subscriptionDTO{Format: f, URL: u, Omitted: om})
	}
	links := []linkDTO{}
	for _, l := range lines {
		if !l.Enabled {
			continue
		}
		// An unusable line is reported through the omitted lists instead.
		if uri, err := share.Link(l, c, host); err == nil {
			links = append(links, linkDTO{LineID: l.ID, LineName: l.Name, URI: uri})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscriptions": subs, "links": links})
}

func (s *Server) getSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.st.GetClientBySubToken(ctx, r.PathValue("token"))
	if errors.Is(err, store.ErrNotFound) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		s.log.Error("panel: subscription lookup", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	format := share.Format(r.URL.Query().Get("format"))
	if format == "" {
		format = share.FormatLinks
	}
	known := false
	for _, f := range subFormats {
		known = known || f == format
	}
	if !known {
		http.Error(w, "unknown format", http.StatusBadRequest)
		return
	}
	var lines []model.Line
	var remotes []model.RemoteLine
	host := ""
	if lines, err = s.st.ListLines(ctx); err == nil {
		if remotes, err = s.st.ListRemoteLines(ctx, c.ID); err == nil {
			host, err = s.dialHost(ctx, r)
		}
	}
	var body []byte
	var ctype string
	if err == nil {
		body, ctype, err = share.Render(format, lines, remotes, c, host)
	}
	if err != nil {
		s.log.Error("panel: render subscription", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Subscription-Userinfo", share.UserInfoHeader(c))
	_, _ = w.Write(body)
}
