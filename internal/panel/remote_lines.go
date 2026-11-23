package panel

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
	"github.com/Link2theWorld/mintyx/internal/share"
)

// maxRemoteLines bounds how many other servers' lines one client's subscription merges.
const maxRemoteLines = 32

// remoteLineDTO describes a line on another server without the client's credential on it.
type remoteLineDTO struct {
	ID        int64       `json:"id"`
	Name      string      `json:"name"`
	CreatedAt time.Time   `json:"createdAt"`
	Summary   exitSummary `json:"summary"`
}

func remoteLineToDTO(r model.RemoteLine) remoteLineDTO {
	return remoteLineDTO{ID: r.ID, Name: r.Name, CreatedAt: r.CreatedAt, Summary: summarize(r.Params)}
}

type remoteLineInput struct {
	Name string `json:"name"`
	// Link is required on create; on update an empty link keeps the stored parameters.
	Link string `json:"link"`
}

// parseRemoteLink reads another server's share link and checks that every subscription format
// can list it. Errors name the bad part as link.<part>, like exit links.
func parseRemoteLink(link string) (model.ExitParams, string, error) {
	p, name, err := parseLink(link)
	if err != nil {
		return p, name, err
	}
	var re *share.RemoteError
	if err := share.CheckRemote(p); errors.As(err, &re) {
		return p, name, invalid("link."+re.Part, re.Problem)
	} else if err != nil {
		return p, name, err
	}
	return p, name, nil
}

func remoteDetail(r model.RemoteLine) string {
	sum := summarize(r.Params)
	return fmt.Sprintf("%s: %s %s %s", r.Name, sum.Protocol, sum.Security, net.JoinHostPort(sum.Host, strconv.Itoa(sum.Port)))
}

// remoteLineIDs reads {id} (the client) and {rid} (its remote line) from the path.
func remoteLineIDs(w http.ResponseWriter, r *http.Request) (clientID, id int64, ok bool) {
	if clientID, ok = pathID(w, r); !ok {
		return 0, 0, false
	}
	id, err := strconv.ParseInt(r.PathValue("rid"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusNotFound, codeNotFound, "not found", "")
		return 0, 0, false
	}
	return clientID, id, true
}

func (s *Server) listRemoteLines(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.st.GetClient(r.Context(), id); err != nil {
		s.writeFail(w, err)
		return
	}
	list, err := s.st.ListRemoteLines(r.Context(), id)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	out := make([]remoteLineDTO, 0, len(list))
	for _, rl := range list {
		out = append(out, remoteLineToDTO(rl))
	}
	writeJSON(w, http.StatusOK, map[string]any{"remoteLines": out})
}

// A remote line only changes what the subscription lists, never the Xray config, so none of
// these handlers syncs the engine.

func (s *Server) createRemoteLine(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in remoteLineInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Link) == "" {
		s.writeFail(w, invalid("link", "paste the other server's share link for this visitor"))
		return
	}
	p, linkName, err := parseRemoteLink(in.Link)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	rl := model.RemoteLine{ClientID: id, Name: exitName(in.Name, linkName, p), Params: p}
	if err := validateName("name", rl.Name); err != nil {
		s.writeFail(w, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.st.GetClient(r.Context(), id)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	existing, err := s.st.ListRemoteLines(r.Context(), id)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	if len(existing) >= maxRemoteLines {
		s.writeFail(w, invalid("link", fmt.Sprintf("a visitor can have at most %d lines from other servers", maxRemoteLines)))
		return
	}
	if self, err := s.pointsAtSelf(r.Context(), r, p); err != nil {
		s.writeFail(w, err)
		return
	} else if self {
		s.writeFail(w, invalid("link", "this link is one of this panel's own lines, which the subscription lists already"))
		return
	}
	if err := s.st.CreateRemoteLine(r.Context(), &rl); err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "client.remote-line.create", c.Name, remoteDetail(rl))
	writeJSON(w, http.StatusCreated, remoteLineToDTO(rl))
}

func (s *Server) updateRemoteLine(w http.ResponseWriter, r *http.Request) {
	clientID, id, ok := remoteLineIDs(w, r)
	if !ok {
		return
	}
	var in remoteLineInput
	if !decodeJSON(w, r, &in) {
		return
	}
	var params *model.ExitParams
	linkName := ""
	if strings.TrimSpace(in.Link) != "" {
		p, n, err := parseRemoteLink(in.Link)
		if err != nil {
			s.writeFail(w, err)
			return
		}
		params, linkName = &p, n
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.st.GetClient(r.Context(), clientID)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	rl, err := s.st.GetRemoteLine(r.Context(), clientID, id)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	if params != nil {
		if self, err := s.pointsAtSelf(r.Context(), r, *params); err != nil {
			s.writeFail(w, err)
			return
		} else if self {
			s.writeFail(w, invalid("link", "this link is one of this panel's own lines, which the subscription lists already"))
			return
		}
		rl.Params = *params
	}
	rl.Name = exitName(in.Name, linkName, rl.Params)
	if err := validateName("name", rl.Name); err != nil {
		s.writeFail(w, err)
		return
	}
	if err := s.st.UpdateRemoteLine(r.Context(), &rl); err != nil {
		s.writeFail(w, err)
		return
	}
	detail := remoteDetail(rl)
	if params != nil {
		detail += " (link replaced)"
	}
	s.audit(r, "client.remote-line.update", c.Name, detail)
	writeJSON(w, http.StatusOK, remoteLineToDTO(rl))
}

func (s *Server) deleteRemoteLine(w http.ResponseWriter, r *http.Request) {
	clientID, id, ok := remoteLineIDs(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.st.GetClient(r.Context(), clientID)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	rl, err := s.st.GetRemoteLine(r.Context(), clientID, id)
	if err == nil {
		err = s.st.DeleteRemoteLine(r.Context(), clientID, id)
	}
	if err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "client.remote-line.delete", c.Name, remoteDetail(rl))
	w.WriteHeader(http.StatusNoContent)
}
