package panel

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ysuhao/mintyx-next/internal/model"
	"github.com/ysuhao/mintyx-next/internal/quota"
)

// clientDTO deliberately leaves out Secret and SubToken; only the share endpoint reveals them.
type clientDTO struct {
	ID         int64                `json:"id"`
	Name       string               `json:"name"`
	Disabled   model.DisabledReason `json:"disabled"`
	QuotaBytes int64                `json:"quotaBytes"`
	ExpiresAt  *time.Time           `json:"expiresAt"`
	UsedUp     int64                `json:"usedUp"`
	UsedDown   int64                `json:"usedDown"`
	CreatedAt  time.Time            `json:"createdAt"`
	// QuotaResetDay is 0 for a quota that never resets; NextResetAt is then null.
	QuotaResetDay int        `json:"quotaResetDay"`
	NextResetAt   *time.Time `json:"nextResetAt"`
}

func (s *Server) clientToDTO(c model.Client, loc *time.Location) clientDTO {
	d := clientDTO{ID: c.ID, Name: c.Name, Disabled: c.Disabled, QuotaBytes: c.QuotaBytes, ExpiresAt: c.ExpiresAt,
		UsedUp: c.UsedUp, UsedDown: c.UsedDown, CreatedAt: c.CreatedAt, QuotaResetDay: c.QuotaResetDay}
	if c.QuotaResetDay > 0 {
		next := quota.NextReset(c.QuotaResetDay, s.now(), loc).UTC()
		d.NextResetAt = &next
	}
	return d
}

type clientInput struct {
	Name          string     `json:"name"`
	QuotaBytes    int64      `json:"quotaBytes"`
	ExpiresAt     *time.Time `json:"expiresAt"`
	QuotaResetDay int        `json:"quotaResetDay"`
}

// setResetDay changes a client's monthly reset day. A new or changed day starts its cycle at
// the current period without touching usage: the admin is choosing a calendar, not resetting.
func (s *Server) setResetDay(c *model.Client, day int, loc *time.Location) {
	if day == c.QuotaResetDay && (day == 0 || c.CycleStart != nil) {
		return
	}
	c.QuotaResetDay = day
	c.CycleStart = nil
	if day > 0 {
		start := quota.CycleStart(day, s.now(), loc).UTC()
		c.CycleStart = &start
	}
}

func (in *clientInput) validate() error {
	in.Name = strings.TrimSpace(in.Name)
	if err := validateName("name", in.Name); err != nil {
		return err
	}
	if in.QuotaBytes < 0 {
		return invalid("quotaBytes", "quota must not be negative")
	}
	if in.QuotaResetDay < 0 || in.QuotaResetDay > 31 {
		return invalid("quotaResetDay", "reset day must be 0 (never) or a day of the month from 1 to 31")
	}
	if in.ExpiresAt != nil {
		t := in.ExpiresAt.UTC()
		in.ExpiresAt = &t
	}
	return nil
}

// reconcile moves a client to the block state quota.Desired gives now, so a raised quota,
// a later expiry or a traffic reset lifts the block at once instead of on the next tick.
func (s *Server) reconcile(ctx context.Context, id int64) (model.Client, error) {
	c, err := s.st.GetClient(ctx, id)
	if err != nil {
		return c, err
	}
	if want := quota.Desired(c, s.now()); want != c.Disabled {
		if err := s.st.SetClientDisabled(ctx, id, want); err != nil {
			return c, err
		}
		c.Disabled = want
	}
	return c, nil
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.st.ListClients(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	loc, err := s.location(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	out := make([]clientDTO, 0, len(clients))
	for _, c := range clients {
		out = append(out, s.clientToDTO(c, loc))
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	var in clientInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := in.validate(); err != nil {
		s.writeFail(w, err)
		return
	}
	loc, err := s.location(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := model.Client{Name: in.Name, Secret: s.keys.NewUUID(), SubToken: newToken(), QuotaBytes: in.QuotaBytes, ExpiresAt: in.ExpiresAt}
	s.setResetDay(&c, in.QuotaResetDay, loc)
	c.Disabled = quota.Desired(c, s.now())
	if err := s.st.CreateClient(r.Context(), &c); err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "client.create", c.Name, "")
	s.applyAndRespond(w, r, http.StatusCreated, s.clientToDTO(c, loc))
}

func (s *Server) updateClient(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in clientInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := in.validate(); err != nil {
		s.writeFail(w, err)
		return
	}
	loc, err := s.location(r.Context())
	if err != nil {
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
	c.Name, c.QuotaBytes, c.ExpiresAt = in.Name, in.QuotaBytes, in.ExpiresAt
	s.setResetDay(&c, in.QuotaResetDay, loc)
	if err := s.st.UpdateClient(r.Context(), &c); err != nil {
		s.writeFail(w, err)
		return
	}
	if c, err = s.reconcile(r.Context(), id); err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "client.update", c.Name, "")
	s.applyAndRespond(w, r, http.StatusOK, s.clientToDTO(c, loc))
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.st.GetClient(r.Context(), id)
	if err == nil {
		err = s.st.DeleteClient(r.Context(), id)
	}
	if err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "client.delete", c.Name, "")
	s.applyAndRespond(w, r, http.StatusNoContent, nil)
}

// clientAction runs one state change on a client under s.mu, then audits and syncs.
func (s *Server) clientAction(action string, change func(ctx context.Context, c model.Client) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		c, err := s.st.GetClient(r.Context(), id)
		if err == nil {
			err = change(r.Context(), c)
		}
		if err != nil {
			s.writeFail(w, err)
			return
		}
		s.audit(r, action, c.Name, "")
		s.applyAndRespond(w, r, http.StatusNoContent, nil)
	}
}

func (s *Server) disableClient(w http.ResponseWriter, r *http.Request) {
	s.clientAction("client.disable", func(ctx context.Context, c model.Client) error {
		return s.st.SetClientDisabled(ctx, c.ID, model.DisabledManual)
	})(w, r)
}

// enableClient only lifts a manual block; a quota or expiry block stays until renewal or reset.
func (s *Server) enableClient(w http.ResponseWriter, r *http.Request) {
	s.clientAction("client.enable", func(ctx context.Context, c model.Client) error {
		was := c.Disabled
		c.Disabled = model.NotDisabled
		if want := quota.Desired(c, s.now()); want != was {
			return s.st.SetClientDisabled(ctx, c.ID, want)
		}
		return nil
	})(w, r)
}

func (s *Server) resetClientTraffic(w http.ResponseWriter, r *http.Request) {
	s.clientAction("client.reset-traffic", func(ctx context.Context, c model.Client) error {
		if err := s.st.ResetTraffic(ctx, c.ID); err != nil {
			return err
		}
		_, err := s.reconcile(ctx, c.ID)
		return err
	})(w, r)
}

func (s *Server) rotateClient(w http.ResponseWriter, r *http.Request) {
	s.clientAction("client.rotate", func(ctx context.Context, c model.Client) error {
		c.Secret, c.SubToken = s.keys.NewUUID(), newToken()
		return s.st.UpdateClient(ctx, &c)
	})(w, r)
}
