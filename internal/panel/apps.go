package panel

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ysuhao/mintyx-next/internal/hostapps"
	"github.com/ysuhao/mintyx-next/internal/model"
)

type appDTO struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Ports    []int  `json:"ports"`
	// Service says whether the app runs in the background, i.e. can be started and stopped.
	Service   bool   `json:"service"`
	Installed bool   `json:"installed"`
	Version   string `json:"version"`
	Status    string `json:"status"`
}

type appJobDTO struct {
	App       string     `json:"app"`
	Action    string     `json:"action"`
	State     string     `json:"state"`
	StartedAt time.Time  `json:"startedAt"`
	EndedAt   *time.Time `json:"endedAt"`
	Error     string     `json:"error"`
	Log       []string   `json:"log"`
}

func (s *Server) listApps(w http.ResponseWriter, r *http.Request) {
	reason := s.apps.Unsupported()
	apps := []appDTO{}
	for _, st := range s.apps.List(r.Context()) {
		ports := st.App.Ports
		if ports == nil {
			ports = []int{}
		}
		apps = append(apps, appDTO{
			ID: st.App.ID, Category: st.App.Category, Ports: ports, Service: len(st.App.Units) > 0,
			Installed: st.Installed, Version: st.Version, Status: st.Service,
		})
	}
	var job *appJobDTO
	if j := s.apps.Job(); j != nil {
		job = &appJobDTO{App: j.App, Action: j.Action, State: j.State, StartedAt: j.StartedAt.UTC(), Error: j.Error, Log: j.Log}
		if !j.EndedAt.IsZero() {
			t := j.EndedAt.UTC()
			job.EndedAt = &t
		}
		if job.Log == nil {
			job.Log = []string{}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"supported": reason == "", "reason": reason, "apps": apps, "job": job})
}

// postAppAction accepts the job and answers at once; the outcome is read from GET /api/apps.
func (s *Server) postAppAction(w http.ResponseWriter, r *http.Request) {
	id, action := r.PathValue("id"), r.PathValue("action")
	ip := s.remoteIP(r)
	// The request is long gone when the job ends, so a failure is recorded from here.
	done := func(j hostapps.Job) {
		if j.State != hostapps.JobFailed {
			return
		}
		e := model.AuditEntry{At: s.now(), Action: "app." + j.Action + ".fail", Target: j.App, Detail: j.Error, RemoteIP: ip}
		if err := s.st.AppendAudit(context.Background(), &e); err != nil {
			s.log.Error("panel: append audit", "action", e.Action, "err", err)
		}
	}
	err := s.apps.Begin(r.Context(), id, action, done)
	var pe *hostapps.PortError
	switch {
	case err == nil:
		s.audit(r, "app."+action, id, "")
		w.WriteHeader(http.StatusAccepted)
	case errors.Is(err, hostapps.ErrUnknownApp), errors.Is(err, hostapps.ErrUnknownVerb):
		writeErr(w, http.StatusNotFound, codeNotFound, "not found", "")
	case errors.Is(err, hostapps.ErrBusy):
		writeErr(w, http.StatusConflict, codeConflict, "another app job is still running", "job")
	case errors.Is(err, hostapps.ErrUnsupported):
		writeErr(w, http.StatusConflict, codeConflict, "apps cannot be managed on this server", "host")
	case errors.As(err, &pe):
		writeErr(w, http.StatusConflict, codeConflict, pe.Error(), "port")
	case errors.Is(err, hostapps.ErrState):
		writeErr(w, http.StatusConflict, codeConflict, "the app is not in a state that allows this", "state")
	default:
		s.writeFail(w, err)
	}
}
