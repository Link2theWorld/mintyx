package panel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/ysuhao/mintyx-next/internal/model"
	"github.com/ysuhao/mintyx-next/internal/store"
)

const (
	codeUnauthorized = "unauthorized"
	codeForbidden    = "forbidden"
	codeNotFound     = "not_found"
	codeConflict     = "conflict"
	codeInvalid      = "invalid"
	codeRateLimited  = "rate_limited"
	codeEngine       = "engine"
	codeInternal     = "internal"
)

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg, field string) {
	writeJSON(w, status, errorBody{errorDetail{Code: code, Message: msg, Field: field}})
}

// fieldError is a validation failure reported as 400 invalid with field set.
type fieldError struct {
	field, msg string
}

func (e *fieldError) Error() string { return e.field + ": " + e.msg }

func invalid(field, msg string) error { return &fieldError{field, msg} }

// writeFail maps validation and store errors to API errors; anything else is a logged 500.
func (s *Server) writeFail(w http.ResponseWriter, err error) {
	var fe *fieldError
	var ce *store.ConflictError
	switch {
	case errors.As(err, &fe):
		writeErr(w, http.StatusBadRequest, codeInvalid, fe.msg, fe.field)
	case errors.As(err, &ce):
		field := ce.Field
		if field == "sub_token" {
			field = "subToken"
		}
		writeErr(w, http.StatusConflict, codeConflict, field+" is already in use", field)
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, codeNotFound, "not found", "")
	default:
		s.log.Error("panel: request failed", "err", err)
		writeErr(w, http.StatusInternalServerError, codeInternal, "internal error", "")
	}
}

// decodeJSON reads one JSON value; on failure it has already written the 400.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	err := json.NewDecoder(r.Body).Decode(v)
	if err == nil {
		return true
	}
	var mbe *http.MaxBytesError
	var ute *json.UnmarshalTypeError
	switch {
	case errors.As(err, &mbe):
		writeErr(w, http.StatusBadRequest, codeInvalid, "request body too large", "")
	case errors.As(err, &ute):
		writeErr(w, http.StatusBadRequest, codeInvalid, "wrong type for "+ute.Field, ute.Field)
	case errors.Is(err, io.EOF):
		writeErr(w, http.StatusBadRequest, codeInvalid, "request body is empty", "")
	default:
		writeErr(w, http.StatusBadRequest, codeInvalid, "malformed JSON", "")
	}
	return false
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusNotFound, codeNotFound, "not found", "")
		return 0, false
	}
	return id, true
}

// audit records one entry; a failure is logged, never surfaced, because the change already happened.
func (s *Server) audit(r *http.Request, action, target, detail string) {
	e := model.AuditEntry{At: s.now(), Action: action, Target: target, Detail: detail, RemoteIP: s.remoteIP(r)}
	if err := s.st.AppendAudit(context.WithoutCancel(r.Context()), &e); err != nil {
		s.log.Error("panel: append audit", "action", action, "err", err)
	}
}

// syncLocked applies the store to the engine; callers hold s.mu. A failure is retried on the next tick.
func (s *Server) syncLocked(ctx context.Context) error {
	err := s.eng.Sync(ctx)
	s.syncPending = err != nil
	if err != nil {
		s.log.Warn("panel: engine sync failed", "err", err)
	}
	return err
}

// applyAndRespond finishes a saved mutation: Sync, then the success body or 502 engine.
func (s *Server) applyAndRespond(w http.ResponseWriter, r *http.Request, status int, body any) {
	if err := s.syncLocked(context.WithoutCancel(r.Context())); err != nil {
		writeErr(w, http.StatusBadGateway, codeEngine, "saved, but the engine failed to apply it: "+err.Error(), "")
		return
	}
	if body == nil {
		w.WriteHeader(status)
		return
	}
	writeJSON(w, status, body)
}
