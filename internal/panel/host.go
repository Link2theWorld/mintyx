package panel

import "net/http"

// getHostSSH reports only the verdict; sshd's own output stays on the server.
func (s *Server) getHostSSH(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"passwordLogin": s.hostCheck.PasswordLogin(r.Context())})
}
