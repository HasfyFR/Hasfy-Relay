package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/HasfyFR/Hasfy-Relay/internal/audit"
	"github.com/google/uuid"
)

// listDevicesReq is what Hasfy-App POSTs to /api/devices.
type listDevicesReq struct {
	OrgID string `json:"org_id"`
}

type deviceRow struct {
	DeviceID string    `json:"device_id"`
	Hostname string    `json:"hostname"`
	OS       string    `json:"os"`
	Arch     string    `json:"arch"`
	Version  string    `json:"version"`
	JoinedAt time.Time `json:"joined_at"`
}

type listDevicesRes struct {
	Devices []deviceRow `json:"devices"`
}

// handleListDevices returns the live agents for an org. Hasfy-App is the
// only legitimate caller; svc HMAC enforces that.
func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	if !s.verifySvcHMAC(w, r, body) {
		return
	}
	var req listDevicesReq
	if err := json.Unmarshal(body, &req); err != nil || req.OrgID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	agents := s.reg.ListByOrg(req.OrgID)
	res := listDevicesRes{Devices: make([]deviceRow, 0, len(agents))}
	for _, a := range agents {
		res.Devices = append(res.Devices, deviceRow{
			DeviceID: a.DeviceID,
			Hostname: a.Hostname,
			OS:       a.OS,
			Arch:     a.Arch,
			Version:  a.Version,
			JoinedAt: a.JoinedAt,
		})
	}
	writeJSON(w, http.StatusOK, res)
}

// issueSessionReq carries the operator identity vouched for by Hasfy-App.
type issueSessionReq struct {
	OrgID    string `json:"org_id"`
	DeviceID string `json:"device_id"`
	UserID   string `json:"user_id"` // operator subject
	IP       string `json:"ip"`      // operator browser IP, captured by app
	UA       string `json:"ua"`      // operator browser UA
}

type issueSessionRes struct {
	SessionID string `json:"session_id"`
	Token     string `json:"token"`
	WSURL     string `json:"ws_url"`
	ExpiresIn int    `json:"expires_in"`
}

// handleIssueSession mints a session token for an operator. The relay
// re-checks that the device is currently online; otherwise we 409 and
// the app surfaces "device offline" without leaking enrolment state.
func (s *Server) handleIssueSession(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	if !s.verifySvcHMAC(w, r, body) {
		return
	}
	var req issueSessionReq
	if err := json.Unmarshal(body, &req); err != nil ||
		req.OrgID == "" || req.DeviceID == "" || req.UserID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	a, err := s.reg.Get(req.DeviceID)
	if err != nil {
		http.Error(w, "device offline", http.StatusConflict)
		return
	}
	if a.OrgID != req.OrgID {
		// Hard refusal — the app shouldn't have asked. Audit it.
		s.audit.Emit(audit.Event{
			Kind: "auth.fail", OrgID: req.OrgID, DeviceID: req.DeviceID,
			Operator: req.UserID, Reason: "org mismatch",
		})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	sid := uuid.NewString()
	tok, err := s.verifier.IssueSession(req.OrgID, req.DeviceID, sid, req.UserID, req.IP, req.UA)
	if err != nil {
		http.Error(w, "issue failed", http.StatusInternalServerError)
		return
	}
	s.audit.Emit(audit.Event{
		Kind: "session.open", OrgID: req.OrgID, DeviceID: req.DeviceID,
		SessionID: sid, Operator: req.UserID, IP: req.IP,
	})
	writeJSON(w, http.StatusOK, issueSessionRes{
		SessionID: sid,
		Token:     tok,
		WSURL:     "/console/ws",
		ExpiresIn: 5 * 60,
	})
}
