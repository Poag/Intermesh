package app

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Poag/Intermesh/server/internal/state"
)

// The admin API is the admin console: JSON over HTTP on a local address, protected by a bearer
// token in the data directory. There is no web interface for members (suggested 3 Oct 2026).

type adminFunc func(r *http.Request) (any, int, error)

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func bad(format string, a ...any) error {
	return &apiError{http.StatusBadRequest, fmt.Sprintf(format, a...)}
}

func (a *App) adminHandler() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, fn adminFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+a.AdminToken)) != 1 {
				http.Error(w, "unauthorised", http.StatusUnauthorized)
				return
			}
			out, status, err := fn(r)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				code := http.StatusInternalServerError
				var ae *apiError
				if asAPIError(err, &ae) {
					code = ae.status
				}
				w.WriteHeader(code)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			if out != nil {
				json.NewEncoder(w).Encode(out)
			}
		})
	}
	body := func(r *http.Request, v any) error {
		b, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil {
			return bad("unreadable body")
		}
		if len(b) == 0 {
			return nil
		}
		if err := json.Unmarshal(b, v); err != nil {
			return bad("bad JSON: %v", err)
		}
		return nil
	}
	nodeParam := func(r *http.Request) (uint32, error) {
		s := r.PathValue("node")
		if len(s) == 9 && s[0] == '!' {
			s = s[1:]
		}
		v, err := strconv.ParseUint(s, 16, 32)
		if err != nil || len(s) != 8 {
			return 0, bad("node must be 8 hex digits")
		}
		return uint32(v), nil
	}

	route("GET /api/status", func(r *http.Request) (any, int, error) { return a.Engine.Status(), 0, nil })
	route("GET /api/contact", func(r *http.Request) (any, int, error) { return a.Engine.ServerContact(), 0, nil })
	route("GET /api/events", func(r *http.Request) (any, int, error) { return a.Engine.Events(), 0, nil })
	route("GET /api/beacon", func(r *http.Request) (any, int, error) {
		return map[string]string{"line": a.Engine.BeaconLine()}, 0, nil
	})
	route("POST /api/beacon/send", func(r *http.Request) (any, int, error) { a.Engine.SendBeacon(); return nil, http.StatusNoContent, nil })
	route("POST /api/announce", func(r *http.Request) (any, int, error) { a.Engine.Announce(); return nil, http.StatusNoContent, nil })

	// gateways
	route("GET /api/gateways", func(r *http.Request) (any, int, error) {
		type view struct {
			Username string   `json:"username"`
			NodeID   string   `json:"nodeId"`
			Channels []string `json:"channels"`
		}
		var out []view
		for _, g := range a.State.Gateways() {
			out = append(out, view{g.Username, g.NodeID, g.Channels})
		}
		return out, 0, nil
	})
	route("POST /api/gateways", func(r *http.Request) (any, int, error) {
		var in struct {
			Name     string   `json:"name"`
			Channels []string `json:"channels"`
		}
		if err := body(r, &in); err != nil {
			return nil, 0, err
		}
		pw, err := a.Engine.AddGateway(in.Name, in.Channels)
		if err != nil {
			return nil, 0, bad("%v", err)
		}
		return map[string]any{"username": in.Name, "password": pw, "note": "shown once; set as the MQTT username and password on the gateway, with MQTT encryption enabled"}, http.StatusCreated, nil
	})
	route("DELETE /api/gateways/{name}", func(r *http.Request) (any, int, error) {
		if !a.State.DeleteGateway(r.PathValue("name")) {
			return nil, 0, &apiError{http.StatusNotFound, "no such gateway"}
		}
		return nil, http.StatusNoContent, nil
	})

	// channels
	route("GET /api/channels", func(r *http.Request) (any, int, error) {
		type view struct {
			Name      string `json:"name"`
			Number    uint8  `json:"number"`
			Scope     string `json:"scope"`
			Uplink    bool   `json:"uplink"`
			Downlink  bool   `json:"downlink"`
			Roaming   bool   `json:"roaming"`
			Retention int    `json:"retentionHours"`
		}
		var out []view
		for _, c := range a.State.Channels() {
			out = append(out, view{c.Name, c.Number, c.Scope, c.Uplink, c.Downlink, c.Roaming, c.RetentionHours})
		}
		return out, 0, nil
	})
	route("POST /api/channels", func(r *http.Request) (any, int, error) {
		var in struct {
			Name      string `json:"name"`
			PSK       string `json:"psk"` // base64; "default" for the firmware's default key; empty for none
			Scope     string `json:"scope"`
			Uplink    bool   `json:"uplink"`
			Downlink  bool   `json:"downlink"`
			Roaming   bool   `json:"roaming"`
			Number    int    `json:"number"`
			Retention int    `json:"retentionHours"`
		}
		if err := body(r, &in); err != nil {
			return nil, 0, err
		}
		var psk []byte
		switch in.PSK {
		case "":
		case "default":
			psk = []byte{1}
		default:
			b, err := base64.StdEncoding.DecodeString(in.PSK)
			if err != nil {
				return nil, 0, bad("psk must be base64")
			}
			psk = b
		}
		if err := a.Engine.SetChannel(in.Name, psk, in.Scope, in.Uplink, in.Downlink, in.Roaming, in.Number, in.Retention); err != nil {
			return nil, 0, bad("%v", err)
		}
		return nil, http.StatusNoContent, nil
	})

	// enrolment PSKs
	route("GET /api/psks", func(r *http.Request) (any, int, error) { return a.State.PSKs(), 0, nil })
	route("POST /api/psks", func(r *http.Request) (any, int, error) {
		var in struct {
			Kind         state.PSKKind `json:"kind"`
			Label        string        `json:"label"`
			PeriodHours  int           `json:"periodHours"`
			ExpiresHours int           `json:"expiresHours"`
		}
		if err := body(r, &in); err != nil {
			return nil, 0, err
		}
		var exp time.Time
		if in.ExpiresHours > 0 {
			exp = time.Now().Add(time.Duration(in.ExpiresHours) * time.Hour)
		}
		p, err := a.State.NewPSK(in.Kind, in.Label, time.Duration(in.PeriodHours)*time.Hour, exp)
		if err != nil {
			return nil, 0, bad("%v", err)
		}
		return p, http.StatusCreated, nil
	})
	route("POST /api/psks/{id}/revoke", func(r *http.Request) (any, int, error) {
		if err := a.State.RevokePSK(r.PathValue("id")); err != nil {
			return nil, 0, &apiError{http.StatusNotFound, err.Error()}
		}
		return nil, http.StatusNoContent, nil
	})

	// members
	route("GET /api/members", func(r *http.Request) (any, int, error) {
		type view struct {
			Node     string `json:"node"`
			Pending  bool   `json:"pending"`
			Via      string `json:"via"`
			Enrolled string `json:"enrolled"`
		}
		var out []view
		for _, m := range a.State.Members() {
			out = append(out, view{fmt.Sprintf("%08x", m.Node), m.Pending, m.Via, m.Enrolled.UTC().Format(time.RFC3339)})
		}
		return out, 0, nil
	})
	route("POST /api/members/{node}/approve", func(r *http.Request) (any, int, error) {
		n, err := nodeParam(r)
		if err != nil {
			return nil, 0, err
		}
		if err := a.State.Approve(n); err != nil {
			return nil, 0, &apiError{http.StatusNotFound, err.Error()}
		}
		return nil, http.StatusNoContent, nil
	})
	route("DELETE /api/members/{node}", func(r *http.Request) (any, int, error) {
		n, err := nodeParam(r)
		if err != nil {
			return nil, 0, err
		}
		if err := a.State.RemoveMember(n); err != nil {
			return nil, 0, &apiError{http.StatusNotFound, err.Error()}
		}
		return nil, http.StatusNoContent, nil
	})

	// servers
	route("GET /api/peers", func(r *http.Request) (any, int, error) {
		type view struct {
			Actor     string `json:"actor"`
			HomeTag   string `json:"homeTag"`
			Blocked   bool   `json:"blocked"`
			Manual    bool   `json:"manual"`
			LastHeard string `json:"lastHeard"`
		}
		var out []view
		for _, p := range a.State.Peers() {
			out = append(out, view{p.Actor, p.HomeTag, p.Blocked, p.Manual, p.LastHeard.UTC().Format(time.RFC3339)})
		}
		return out, 0, nil
	})
	peerOp := func(fn func(actor string) error) adminFunc {
		return func(r *http.Request) (any, int, error) {
			var in struct {
				Actor string `json:"actor"`
			}
			if err := body(r, &in); err != nil {
				return nil, 0, err
			}
			if !strings.HasPrefix(in.Actor, "http") {
				return nil, 0, bad("actor must be a URL")
			}
			if err := fn(in.Actor); err != nil {
				return nil, 0, bad("%v", err)
			}
			return nil, http.StatusNoContent, nil
		}
	}
	route("POST /api/peers/block", peerOp(func(s string) error { return a.State.SetBlocked(s, true) }))
	route("POST /api/peers/unblock", peerOp(func(s string) error { return a.State.SetBlocked(s, false) }))
	route("POST /api/peers/link", peerOp(func(s string) error { _, err := a.Engine.LinkUp(r0(), s); return err }))
	route("POST /api/peers/unlink", peerOp(func(s string) error { a.Engine.Unlink(s); return nil }))

	route("GET /api/visits", func(r *http.Request) (any, int, error) {
		type view struct {
			Node     string `json:"node"`
			HomeTag  string `json:"homeTag"`
			Accepted bool   `json:"accepted"`
			Expires  string `json:"expires,omitempty"`
		}
		var out []view
		for _, v := range a.State.Visits() {
			x := view{Node: fmt.Sprintf("%08x", v.Node), HomeTag: v.HomeTag, Accepted: v.Accepted}
			if v.Accepted {
				x.Expires = v.Expires.UTC().Format(time.RFC3339)
			}
			out = append(out, x)
		}
		return out, 0, nil
	})
	route("GET /api/roamers", func(r *http.Request) (any, int, error) {
		type view struct {
			Node    string `json:"node"`
			Visitor string `json:"visitor"`
			Expires string `json:"expires"`
		}
		var out []view
		for _, g := range a.State.Registrations() {
			out = append(out, view{fmt.Sprintf("%08x", g.Node), g.Visitor, g.Expires.UTC().Format(time.RFC3339)})
		}
		return out, 0, nil
	})
	route("POST /api/rotate-key", func(r *http.Request) (any, int, error) {
		var in struct {
			OverlapHours int `json:"overlapHours"`
		}
		if err := body(r, &in); err != nil {
			return nil, 0, err
		}
		if in.OverlapHours <= 0 {
			in.OverlapHours = a.Cfg.KeyOverlapHours
		}
		if err := a.Engine.RotateAPKey(a.Client, time.Duration(in.OverlapHours)*time.Hour); err != nil {
			return nil, 0, err
		}
		return nil, http.StatusNoContent, nil
	})
	return mux
}

func asAPIError(err error, target **apiError) bool {
	ae, ok := err.(*apiError)
	if ok {
		*target = ae
	}
	return ok
}
