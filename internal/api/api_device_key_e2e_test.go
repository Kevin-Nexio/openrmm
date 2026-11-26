package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/p1ngu/rmm/internal/ai"
	"github.com/p1ngu/rmm/internal/auth"
	"github.com/p1ngu/rmm/internal/config"
	"github.com/p1ngu/rmm/internal/e2e"
	"github.com/p1ngu/rmm/internal/hub"
	"github.com/p1ngu/rmm/internal/jobs"
	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/protocol"
	"github.com/p1ngu/rmm/internal/remote"
	"github.com/p1ngu/rmm/internal/store"
)

type keyIssueAlert struct{ agentID, hostname, issue, pinned, presented, ip string }

type recordingKeyNotifier struct{ ch chan keyIssueAlert }

func (n recordingKeyNotifier) QueueDeviceKeyIssue(_ context.Context, agentID, hostname, issue, pinned, presented, ip string) {
	n.ch <- keyIssueAlert{agentID, hostname, issue, pinned, presented, ip}
}

// The whole review, against a real database and real agent and console
// connections: a device that presents another key, none, or shares its
// identity stays online, its native sessions pause, it is audited and alerted
// once, and only an unrestricted administrator resolves it, approving exactly
// the key it presented or keeping the pinned one.
func TestDeviceKeyReviewEndToEnd(t *testing.T) {
	dbURL := os.Getenv("RMM_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("RMM_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	st := newTestStore(t, dbURL)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	login := func(role string) (*models.User, string) {
		u, err := st.CreateUser(ctx, "key-"+role+"-"+uuid.NewString()[:8], "hash", role)
		must(err)
		tok := auth.NewToken()
		must(st.CreateSession(ctx, u.ID, auth.Hash(tok), time.Now().Add(time.Hour)))
		return u, "Bearer " + tok
	}
	_, asAdmin := login(models.RoleAdmin)
	_, asTech := login(models.RoleTech)
	scopedAdmin, asScopedAdmin := login(models.RoleAdmin)

	enrollTok := "enroll-" + uuid.NewString()
	_, err := st.CreateEnrollToken(ctx, enrollTok, "key-review", 10, nil, nil, nil, "")
	must(err)

	h := hub.New()
	cfg := &config.Config{APIRateLimit: 100000, RemoteE2EPolicy: "preferred", TrustProxyHeaders: true}
	rm := remote.NewManager(st, h, "", "", "", false, false)
	srv := New(cfg, st, h, jobs.New(st, h), rm, remote.NewRelay(), ai.NewEngine(ai.NewClient("", "", ""), st, nil, nil, cfg), nil, nil)
	alerts := recordingKeyNotifier{ch: make(chan keyIssueAlert, 16)}
	srv.SetDeviceKeyNotifier(alerts)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	wsBase := "ws" + strings.TrimPrefix(ts.URL, "http")

	call := func(method, path, authz string, body any) (int, map[string]any) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, ts.URL+path, rdr)
		must(err)
		req.Header.Set("Authorization", authz)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		must(err)
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		out := map[string]any{}
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, out
	}
	register := func(req protocol.RegisterReq, ip string) (*websocket.Conn, protocol.Envelope) {
		t.Helper()
		header := http.Header{}
		if ip != "" {
			header.Set("X-Forwarded-For", ip)
		}
		c, _, err := websocket.DefaultDialer.Dial(wsBase+"/ws/agent", header)
		must(err)
		data, _ := json.Marshal(req)
		frame, _ := json.Marshal(protocol.Envelope{Type: protocol.MsgRegister, Data: data})
		must(c.WriteMessage(websocket.TextMessage, frame))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, raw, err := c.ReadMessage()
		must(err)
		_ = c.SetReadDeadline(time.Time{})
		var env protocol.Envelope
		must(json.Unmarshal(raw, &env))
		return c, env
	}
	gen := func() string {
		_, pub, err := e2e.GenerateKeyPair()
		must(err)
		return pub
	}
	k1, k2, k3 := gen(), gen(), gen()

	c, env := register(protocol.RegisterReq{EnrollToken: enrollTok, Hostname: "key-host", OS: "linux", Arch: "amd64", Version: "0.13.0", DevicePublicKey: k1}, "192.0.2.10")
	if env.Type != protocol.MsgRegistered {
		t.Fatalf("enrollment: %s %s", env.Type, env.Data)
	}
	_ = c.Close()
	var reg protocol.RegisterResp
	must(json.Unmarshal(env.Data, &reg))
	id, token := reg.AgentID, reg.AgentToken
	must(st.ReplaceUserScopes(ctx, scopedAdmin.ID, []models.UserScope{{ScopeType: models.ScopeAgent, ScopeID: id}}))
	as := func(key, status, version, ip string) protocol.Envelope {
		t.Helper()
		c, env := register(protocol.RegisterReq{AgentID: id, AgentToken: token, Hostname: "key-host", OS: "linux", Arch: "amd64",
			Version: version, DevicePublicKey: key, DeviceKeyStatus: status}, ip)
		_ = c.Close()
		if env.Type != protocol.MsgRegistered {
			t.Fatalf("registration with key %.8q status %q was refused: %s %s", key, status, env.Type, env.Data)
		}
		return env
	}
	device := func() map[string]any {
		t.Helper()
		code, d := call(http.MethodGet, "/api/devices/"+id, asAdmin, nil)
		if code != http.StatusOK {
			t.Fatalf("GET device: %d %v", code, d)
		}
		return d
	}
	expectAlert := func(issue, pinned, presented string) {
		t.Helper()
		select {
		case a := <-alerts.ch:
			if a.agentID != id || a.issue != issue || a.pinned != e2e.DisplayFingerprint(pinned) || a.presented != e2e.DisplayFingerprint(presented) || a.hostname != "key-host" {
				t.Fatalf("alert = %+v, want %s pinned %s presented %s", a, issue, e2e.DisplayFingerprint(pinned), e2e.DisplayFingerprint(presented))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s alert", issue)
		}
	}
	audited := func(action string) {
		t.Helper()
		entries, _, err := st.ListAudit(ctx, store.AuditFilter{Action: action, Target: id, Limit: 5})
		must(err)
		if len(entries) == 0 {
			t.Fatalf("no %s audit entry", action)
		}
	}
	start := func(provider string) (int, map[string]any) {
		t.Helper()
		return call(http.MethodPost, "/api/devices/"+id+"/remote", asAdmin, map[string]any{"provider": provider, "viewer_key": gen()})
	}

	// ---- A different key: online, under review, sessions paused ----
	as(k2, "", "0.13.0", "198.51.100.20")
	d := device()
	if d["device_public_key"] != k1 || d["device_key_issue"] != models.DeviceKeyChanged || d["pending_device_public_key"] != k2 ||
		d["device_key_issue_ip"] != "198.51.100.20" || d["status"] != string(models.AgentOnline) {
		t.Fatalf("after a different key: %v", d)
	}
	expectAlert(models.DeviceKeyChanged, k1, k2)
	audited("device.e2e_key_issue")
	as(k2, "", "0.13.0", "198.51.100.20")
	select {
	case a := <-alerts.ch:
		t.Fatalf("the same key alerted twice: %+v", a)
	case <-time.After(300 * time.Millisecond):
	}
	for _, provider := range []string{"native", "terminal", "files"} {
		if code, out := start(provider); code != http.StatusConflict || out["code"] != "remote_device_key_issue" || out["issue"] != models.DeviceKeyChanged {
			t.Fatalf("%s start under review: %d %v", provider, code, out)
		}
	}
	if code, out := call(http.MethodPut, "/api/config", asAdmin, map[string]any{"remote": map[string]any{"guest_access": true}}); code != http.StatusOK {
		t.Fatalf("enable guest access: %d %v", code, out)
	}
	if code, out := call(http.MethodPost, "/api/devices/"+id+"/remote-shares", asAdmin, map[string]any{"mode": "view", "minutes": 60}); code != http.StatusConflict || out["code"] != "remote_device_key_issue" || out["issue"] != models.DeviceKeyChanged {
		t.Fatalf("guest share under review: %d %v", code, out)
	}

	// ---- Only an unrestricted administrator approves, and only the presented key ----
	approve := func(authz, key, reason string) (int, map[string]any) {
		return call(http.MethodPost, "/api/devices/"+id+"/device-key/approve", authz, map[string]any{"pending_device_public_key": key, "reason": reason})
	}
	if code, out := approve(asTech, k2, "checked"); code != http.StatusForbidden {
		t.Fatalf("technician approve: %d %v", code, out)
	}
	if code, out := approve(asScopedAdmin, k2, "checked"); code != http.StatusForbidden {
		t.Fatalf("scoped administrator approve: %d %v", code, out)
	}
	if code, out := approve(asAdmin, k3, "checked"); code != http.StatusConflict || out["code"] != "device_key_not_pending" {
		t.Fatalf("approve a key never presented: %d %v", code, out)
	}
	if code, out := approve(asAdmin, k2, "  "); code != http.StatusBadRequest || out["code"] != "reason_required" {
		t.Fatalf("approve without a reason: %d %v", code, out)
	}
	if code, out := approve(asAdmin, "not-a-key", "checked"); code != http.StatusBadRequest {
		t.Fatalf("approve an invalid key: %d %v", code, out)
	}
	if code, out := approve(asAdmin, k2, "compared on the device"); code != http.StatusOK || out["device_public_key"] != k2 || out["device_key_issue"] != nil || out["device_key_changed_by"] == nil {
		t.Fatalf("approve: %d %v", code, out)
	}
	audited("device.e2e_key_approved")
	as(k2, "", "0.13.0", "198.51.100.20")
	if code, out := start("native"); code != http.StatusCreated || out["e2e"] != true || out["device_public_key"] != k2 {
		t.Fatalf("native start after approval: %d %v", code, out)
	}

	// ---- The old key again: kept off by the administrator ----
	as(k1, "", "0.13.0", "192.0.2.10")
	if d := device(); d["device_key_issue"] != models.DeviceKeyChanged || d["pending_device_public_key"] != k1 || d["device_public_key"] != k2 {
		t.Fatalf("old key again: %v", d)
	}
	expectAlert(models.DeviceKeyChanged, k2, k1)
	dismiss := func(authz, reason string) (int, map[string]any) {
		return call(http.MethodPost, "/api/devices/"+id+"/device-key/dismiss", authz, map[string]any{"reason": reason})
	}
	if code, out := dismiss(asTech, "old machine"); code != http.StatusForbidden {
		t.Fatalf("technician dismiss: %d %v", code, out)
	}
	if code, out := dismiss(asAdmin, ""); code != http.StatusBadRequest || out["code"] != "reason_required" {
		t.Fatalf("dismiss without a reason: %d %v", code, out)
	}
	if code, out := dismiss(asAdmin, "old machine re-imaged"); code != http.StatusOK || out["device_public_key"] != k2 || out["device_key_issue"] != nil {
		t.Fatalf("dismiss: %d %v", code, out)
	}
	audited("device.e2e_key_issue_dismissed")
	if code, out := dismiss(asAdmin, "again"); code != http.StatusConflict || out["code"] != "device_key_no_issue" {
		t.Fatalf("dismiss with no issue: %d %v", code, out)
	}

	// ---- A key the agent cannot read, then an older agent: both clear on their own ----
	as("", protocol.DeviceKeyUnavailable, "0.13.0", "198.51.100.20")
	if d := device(); d["device_key_issue"] != models.DeviceKeyMissing || d["device_public_key"] != k2 {
		t.Fatalf("unreadable key: %v", d)
	}
	expectAlert(models.DeviceKeyMissing, k2, "")
	as(k2, "", "0.13.0", "198.51.100.20")
	if d := device(); d["device_key_issue"] != nil {
		t.Fatalf("after the key came back: %v", d)
	}
	audited("device.e2e_key_restored")
	as("", "", "0.12.3", "198.51.100.20")
	if d := device(); d["device_key_issue"] != models.DeviceKeyOutdated {
		t.Fatalf("older agent: %v", d)
	}
	expectAlert(models.DeviceKeyOutdated, k2, "")
	as(k2, "", "0.13.0", "198.51.100.20")

	// ---- Two machines with the same identity and key, taking the connection from each other ----
	var open []*websocket.Conn
	for i := 0; i < 7; i++ {
		ip := "203.0.113.1"
		if i%2 == 1 {
			ip = "203.0.113.2"
		}
		c, env := register(protocol.RegisterReq{AgentID: id, AgentToken: token, Hostname: "key-host", OS: "linux", Arch: "amd64", Version: "0.13.0", DevicePublicKey: k2}, ip)
		if env.Type != protocol.MsgRegistered {
			t.Fatalf("clone registration %d refused: %s", i, env.Data)
		}
		open = append(open, c)
	}
	for _, c := range open {
		_ = c.Close()
	}
	if d := device(); d["device_key_issue"] != models.DeviceKeyDuplicate || d["device_public_key"] != k2 {
		t.Fatalf("clones: %v", d)
	}
	expectAlert(models.DeviceKeyDuplicate, k2, "")
	if code, out := start("native"); code != http.StatusConflict || out["issue"] != models.DeviceKeyDuplicate {
		t.Fatalf("native start with clones: %d %v", code, out)
	}
	if code, out := approve(asAdmin, k2, "x"); code != http.StatusConflict {
		t.Fatalf("approve during duplicate: %d %v", code, out)
	}
}
