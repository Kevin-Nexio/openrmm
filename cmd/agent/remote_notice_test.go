package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/p1ngu/rmm/internal/e2e"
	"github.com/p1ngu/rmm/internal/protocol"
)

// A sidecar that cannot be prepared never reaches the relay, so the viewer has
// only a black canvas to go on. The agent takes its place for one message.
func TestReportRemoteFailureReachesTheViewer(t *testing.T) {
	type received struct {
		request *http.Request
		body    []byte
	}
	got := make(chan received, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		got <- received{request: r, body: raw}
	}))
	defer server.Close()

	a := &agent{wsURL: "ws" + strings.TrimPrefix(server.URL, "http") + "/ws/agent"}
	a.reportRemoteFailure(protocol.RemoteStartMsg{SessionID: "s", AgentTicket: "ticket-1"},
		"this endpoint could not prepare the remote module: no such file")

	select {
	case r := <-got:
		if r.request.URL.RequestURI() != "/ws/remote?role=agent&session=s" {
			t.Fatalf("notice route = %q", r.request.URL.RequestURI())
		}
		if auth := r.request.Header.Get("Authorization"); auth != "Remote-Agent ticket-1" {
			t.Fatalf("authorization = %q", auth)
		}
		var notice struct{ T, Text string }
		if err := json.Unmarshal(r.body, &notice); err != nil {
			t.Fatalf("notice is not JSON: %v", err)
		}
		if notice.T != "notice" {
			t.Fatalf("type = %q, want notice", notice.T)
		}
		if !strings.Contains(notice.Text, "could not prepare the remote module") {
			t.Fatalf("text = %q", notice.Text)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the viewer never received the failure notice")
	}
}

// Reporting is best effort: an unreachable relay must not panic or block the
// agent, which still has the original failure to log.
func TestReportRemoteFailureToleratesAnUnreachableRelay(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		a := &agent{wsURL: "ws://127.0.0.1:1/ws/agent"}
		a.reportRemoteFailure(protocol.RemoteStartMsg{}, "unreachable")
		a.wsURL = ""
		a.reportRemoteFailure(protocol.RemoteStartMsg{}, "no relay")
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("reporting blocked the agent")
	}
}

func TestReportRemoteFailureE2EReachesTheViewer(t *testing.T) {
	ikPriv, ikPub, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	viewPriv, viewPub, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		body []byte
		err  error
	}
	got := make(chan result, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			got <- result{err: err}
			return
		}
		defer raw.Close()
		conn, err := e2e.HandshakeViewer(raw, e2e.ViewerHandshakeOpts{
			SessionID:       "sess-e2e-notice",
			EKPriv:          viewPriv,
			ExpectedAgentID: "agent-e2e-1",
			ExpectedKind:    protocol.RemoteKindDesktop,
			ExpectedIKPub:   ikPub,
		})
		if err != nil {
			got <- result{err: err}
			return
		}
		_, body, err := conn.ReadMessage()
		got <- result{body: body, err: err}
	}))
	defer server.Close()

	a := &agent{
		wsURL: "ws" + strings.TrimPrefix(server.URL, "http") + "/ws/agent",
		st: state{
			AgentID:          "agent-e2e-1",
			DevicePrivateKey: ikPriv,
			DevicePublicKey:  ikPub,
		},
	}
	const wantText = "this endpoint's remote module predates end-to-end encryption"
	a.reportRemoteFailure(protocol.RemoteStartMsg{
		SessionID:   "sess-e2e-notice",
		AgentTicket: "ticket-e2e",
		Kind:        protocol.RemoteKindDesktop,
		E2E:         true,
		ViewerKey:   viewPub,
	}, wantText)

	select {
	case res := <-got:
		if res.err != nil {
			t.Fatalf("viewer did not receive E2E notice: %v", res.err)
		}
		var notice struct{ T, Text string }
		if err := json.Unmarshal(res.body, &notice); err != nil {
			t.Fatalf("E2E notice is not JSON: %v", err)
		}
		if notice.T != "notice" || !bytes.Contains([]byte(notice.Text), []byte(wantText)) {
			t.Fatalf("unexpected E2E notice = %+v", notice)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for E2E failure notice")
	}
}
