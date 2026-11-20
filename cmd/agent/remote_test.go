package main

import (
	"testing"

	"github.com/p1ngu/rmm/internal/protocol"
)

func TestRelayURL(t *testing.T) {
	cases := []struct{ ws, want string }{
		{"ws://192.168.0.40:3000/ws/agent", "ws://192.168.0.40:3000/ws/remote?session=session-id&role=agent"},
		{"wss://rmm.example.com/ws/agent", "wss://rmm.example.com/ws/remote?session=session-id&role=agent"},
	}
	for _, c := range cases {
		a := &agent{wsURL: c.ws}
		if got := a.relayURL("session-id"); got != c.want {
			t.Errorf("relayURL(%q) = %q, want %q", c.ws, got, c.want)
		}
	}
}

func TestLegacyRelayURL(t *testing.T) {
	a := &agent{wsURL: "wss://rmm.example.com/ws/agent"}
	if got, want := a.legacyRelayURL("ticket"), "wss://rmm.example.com/ws/remote?role=agent&token=ticket"; got != want {
		t.Fatalf("legacyRelayURL() = %q, want %q", got, want)
	}
}

// A pre-ticket server's relay URL is used only on this agent's own server
// (scheme, host and port). Any other is replaced by the relay derived from the
// agent's server, so the screen and the elevated shell never go elsewhere.
func TestRelayForStartKeepsALegacyRelayOnTheAgentsServer(t *testing.T) {
	a := &agent{wsURL: "wss://rmm.example.com/ws/agent"}
	legacy := a.legacyRelayURL("ticket")
	for _, c := range []struct{ relay, want string }{
		{"wss://rmm.example.com/ws/remote?role=agent&token=ticket", "wss://rmm.example.com/ws/remote?role=agent&token=ticket"},
		{"wss://RMM.example.com/ws/remote?token=ticket", "wss://RMM.example.com/ws/remote?token=ticket"},
		{"wss://evil.example.net/ws/remote", legacy},
		{"wss://rmm.example.com:8443/ws/remote", legacy},
		{"ws://rmm.example.com/ws/remote", legacy},
		{"https://rmm.example.com/ws/remote", legacy},
		{"wss://user@rmm.example.com/ws/remote", legacy},
		{"wss://rmm.example.com.evil.example.net/ws/remote", legacy},
		{"::not a url", legacy},
	} {
		relay, ticket := a.relayForStart(protocol.RemoteStartMsg{SessionID: "s", Token: "ticket", RelayURL: c.relay})
		if relay != c.want || ticket != "" {
			t.Errorf("relay %q: got (%q, %q), want (%q, \"\")", c.relay, relay, ticket, c.want)
		}
	}
	// The ticketed handshake never takes a URL from the server.
	if relay, ticket := a.relayForStart(protocol.RemoteStartMsg{SessionID: "s", AgentTicket: "t", RelayURL: "wss://evil.example.net/x"}); relay != a.relayURL("s") || ticket != "t" {
		t.Fatalf("ticketed start = (%q, %q)", relay, ticket)
	}
}

func TestSidecarArgsNeverAddsEmptyTicket(t *testing.T) {
	args := sidecarArgs("wss://rmm.example.com/ws/remote", "", []string{"-files"})
	if len(args) != 3 || args[2] != "-files" {
		t.Fatalf("sidecarArgs = %#v, want relay args without -ticket", args)
	}
}

func TestHTTPBase(t *testing.T) {
	cases := []struct{ ws, want string }{
		{"ws://192.168.0.40:3000/ws/agent", "http://192.168.0.40:3000"},
		{"wss://rmm.example.com/ws/agent", "https://rmm.example.com"},
	}
	for _, c := range cases {
		a := &agent{wsURL: c.ws}
		if got := a.httpBase(); got != c.want {
			t.Errorf("httpBase(%q) = %q, want %q", c.ws, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	// truncateRunes replaced the byte-slicing truncate; see output_test.go for
	// the multi-byte behaviour that motivated it.
	if got := truncateRunes("hello", 10); got != "hello" {
		t.Errorf("truncate under cap changed value: %q", got)
	}
	got := truncateRunes("hello world", 5)
	if got[:5] != "hello" || got == "hello world" {
		t.Errorf("truncate over cap = %q, want prefix kept + marker", got)
	}
}
