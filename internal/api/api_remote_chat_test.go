package api

import (
	"encoding/json"
	"testing"

	"github.com/p1ngu/rmm/internal/remote"
)

func TestEncryptedChatEpochIsBoundToApprovedMembership(t *testing.T) {
	sessions := newGuestSessions()
	viewer := remote.Viewer{SessionID: "tech-session", AgentID: "device", User: "technician", E2E: true}
	first := map[string]int{"guest-a": 1}
	both := map[string]int{"guest-a": 1, "guest-b": 1}
	second := map[string]int{"guest-b": 1}
	publish := func(kid string, generation uint64, members map[string]int, wrapped bool) ([]remoteChatLine, bool) {
		return sessions.exchangeChat(viewer, remoteChatRequest{
			Kid: kid, Generation: generation, Envelope: json.RawMessage(`{"t":"e2e_chat"}`),
		}, "tech", "", members, wrapped, func() bool { return true })
	}
	read := func(kid, share string, members map[string]int) ([]remoteChatLine, bool) {
		return sessions.exchangeChat(viewer, remoteChatRequest{Kid: kid}, "guest", share, members, true, func() bool { return true })
	}

	if _, ok := publish("initial", 1, first, true); !ok {
		t.Fatal("initial room was rejected")
	}
	if lines, ok := read("initial", "guest-a", first); !ok || len(lines) != 1 {
		t.Fatal("approved guest could not read the current room")
	}
	if _, ok := read("initial", "guest-b", both); ok {
		t.Fatal("new guest accessed the old room")
	}
	if _, ok := publish("second", 2, both, false); ok {
		t.Fatal("room activated before every guest received the new key")
	}
	if _, ok := publish("second", 2, both, true); !ok {
		t.Fatal("new room was rejected")
	}
	if lines, ok := read("second", "guest-b", both); !ok || len(lines) != 1 || lines[0].Cursor != 1 {
		t.Fatal("new room exposed history from the previous epoch")
	}
	if _, ok := publish("second", 3, second, true); ok {
		t.Fatal("same key accepted after removal")
	}
	if _, ok := publish("second", 3, both, true); ok {
		t.Fatal("suspended room reactivated when membership matched again")
	}
	if _, ok := publish("third", 3, second, true); !ok {
		t.Fatal("replacement key after removal was rejected")
	}
	if _, ok := read("third", "guest-a", second); ok {
		t.Fatal("removed guest could read the new epoch")
	}
	if _, ok := publish("initial", 1, first, true); ok {
		t.Fatal("out-of-order previous epoch reactivated")
	}
	sessions.forgetChat(viewer.SessionID)
	if _, ok := read("third", "guest-b", second); ok {
		t.Fatal("room survived the technician's session")
	}
}
