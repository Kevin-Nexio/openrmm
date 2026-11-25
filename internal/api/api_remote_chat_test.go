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

	// A local endpoint user line forwarded by the technician may also activate a new generation.
	if lines, ok := sessions.exchangeChat(viewer, remoteChatRequest{
		Kid: "fourth", Generation: 4, Envelope: json.RawMessage(`{"t":"e2e_chat"}`),
	}, "user", "", second, true, func() bool { return true }); !ok || len(lines) != 1 || lines[0].From != "user" {
		t.Fatalf("endpoint user line failed to activate new generation: lines=%+v ok=%v", lines, ok)
	}
	if _, ok := sessions.exchangeChat(viewer, remoteChatRequest{
		Kid: "guest-epoch", Generation: 5, Envelope: json.RawMessage(`{"t":"e2e_chat"}`),
	}, "guest", "guest-b", second, true, func() bool { return true }); ok {
		t.Fatal("guest activated a new chat epoch")
	}

	// Suspending a room clears buffered messages and refuses the suspended kid until rekeyed.
	sessions.suspendChat(viewer.SessionID)
	if _, ok := read("fourth", "guest-b", second); ok {
		t.Fatal("suspended room remained readable")
	}
	if _, ok := publish("fourth", 5, second, true); ok {
		t.Fatal("suspended room reactivated under the same kid")
	}
	if lines, ok := publish("fifth", 5, second, true); !ok || len(lines) != 1 || lines[0].Cursor != 1 {
		t.Fatalf("replacement epoch after suspend failed: lines=%+v ok=%v", lines, ok)
	}

	sessions.forgetChat(viewer.SessionID)
	if _, ok := read("fifth", "guest-b", second); ok {
		t.Fatal("room survived the technician's session")
	}
}
