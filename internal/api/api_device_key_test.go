package api

import (
	"testing"
	"time"
)

// Machines that share one identity take the connection from each other, back
// and forth between their addresses; one machine moving between networks, or
// reconnecting from one address, never trips it.
func TestConnectionWatchFlagsMachinesSharingAnIdentity(t *testing.T) {
	start := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	run := func(w *connectionWatch, agent string, steps []struct {
		ip       string
		replaced bool
	}) (flagged bool, at int) {
		for i, s := range steps {
			if w.observe(agent, s.ip, s.replaced, start.Add(time.Duration(i)*5*time.Second)) {
				return true, i
			}
		}
		return false, -1
	}
	type step = struct {
		ip       string
		replaced bool
	}

	// Two clones ping-ponging: flagged once each address took over three times.
	var clones []step
	clones = append(clones, step{"10.0.0.1", false})
	for i := 0; i < 8; i++ {
		ip := "10.0.0.2"
		if i%2 == 1 {
			ip = "10.0.0.1"
		}
		clones = append(clones, step{ip, true})
	}
	if flagged, at := run(&connectionWatch{}, "clones", clones); !flagged || at != 6 {
		t.Fatalf("clones flagged=%v at step %d, want true at 6", flagged, at)
	}

	// A laptop moving across networks, replacing a half-open connection each time.
	roaming := []step{{"10.0.0.1", false}, {"10.0.0.2", true}, {"10.0.0.3", true}, {"10.0.0.4", true}, {"10.0.0.5", true}, {"10.0.0.6", true}, {"10.0.0.7", true}}
	if flagged, _ := run(&connectionWatch{}, "laptop", roaming); flagged {
		t.Fatal("a roaming laptop was flagged as a duplicate")
	}

	// Reconnects from one address, even replacing a live connection.
	var same []step
	for i := 0; i < 12; i++ {
		same = append(same, step{"10.0.0.9", i > 0})
	}
	if flagged, _ := run(&connectionWatch{}, "same", same); flagged {
		t.Fatal("reconnects from one address were flagged")
	}

	// Alternation without displacing a live connection is ordinary reconnecting.
	var calm []step
	for i := 0; i < 12; i++ {
		ip := "10.0.0.1"
		if i%2 == 1 {
			ip = "10.0.0.2"
		}
		calm = append(calm, step{ip, false})
	}
	if flagged, _ := run(&connectionWatch{}, "calm", calm); flagged {
		t.Fatal("reconnects that replaced nothing were flagged")
	}

	// Takeovers spread over more than the window do not add up.
	w := &connectionWatch{}
	w.observe("slow", "10.0.0.1", false, start)
	for i := 0; i < 10; i++ {
		ip := "10.0.0.2"
		if i%2 == 1 {
			ip = "10.0.0.1"
		}
		if w.observe("slow", ip, true, start.Add(time.Duration(i+1)*3*time.Minute)) {
			t.Fatalf("takeovers three minutes apart were flagged at %d", i)
		}
	}

	// An unknown address never counts.
	if (&connectionWatch{}).observe("x", "", true, start) {
		t.Fatal("an empty address was flagged")
	}

	// Clearing history after a review prevents old takeovers from re-triggering
	// on one legitimate reconnect, while ongoing clones still trigger again.
	rw := &connectionWatch{}
	if flagged, at := run(rw, "clones", clones); !flagged || at != 6 {
		t.Fatalf("before reset: flagged=%v at %d, want true at 6", flagged, at)
	}
	rw.reset("clones")
	if rw.observe("clones", "10.0.0.1", false, start.Add(time.Minute)) ||
		rw.observe("clones", "10.0.0.2", true, start.Add(time.Minute+5*time.Second)) {
		t.Fatal("a single IP change after reset was flagged as duplicate")
	}
	if flagged, at := run(rw, "clones", clones); !flagged || at != 6 {
		t.Fatalf("ongoing clones after reset: flagged=%v at %d, want true at 6", flagged, at)
	}
}
