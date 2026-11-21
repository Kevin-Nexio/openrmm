package scheduler

import (
	"testing"
	"time"
)

func TestCheckDispatchTimeoutWaitsForTheAgentResult(t *testing.T) {
	if got := checkDispatchTimeout(180); got != 210*time.Second {
		t.Fatalf("deadline = %s, want 210s (180s timeout plus 30s)", got)
	}
	if got := checkDispatchTimeout(5); got != 35*time.Second {
		t.Fatalf("deadline = %s, want 35s", got)
	}
}
