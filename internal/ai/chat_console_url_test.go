package ai

import (
	"testing"

	"github.com/p1ngu/rmm/internal/config"
)

// The chat hands out download links on the browser console's origin, which
// serves /api, not on the agents origin of a split ingress.
func TestChatDownloadLinksUseTheConsoleOrigin(t *testing.T) {
	e := NewEngine(nil, nil, nil, nil, &config.Config{PublicURL: "https://agents.example.test", ConsolePublicURL: "https://console.example.test"})
	if e.publicURL != "https://console.example.test" {
		t.Fatalf("chat link origin = %q, want the console", e.publicURL)
	}
	e = NewEngine(nil, nil, nil, nil, &config.Config{PublicURL: "https://rmm.example.test"})
	if e.publicURL != "https://rmm.example.test" {
		t.Fatalf("single-origin chat link origin = %q", e.publicURL)
	}
}
