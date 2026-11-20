package config

import "testing"

func TestNotificationConsoleURL(t *testing.T) {
	c := &Config{PublicURL: "https://agents.example", ConsolePublicURL: "https://console.example"}
	if c.NotificationConsoleURL() != "https://console.example" {
		t.Fatal("notification links used the agent origin")
	}
	c.ConsolePublicURL = ""
	if c.NotificationConsoleURL() != c.PublicURL {
		t.Fatal("single-origin fallback changed")
	}
}
