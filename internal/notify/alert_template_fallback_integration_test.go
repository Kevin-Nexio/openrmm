package notify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/p1ngu/rmm/internal/store"
)

// A saved alert email template this version cannot use (here one naming a
// variable it does not know, as a newer version could have saved before a
// rollback) must not stop alert mail: the alert goes out with the default
// template. A template it can use is still the one that decides.
func TestAlertMailFallsBackToTheDefaultTemplateIntegration(t *testing.T) {
	ctx, st := drainTestStore(t)
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	agent, err := st.CreateAgent(ctx, "srv-wiki", "linux", "amd64", "1.0.0", "tok-template", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	newRecipient(t, ctx, st, "oncall@example.test", true)
	relay := Config{Host: "127.0.0.1", Port: 1, From: "alerts@notify.test", TLSMode: "none"}
	svc := New(st, func(context.Context) (Config, string, error) { return relay, "https://rmm.example.test", nil })

	queue := func(dedupe string) (subject, body string) {
		t.Helper()
		ev := AlertOpenedEvent(store.NotifyAgentOffline, agent.ID, "srv-wiki", "Wiki server", "", "No heartbeat for 5 minutes.", "https://rmm.example.test")
		ev.DedupeKey = "fallback-test:" + dedupe
		if err := svc.Queue(ctx, ev); err != nil {
			t.Fatalf("queue with template setting: %v", err)
		}
		queued, err := st.ClaimPendingNotificationsLeased(ctx, 10, time.Minute)
		if err != nil || len(queued) != 1 {
			t.Fatalf("queued %d notifications (%v), want 1", len(queued), err)
		}
		return queued[0].Subject, queued[0].Body
	}

	unusable := `{"device_name":"hostname","alert":{"subject":"{{site}} is down","body":"{{site}}"},"recovery":{"subject":"up","body":"up"}}`
	if err := st.UpsertAppSetting(ctx, AlertTemplatesKey, unusable, false); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAlertTemplates(ctx, st); err == nil {
		t.Fatal("the test setting should not load")
	}
	subject, body := queue("unusable")
	if subject != "[OpenRMM] Agent offline — srv-wiki" {
		t.Fatalf("fallback subject = %q, want the default template's", subject)
	}
	if !strings.Contains(body, "No heartbeat for 5 minutes.") || !strings.Contains(body, "Device: srv-wiki") {
		t.Fatalf("fallback body = %q, want the default template's", body)
	}

	// Control: a template this version can use still decides the message.
	usable := `{"device_name":"description","alert":{"subject":"Down: {{device}}","body":"{{details}}"},"recovery":{"subject":"Up: {{device}}","body":"{{details}}"}}`
	if err := st.UpsertAppSetting(ctx, AlertTemplatesKey, usable, false); err != nil {
		t.Fatal(err)
	}
	if subject, _ := queue("usable"); subject != "Down: Wiki server" {
		t.Fatalf("saved template subject = %q, want it used", subject)
	}
}
