package scheduler

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/p1ngu/rmm/internal/config"
	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/notify"
	"github.com/p1ngu/rmm/internal/store"
	"github.com/p1ngu/rmm/internal/store/storetest"
)

func TestAlertDescriptionOutboxIntegration(t *testing.T) {
	url := os.Getenv("RMM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("RMM_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	st := storetest.NewSchema(t, "alert_description", url)
	u, err := st.CreateUser(ctx, "operator", "unused", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.UpdateUserEmail(ctx, u.ID, "operator@example.test"); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAgent(ctx, "technical-host", "linux", "amd64", "test", "hash", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.SetAgentMeta(ctx, a.ID, "Friendly device", ""); err != nil {
		t.Fatal(err)
	}
	s := &Scheduler{store: st, notifier: notify.New(st, func(context.Context) (notify.Config, string, error) {
		return notify.Config{Host: "relay.example.test", From: "rmm@example.test"}, "", nil
	})}
	opened, err := st.ObserveAlert(ctx, store.AlertObservation{
		AgentID: &a.ID, SourceType: models.AlertSourceAgent, SourceID: &a.ID,
		ConditionKey: "offline", Severity: models.SeverityError, Message: "Offline", ObservedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.queueAlertNotification(ctx, &opened.Alert, ""); err != nil {
		t.Fatal(err)
	}
	// A description edit during a retry must not duplicate the transition.
	if err = st.SetAgentMeta(ctx, a.ID, "Renamed device", ""); err != nil {
		t.Fatal(err)
	}
	if err = s.queueAlertNotification(ctx, &opened.Alert, ""); err != nil {
		t.Fatal(err)
	}
	queued, err := st.ClaimPendingNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 1 || queued[0].Subject != "[OpenRMM] Agent offline — Friendly device" || !strings.Contains(queued[0].Body, "Device: technical-host\n") {
		t.Fatalf("unexpected opening notifications: %+v", queued)
	}
	templates := notify.DefaultAlertTemplates()
	templates.DeviceName = "both"
	templates.Recovery.Subject = "Retour {{device}}"
	templates.Recovery.Body = "{{description}}|{{hostname}}|{{details}}"
	stored, _ := json.Marshal(templates)
	if err := st.UpsertAppSetting(ctx, notify.AlertTemplatesKey, string(stored), false); err != nil {
		t.Fatal(err)
	}
	resolved, err := st.ResolveAlertCondition(ctx, models.AlertSourceAgent, &a.ID, &a.ID, "offline", "system", "automatic", "Online", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 {
		t.Fatalf("resolved = %+v", resolved)
	}
	if err = s.queueAlertNotification(ctx, &resolved[0], ""); err != nil {
		t.Fatal(err)
	}
	queued, err = st.ClaimPendingNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 1 || queued[0].Subject != "Retour Renamed device (technical-host)" || queued[0].Body != "Renamed device|technical-host|Online" {
		t.Fatalf("unexpected recovery notifications: %+v", queued)
	}
}

// The release combines saved mail templates and device descriptions with the
// atomic outbox and historical Client/Site routes. Exercise that boundary through
// the scheduler, including retries after both presentation and routing changes.
func TestSavedTemplateDescriptionConsoleAndHistoricalRouteIntegration(t *testing.T) {
	databaseURL := os.Getenv("RMM_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("RMM_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	st := storetest.NewSchema(t, "release_notification", databaseURL)
	client, err := st.CreateClient(ctx, "Client")
	if err != nil {
		t.Fatal(err)
	}
	site, err := st.CreateSite(ctx, client.ID, "Site")
	if err != nil {
		t.Fatal(err)
	}
	makeRecipient := func(name string) string {
		t.Helper()
		user, err := st.CreateUser(ctx, name, "unused", models.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = st.UpdateUserEmail(ctx, user.ID, name+"@example.test"); err != nil {
			t.Fatal(err)
		}
		return user.ID
	}
	clientUser, siteUser := makeRecipient("client-oncall"), makeRecipient("site-oncall")
	for _, route := range []struct{ scope, id, user string }{{"client", client.ID, clientUser}, {"site", site.ID, siteUser}} {
		if _, err = st.UpdateNotificationRouting(ctx, route.scope, route.id, "operator", 0, models.NotificationRouteUpdate{Mode: "selected", UserIDs: []string{route.user}}); err != nil {
			t.Fatal(err)
		}
	}
	agent, err := st.CreateAgent(ctx, "technical-host", "linux", "amd64", "test", "hash", &site.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.SetAgentMeta(ctx, agent.ID, "Friendly device", ""); err != nil {
		t.Fatal(err)
	}
	templates := notify.DefaultAlertTemplates()
	templates.Alert.Subject = "ALERT {{device}}"
	templates.Recovery.Subject = "RECOVERY {{device}}"
	templates.Alert.Body = "{{description}}|{{hostname}}|{{details}}|{{console_url}}"
	templates.Recovery.Body = templates.Alert.Body
	raw, err := json.Marshal(templates)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.UpsertAppSetting(ctx, notify.AlertTemplatesKey, string(raw), false); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{PublicURL: "https://agents.example.test", ConsolePublicURL: "https://console.example.test"}
	scheduler := &Scheduler{store: st, consoleURL: cfg.NotificationConsoleURL(), notifier: notify.New(st, func(context.Context) (notify.Config, string, error) {
		return notify.Config{Host: "relay.example.test", From: "rmm@example.test"}, cfg.PublicURL, nil
	})}
	observe := func() *models.Alert {
		t.Helper()
		transition, err := st.ObserveAlert(ctx, store.AlertObservation{AgentID: &agent.ID, SourceType: models.AlertSourceAgent, SourceID: &agent.ID, ConditionKey: "offline", Severity: models.SeverityError, Message: "Offline", ObservedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return &transition.Alert
	}
	checkOutbox := func(alert *models.Alert, userID, subject, body string) {
		t.Helper()
		current, err := st.GetAlert(ctx, alert.ID)
		if err != nil || current.NotificationPending {
			t.Fatalf("transition not consumed atomically: %+v %v", current, err)
		}
		queued, err := st.ClaimPendingNotifications(ctx, 10)
		if err != nil || len(queued) != 1 {
			t.Fatalf("deduplicated fanout=%+v err=%v", queued, err)
		}
		n := queued[0]
		if n.UserID == nil || *n.UserID != userID || n.Subject != subject || n.Body != body || strings.Contains(n.Body, cfg.PublicURL) {
			t.Fatalf("unexpected rendered/targeted mail: %+v", n)
		}
		var provenance models.NotificationDeliveryContext
		if err = json.Unmarshal(n.DeliveryContext, &provenance); err != nil {
			t.Fatal(err)
		}
		if provenance.AlertID != alert.ID || provenance.NotificationSeq != alert.NotificationSeq || len(provenance.Route.UserIDs) != 1 || provenance.Route.UserIDs[0] != userID {
			t.Fatalf("wrong immutable provenance: %+v", provenance)
		}
		allowed, reason, err := st.NotificationDeliveryAllowed(ctx, &n, false)
		if err != nil || !allowed {
			t.Fatalf("historical delivery denied: %s %v", reason, err)
		}
	}
	opening := observe()
	// Subsequent incidents should inherit Client, while this incident stays on Site.
	if _, err = st.UpdateNotificationRouting(ctx, "site", site.ID, "operator", 1, models.NotificationRouteUpdate{Mode: "inherit"}); err != nil {
		t.Fatal(err)
	}
	if err = scheduler.queueAlertNotification(ctx, opening, ""); err != nil {
		t.Fatal(err)
	}
	if err = st.SetAgentMeta(ctx, agent.ID, "Renamed device", ""); err != nil {
		t.Fatal(err)
	}
	if err = scheduler.queueAlertNotification(ctx, opening, ""); err != nil {
		t.Fatal(err)
	}
	checkOutbox(opening, siteUser, "ALERT Friendly device", "Friendly device|technical-host|Offline|https://console.example.test")
	resolved, err := st.ResolveAlertCondition(ctx, models.AlertSourceAgent, &agent.ID, &agent.ID, "offline", "system", "automatic", "Online", time.Now())
	if err != nil || len(resolved) != 1 || !resolved[0].NotificationPending {
		t.Fatalf("recovery=%+v err=%v", resolved, err)
	}
	for i := 0; i < 2; i++ {
		if err = scheduler.queueAlertNotification(ctx, &resolved[0], ""); err != nil {
			t.Fatal(err)
		}
	}
	checkOutbox(&resolved[0], siteUser, "RECOVERY Renamed device", "Renamed device|technical-host|Online|https://console.example.test")
	reopened := observe()
	if reopened.ID == opening.ID {
		t.Fatal("reopen did not create a new incident")
	}
	for i := 0; i < 2; i++ {
		if err = scheduler.queueAlertNotification(ctx, reopened, ""); err != nil {
			t.Fatal(err)
		}
	}
	checkOutbox(reopened, clientUser, "ALERT Renamed device", "Renamed device|technical-host|Offline|https://console.example.test")
}
