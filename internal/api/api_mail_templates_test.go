package api

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/p1ngu/rmm/internal/config"
	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/notify"
	"github.com/p1ngu/rmm/internal/notify/smtptest"
	"github.com/p1ngu/rmm/internal/store"
)

func TestAlertTemplatesConfigurationIntegration(t *testing.T) {
	e := newSMTPE2E(t, func(c *config.Config) {
		c.PublicURL = "https://agents.example.test"
		c.ConsolePublicURL = "https://console.example.test"
	})
	code, view := e.do(http.MethodGet, "/api/config/mail/templates", "", e.admin)
	if code != 200 || view["config"].(map[string]any)["device_name"] != "hostname" {
		t.Fatalf("defaults: %d %+v", code, view)
	}
	c := notify.DefaultAlertTemplates()
	c.DeviceName = "both"
	c.Alert.Subject, c.Alert.Body = "Incident {{device}}", "Détails : {{details}}\n{{console_url}}"
	preview, _ := json.Marshal(map[string]any{"config": c, "event": "alert"})
	code, view = e.do(http.MethodPost, "/api/config/mail/templates/preview", string(preview), e.admin)
	if code != 200 || view["subject"] != "Incident Wiki server (server-01)" {
		t.Fatalf("preview: %d %+v", code, view)
	}
	if !strings.Contains(view["body"].(string), "https://console.example.test") || strings.Contains(view["body"].(string), "https://agents.example.test") {
		t.Fatalf("preview console link: %+v", view)
	}
	if got, err := notify.LoadAlertTemplates(e.ctx, e.store); err != nil || got.DeviceName != "hostname" {
		t.Fatal("preview persisted changes")
	}
	body, _ := json.Marshal(c)
	if code, view = e.do(http.MethodPut, "/api/config/mail/templates", string(body), e.admin); code != 200 {
		t.Fatalf("save: %d %+v", code, view)
	}
	if got, err := notify.LoadAlertTemplates(e.ctx, e.store); err != nil || got != c {
		t.Fatalf("stored: %+v %v", got, err)
	}
	c.Recovery.Body = "{{unknown}}"
	body, _ = json.Marshal(c)
	if code, _ = e.do(http.MethodPut, "/api/config/mail/templates", string(body), e.admin); code != 400 {
		t.Fatalf("invalid template: %d", code)
	}
	got, _ := notify.LoadAlertTemplates(e.ctx, e.store)
	if got.Recovery.Body == c.Recovery.Body {
		t.Fatal("invalid save overwrote settings")
	}
	if _, err := e.store.GetAppSetting(e.ctx, "smtp.alerts.host"); err == nil {
		t.Fatal("template save altered SMTP settings")
	}
}

func TestAlertTemplatesRequireGlobalSettingsPermissionIntegration(t *testing.T) {
	e := newSMTPE2E(t)
	client, err := e.store.CreateClient(e.ctx, "template-client")
	if err != nil {
		t.Fatal(err)
	}
	scoped := e.session(models.RoleAdmin, []models.UserScope{{ScopeType: models.ScopeClient, ScopeID: client.ID}})
	tech := e.session(models.RoleTech, nil)
	for _, token := range []string{tech, scoped, ""} {
		for _, route := range []struct{ method, path string }{{"GET", "/api/config/mail/templates"}, {"PUT", "/api/config/mail/templates"}, {"POST", "/api/config/mail/templates/preview"}} {
			code, _ := e.do(route.method, route.path, `{}`, token)
			if code != 401 && code != 403 {
				t.Fatalf("%s %s: unauthorized status %d", route.method, route.path, code)
			}
		}
	}
}

func TestAlertTemplatesSendStoredExampleIntegration(t *testing.T) {
	relay := smtptest.New(t)
	e := newSMTPE2E(t, func(c *config.Config) { c.SMTPAlertsAllowPrivate = true })
	relayBody := fmt.Sprintf(`{"host":"127.0.0.1","port":%d,"from":"alerts@example.test","tls_mode":"none"}`, relay.Port)
	if code, out := e.do("PUT", "/api/config/smtp/alerts", relayBody, e.admin); code != 200 {
		t.Fatalf("relay: %d %+v", code, out)
	}
	user, err := e.store.CreateUser(e.ctx, "template-operator", "hash", models.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.store.UpdateUserEmail(e.ctx, user.ID, "operator@example.test"); err != nil {
		t.Fatal(err)
	}
	session := e.sessionFor(user.ID)
	c := notify.DefaultAlertTemplates()
	c.DeviceName = "description"
	c.Recovery.Subject, c.Recovery.Body = "Restored {{device}}", "{{description}}: {{details}}"
	body, _ := json.Marshal(c)
	if code, out := e.do("PUT", "/api/config/mail/templates", string(body), session); code != 200 {
		t.Fatalf("save: %d %+v", code, out)
	}
	if code, out := e.do("POST", "/api/config/smtp/alerts/test", `{"template_event":"recovery"}`, session); code != 200 {
		t.Fatalf("send: %d %+v", code, out)
	}
	messages := relay.Messages()
	if len(messages) != 1 || messages[0].To[0] != "operator@example.test" {
		t.Fatalf("delivery: %+v", messages)
	}
	message, err := mail.ReadMessage(strings.NewReader(messages[0].Data))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil || subject != "[TEST] Restored Wiki server" {
		t.Fatalf("subject: %q %v", subject, err)
	}
	if rendered := messages[0].Text(t); !strings.Contains(rendered, "Wiki server: Example only:") {
		t.Fatalf("body: %s", rendered)
	}
	if code, _ := e.do("POST", "/api/config/smtp/alerts/test", `{"template_event":"unknown"}`, session); code != 400 {
		t.Fatalf("invalid kind: %d", code)
	}
	if len(relay.Messages()) != 1 {
		t.Fatal("invalid event sent a message")
	}
}

func TestSharedAlertTemplateSampleUsesSeparateBudgetIntegration(t *testing.T) {
	relay := smtptest.New(t)
	e := newSMTPE2E(t, withAlertService(relay))
	const to = "admin@example.test"
	user, err := e.store.CreateUser(e.ctx, "template-operator", "hash", models.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.store.UpdateUserEmail(e.ctx, user.ID, to); err != nil {
		t.Fatal(err)
	}
	verification := "verify-" + user.ID
	if err = e.store.CreateEmailVerification(e.ctx, user.ID, to, verification, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = e.store.ConfirmEmailVerification(e.ctx, verification); err != nil {
		t.Fatal(err)
	}
	session := e.sessionFor(user.ID)
	const route = "/api/config/smtp/alerts/test"
	for i := range store.SharedAlertTestHourlyLimit {
		body := `{"template_event":"alert"}`
		if i == 0 {
			body = `{}` // the fixed and customizable tests share the test budget
		}
		if code, out := e.do(http.MethodPost, route, body, session); code != http.StatusOK {
			t.Fatalf("test mail %d: HTTP %d (%v)", i, code, out)
		}
	}
	code, out := e.do(http.MethodPost, route, `{"template_event":"recovery"}`, session)
	if code != http.StatusTooManyRequests || out["code"] != "shared_alert_test_limit" {
		t.Fatalf("exhausted test budget: HTTP %d (%v)", code, out)
	}
	messages := relay.Messages()
	if len(messages) != store.SharedAlertTestHourlyLimit {
		t.Fatalf("sent %d samples", len(messages))
	}
	for _, m := range messages {
		if len(m.To) != 1 || m.To[0] != to {
			t.Fatal("test did not go to the confirmed address")
		}
		if !strings.Contains(m.Text(t), "for the instance acme.openrmm.test.") {
			t.Fatal("test lacks the shared service footer")
		}
	}
	sent, err := e.store.NotificationsSentSince(e.ctx, time.Now().Add(-time.Hour))
	if err != nil || sent != 0 {
		t.Fatalf("alert budget counted %d samples: %v", sent, err)
	}
	if got := e.auditCount("config.smtp.alerts.test", "app_settings"); got != store.SharedAlertTestHourlyLimit {
		t.Fatalf("test audit entries = %d", got)
	}
}
