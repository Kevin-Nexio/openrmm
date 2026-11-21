package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/p1ngu/rmm/internal/store"
)

const AlertTemplatesKey = "notify.alert_templates"

const (
	maxAlertSubjectRunes = 200
	maxAlertSubjectBytes = maxAlertSubjectRunes * utf8.UTFMax
	maxAlertBodyBytes    = 32 * 1024
)

type MailTemplate struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

type AlertTemplates struct {
	DeviceName string       `json:"device_name"`
	Alert      MailTemplate `json:"alert"`
	Recovery   MailTemplate `json:"recovery"`
}

type AlertTemplateData struct {
	Event, AgentID, AlertID, Hostname, Description, Details, ConsoleURL string
	Time                                                                time.Time
}

var AlertTemplateVariables = []string{"device", "description", "hostname", "event", "details", "time", "console_url", "agent_id", "alert_id"}
var templateVariable = regexp.MustCompile(`\{\{\s*([a-z_]+)\s*\}\}`)

func DefaultAlertTemplates() AlertTemplates {
	return AlertTemplates{
		DeviceName: "hostname",
		Alert: MailTemplate{
			Subject: "[OpenRMM] {{event}} — {{device}}",
			Body:    "{{details}}\n\nDevice: {{hostname}}\nDetected: {{time}}\n\nOpen the console: {{console_url}}\n\nYou receive this because the device is inside your access scope.\nChange what you are notified about in Users & Settings.\n",
		},
		Recovery: MailTemplate{
			Subject: "[OpenRMM] Recovered — {{device}}",
			Body:    "{{details}}\n\nDevice: {{hostname}}\nRecovered: {{time}}\n\nOpen the console: {{console_url}}\n",
		},
	}
}

func ValidateAlertTemplates(c AlertTemplates) error {
	if c.DeviceName != "description" && c.DeviceName != "hostname" && c.DeviceName != "both" {
		return errors.New("device_name must be description, hostname or both")
	}
	allowed := map[string]bool{}
	for _, key := range AlertTemplateVariables {
		allowed[key] = true
	}
	for _, item := range []struct {
		name, value string
		limit       int
		subject     bool
	}{
		{"alert.subject", c.Alert.Subject, 512, true}, {"alert.body", c.Alert.Body, 16384, false},
		{"recovery.subject", c.Recovery.Subject, 512, true}, {"recovery.body", c.Recovery.Body, 16384, false},
	} {
		if !utf8.ValidString(item.value) || strings.TrimSpace(item.value) == "" || len(item.value) > item.limit || strings.ContainsRune(item.value, '\x00') {
			return fmt.Errorf("%s must contain valid text (1–%d bytes)", item.name, item.limit)
		}
		if item.subject && strings.ContainsAny(item.value, "\r\n") {
			return fmt.Errorf("%s must be a single line", item.name)
		}
		for _, match := range templateVariable.FindAllStringSubmatch(item.value, -1) {
			if !allowed[match[1]] {
				return fmt.Errorf("%s: unknown variable {{%s}}", item.name, match[1])
			}
		}
		rest := templateVariable.ReplaceAllString(item.value, "")
		if strings.Contains(rest, "{{") || strings.Contains(rest, "}}") {
			return fmt.Errorf("%s: invalid variable syntax", item.name)
		}
	}
	return nil
}

func LoadAlertTemplates(ctx context.Context, st *store.Store) (AlertTemplates, error) {
	row, err := st.GetAppSetting(ctx, AlertTemplatesKey)
	if errors.Is(err, store.ErrNotFound) {
		return DefaultAlertTemplates(), nil
	}
	if err != nil {
		return AlertTemplates{}, err
	}
	var c AlertTemplates
	if err := json.Unmarshal([]byte(row.Value), &c); err != nil {
		return c, err
	}
	return c, ValidateAlertTemplates(c)
}

// RenderAlertTemplate only substitutes known values once; it never evaluates
// expressions, HTML, code, or placeholders contained in agent-supplied data.
func RenderAlertTemplate(c AlertTemplates, kind string, d AlertTemplateData) (Message, error) {
	if err := ValidateAlertTemplates(c); err != nil {
		return Message{}, err
	}
	tpl := c.Alert
	if kind == "recovery" {
		tpl = c.Recovery
	} else if kind != "alert" {
		return Message{}, errors.New("event must be alert or recovery")
	}
	device := deviceSubjectName(d.Description, d.Hostname, d.AgentID)
	if c.DeviceName == "hostname" {
		device = deviceSubjectName("", d.Hostname, d.AgentID)
	}
	if c.DeviceName == "both" && strings.TrimSpace(d.Description) != "" && strings.TrimSpace(d.Hostname) != "" && strings.TrimSpace(d.Description) != strings.TrimSpace(d.Hostname) {
		device = deviceSubjectName(d.Description, "", "") + " (" + deviceSubjectName("", d.Hostname, "") + ")"
	}
	values := map[string]string{
		"device": device, "description": d.Description, "hostname": d.Hostname,
		"event": d.Event, "details": d.Details, "time": d.Time.UTC().Format(time.RFC3339),
		"console_url": strings.TrimRight(d.ConsoleURL, "/"), "agent_id": d.AgentID, "alert_id": d.AlertID,
	}
	subject := strings.Join(strings.Fields(expandAlertTemplate(tpl.Subject, values, maxAlertSubjectBytes)), " ")
	if subject == "" {
		subject = "[OpenRMM] " + device
	}
	if runes := []rune(subject); len(runes) > maxAlertSubjectRunes {
		subject = string(runes[:maxAlertSubjectRunes-1]) + "…"
	}
	return Message{Subject: subject, Body: expandAlertTemplate(tpl.Body, values, maxAlertBodyBytes)}, nil
}

// expandAlertTemplate bounds each append so repeated variables cannot grow the
// buffer beyond the output budget. Truncate at a UTF-8 boundary.
func expandAlertTemplate(template string, values map[string]string, limit int) string {
	var result strings.Builder
	appendPart := func(part string) bool {
		prefix := alertTextPrefix(part, limit-result.Len())
		result.WriteString(prefix)
		return len(prefix) == len(part)
	}
	for {
		match := templateVariable.FindStringSubmatchIndex(template)
		if match == nil {
			if appendPart(template) {
				return result.String()
			}
			break
		}
		if !appendPart(template[:match[0]]) || !appendPart(values[template[match[2]:match[3]]]) {
			break
		}
		template = template[match[1]:]
	}
	const ellipsis = "…"
	return alertTextPrefix(result.String(), limit-len(ellipsis)) + ellipsis
}

func alertTextPrefix(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	for limit > 0 && !utf8.RuneStart(text[limit]) {
		limit--
	}
	return text[:limit]
}

func SampleAlertTemplateData(kind, consoleURL string) AlertTemplateData {
	event, details := "Check failing", "Example only: disk usage is above 95%. No incident was created."
	if kind == "recovery" {
		event, details = "Recovered", "Example only: disk usage has returned to normal. No incident was created."
	}
	return AlertTemplateData{Event: event, AgentID: "example-agent", AlertID: "example-alert", Hostname: "server-01", Description: "Wiki server", Details: details, ConsoleURL: consoleURL, Time: time.Now()}
}
