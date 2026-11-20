package notify

import (
	"strings"
	"testing"
)

// Subjects carry hostnames and check names that originate on an endpoint, so a
// compromised agent could try to smuggle headers through them.
func TestRenderStripsHeaderInjection(t *testing.T) {
	msg := Message{
		To:      "ops@example.test",
		Subject: "disk full\r\nBcc: attacker@evil.test",
		Body:    "ok",
	}
	out := render(Config{From: "rmm@example.test"}, msg)

	headers, _, ok := strings.Cut(out, "\r\n\r\n")
	if !ok {
		t.Fatal("rendered message has no header/body separator")
	}
	// The payload may survive as literal text inside the Subject value — that is
	// harmless. What must not happen is it becoming a header line of its own.
	for _, line := range strings.Split(headers, "\r\n") {
		name, _, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(name), "bcc") {
			t.Fatalf("injected Bcc became a real header:\n%s", headers)
		}
	}
	if strings.Count(headers, "\r\nSubject:") != 1 {
		t.Fatalf("expected exactly one Subject header, got:\n%s", headers)
	}
}

// A body line consisting of a single dot terminates DATA; it must be stuffed.
func TestNormalizeBodyStuffsLeadingDots(t *testing.T) {
	got := normalizeBody("first\n.\n.hidden\nlast")
	want := "first\r\n..\r\n..hidden\r\nlast\r\n"
	if got != want {
		t.Fatalf("dot stuffing wrong:\n got %q\nwant %q", got, want)
	}
}

// A lone CR is a line break: no CR may reach the relay outside a CRLF, and a
// dot after one is stuffed like any other line, so "\r.\r\n" in endpoint text
// cannot end the message early on a server that splits lines on CR.
func TestNormalizeBodyTreatsBareCRAsLineBreak(t *testing.T) {
	for _, in := range []string{"host\r.\r\nMAIL FROM:<x@evil>", "a\r.\rb", "a\n.\r\nb", "x\r\r\n.\ry"} {
		got := normalizeBody(in)
		if strings.Contains(strings.ReplaceAll(got, "\r\n", ""), "\r") {
			t.Errorf("normalizeBody(%q) = %q keeps a bare CR", in, got)
		}
		if strings.Contains(got, "\r\n.\r\n") {
			t.Errorf("normalizeBody(%q) = %q has a terminating dot line", in, got)
		}
	}
	if got, want := normalizeBody("host\r.\r\nnext"), "host\r\n..\r\nnext\r\n"; got != want {
		t.Fatalf("normalizeBody = %q, want %q", got, want)
	}
}

func TestValidateRejectsCredentialsWithoutTLS(t *testing.T) {
	cfg := Config{Host: "mail.example.test", Port: 25, From: "rmm@example.test",
		TLSMode: "none", Password: "hunter2"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected refusal to send credentials over an unencrypted link")
	}
}

func TestEnabledRequiresHostAndSender(t *testing.T) {
	if (Config{Host: "mail.example.test"}).Enabled() {
		t.Fatal("a config without a sender must not count as enabled")
	}
	if !(Config{Host: "mail.example.test", From: "rmm@example.test"}).Enabled() {
		t.Fatal("host + sender should be enough to attempt delivery")
	}
}
