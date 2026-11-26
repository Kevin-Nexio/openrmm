package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/p1ngu/rmm/internal/e2e"
)

func TestReadSessionFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid_e2e_params_and_unlink", func(t *testing.T) {
		want := e2e.SessionParams{
			Relay:     "wss://rmm.example.test/ws/remote?role=agent&session=s1",
			Ticket:    "ticket-1",
			FilesOnly: true,
			NoFiles:   false,
			NoChat:    true,
			E2E:       true,
			SessionID: "s1",
			AgentID:   "a1",
			Kind:      "files",
			GuestMode: "",
			EKPriv:    "ek-priv",
			ViewerKey: "viewer-key",
			IKPub:     "ik-pub",
			Exp:       1900000000,
			SigDel:    "sig-del",
		}
		path := filepath.Join(dir, "valid.json")
		body, _ := json.Marshal(want)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readSessionFile(path)
		if err != nil {
			t.Fatalf("readSessionFile: %v", err)
		}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("session file was not unlinked after read: err=%v", err)
		}
	})

	t.Run("missing_relay_rejected_and_unlinked", func(t *testing.T) {
		path := filepath.Join(dir, "norelay.json")
		if err := os.WriteFile(path, []byte(`{"ticket":"t"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSessionFile(path); err == nil || !strings.Contains(err.Error(), "no relay") {
			t.Fatalf("err = %v, want no relay error", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("missing-relay file was not unlinked")
		}
	})

	t.Run("invalid_json_rejected_and_unlinked", func(t *testing.T) {
		path := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(path, []byte(`{not-json`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSessionFile(path); err == nil {
			t.Fatal("readSessionFile accepted invalid JSON")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("invalid JSON file was not unlinked")
		}
	})

	t.Run("oversized_rejected_and_unlinked", func(t *testing.T) {
		path := filepath.Join(dir, "big.json")
		payload := append([]byte(`{"relay":"wss://x","ticket":"`), bytes.Repeat([]byte("a"), 17<<10)...)
		payload = append(payload, []byte(`"}`)...)
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSessionFile(path); err == nil || !strings.Contains(err.Error(), "exceed") {
			t.Fatalf("err = %v, want size limit error", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("oversized file was not unlinked")
		}
	})

	t.Run("missing_file_returns_error", func(t *testing.T) {
		if _, err := readSessionFile(filepath.Join(dir, "does-not-exist.json")); err == nil {
			t.Fatal("readSessionFile succeeded for missing file")
		}
	})
}
