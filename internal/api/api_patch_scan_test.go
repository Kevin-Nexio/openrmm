package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/p1ngu/rmm/internal/config"
	"github.com/p1ngu/rmm/internal/hub"
	"github.com/p1ngu/rmm/internal/patches"
	"github.com/p1ngu/rmm/internal/protocol"
)

func TestPatchScanDistinguishesOfflineFromBackpressure(t *testing.T) {
	f := newScriptFixture(t)
	h := hub.New()
	f.handler = (&Server{
		cfg: &config.Config{APIRateLimit: 10000}, store: f.store,
		patches: patches.New(f.store, h),
	}).Router()
	device, err := f.store.CreateAgent(context.Background(), "scan-target", "linux", "amd64", "1.0", "synthetic-scan-token", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/devices/" + device.ID + "/patches/scan"
	scan := func(status int, wantKey, wantValue string) map[string]string {
		t.Helper()
		res := f.do(http.MethodPost, path, "")
		if res.Code != status {
			t.Fatalf("scan returned %d, want %d: %s", res.Code, status, res.Body)
		}
		var body map[string]string
		if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body[wantKey] != wantValue {
			t.Fatalf("response %v, want %s=%q", body, wantKey, wantValue)
		}
		return body
	}

	scan(http.StatusServiceUnavailable, "code", "device_offline")
	if f.audit("patch.scan") != nil {
		t.Fatal("an offline request should not be recorded as dispatched")
	}

	frames := h.Add(device.ID, nil)
	for range cap(frames) {
		frames <- []byte("queued")
	}
	body := scan(http.StatusServiceUnavailable, "error", "internal server error")
	if body["code"] != "" {
		t.Fatalf("a full queue must not be reported as offline: %v", body)
	}
	for range cap(frames) {
		<-frames
	}

	scan(http.StatusAccepted, "status", "scanning")
	select {
	case frame := <-frames:
		var message protocol.Envelope
		if err := json.Unmarshal(frame, &message); err != nil || message.Type != protocol.MsgPatchScan {
			t.Fatalf("expected patch scan frame, got %q (%v)", frame, err)
		}
	default:
		t.Fatal("scan accepted without dispatch")
	}
	if f.audit("patch.scan") == nil {
		t.Fatal("dispatched scan was not audited")
	}
}
