package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Runs in the PostgreSQL CI job. The Devices list and a device's own read
// carry last_boot_at, worked out from the uptime its inventory reports, and
// leave it out for a device that has sent no inventory yet (the console shows
// a dash for it).
func TestDevicesReadLastBootE2EIntegration(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	c, err := f.store.CreateClient(ctx, "Boot-"+uuid.NewString()[:8])
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.store.CreateSite(ctx, c.ID, "HQ")
	if err != nil {
		t.Fatal(err)
	}
	agent := func(host string) string {
		t.Helper()
		a, err := f.store.CreateAgent(ctx, host+"-"+uuid.NewString()[:8], "windows", "amd64", "0.11.4", "tok-"+uuid.NewString(), &s.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	booted, fresh := agent("BOOTED"), agent("FRESH")
	if err := f.store.UpsertInventory(ctx, booted, []byte(`{"hostname":"booted","uptime_sec":7200}`)); err != nil {
		t.Fatal(err)
	}
	want := time.Now().Add(-2 * time.Hour)

	rec := f.do("GET", "/api/devices", "")
	if rec.Code != 200 {
		t.Fatalf("list devices = %d %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Devices []map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	byID := map[string]map[string]any{}
	for _, d := range list.Devices {
		byID[d["id"].(string)] = d
	}
	near := func(raw any, what string) {
		t.Helper()
		s, _ := raw.(string)
		got, err := time.Parse(time.RFC3339Nano, s)
		if err != nil || got.Sub(want).Abs() > time.Minute {
			t.Fatalf("%s: last_boot_at = %v, want about %s", what, raw, want.Format(time.RFC3339))
		}
	}
	near(byID[booted]["last_boot_at"], "the list")
	freshDevice, ok := byID[fresh]
	if !ok {
		t.Fatal("the list is missing the device without inventory")
	}
	if _, ok := freshDevice["last_boot_at"]; ok {
		t.Fatalf("a device with no inventory reads a boot time: %v", freshDevice)
	}

	rec = f.do("GET", "/api/devices/"+booted, "")
	if rec.Code != 200 {
		t.Fatalf("get device = %d %s", rec.Code, rec.Body.String())
	}
	var one map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil {
		t.Fatal(err)
	}
	near(one["last_boot_at"], "the device's own read")
}
