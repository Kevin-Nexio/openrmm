package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/p1ngu/rmm/internal/auth"
	"github.com/p1ngu/rmm/internal/models"
)

// Alerts ▸ Silences & maintenance, through the real router and store. An
// administrator with no scope restriction got a 500 from the list (an empty
// scope user sent where PostgreSQL expects a uuid); a restricted reader still
// sees only what its scope covers.
func TestAlertSuppressionsListForUnrestrictedAdminE2E(t *testing.T) {
	f := newPolicyAPIFixture(t)
	ctx := context.Background()
	client, err := f.store.CreateClient(ctx, "suppressions e2e")
	if err != nil {
		t.Fatal(err)
	}
	site, err := f.store.CreateSite(ctx, client.ID, "suppressions e2e")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := f.store.CreateAgent(ctx, "suppressions-e2e", "linux", "amd64", "0.11.3", "test", &site.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"kind": "maintenance", "scope_type": "agent", "scope_id": agent.ID,
		"ends_at": time.Now().Add(time.Hour), "reason": "patch night"})
	if err != nil {
		t.Fatal(err)
	}
	if r := f.do(http.MethodPost, "/api/alert-suppressions", string(body)); r.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", r.Code, r.Body.String())
	}
	list := func(query string) []models.AlertSuppression {
		t.Helper()
		r := f.do(http.MethodGet, "/api/alert-suppressions"+query, "")
		if r.Code != http.StatusOK {
			t.Fatalf("GET /api/alert-suppressions%s = %d: %s", query, r.Code, r.Body.String())
		}
		var out struct {
			Suppressions []models.AlertSuppression `json:"suppressions"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Suppressions
	}
	has := func(rows []models.AlertSuppression) bool {
		for _, row := range rows {
			if row.ScopeID == agent.ID && row.Reason == "patch night" {
				return true
			}
		}
		return false
	}
	for _, query := range []string{"", "?active=false"} {
		if rows := list(query); !has(rows) {
			t.Fatalf("administrator list%s misses the suppression: %+v", query, rows)
		}
	}
	// Control: a principal restricted to another device sees none of it.
	scoped, err := f.store.CreateUserWithScopes(ctx, "suppressions-elsewhere", "hash", models.RoleTech,
		[]models.UserScope{{ScopeType: models.ScopeAgent, ScopeID: uuid.NewString()}})
	if err != nil {
		t.Fatal(err)
	}
	f.token = auth.NewToken()
	if err := f.store.CreateSession(ctx, scoped.ID, auth.Hash(f.token), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rows := list("?active=false"); has(rows) {
		t.Fatalf("a reader scoped elsewhere sees the suppression: %+v", rows)
	}
}
