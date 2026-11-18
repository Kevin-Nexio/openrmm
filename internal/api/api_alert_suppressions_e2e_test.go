package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/p1ngu/rmm/internal/auth"
	"github.com/p1ngu/rmm/internal/config"
	"github.com/p1ngu/rmm/internal/models"
)

// Alerts ▸ Silences & maintenance, through the real router and store. An
// unrestricted principal (an administrator, or the server's admin token) got a
// 500 from the list: an empty scope user was sent where PostgreSQL expects a
// uuid. Restricted readers still see only what their scope covers.
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
	create := func(reason string) models.AlertSuppression {
		t.Helper()
		body, err := json.Marshal(map[string]any{"kind": "maintenance", "scope_type": "agent", "scope_id": agent.ID,
			"ends_at": time.Now().Add(time.Hour), "reason": reason})
		if err != nil {
			t.Fatal(err)
		}
		r := f.do(http.MethodPost, "/api/alert-suppressions", string(body))
		if r.Code != http.StatusCreated {
			t.Fatalf("create = %d: %s", r.Code, r.Body.String())
		}
		var sup models.AlertSuppression
		if err := json.Unmarshal(r.Body.Bytes(), &sup); err != nil || sup.ID == "" {
			t.Fatalf("created suppression: %+v %v", sup, err)
		}
		return sup
	}
	listWith := func(do func(method, target, body string) *httptest.ResponseRecorder, query string) []models.AlertSuppression {
		t.Helper()
		r := do(http.MethodGet, "/api/alert-suppressions"+query, "")
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
	list := func(query string) []models.AlertSuppression { return listWith(f.do, query) }
	find := func(rows []models.AlertSuppression, id string) *models.AlertSuppression {
		for i := range rows {
			if rows[i].ID == id {
				return &rows[i]
			}
		}
		return nil
	}

	patchNight := create("patch night")
	for _, query := range []string{"", "?active=false"} {
		if row := find(list(query), patchNight.ID); row == nil || row.Reason != "patch night" || row.ScopeID != agent.ID {
			t.Fatalf("administrator list%s misses the suppression: %+v", query, row)
		}
	}

	// The server's admin token is unrestricted too: the identity the lab hit.
	adminToken := "suppressions-e2e-" + auth.NewToken()
	tokenRouter := (&Server{cfg: &config.Config{APIRateLimit: 10000, AdminToken: adminToken}, store: f.store}).Router()
	withAdminToken := func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		tokenRouter.ServeHTTP(rec, req)
		return rec
	}
	for _, query := range []string{"", "?active=false"} {
		if find(listWith(withAdminToken, query), patchNight.ID) == nil {
			t.Fatalf("admin token list%s misses the suppression", query)
		}
	}

	// A canceled window leaves the active list and stays in the full one.
	calledOff := create("called off")
	if r := f.do(http.MethodDelete, "/api/alert-suppressions/"+calledOff.ID, ""); r.Code != http.StatusOK {
		t.Fatalf("cancel = %d: %s", r.Code, r.Body.String())
	}
	if active := list(""); find(active, calledOff.ID) != nil || find(active, patchNight.ID) == nil {
		t.Fatalf("the active list must drop the canceled window and keep the active one: %+v", active)
	}
	if row := find(list("?active=false"), calledOff.ID); row == nil || row.CanceledAt == nil {
		t.Fatalf("the full list must keep the canceled window with its cancellation: %+v", row)
	}

	session := func(name string, scopes []models.UserScope) {
		t.Helper()
		user, err := f.store.CreateUserWithScopes(ctx, name, "hash", models.RoleTech, scopes)
		if err != nil {
			t.Fatal(err)
		}
		f.token = auth.NewToken()
		if err := f.store.CreateSession(ctx, user.ID, auth.Hash(f.token), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	// A reader restricted to this device sees its window.
	session("suppressions-here", []models.UserScope{{ScopeType: models.ScopeAgent, ScopeID: agent.ID}})
	if find(list("?active=false"), patchNight.ID) == nil {
		t.Fatal("a reader scoped to the device must see its suppression")
	}
	// A principal restricted to another device sees none of it.
	session("suppressions-elsewhere", []models.UserScope{{ScopeType: models.ScopeAgent, ScopeID: uuid.NewString()}})
	if rows := list("?active=false"); find(rows, patchNight.ID) != nil || find(rows, calledOff.ID) != nil {
		t.Fatalf("a reader scoped elsewhere sees the suppressions: %+v", rows)
	}
}
