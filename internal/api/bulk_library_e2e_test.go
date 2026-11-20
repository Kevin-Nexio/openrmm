package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/p1ngu/rmm/internal/config"
	"github.com/p1ngu/rmm/internal/jobs"
	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/protocol"
)

// Runs in the PostgreSQL CI job. Deploy to many with a saved script: one batch
// per company, each job running the script by id with the parameter values
// given, and with its script variables resolved for each device when its batch
// is approved: two companies with different values each get their own. The
// request is refused, creating nothing, when a device has no value for a
// variable, a parameter value is not one the script accepts, or the body mixes
// a script's text with its id.
func TestBulkDeployLibraryScriptE2EIntegration(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	cfg := &config.Config{APIRateLimit: 10000, SettingsEncryptionKey: "synthetic-instance-key"}
	sender := &variableE2ESender{}
	service := jobs.New(f.store, sender).WithSettings(cfg)
	f.handler = (&Server{cfg: cfg, store: f.store, jobs: service}).Router()

	device := func(company, host string) (clientID, agentID string) {
		t.Helper()
		c, err := f.store.CreateClient(ctx, company)
		if err != nil {
			t.Fatal(err)
		}
		s, err := f.store.CreateSite(ctx, c.ID, "HQ")
		if err != nil {
			t.Fatal(err)
		}
		a, err := f.store.CreateAgent(ctx, host, "linux", "amd64", "0.11.0", "synthetic-token-"+host, &s.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c.ID, a.ID
	}
	clientA, pcA := device("Bulk Customer A", "BULK-A1")
	clientB, pcB := device("Bulk Customer B", "BULK-B1")
	_, pcC := device("Bulk Customer C", "BULK-C1")

	variable, err := f.store.CreateScriptVariable(ctx, "BULK_CUSTOMER_KEY", "", true)
	if err != nil {
		t.Fatal(err)
	}
	for client, value := range map[string]string{clientA: "synthetic-key-a", clientB: "synthetic-key-b"} {
		if rec := f.do("PUT", "/api/script-variables/"+variable.ID+"/values", `{"scope_type":"client","scope_id":"`+client+`","value":"`+value+`"}`); rec.Code != 200 {
			t.Fatalf("set value: %d %s", rec.Code, rec.Body)
		}
	}
	rec := f.do("POST", "/api/scripts", `{"name":"Bulk installer","shell":"sh","body":"install \"$BULK_CUSTOMER_KEY\" \"$OPENRMM_PARAM_SITE\"","variables":["BULK_CUSTOMER_KEY"],"params":[{"name":"site","kind":"enum","values":["hq","branch"]}]}`)
	if rec.Code != 201 {
		t.Fatalf("create script: %d %s", rec.Code, rec.Body)
	}
	var sc models.Script
	if err := json.Unmarshal(rec.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	countJobs := func() int {
		t.Helper()
		n := 0
		for _, id := range []string{pcA, pcB, pcC} {
			list, err := f.store.ListJobs(ctx, id, 100)
			if err != nil {
				t.Fatal(err)
			}
			n += len(list)
		}
		return n
	}

	// Refused, with nothing created.
	for _, tc := range []struct{ body, want string }{
		{`{"agent_ids":["` + pcA + `","` + pcC + `"],"script_id":"` + sc.ID + `","params":{"site":"hq"}}`, "BULK-C1"},
		{`{"agent_ids":["` + pcA + `"],"script_id":"` + sc.ID + `","params":{"site":"moon"}}`, "site"},
		{`{"agent_ids":["` + pcA + `"],"script_id":"` + sc.ID + `","script":"echo","params":{"site":"hq"}}`, "not both"},
		{`{"agent_ids":["` + pcA + `"],"shell":"sh","script":"echo","params":{"site":"hq"}}`, "script_id"},
	} {
		rec := f.do("POST", "/api/jobs/bulk", tc.body)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: %d %s, want 400 mentioning %q", tc.body, rec.Code, rec.Body, tc.want)
		}
	}
	if n := countJobs(); n != 0 || len(sender.frames) != 0 {
		t.Fatalf("a refused deployment left %d jobs and %d sends", n, len(sender.frames))
	}

	rec = f.do("POST", "/api/jobs/bulk", `{"agent_ids":["`+pcA+`","`+pcB+`"],"script_id":"`+sc.ID+`","params":{"site":"hq"}}`)
	if rec.Code != 201 {
		t.Fatalf("bulk deploy: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Batches []struct {
			ClientID string `json:"client_id"`
			BatchID  string `json:"batch_id"`
			Count    int    `json:"count"`
		} `json:"batches"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 2 || len(out.Batches) != 2 || len(sender.frames) != 0 || strings.Contains(rec.Body.String(), "synthetic-key") {
		t.Fatalf("response %s, sends %d", rec.Body, len(sender.frames))
	}
	listed, err := f.store.ListJobs(ctx, pcA, 10)
	if err != nil || len(listed) != 1 {
		t.Fatalf("jobs on %s: %v %v", pcA, listed, err)
	}
	if j := listed[0]; j.ScriptID == nil || *j.ScriptID != sc.ID || j.Params["site"] != "hq" || j.Description != "library: Bulk installer" || j.Status != models.JobAwaitingApproval {
		t.Fatalf("job %+v", j)
	}

	// Each company's batch is approved on its own, and each device gets its
	// company's value.
	want := map[string]string{clientA: "synthetic-key-a", clientB: "synthetic-key-b"}
	for _, b := range out.Batches {
		before := len(sender.frames)
		if rec := f.do("POST", "/api/jobs/batch/"+b.BatchID+"/approve", `{}`); rec.Code != 200 {
			t.Fatalf("approve %s: %d %s", b.BatchID, rec.Code, rec.Body)
		}
		if len(sender.frames) != before+1 {
			t.Fatalf("approving %s sent %d jobs", b.BatchID, len(sender.frames)-before)
		}
		var envelope protocol.Envelope
		var msg protocol.JobMsg
		if json.Unmarshal(sender.frames[before], &envelope) != nil || json.Unmarshal(envelope.Data, &msg) != nil {
			t.Fatal("undecodable frame")
		}
		if msg.Vars["BULK_CUSTOMER_KEY"] != want[b.ClientID] || msg.Params["site"] != "hq" {
			t.Fatalf("company %s got key %q params %v", b.ClientID, msg.Vars["BULK_CUSTOMER_KEY"], msg.Params)
		}
	}
}
