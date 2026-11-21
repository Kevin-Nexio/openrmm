package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/protocol"
)

// A saved script deployed to many devices runs by id on each of them, as it
// does from one device's page: its parameters and script variables go with it,
// the variables resolved for each device when the batch is approved and sent.
func TestProposeBulkScriptRunsTheSavedScriptByIdOnEveryDevice(t *testing.T) {
	ctx := context.Background()
	svc, fs, sender := variableService()
	fs.agents["a2"], fs.agents["a3"] = true, true
	fs.clientOf["a1"], fs.clientOf["a2"], fs.clientOf["a3"] = "client-a", "client-a", "client-b"
	sc := &models.Script{ID: "script-1", Name: "Install agent", Shell: "sh", Body: `install --key "$CUSTOMER_KEY" --site "$OPENRMM_PARAM_SITE"`,
		Variables: []string{"CUSTOMER_KEY"}, Params: []models.ScriptParam{{Name: "site", Kind: "enum", Values: []string{"hq", "branch"}}}}
	params := map[string]string{"site": "hq"}

	batches, err := svc.ProposeBulkScript(ctx, []string{"a1", "a2", "a3"}, sc, params, "library: Install agent", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || len(sender.frames) != 0 {
		t.Fatalf("batches=%d sends=%d, want one batch per client and nothing sent", len(batches), len(sender.frames))
	}
	for _, b := range batches {
		for _, id := range b.JobIDs {
			j := fs.jobs[id]
			if j.ScriptID == nil || *j.ScriptID != "script-1" || j.Script != sc.Body || j.Shell != "sh" ||
				!slices.Equal(j.Variables, sc.Variables) || !maps.Equal(j.Params, params) ||
				j.Status != models.JobAwaitingApproval || !j.RequiresApproval || j.BatchID == nil || *j.BatchID != b.BatchID {
				t.Fatalf("job %+v is not the saved script awaiting approval in batch %s", j, b.BatchID)
			}
		}
	}
	if !strings.Contains(fs.auditDetail["job.batch.propose"], `"script_id":"script-1"`) {
		t.Fatalf("the audit does not name the script: %s", fs.auditDetail["job.batch.propose"])
	}
	for _, j := range fs.jobs {
		raw, _ := json.Marshal(j)
		if strings.Contains(string(raw), fs.secret) {
			t.Fatal("a variable value was stored on a job")
		}
	}

	// Approving one company's batch sends its jobs with the values resolved now.
	fs.secret = "rotated-customer-key"
	var clientA BatchInfo
	for _, b := range batches {
		if b.ClientID == "client-a" {
			clientA = b
		}
	}
	if n, err := svc.ApproveBatch(ctx, clientA.BatchID, "approver"); err != nil || n != 2 {
		t.Fatalf("ApproveBatch = %d, %v", n, err)
	}
	if len(sender.frames) != 2 {
		t.Fatalf("sends = %d, want the two client-a jobs", len(sender.frames))
	}
	for _, frame := range sender.frames {
		var envelope protocol.Envelope
		var msg protocol.JobMsg
		if json.Unmarshal(frame, &envelope) != nil || json.Unmarshal(envelope.Data, &msg) != nil {
			t.Fatal("undecodable job frame")
		}
		if msg.Vars["CUSTOMER_KEY"] != "rotated-customer-key" || msg.Params["site"] != "hq" || msg.Script != sc.Body {
			t.Fatalf("sent job lacks the script's variables or parameters: %+v", msg)
		}
	}
}

// The whole deployment is refused, and nothing is created, when any device
// could not run the script; the answer names the devices.
func TestProposeBulkScriptRefusesWhatOneDeviceCouldNotRun(t *testing.T) {
	ctx := context.Background()
	withVars := &models.Script{ID: "s-vars", Shell: "sh", Body: `echo "$CUSTOMER_KEY"`, Variables: []string{"CUSTOMER_KEY"}}
	withParams := &models.Script{ID: "s-params", Shell: "sh", Body: "echo", Params: []models.ScriptParam{{Name: "site", Kind: "enum", Values: []string{"hq"}}}}

	for _, tc := range []struct {
		name   string
		setup  func(*variableStore)
		script *models.Script
		params map[string]string
		want   []string
	}{
		{"a variable without a value", func(fs *variableStore) { fs.secret = "" }, withVars, nil, []string{"host-a1", "host-a2", "variable unset"}},
		{"an agent too old for parameters", func(fs *variableStore) { fs.versions["a2"] = "0.9.0" }, withParams, map[string]string{"site": "hq"}, []string{"host-a2", models.MinAgentVersionAutonomy}},
		{"an agent too old for variables", func(fs *variableStore) { fs.versions["a1"] = "0.10.0" }, withVars, nil, []string{"host-a1", models.MinAgentVersionScriptVars}},
		{"an unknown device", func(fs *variableStore) { delete(fs.agents, "a2") }, withVars, nil, []string{"a2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, fs, sender := variableService()
			fs.agents["a2"] = true
			tc.setup(fs)
			_, err := svc.ProposeBulkScript(ctx, []string{"a1", "a2"}, tc.script, tc.params, "d", "admin")
			if err == nil {
				t.Fatal("the deployment was accepted")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not mention %q", err, w)
				}
			}
			if len(fs.jobs) != 0 || len(sender.frames) != 0 {
				t.Fatalf("jobs=%d sends=%d after a refusal", len(fs.jobs), len(sender.frames))
			}
		})
	}

	svc, fs, _ := variableService()
	pending := &models.Script{ID: "s-ai", Shell: "sh", Body: "echo", Pending: true}
	if _, err := svc.ProposeBulkScript(ctx, []string{"a1"}, pending, nil, "d", "admin"); !errors.Is(err, ErrScriptPending) {
		t.Fatalf("a proposal awaiting review: %v", err)
	}
	cmd := &models.Script{ID: "s-cmd", Shell: models.ShellCmd, Body: "echo %CUSTOMER_KEY%", Variables: []string{"CUSTOMER_KEY"}}
	if _, err := svc.ProposeBulkScript(ctx, []string{"a1"}, cmd, nil, "d", "admin"); err == nil {
		t.Fatal("a CMD script with variables was accepted")
	}
	if len(fs.jobs) != 0 {
		t.Fatalf("%d jobs created", len(fs.jobs))
	}
}

// A long list of devices that cannot run it is cut short, with the rest counted.
func TestProposeBulkScriptListsAtMostTenDevices(t *testing.T) {
	svc, fs, _ := variableService()
	fs.secret = ""
	ids := []string{}
	for i := 0; i < 13; i++ {
		id := "d" + string(rune('a'+i))
		fs.agents[id] = true
		ids = append(ids, id)
	}
	sc := &models.Script{ID: "s", Shell: "sh", Body: "echo", Variables: []string{"CUSTOMER_KEY"}}
	_, err := svc.ProposeBulkScript(context.Background(), ids, sc, nil, "d", "admin")
	if err == nil || !errors.Is(err, ErrFleetCannotRun) || !strings.Contains(err.Error(), "and 3 more") || strings.Contains(err.Error(), "host-dm") {
		t.Fatalf("error = %v", err)
	}
}
