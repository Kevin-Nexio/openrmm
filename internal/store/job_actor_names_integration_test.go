package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/p1ngu/rmm/internal/models"
)

// Runs in the PostgreSQL CI job. A job stores who created and approved it as a
// user id; reads add the username behind it for display: a plain id, the id
// behind ai:/mcp: (the person the assistant acted for) and the releaser inside
// an autonomous run's "pre-approved by <id> (hash …)". Values that are not a
// user id — the bootstrap admin, an API token, the scheduler, an autonomy
// permission, a user that no longer exists — get no name, and the stored
// values never change. Every job read (by id, by device, all, by batch)
// carries the names.
func TestJobActorNamesIntegration(t *testing.T) {
	url := os.Getenv("RMM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("RMM_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	st := newIsolatedStore(t, "job_actor_names", url)

	maria, err := st.CreateUser(ctx, "maria-"+uuid.NewString()[:6], "hash", models.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	joao, err := st.CreateUser(ctx, "joao-"+uuid.NewString()[:6], "hash", models.RoleTech)
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAgent(ctx, "PC-"+uuid.NewString()[:8], "windows", "amd64", "0.11.0", "hash-"+uuid.NewString(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	str := func(s string) *string { return &s }
	gone := uuid.NewString()
	batch := uuid.NewString()
	cases := map[string]struct {
		createdBy, wantCreator string
		approvedBy             *string
		wantApprover           string
	}{
		"person and approver":   {maria.ID, maria.Username, str(joao.ID), joao.Username},
		"assistant for maria":   {"ai:" + maria.ID, maria.Username, nil, ""},
		"mcp for joao":          {"mcp:" + joao.ID, joao.Username, nil, ""},
		"released for the AI":   {"ai:" + joao.ID, joao.Username, str("pre-approved by " + maria.ID + " (hash 0123456789ab)"), maria.Username},
		"autonomy permission":   {"mcp:" + maria.ID, maria.Username, str("autonomy: " + models.PermAIAutonomyQuery), ""},
		"bootstrap admin":       {"admin", "", str("admin"), ""},
		"api token, scheduler":  {"api", "", str("scheduler"), ""},
		"user no longer exists": {gone, "", str(gone), ""},
	}
	ids := map[string]string{}
	for name, c := range cases {
		j, err := st.CreateJob(ctx, &models.Job{AgentID: a.ID, Type: models.JobRunScript, Description: name, Shell: "powershell",
			Script: "Write-Output ok", Status: models.JobAwaitingApproval, RequiresApproval: true, CreatedBy: c.createdBy, BatchID: &batch})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.approvedBy != nil {
			if _, err := st.pool.Exec(ctx, `UPDATE jobs SET approved_by=$2 WHERE id=$1`, j.ID, *c.approvedBy); err != nil {
				t.Fatal(err)
			}
		}
		ids[name] = j.ID
	}
	check := func(source string, j models.Job) {
		t.Helper()
		c := cases[j.Description]
		if j.CreatedBy != c.createdBy || j.CreatedByName != c.wantCreator || j.ApprovedByName != c.wantApprover {
			t.Fatalf("%s %q: created_by %q name %q, approved name %q; want %q %q", source, j.Description, j.CreatedBy, j.CreatedByName, j.ApprovedByName, c.wantCreator, c.wantApprover)
		}
		if c.approvedBy != nil && (j.ApprovedBy == nil || *j.ApprovedBy != *c.approvedBy) {
			t.Fatalf("%s %q: the stored approver changed: %v", source, j.Description, j.ApprovedBy)
		}
	}
	for name, id := range ids {
		j, err := st.GetJob(ctx, id)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		check("GetJob", *j)
	}
	for source, list := range map[string]func() ([]models.Job, error){
		"ListJobs(device)": func() ([]models.Job, error) { return st.ListJobs(ctx, a.ID, 100) },
		"ListJobs(all)":    func() ([]models.Job, error) { return st.ListJobs(ctx, "", 100) },
		"ListJobsByBatch":  func() ([]models.Job, error) { return st.ListJobsByBatch(ctx, batch) },
	} {
		jobs, err := list()
		if err != nil {
			t.Fatal(err)
		}
		if len(jobs) != len(cases) {
			t.Fatalf("%s: %d jobs, want %d", source, len(jobs), len(cases))
		}
		for _, j := range jobs {
			check(source, j)
		}
	}
}
