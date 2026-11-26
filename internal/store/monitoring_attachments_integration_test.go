package store

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/p1ngu/rmm/internal/models"
)

// Runs in the PostgreSQL CI job. Checks and tasks attached to any number of
// policies and devices: a device gets each once, through any attachment that
// reaches it; detaching one attachment leaves the others; a copy takes one
// attachment away with it.

func (f *policyFixture) policy(name string) *models.Policy {
	f.t.Helper()
	p, err := f.store.CreatePolicy(f.ctx, name, "", "")
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *policyFixture) assign(p *models.Policy, scopeType, scopeID string) {
	f.t.Helper()
	if _, err := f.store.AssignPolicy(f.ctx, p.ID, scopeType, scopeID); err != nil {
		f.t.Fatal(err)
	}
}

func checkIDs(list []models.Check) []string {
	out := make([]string, 0, len(list))
	for _, c := range list {
		out = append(out, c.ID)
	}
	return out
}

func taskIDs(list []models.Task) []string {
	out := make([]string, 0, len(list))
	for _, t := range list {
		out = append(out, t.ID)
	}
	return out
}

func countOf(ids []string, id string) int {
	n := 0
	for _, x := range ids {
		if x == id {
			n++
		}
	}
	return n
}

func TestSharedCheckReachesEachDeviceOnceIntegration(t *testing.T) {
	f := newPolicyFixture(t)
	files, backup := f.policy("File server"), f.policy("Backup server")
	f.assign(files, models.ScopeClient, f.clientA.ID)
	f.assign(backup, models.ScopeAgent, f.agentA.ID)
	f.assign(backup, models.ScopeClient, f.clientB.ID)

	disk, err := f.store.CreateCheck(f.ctx, &models.Check{
		Attachments: []models.Attachment{{PolicyID: &files.ID}, {PolicyID: &backup.ID}},
		Type:        models.CheckDiskSpace, Name: "disk D:", IntervalSec: 300, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(disk.Attachments) != 2 || disk.SinglePolicyID != nil {
		t.Fatalf("attachments = %+v single=%v", disk.Attachments, disk.SinglePolicyID)
	}
	names := []string{disk.Attachments[0].Name, disk.Attachments[1].Name}
	if !slices.Contains(names, "File server") || !slices.Contains(names, "Backup server") {
		t.Fatalf("attachment names = %v", names)
	}

	// agentA is reached by both policies, agentB by one: each gets it once.
	for _, agent := range []*models.Agent{f.agentA, f.agentB} {
		checks, err := f.store.ChecksForAgent(f.ctx, agent.ID, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if n := countOf(checkIDs(checks), disk.ID); n != 1 {
			t.Fatalf("%s gets the shared check %d times", agent.Hostname, n)
		}
		if ok, err := f.store.CheckAppliesToAgent(f.ctx, disk.ID, agent.ID); err != nil || !ok {
			t.Fatalf("%s may not report the shared check: %v", agent.Hostname, err)
		}
	}
	covered, err := f.store.CheckCoveredAgents(f.ctx, disk.ID)
	if err != nil || len(covered) != 2 {
		t.Fatalf("covered = %v %v", covered, err)
	}

	// Taking it out of Backup server leaves agentA (File server) and drops agentB.
	if err := f.store.DetachCheck(f.ctx, disk.ID, models.Attachment{PolicyID: &backup.ID}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.store.CheckAppliesToAgent(f.ctx, disk.ID, f.agentB.ID); ok {
		t.Fatal("agentB still gets the check after its policy was detached")
	}
	if ok, _ := f.store.CheckAppliesToAgent(f.ctx, disk.ID, f.agentA.ID); !ok {
		t.Fatal("agentA lost the check it still gets through File server")
	}
	if err := f.store.DetachCheck(f.ctx, disk.ID, models.Attachment{PolicyID: &backup.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("detaching twice = %v", err)
	}

	// A direct attachment to agentB brings it back, and attaching twice is refused.
	if err := f.store.AttachCheck(f.ctx, disk.ID, models.Attachment{AgentID: &f.agentB.ID}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AttachCheck(f.ctx, disk.ID, models.Attachment{AgentID: &f.agentB.ID}); !errors.Is(err, ErrAttachmentExists) {
		t.Fatalf("attaching twice = %v", err)
	}
	if ok, _ := f.store.CheckAppliesToAgent(f.ctx, disk.ID, f.agentB.ID); !ok {
		t.Fatal("a direct attachment does not reach the device")
	}
	direct, err := f.store.ListChecks(f.ctx, f.agentB.ID, "")
	if err != nil || countOf(checkIDs(direct), disk.ID) != 1 {
		t.Fatalf("ListChecks(agentB) = %v %v", checkIDs(direct), err)
	}
	byPolicy, err := f.store.ListChecks(f.ctx, "", files.ID)
	if err != nil || countOf(checkIDs(byPolicy), disk.ID) != 1 {
		t.Fatalf("ListChecks(File server) = %v %v", checkIDs(byPolicy), err)
	}

	// Detaching everything leaves it Not in use: it exists, applies nowhere.
	for _, a := range []models.Attachment{{PolicyID: &files.ID}, {AgentID: &f.agentB.ID}} {
		if err := f.store.DetachCheck(f.ctx, disk.ID, a); err != nil {
			t.Fatal(err)
		}
	}
	unused, err := f.store.GetCheck(f.ctx, disk.ID)
	if err != nil || len(unused.Attachments) != 0 {
		t.Fatalf("not in use = %+v %v", unused, err)
	}
	if ok, _ := f.store.CheckAppliesToAgent(f.ctx, disk.ID, f.agentA.ID); ok {
		t.Fatal("a check with no attachment still applies")
	}

	// Deleting a policy removes its attachments, not the shared check.
	if err := f.store.AttachCheck(f.ctx, disk.ID, models.Attachment{PolicyID: &backup.ID}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.DeletePolicy(f.ctx, backup.ID); err != nil {
		t.Fatal(err)
	}
	if kept, err := f.store.GetCheck(f.ctx, disk.ID); err != nil || len(kept.Attachments) != 0 {
		t.Fatalf("after deleting the policy = %+v %v", kept, err)
	}
}

func TestCopyCheckForOneAttachmentIntegration(t *testing.T) {
	f := newPolicyFixture(t)
	files, branch := f.policy("File server"), f.policy("Branch office")
	f.assign(files, models.ScopeAgent, f.agentA.ID)
	f.assign(branch, models.ScopeAgent, f.agentB.ID)
	warn := 15.0
	orig, err := f.store.CreateCheck(f.ctx, &models.Check{
		Attachments: []models.Attachment{{PolicyID: &files.ID}, {PolicyID: &branch.ID}},
		Type:        models.CheckDiskSpace, Name: "disk", WarnThreshold: &warn, IntervalSec: 300, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := f.store.CopyCheckFor(f.ctx, orig.ID, models.Attachment{PolicyID: &branch.ID}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if cp.ID == orig.ID || cp.Name != "disk" || cp.WarnThreshold == nil || *cp.WarnThreshold != warn ||
		cp.SinglePolicyID == nil || *cp.SinglePolicyID != branch.ID || cp.Attachments[0].AddedBy != "admin" {
		t.Fatalf("copy = %+v", cp)
	}
	left, err := f.store.GetCheck(f.ctx, orig.ID)
	if err != nil || left.SinglePolicyID == nil || *left.SinglePolicyID != files.ID {
		t.Fatalf("original after the copy = %+v %v", left, err)
	}
	// Each device now runs its own: agentA the original, agentB the copy.
	for agent, want := range map[string]string{f.agentA.ID: orig.ID, f.agentB.ID: cp.ID} {
		checks, err := f.store.ChecksForAgent(f.ctx, agent, nil, nil)
		if err != nil || !slices.Contains(checkIDs(checks), want) || len(checks) != 1 {
			t.Fatalf("%s runs %v, want only %s (%v)", agent, checkIDs(checks), want, err)
		}
	}
	if _, err := f.store.CopyCheckFor(f.ctx, orig.ID, models.Attachment{PolicyID: &branch.ID}, "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("copying for an attachment it does not have = %v", err)
	}
}

func TestSharedTaskRunsOnceAndRunNowReachesEveryAttachmentIntegration(t *testing.T) {
	f := newPolicyFixture(t)
	pos, kiosks := f.policy("Point of sale"), f.policy("Kiosks")
	f.assign(pos, models.ScopeClient, f.clientA.ID)
	f.assign(kiosks, models.ScopeAgent, f.agentA.ID)
	reboot, err := f.store.CreateTask(f.ctx, &models.Task{
		Attachments: []models.Attachment{{PolicyID: &pos.ID}, {PolicyID: &kiosks.ID}, {AgentID: &f.agentB.ID}},
		Name:        "Sunday reboot", Shell: models.ShellBash, Script: "reboot", ScheduleKind: models.ScheduleInterval, IntervalSec: 3600, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, agent := range []string{f.agentA.ID, f.agentB.ID} {
		tasks, err := f.store.TasksForAgent(f.ctx, agent, nil, nil)
		if err != nil || countOf(taskIDs(tasks), reboot.ID) != 1 {
			t.Fatalf("%s gets the shared task %v times (%v)", agent, countOf(taskIDs(tasks), reboot.ID), err)
		}
	}
	targets, err := f.store.AgentIDsForTask(f.ctx, reboot.ID)
	if err != nil || len(targets) != 2 || !slices.Contains(targets, f.agentA.ID) || !slices.Contains(targets, f.agentB.ID) {
		t.Fatalf("run-now targets = %v %v", targets, err)
	}
	cp, err := f.store.CopyTaskFor(f.ctx, reboot.ID, models.Attachment{AgentID: &f.agentB.ID}, "admin")
	if err != nil || cp.SingleAgentID == nil || *cp.SingleAgentID != f.agentB.ID || cp.Script != "reboot" {
		t.Fatalf("task copy = %+v %v", cp, err)
	}
	if targets, _ := f.store.AgentIDsForTask(f.ctx, reboot.ID); len(targets) != 1 || targets[0] != f.agentA.ID {
		t.Fatalf("after the copy the original reaches %v", targets)
	}
}

// An AI proposal nobody approved applies to one policy or device only, and a
// policy's activation approves only the proposals attached to it alone, so
// approving one policy can never make something live through another.
func TestPendingProposalTakesOneAttachmentIntegration(t *testing.T) {
	f := newPolicyFixture(t)
	a, b := f.policy("A"), f.policy("B")
	two := []models.Attachment{{PolicyID: &a.ID}, {PolicyID: &b.ID}}
	if _, err := f.store.CreateCheck(f.ctx, &models.Check{Attachments: two, Type: models.CheckMemory, Name: "m", IntervalSec: 300, ProposedBy: "ai:x"}); !errors.Is(err, ErrPendingSingleAttachment) {
		t.Fatalf("proposal with two attachments = %v", err)
	}
	if _, err := f.store.CreateTask(f.ctx, &models.Task{Attachments: two, Name: "t", Shell: models.ShellBash, Script: "true", ScheduleKind: models.ScheduleInterval, IntervalSec: 3600, ProposedBy: "ai:x"}); !errors.Is(err, ErrPendingSingleAttachment) {
		t.Fatalf("task proposal with two attachments = %v", err)
	}
	proposal, err := f.store.CreateCheck(f.ctx, &models.Check{Attachments: models.OnPolicy(&a.ID), Type: models.CheckMemory, Name: "m", IntervalSec: 300, ProposedBy: "ai:x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.AttachCheck(f.ctx, proposal.ID, models.Attachment{PolicyID: &b.ID}); !errors.Is(err, ErrPendingSingleAttachment) {
		t.Fatalf("attaching a proposal elsewhere = %v", err)
	}
	// Even a row slipped in past those checks is not approved by A's activation.
	if _, err := f.store.pool.Exec(f.ctx, `INSERT INTO check_attachments (check_id, policy_id) VALUES ($1,$2)`, proposal.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	review, err := f.store.PolicyReview(f.ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ActivatePolicy(f.ctx, a.ID, "admin", review.Fingerprint, ActivationRights{ApproveTasks: true, ApproveChecks: true}); err != nil {
		t.Fatal(err)
	}
	still, err := f.store.GetCheck(f.ctx, proposal.ID)
	if err != nil || still.ApprovedBy != "" || still.Enabled {
		t.Fatalf("a proposal attached elsewhere was approved through A: %+v %v", still, err)
	}
}

// A policy's review shows what it shares, and an edit to a shared check makes
// an open review of every policy holding it stale.
func TestEditingASharedCheckStalesEveryPolicyReviewIntegration(t *testing.T) {
	f := newPolicyFixture(t)
	a, b := f.policy("A"), f.policy("B")
	shared, err := f.store.CreateCheck(f.ctx, &models.Check{
		Attachments: []models.Attachment{{PolicyID: &a.ID}, {PolicyID: &b.ID}},
		Type:        models.CheckMemory, Name: "memory", IntervalSec: 300, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ra, err := f.store.PolicyReview(f.ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := f.store.PolicyReview(f.ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ra.Checks) != 1 || len(ra.Checks[0].Attachments) != 2 {
		t.Fatalf("review of A = %+v", ra.Checks)
	}
	shared.IntervalSec = 600
	if err := f.store.UpdateCheck(f.ctx, shared); err != nil {
		t.Fatal(err)
	}
	for _, r := range []*models.PolicyReview{ra, rb} {
		if _, err := f.store.ActivatePolicy(f.ctx, r.Policy.ID, "admin", r.Fingerprint, ActivationRights{ApproveTasks: true, ApproveChecks: true}); !errors.Is(err, ErrReviewStale) {
			t.Fatalf("activation of %s after the shared check changed = %v", r.Policy.Name, err)
		}
	}
	// Attaching it to a third policy does not change what A puts into effect.
	c := f.policy("C")
	ra, _ = f.store.PolicyReview(f.ctx, a.ID)
	if err := f.store.AttachCheck(f.ctx, shared.ID, models.Attachment{PolicyID: &c.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ActivatePolicy(f.ctx, a.ID, "admin", ra.Fingerprint, ActivationRights{}); err != nil {
		t.Fatalf("A's review went stale over another policy's attachment: %v", err)
	}
}

// A check-scoped silence covers what it covered when it was made. Attaching
// the check to another device or to a policy later never widens a silence a
// restricted user made; one made with a policy attachment follows the check.
func TestCheckSilenceCoversWhatItRecordedIntegration(t *testing.T) {
	f := newPolicyFixture(t)
	ctx := context.Background()
	check, err := f.store.CreateCheck(ctx, &models.Check{Attachments: models.OnAgent(&f.agentA.ID), Type: models.CheckScript,
		Name: "probe", Config: []byte(`{"shell":"bash","script":"exit 1"}`), IntervalSec: 300, TimeoutSec: 30, FailureCount: 1, RecoveryCount: 1, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	observe := func(agent *models.Agent) models.Alert {
		t.Helper()
		obs := AlertObservation{AgentID: &agent.ID, SourceType: models.AlertSourceCheck, SourceID: &check.ID,
			ConditionKey: "health", Severity: models.SeverityWarning, Message: "failing", Cooldown: time.Minute, ObservedAt: time.Now()}
		res, err := f.store.ObserveAlert(ctx, obs)
		if err != nil {
			t.Fatal(err)
		}
		return res.Alert
	}
	sup := &models.AlertSuppression{Kind: models.SuppressionSilence, ScopeType: "check", ScopeID: check.ID,
		StartsAt: time.Now().Add(-time.Minute), EndsAt: time.Now().Add(time.Hour), Reason: "device-only", CreatedBy: "tech"}
	if sup.Snapshot, err = f.store.SuppressionSnapshot(ctx, sup); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateAlertSuppression(ctx, sup); err != nil {
		t.Fatal(err)
	}
	if a := observe(f.agentA); a.Status != models.AlertSuppressed {
		t.Fatalf("the recorded device is not silenced: %s", a.Status)
	}
	// agentB attached after the silence, and then a policy reaching it: still loud.
	if err := f.store.AttachCheck(ctx, check.ID, models.Attachment{AgentID: &f.agentB.ID}); err != nil {
		t.Fatal(err)
	}
	p := f.policy("later")
	f.assign(p, models.ScopeAgent, f.agentB.ID)
	if err := f.store.AttachCheck(ctx, check.ID, models.Attachment{PolicyID: &p.ID}); err != nil {
		t.Fatal(err)
	}
	if b := observe(f.agentB); b.Status == models.AlertSuppressed {
		t.Fatal("a silence made on one device widened to a device attached later")
	}
	// Made now, with the policy attachment, it follows the check everywhere.
	wide := &models.AlertSuppression{Kind: models.SuppressionSilence, ScopeType: "check", ScopeID: check.ID,
		StartsAt: time.Now().Add(-time.Minute), EndsAt: time.Now().Add(time.Hour), Reason: "everywhere", CreatedBy: "admin"}
	if err := f.store.CreateAlertSuppression(ctx, wide); err != nil {
		t.Fatal(err)
	}
	if b := observe(f.agentB); b.Status != models.AlertSuppressed {
		t.Fatalf("a silence made with a policy attachment does not follow the check: %s", b.Status)
	}
}

// A policy-scoped silence covers the policy's checks on the devices that
// policy reaches; the same check shared with another policy stays loud on the
// devices only that other policy reaches.
func TestPolicySilenceStaysWithItsPolicyIntegration(t *testing.T) {
	f := newPolicyFixture(t)
	ctx := context.Background()
	pa, pb := f.policy("A"), f.policy("B")
	f.assign(pa, models.ScopeAgent, f.agentA.ID)
	f.assign(pb, models.ScopeAgent, f.agentB.ID)
	check, err := f.store.CreateCheck(ctx, &models.Check{Attachments: []models.Attachment{{PolicyID: &pa.ID}, {PolicyID: &pb.ID}},
		Type: models.CheckScript, Name: "probe", Config: []byte(`{"shell":"bash","script":"exit 1"}`), IntervalSec: 300, TimeoutSec: 30, FailureCount: 1, RecoveryCount: 1, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateAlertSuppression(ctx, &models.AlertSuppression{Kind: models.SuppressionSilence, ScopeType: "policy", ScopeID: pa.ID,
		StartsAt: time.Now().Add(-time.Minute), EndsAt: time.Now().Add(time.Hour), Reason: "A only", CreatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	for agent, want := range map[*models.Agent]bool{f.agentA: true, f.agentB: false} {
		res, err := f.store.ObserveAlert(ctx, AlertObservation{AgentID: &agent.ID, SourceType: models.AlertSourceCheck, SourceID: &check.ID,
			ConditionKey: "health", Severity: models.SeverityWarning, Message: "failing", Cooldown: time.Minute, ObservedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Alert.Status == models.AlertSuppressed; got != want {
			t.Fatalf("%s silenced=%v, want %v", agent.Hostname, got, want)
		}
	}
}

// Migration 037 turns every one-owner check and task into one attachment,
// dated when it was made, carries check silences over unchanged, and drops the
// owner columns.
func TestMonitoringAttachmentsMigrationIntegration(t *testing.T) {
	url := databaseURLOrSkip(t)
	st := newMigrationTestStore(t, url)
	ctx := context.Background()
	idx := slices.IndexFunc(migrations, func(m migration) bool { return m.version == 37 })
	if idx < 0 {
		t.Fatal("migration 037 is not registered")
	}
	if err := st.migrate(ctx, migrations[:idx]); err != nil {
		t.Fatal(err)
	}
	client, err := st.CreateClient(ctx, "migration client")
	if err != nil {
		t.Fatal(err)
	}
	site, err := st.CreateSite(ctx, client.ID, "migration site")
	if err != nil {
		t.Fatal(err)
	}
	// Keep this fixture on schema 036. The current GetAgent query also
	// reads columns from later migrations, including the device key.
	agentID := newID()
	if _, err := st.pool.Exec(ctx, `INSERT INTO agents (id, hostname, os, arch, version, token_hash, site_id, status, last_seen)
		VALUES ($1,'MIG-PC','linux','amd64','0.11.4','hash-mig',$2,'online',now())`, agentID, site.ID); err != nil {
		t.Fatal(err)
	}
	policyID, policyCheck, deviceCheck, policyTask, deviceTask := newID(), newID(), newID(), newID(), newID()
	made := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO policies (id, name) VALUES ($1,'old')`, []any{policyID}},
		{`INSERT INTO policy_assignments (id, policy_id, scope_type, scope_id) VALUES ($1,$2,'client',$3)`, []any{newID(), policyID, client.ID}},
		{`INSERT INTO checks (id, policy_id, type, name, config, created_at) VALUES ($1,$2,'memory','p','{}',$3)`, []any{policyCheck, policyID, made}},
		{`INSERT INTO checks (id, agent_id, type, name, config, created_at) VALUES ($1,$2,'memory','d','{}',$3)`, []any{deviceCheck, agentID, made}},
		{`INSERT INTO tasks (id, policy_id, name, script, created_at) VALUES ($1,$2,'p','true',$3)`, []any{policyTask, policyID, made}},
		{`INSERT INTO tasks (id, agent_id, name, script, created_at) VALUES ($1,$2,'d','true',$3)`, []any{deviceTask, agentID, made}},
	} {
		if _, err := st.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql, err)
		}
	}
	var scopeSince time.Time
	if err := st.pool.QueryRow(ctx, `SELECT monitoring_scope_since FROM agents WHERE id=$1`, agentID).Scan(&scopeSince); err != nil {
		t.Fatal(err)
	}
	deviceSilence, policySilence := newID(), newID()
	for id, check := range map[string]string{deviceSilence: deviceCheck, policySilence: policyCheck} {
		if _, err := st.pool.Exec(ctx, `INSERT INTO alert_suppressions (id, kind, scope_type, scope_id, ends_at, created_by, agent_monitoring_scope_since)
			VALUES ($1,'silence','check',$2,now()+interval '1 hour','tech',$3)`, id, check, scopeSince); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	for id, want := range map[string]models.Attachment{policyCheck: {PolicyID: &policyID}, deviceCheck: {AgentID: &agentID}} {
		c, err := st.GetCheck(ctx, id)
		if err != nil || len(c.Attachments) != 1 || c.Attachments[0].Key() != want.Key() || !c.Attachments[0].AddedAt.Equal(made) {
			t.Fatalf("check %s attachments = %+v %v", id, c.Attachments, err)
		}
	}
	for id, want := range map[string]models.Attachment{policyTask: {PolicyID: &policyID}, deviceTask: {AgentID: &agentID}} {
		tk, err := st.GetTask(ctx, id)
		if err != nil || len(tk.Attachments) != 1 || tk.Attachments[0].Key() != want.Key() {
			t.Fatalf("task %s attachments = %+v %v", id, tk.Attachments, err)
		}
	}
	checks, err := st.ChecksForAgent(ctx, agentID, nil, nil)
	if err != nil || len(checks) != 2 {
		t.Fatalf("the device's checks after the migration = %v %v", checkIDs(checks), err)
	}
	var covers bool
	var recorded int
	if err := st.pool.QueryRow(ctx, `SELECT covers_policy_reach FROM alert_suppressions WHERE id=$1`, policySilence).Scan(&covers); err != nil || !covers {
		t.Fatalf("a policy check's silence must follow the check: %v %v", covers, err)
	}
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM alert_suppression_agents WHERE suppression_id=$1 AND agent_id=$2 AND monitoring_scope_since=$3`,
		deviceSilence, agentID, scopeSince).Scan(&recorded); err != nil || recorded != 1 {
		t.Fatalf("a device check's silence must record its device: %d %v", recorded, err)
	}
	var owners int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name IN ('checks','tasks') AND column_name IN ('agent_id','policy_id')`).Scan(&owners); err != nil || owners != 0 {
		t.Fatalf("owner columns left: %d %v", owners, err)
	}
}

func databaseURLOrSkip(t *testing.T) string {
	t.Helper()
	url := os.Getenv("RMM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("RMM_TEST_DATABASE_URL is not set")
	}
	return url
}
