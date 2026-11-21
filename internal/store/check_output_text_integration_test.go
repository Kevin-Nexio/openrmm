package store

import (
	"context"
	"testing"
	"time"

	"github.com/p1ngu/rmm/internal/models"
)

// Runs in the PostgreSQL CI job. A check's output in any language is stored and
// read back unchanged, in the result history and in the check's state, so an
// agent that decodes ping or sc output (cmd/agent pingResult and
// serviceQueryResult) shows it as printed.
func TestCheckOutputKeepsEveryLanguageIntegration(t *testing.T) {
	f := newAlertReliabilityFixture(t, "check-output-text")
	ctx := context.Background()
	for i, text := range []string{
		"Estatísticas do Ping para 8.8.8.8: número redondo",
		"NOME_DO_SERVIÇO: Spooler — O serviço especificado não existe",
		"Статистика Ping · ping 統計 · 핑 통계 · Ölçüm ✓",
	} {
		e, created, err := f.store.CreateCheckExecution(ctx, f.check.ID, f.agent.ID, time.Now().UTC().Add(time.Duration(i)*time.Second), 10*time.Second)
		if err != nil || !created {
			t.Fatalf("execution %d: created=%v err=%v", i, created, err)
		}
		state, _, err := f.store.RecordCheckResult(ctx, &models.CheckResult{
			CheckID: f.check.ID, AgentID: f.agent.ID, ExecutionID: &e.ID, Status: models.CheckPassing, Output: text,
		})
		if err != nil {
			t.Fatal(err)
		}
		if state.LastOutput != text {
			t.Fatalf("state output = %q, want %q", state.LastOutput, text)
		}
		results, err := f.store.ListCheckResults(ctx, f.check.ID, f.agent.ID, 1)
		if err != nil || len(results) != 1 || results[0].Output != text {
			t.Fatalf("history = %+v %v, want %q", results, err, text)
		}
	}
}
