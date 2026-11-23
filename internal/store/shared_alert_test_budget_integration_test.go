package store

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestSharedAlertTestBudgetConcurrentReservationsIntegration(t *testing.T) {
	url := os.Getenv("RMM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("RMM_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := newMigrationTestStore(t, url)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	type result struct {
		reserved bool
		err      error
	}
	const requests = SharedAlertTestHourlyLimit * 3
	start := make(chan struct{})
	results := make(chan result, requests)
	for range requests {
		go func() {
			<-start
			reserved, err := st.ReserveSharedAlertTest(ctx)
			results <- result{reserved, err}
		}()
	}
	close(start)
	reserved := 0
	for range requests {
		r := <-results
		if r.err != nil {
			t.Error(r.err)
		}
		if r.reserved {
			reserved++
		}
	}
	if reserved != SharedAlertTestHourlyLimit {
		t.Fatalf("reserved %d tests, want %d", reserved, SharedAlertTestHourlyLimit)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE shared_alert_test_budget SET hour_start = hour_start - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.ReserveSharedAlertTest(ctx); err != nil || !ok {
		t.Fatalf("next hour did not reset the quota: %v, %v", ok, err)
	}
}
