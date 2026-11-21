//go:build !windows

package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A script stopped at its timeout takes what it started in the background
// with it. Before, only the shell was killed: the background child kept the
// output open and the run lasted until that child exited.
func TestTimedOutScriptStopsItsBackgroundChildren(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	code, _, _ := runScriptCtx(ctx, "sh", "sleep 20 & sleep 20")
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("the stopped script ran %s", elapsed)
	}
	if code == 0 {
		t.Fatal("a script stopped at its timeout reported success")
	}
}

// A script that exits while a child it left in the background still holds its
// output finishes shortly after, with its own exit status and output so far.
func TestScriptLeavingABackgroundChildFinishes(t *testing.T) {
	started := time.Now()
	code, stdout, stderr := runScriptCtx(context.Background(), "sh", "sleep 20 & echo started")
	elapsed := time.Since(started)
	if elapsed > 15*time.Second {
		t.Fatalf("the script ran %s, waiting for its background child", elapsed)
	}
	if code != 0 || strings.TrimSpace(stdout) != "started" || !strings.Contains(stderr, scriptOutputHeldNote) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	// Control: a script that leaves nothing behind is not delayed or noted.
	started = time.Now()
	code, stdout, stderr = runScriptCtx(context.Background(), "sh", "echo done")
	if time.Since(started) > 3*time.Second || code != 0 || strings.TrimSpace(stdout) != "done" || stderr != "" {
		t.Fatalf("plain script code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
