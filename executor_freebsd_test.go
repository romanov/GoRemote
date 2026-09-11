//go:build freebsd

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFreeBSDRunnerStreamsAndReportsExit(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	result := newShellRunner().Run(
		context.Background(),
		"printf 'out'; printf 'err' >&2; exit 7",
		&stdout,
		&stderr,
	)

	if !result.Started || result.ExitCode != 7 || result.Failure != nil {
		t.Fatalf("unexpected result: %#v", result)
	}
	if stdout.String() != "out" || stderr.String() != "err" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestFreeBSDRunnerKillsProcessGroupOnTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	startedAt := time.Now()
	result := newShellRunner().Run(ctx, "sleep 30 & wait", io.Discard, io.Discard)

	if !result.Started || !result.TimedOut {
		t.Fatalf("unexpected result: %#v", result)
	}
	if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
		t.Fatalf("process group cleanup took %s", elapsed)
	}
}

func TestFreeBSDRunnerDoesNotPersistWorkingDirectory(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	runner := newShellRunner()
	first := runner.Run(context.Background(), "cd /tmp", io.Discard, io.Discard)
	if first.ExitCode != 0 {
		t.Fatalf("cd command failed: %#v", first)
	}
	var stdout bytes.Buffer
	second := runner.Run(context.Background(), "pwd", &stdout, io.Discard)
	if second.ExitCode != 0 {
		t.Fatalf("pwd command failed: %#v", second)
	}
	if got := strings.TrimSpace(stdout.String()); got != workingDirectory {
		t.Fatalf("working directory persisted: got %q, want %q", got, workingDirectory)
	}
}
