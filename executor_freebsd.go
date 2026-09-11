//go:build freebsd

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"syscall"
)

type freeBSDShellRunner struct{}

func newShellRunner() commandRunner {
	return freeBSDShellRunner{}
}

func (freeBSDShellRunner) Run(ctx context.Context, command string, stdout, stderr io.Writer) runResult {
	if err := ctx.Err(); err != nil {
		return canceledResult(err)
	}

	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return runResult{ExitCode: -1, Failure: fmt.Errorf("start command: %w", err)}
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		exitCode, failure := commandExit(err)
		return runResult{Started: true, ExitCode: exitCode, Failure: failure}
	case <-ctx.Done():
		killErr := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		waitErr := <-done
		exitCode, failure := commandExit(waitErr)
		if killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
			failure = fmt.Errorf("kill command process group: %w", killErr)
		}
		result := runResult{Started: true, ExitCode: exitCode, Failure: failure}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result.TimedOut = true
		} else {
			result.Canceled = true
		}
		return result
	}
}

func commandExit(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode(), nil
	}
	return -1, fmt.Errorf("wait for command: %w", err)
}

func canceledResult(err error) runResult {
	result := runResult{ExitCode: -1, Failure: err}
	if errors.Is(err, context.DeadlineExceeded) {
		result.TimedOut = true
	} else {
		result.Canceled = true
	}
	return result
}
