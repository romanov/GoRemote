//go:build !freebsd

package main

import (
	"context"
	"errors"
	"io"
)

type unsupportedShellRunner struct{}

func newShellRunner() commandRunner {
	return unsupportedShellRunner{}
}

func (unsupportedShellRunner) Run(context.Context, string, io.Writer, io.Writer) runResult {
	return runResult{
		ExitCode: -1,
		Failure:  errors.New("command execution is supported only on FreeBSD"),
	}
}
