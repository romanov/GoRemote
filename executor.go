package main

import (
	"context"
	"io"
)

type commandRunner interface {
	Run(ctx context.Context, command string, stdout, stderr io.Writer) runResult
}

type runResult struct {
	Started  bool
	ExitCode int
	TimedOut bool
	Canceled bool
	Failure  error
}
