package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type runnerFunc func(context.Context, string, io.Writer, io.Writer) runResult

func (f runnerFunc) Run(ctx context.Context, command string, stdout, stderr io.Writer) runResult {
	return f(ctx, command, stdout, stderr)
}

func testApplication(runner commandRunner, timeout time.Duration) http.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newApplication(runner, timeout, logger).routes()
}

func TestIndexPageAndSecurityHeaders(t *testing.T) {
	handler := testApplication(runnerFunc(nil), time.Second)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), "FreeBSD Command Console") {
		t.Fatal("index page does not contain its title")
	}
	if !strings.Contains(response.Body.String(), `id="client-ip"`) {
		t.Fatal("index page does not contain the client IP badge")
	}
	for _, header := range []string{"Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
		if response.Header().Get(header) == "" {
			t.Errorf("security header %s is missing", header)
		}
	}
}

func TestCommandValidation(t *testing.T) {
	handler := testApplication(runnerFunc(nil), time.Second)
	tests := []struct {
		name        string
		body        string
		contentType string
		origin      string
		wantStatus  int
	}{
		{name: "wrong content type", body: `{}`, contentType: "text/plain", wantStatus: http.StatusUnsupportedMediaType},
		{name: "empty command", body: `{"command":"  "}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "unknown field", body: `{"command":"id","extra":true}`, contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "cross origin", body: `{"command":"id"}`, contentType: "application/json", origin: "http://attacker.example", wantStatus: http.StatusForbidden},
		{name: "oversized", body: `{"command":"` + strings.Repeat("x", maxCommandBody) + `"}`, contentType: "application/json", wantStatus: http.StatusRequestEntityTooLarge},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://console.example/api/commands", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %q", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}

func TestCommandStreamsEvents(t *testing.T) {
	runner := runnerFunc(func(_ context.Context, _ string, stdout, stderr io.Writer) runResult {
		_, _ = io.WriteString(stdout, "standard output\n")
		_, _ = io.WriteString(stderr, "standard error\n")
		return runResult{Started: true, ExitCode: 7}
	})
	handler := testApplication(runner, time.Second)
	request := commandHTTPPost(`{"command":"example"}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/x-ndjson") {
		t.Fatalf("Content-Type = %q", got)
	}

	decoder := json.NewDecoder(response.Body)
	var events []commandEvent
	for {
		var event commandEvent
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) != 4 {
		t.Fatalf("got %d events, want 4: %#v", len(events), events)
	}
	if events[0].Type != "started" || events[1].Type != "stdout" || events[2].Type != "stderr" || events[3].Type != "exited" {
		t.Fatalf("unexpected event order: %#v", events)
	}
	if events[3].ExitCode == nil || *events[3].ExitCode != 7 || events[3].DurationMS == nil {
		t.Fatalf("incomplete exit event: %#v", events[3])
	}
}

func TestCommandTimeoutReachesRunner(t *testing.T) {
	contextErrors := make(chan error, 1)
	runner := runnerFunc(func(ctx context.Context, _ string, _, _ io.Writer) runResult {
		<-ctx.Done()
		contextErrors <- ctx.Err()
		return runResult{Started: true, ExitCode: -1, TimedOut: true}
	})
	handler := testApplication(runner, 20*time.Millisecond)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, commandHTTPPost(`{"command":"wait"}`))

	select {
	case err := <-contextErrors:
		if err != context.DeadlineExceeded {
			t.Fatalf("context error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runner did not observe timeout")
	}
	if !strings.Contains(response.Body.String(), `"timed_out":true`) {
		t.Fatalf("response does not report timeout: %s", response.Body.String())
	}
}

func TestClientCancellationReachesRunner(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	runner := runnerFunc(func(ctx context.Context, _ string, _, _ io.Writer) runResult {
		close(started)
		<-ctx.Done()
		close(canceled)
		return runResult{Started: true, ExitCode: -1, Canceled: true}
	})
	handler := testApplication(runner, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	request := commandHTTPPost(`{"command":"wait"}`).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), request)
		close(done)
	}()

	<-started
	cancel()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("runner did not observe client cancellation")
	}
	<-done
}

func TestConcurrentCommandsKeepOutputSeparate(t *testing.T) {
	runner := runnerFunc(func(_ context.Context, command string, stdout, _ io.Writer) runResult {
		_, _ = io.WriteString(stdout, command)
		return runResult{Started: true, ExitCode: 0}
	})
	handler := testApplication(runner, time.Second)

	commands := []string{"alpha", "beta"}
	responses := make([]*httptest.ResponseRecorder, len(commands))
	var group sync.WaitGroup
	for index, command := range commands {
		group.Add(1)
		go func() {
			defer group.Done()
			body, _ := json.Marshal(commandRequest{Command: command})
			responses[index] = httptest.NewRecorder()
			handler.ServeHTTP(responses[index], commandHTTPPost(string(body)))
		}()
	}
	group.Wait()

	for index, command := range commands {
		other := commands[1-index]
		body := responses[index].Body.String()
		if !strings.Contains(body, command) || strings.Contains(body, other) {
			t.Fatalf("response for %q is not isolated: %s", command, body)
		}
	}
}

func commandHTTPPost(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "http://console.example/api/commands", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://console.example")
	return request
}
