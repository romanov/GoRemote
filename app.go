package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxCommandBody = 16 << 10

type application struct {
	runner    commandRunner
	timeout   time.Duration
	logger    *slog.Logger
	allowlist *allowlistStore
	nextID    atomic.Uint64
}

type commandRequest struct {
	Command string `json:"command"`
}

type commandEvent struct {
	Type       string `json:"type"`
	ID         string `json:"id,omitempty"`
	Data       string `json:"data,omitempty"`
	Message    string `json:"message,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	DurationMS *int64 `json:"duration_ms,omitempty"`
	TimedOut   bool   `json:"timed_out,omitempty"`
	Canceled   bool   `json:"canceled,omitempty"`
}

func newApplication(runner commandRunner, timeout time.Duration, logger *slog.Logger) *application {
	return newApplicationWithAllowlist(runner, timeout, logger, newEmptyAllowlistStore())
}

func newApplicationWithAllowlist(runner commandRunner, timeout time.Duration, logger *slog.Logger, allowlist *allowlistStore) *application {
	if allowlist == nil {
		allowlist = newEmptyAllowlistStore()
	}
	return &application{runner: runner, timeout: timeout, logger: logger, allowlist: allowlist}
}

func (a *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/settings", a.handleSettings)
	mux.HandleFunc("/api/commands", a.handleCommand)
	mux.HandleFunc("/api/allowlist", a.handleAllowlist)
	return securityHeaders(allowlistMiddleware(a.allowlist, mux))
}

func allowlistMiddleware(allowlist *allowlistStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowlist != nil && !allowlist.allows(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (a *application) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(indexHTML)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(indexHTML)
	}
}

func (a *application) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/settings" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(settingsHTML)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(settingsHTML)
	}
}

type allowlistRequest struct {
	Addresses []string `json:"addresses"`
}

type allowlistResponse struct {
	Addresses []string `json:"addresses"`
	Enabled   bool     `json:"enabled"`
	ClientIP  string   `json:"client_ip,omitempty"`
}

func (a *application) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		clientIP := remoteIP(r.RemoteAddr)
		response := allowlistResponse{Addresses: a.allowlist.snapshot()}
		response.Enabled = len(response.Addresses) > 0
		if clientIP != nil {
			response.ClientIP = clientIP.String()
		}
		writeJSON(w, response)
	case http.MethodPost:
		if !sameOrigin(r) {
			http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxAllowlistBody)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var request allowlistRequest
		if err := decoder.Decode(&request); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, fmt.Sprintf("request body exceeds %d bytes", maxAllowlistBody), http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, fmt.Sprintf("invalid JSON request: %v", err), http.StatusBadRequest)
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			http.Error(w, "request body must contain one JSON object", http.StatusBadRequest)
			return
		}
		if request.Addresses == nil {
			http.Error(w, "addresses must be a JSON array", http.StatusBadRequest)
			return
		}
		if err := a.allowlist.save(request.Addresses); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, allowlistResponse{Addresses: a.allowlist.snapshot(), Enabled: len(request.Addresses) > 0})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}

func (a *application) handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	request, status, err := decodeCommandRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is unavailable", http.StatusInternalServerError)
		return
	}

	id := strconv.FormatUint(a.nextID.Add(1), 10)
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	stream := &eventStream{encoder: json.NewEncoder(w), flusher: flusher}
	if err := stream.send(commandEvent{Type: "started", ID: id}); err != nil {
		return
	}

	startedAt := time.Now()
	commandContext, cancel := contextWithTimeout(r, a.timeout)
	defer cancel()

	result := a.runner.Run(
		commandContext,
		request.Command,
		&eventWriter{eventType: "stdout", stream: stream},
		&eventWriter{eventType: "stderr", stream: stream},
	)
	durationMS := time.Since(startedAt).Milliseconds()

	if result.Failure != nil {
		_ = stream.send(commandEvent{Type: "error", Message: result.Failure.Error(), DurationMS: &durationMS})
	}
	if result.Started {
		exitCode := result.ExitCode
		_ = stream.send(commandEvent{
			Type:       "exited",
			ExitCode:   &exitCode,
			DurationMS: &durationMS,
			TimedOut:   result.TimedOut,
			Canceled:   result.Canceled,
		})
	}

	remoteAddress := r.RemoteAddr
	if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
		remoteAddress = host
	}
	a.logger.Info("command finished",
		"id", id,
		"remote", remoteAddress,
		"started", result.Started,
		"exit_code", result.ExitCode,
		"timed_out", result.TimedOut,
		"canceled", result.Canceled,
		"duration_ms", durationMS,
	)
}

func decodeCommandRequest(w http.ResponseWriter, r *http.Request) (commandRequest, int, error) {
	var request commandRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxCommandBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return request, http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", maxCommandBody)
		}
		return request, http.StatusBadRequest, fmt.Errorf("invalid JSON request: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return request, http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", maxCommandBody)
		}
		return request, http.StatusBadRequest, errors.New("request body must contain one JSON object")
	}
	if strings.TrimSpace(request.Command) == "" {
		return request, http.StatusBadRequest, errors.New("command must not be empty")
	}
	return request, http.StatusOK, nil
}

func sameOrigin(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func contextWithTimeout(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), timeout)
}

type eventStream struct {
	mutex   sync.Mutex
	encoder *json.Encoder
	flusher http.Flusher
}

func (s *eventStream) send(event commandEvent) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.encoder.Encode(event); err != nil {
		return err
	}
	s.flusher.Flush()
	return nil
}

type eventWriter struct {
	eventType string
	stream    *eventStream
}

func (w *eventWriter) Write(data []byte) (int, error) {
	if len(data) > 0 {
		// The request context is canceled by net/http when the client disconnects.
		// Ignore a failed response write here so process cleanup stays controlled by
		// that context rather than by os/exec's pipe-copy implementation.
		_ = w.stream.send(commandEvent{Type: w.eventType, Data: string(data)})
	}
	return len(data), nil
}
