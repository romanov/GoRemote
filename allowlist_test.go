package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAllowlistGuardsEveryRoute(t *testing.T) {
	store := newEmptyAllowlistStore()
	if err := store.save([]string{"192.0.2.10", "2001:db8::10"}); err != nil {
		t.Fatal(err)
	}
	runnerCalled := false
	runner := runnerFunc(func(_ context.Context, _ string, _, _ io.Writer) runResult {
		runnerCalled = true
		return runResult{Started: true, ExitCode: 0}
	})
	handler := newApplicationWithAllowlist(runner, time.Second, testLogger(), store).routes()

	deniedIndex := httptest.NewRequest(http.MethodGet, "http://console.example/", nil)
	deniedIndex.RemoteAddr = "192.0.2.11:1234"
	deniedResponse := httptest.NewRecorder()
	handler.ServeHTTP(deniedResponse, deniedIndex)
	if deniedResponse.Code != http.StatusForbidden {
		t.Fatalf("denied index status = %d, want %d", deniedResponse.Code, http.StatusForbidden)
	}

	deniedCommand := commandHTTPPost(`{"command":"id"}`)
	deniedCommand.RemoteAddr = "192.0.2.11:1234"
	commandResponse := httptest.NewRecorder()
	handler.ServeHTTP(commandResponse, deniedCommand)
	if commandResponse.Code != http.StatusForbidden {
		t.Fatalf("denied command status = %d, want %d", commandResponse.Code, http.StatusForbidden)
	}
	if runnerCalled {
		t.Fatal("runner was called for a denied request")
	}

	allowed := httptest.NewRequest(http.MethodGet, "http://console.example/settings", nil)
	allowed.RemoteAddr = "[2001:db8::10]:1234"
	allowedResponse := httptest.NewRecorder()
	handler.ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != http.StatusOK {
		t.Fatalf("allowed settings status = %d, want %d", allowedResponse.Code, http.StatusOK)
	}
}

func TestAllowlistPersistsAndNormalizesAddresses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "allowed-ips.json")
	store, err := newAllowlistStore(path)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "http://console.example/api/allowlist", bytes.NewBufferString(`{"addresses":[" 192.0.2.10 ","192.0.2.10","2001:0db8:0:0:0:0:0:10"]}`))
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://console.example")
	response := httptest.NewRecorder()
	newApplicationWithAllowlist(nil, time.Second, testLogger(), store).routes().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("save status = %d, want %d; body = %q", response.Code, http.StatusOK, response.Body.String())
	}
	var saved allowlistResponse
	if err := json.NewDecoder(response.Body).Decode(&saved); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(saved.Addresses, ","), "192.0.2.10,2001:db8::10"; got != want {
		t.Fatalf("saved addresses = %q, want %q", got, want)
	}

	reloaded, err := newAllowlistStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.allows("[2001:db8::10]:1234") {
		t.Fatal("persisted IPv6 address was not admitted")
	}
	if reloaded.allows("192.0.2.100:1234") {
		t.Fatal("near-matching IPv4 address was admitted")
	}

	badRequest := httptest.NewRequest(http.MethodPost, "http://console.example/api/allowlist", bytes.NewBufferString(`{"addresses":["192.0.2.0/24"]}`))
	badRequest.RemoteAddr = "192.0.2.10:1234"
	badRequest.Header.Set("Content-Type", "application/json")
	badRequest.Header.Set("Origin", "http://console.example")
	badResponse := httptest.NewRecorder()
	newApplicationWithAllowlist(nil, time.Second, testLogger(), reloaded).routes().ServeHTTP(badResponse, badRequest)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("CIDR status = %d, want %d", badResponse.Code, http.StatusBadRequest)
	}
	if !reloaded.allows("192.0.2.10:1234") {
		t.Fatal("invalid save changed the existing allowlist")
	}
}

func TestEmptyAllowlistDisablesEnforcement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed-ips.json")
	store, err := newAllowlistStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !store.allows("not-a-remote-address") {
		t.Fatal("missing allowlist file should allow bootstrap access")
	}

	if err := store.save([]string{"192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	if store.allows("192.0.2.11:1234") {
		t.Fatal("configured allowlist admitted a denied address")
	}
	if err := store.save(nil); err != nil {
		t.Fatal(err)
	}
	if !store.allows("192.0.2.11:1234") {
		t.Fatal("empty saved allowlist did not disable enforcement")
	}
}

func TestAllowlistAPIValidationAndOrigin(t *testing.T) {
	store := newEmptyAllowlistStore()
	handler := newApplicationWithAllowlist(nil, time.Second, testLogger(), store).routes()

	tests := []struct {
		name        string
		content     string
		contentType string
		origin      string
		wantStatus  int
	}{
		{name: "wrong content type", content: `{}`, contentType: "text/plain", origin: "http://console.example", wantStatus: http.StatusUnsupportedMediaType},
		{name: "cross origin", content: `{"addresses":["192.0.2.10"]}`, contentType: "application/json", origin: "http://attacker.example", wantStatus: http.StatusForbidden},
		{name: "missing addresses", content: `{}`, contentType: "application/json", origin: "http://console.example", wantStatus: http.StatusBadRequest},
		{name: "unknown field", content: `{"addresses":[],"extra":true}`, contentType: "application/json", origin: "http://console.example", wantStatus: http.StatusBadRequest},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://console.example/api/allowlist", bytes.NewBufferString(test.content))
			request.RemoteAddr = "192.0.2.10:1234"
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Origin", test.origin)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %q", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}

func TestAllowlistAPIReportsTCPPeerIP(t *testing.T) {
	store := newEmptyAllowlistStore()
	handler := newApplicationWithAllowlist(nil, time.Second, testLogger(), store).routes()
	request := httptest.NewRequest(http.MethodGet, "http://console.example/api/allowlist", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.20")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	var body allowlistResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.ClientIP != "192.0.2.10" {
		t.Fatalf("client IP = %q, want TCP peer IP", body.ClientIP)
	}
}

func TestAllowlistRejectsMalformedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed-ips.json")
	if err := os.WriteFile(path, []byte(`{"addresses":["192.0.2.10"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newAllowlistStore(path); err == nil {
		t.Fatal("malformed allowlist file was accepted")
	}
}
