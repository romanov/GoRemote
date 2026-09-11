package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const (
	defaultAllowlistFile = "/var/db/goremote/allowed-ips.json"
	maxAllowlistBody     = 16 << 10
)

type allowlistStore struct {
	path      string
	mutex     sync.RWMutex
	addresses []string
	ips       []net.IP
}

func newAllowlistStore(path string) (*allowlistStore, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &allowlistStore{path: path}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read allowlist file %q: %w", path, err)
	}

	var addresses []string
	if err := json.Unmarshal(data, &addresses); err != nil {
		return nil, fmt.Errorf("decode allowlist file %q: %w", path, err)
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, fmt.Errorf("decode allowlist file %q: expected a JSON array", path)
	}
	normalized, ips, err := parseAllowlistAddresses(addresses)
	if err != nil {
		return nil, fmt.Errorf("decode allowlist file %q: %w", path, err)
	}
	return &allowlistStore{path: path, addresses: normalized, ips: ips}, nil
}

func newEmptyAllowlistStore() *allowlistStore {
	return &allowlistStore{}
}

func parseAllowlistAddresses(addresses []string) ([]string, []net.IP, error) {
	normalized := make([]string, 0, len(addresses))
	ips := make([]net.IP, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for index, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" {
			return nil, nil, fmt.Errorf("address %d must not be empty", index+1)
		}
		ip := net.ParseIP(address)
		if ip == nil {
			return nil, nil, fmt.Errorf("address %q is not a valid IP address", address)
		}
		canonical := ip.String()
		if ipv4 := ip.To4(); ipv4 != nil {
			canonical = ipv4.String()
			ip = ipv4
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
		ips = append(ips, ip)
	}
	return normalized, ips, nil
}

func (s *allowlistStore) snapshot() []string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return append([]string(nil), s.addresses...)
}

func (s *allowlistStore) allows(remoteAddress string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if len(s.ips) == 0 {
		return true
	}

	ip := remoteIP(remoteAddress)
	if ip == nil {
		return false
	}
	for _, allowed := range s.ips {
		if ip.Equal(allowed) {
			return true
		}
	}
	return false
}

func (s *allowlistStore) save(addresses []string) error {
	normalized, ips, err := parseAllowlistAddresses(addresses)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("encode allowlist: %w", err)
	}
	data = append(data, '\n')

	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.path != "" {
		if err := writeAllowlistFile(s.path, data); err != nil {
			return err
		}
	}
	s.addresses = normalized
	s.ips = ips
	return nil
}

func remoteIP(remoteAddress string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.TrimSpace(remoteAddress))
}

func writeAllowlistFile(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return fmt.Errorf("create allowlist directory %q: %w", directory, err)
	}

	temporary, err := os.CreateTemp(directory, ".allowed-ips-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary allowlist file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set allowlist file permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary allowlist file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary allowlist file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary allowlist file: %w", err)
	}

	if runtime.GOOS == "windows" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("replace allowlist file: %w", err)
		}
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace allowlist file: %w", err)
	}
	removeTemporary = false
	return nil
}
