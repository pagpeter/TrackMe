package server

import (
	"sync"
	"time"

	"github.com/pagpeter/trackme/pkg/types"
)

// FingerprintStore holds captured TCP/IP fingerprints with support for
// blocking lookups — callers can wait for a SYN capture that hasn't
// arrived yet (the capture runs async in a separate goroutine).
type FingerprintStore struct {
	mu      sync.Mutex
	entries map[string]types.TCPIPDetails
	waiters map[string][]chan struct{}
}

func NewFingerprintStore() *FingerprintStore {
	return &FingerprintStore{
		entries: make(map[string]types.TCPIPDetails),
		waiters: make(map[string][]chan struct{}),
	}
}

func (s *FingerprintStore) Store(key string, val types.TCPIPDetails) {
	s.mu.Lock()
	s.entries[key] = val
	waiting := s.waiters[key]
	delete(s.waiters, key)
	s.mu.Unlock()

	for _, ch := range waiting {
		close(ch)
	}
}

// Get returns the fingerprint for key. If not found, blocks up to
// timeout waiting for the capture goroutine to deliver it.
func (s *FingerprintStore) Get(key string, timeout time.Duration) (types.TCPIPDetails, bool) {
	s.mu.Lock()
	if v, ok := s.entries[key]; ok {
		s.mu.Unlock()
		return v, true
	}

	ch := make(chan struct{})
	s.waiters[key] = append(s.waiters[key], ch)
	s.mu.Unlock()

	select {
	case <-ch:
		s.mu.Lock()
		v, ok := s.entries[key]
		s.mu.Unlock()
		return v, ok
	case <-time.After(timeout):
		return types.TCPIPDetails{}, false
	}
}
