package server

import (
	"sync"
	"time"

	"github.com/pagpeter/trackme/pkg/types"
)

const (
	maxEntries = 10000
	entryTTL   = 30 * time.Second
	sweepEvery = 10 * time.Second
)

type fpEntry struct {
	val     types.TCPIPDetails
	created time.Time
}

type FingerprintStore struct {
	mu      sync.Mutex
	entries map[string]fpEntry
	waiters map[string][]chan struct{}
}

func NewFingerprintStore() *FingerprintStore {
	s := &FingerprintStore{
		entries: make(map[string]fpEntry, 256),
		waiters: make(map[string][]chan struct{}),
	}
	go s.sweepLoop()
	return s
}

func (s *FingerprintStore) Store(key string, val types.TCPIPDetails) {
	s.mu.Lock()
	if len(s.entries) >= maxEntries {
		i := 0
		for k := range s.entries {
			delete(s.entries, k)
			i++
			if i >= maxEntries/2 {
				break
			}
		}
	}
	s.entries[key] = fpEntry{val: val, created: time.Now()}
	waiting := s.waiters[key]
	delete(s.waiters, key)
	s.mu.Unlock()

	for _, ch := range waiting {
		close(ch)
	}
}

func (s *FingerprintStore) Get(key string, timeout time.Duration) (types.TCPIPDetails, bool) {
	s.mu.Lock()
	if e, ok := s.entries[key]; ok {
		s.mu.Unlock()
		return e.val, true
	}

	ch := make(chan struct{})
	s.waiters[key] = append(s.waiters[key], ch)
	s.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ch:
		s.mu.Lock()
		e, ok := s.entries[key]
		s.mu.Unlock()
		return e.val, ok
	case <-timer.C:
		// Remove our waiter so it doesn't leak in the map.
		s.mu.Lock()
		if chs, ok := s.waiters[key]; ok {
			for i, c := range chs {
				if c == ch {
					s.waiters[key] = append(chs[:i], chs[i+1:]...)
					break
				}
			}
			if len(s.waiters[key]) == 0 {
				delete(s.waiters, key)
			}
		}
		s.mu.Unlock()
		return types.TCPIPDetails{}, false
	}
}

func (s *FingerprintStore) sweepLoop() {
	t := time.NewTicker(sweepEvery)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for k, e := range s.entries {
			if now.Sub(e.created) > entryTTL {
				delete(s.entries, k)
			}
		}
		s.mu.Unlock()
	}
}
