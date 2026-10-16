package policy

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// Store holds the active policy and swaps it atomically on reload, so
// in-flight requests keep the policy they started with.
type Store struct {
	current atomic.Pointer[Policy]
}

// NewStore returns a store holding p.
func NewStore(p *Policy) *Store {
	s := &Store{}
	s.current.Store(p)
	return s
}

// Get returns the active policy.
func (s *Store) Get() *Policy { return s.current.Load() }

// Set replaces the active policy.
func (s *Store) Set(p *Policy) { s.current.Store(p) }

// Watch polls file and reloads it when its content changes. Polling, rather
// than inotify, survives the symlink swap Kubernetes uses to update mounted
// ConfigMaps. An invalid file is logged and ignored: the last good policy
// stays active, so a bad edit can never open the gateway up.
func (s *Store) Watch(ctx context.Context, file string, every time.Duration, log *slog.Logger) {
	var last []byte // nil: the first tick parses the file and compares versions
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		raw, err := os.ReadFile(file)
		if err != nil || bytes.Equal(raw, last) {
			continue
		}
		last = raw
		p, err := Parse(raw)
		if err != nil {
			log.Error("policy reload rejected, keeping previous policy",
				"error", err, "active_version", s.Get().Version)
			continue
		}
		prev := s.Get().Version
		if p.Version == prev {
			continue
		}
		s.Set(p)
		log.Info("policy reloaded", "previous_version", prev, "version", p.Version)
	}
}
