// Package state persists what has been sent and what is broken, between runs.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// State is everything one run hands to the next.
type State struct {
	// NVDCursor: every NVD change before it has been fully handled.
	NVDCursor time.Time `json:"nvd_cursor,omitzero"`
	// NVDPolled: when NVD was last requested, successfully or not.
	NVDPolled time.Time `json:"nvd_polled,omitzero"`
	// Sent: profile -> alert key ("kev:CVE-..." or "nvd:CVE-...") -> when.
	Sent map[string]map[string]time.Time `json:"sent"`
	// Broken: what is failing (feed, watch list) -> its error, reported once.
	Broken map[string]string `json:"broken"`
}

// Load reads the state file. A missing file is an empty state.
func Load(path string) (*State, error) {
	st := &State{}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, st); err != nil {
			return nil, fmt.Errorf("%s is corrupt: %w", path, err)
		}
	}
	if st.Sent == nil {
		st.Sent = map[string]map[string]time.Time{}
	}
	if st.Broken == nil {
		st.Broken = map[string]string{}
	}
	return st, nil
}

// Save writes the state atomically: a crash leaves the old file or the new
// one, never half of one.
func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *State) WasSent(profile, key string) bool {
	_, ok := s.Sent[profile][key]
	return ok
}

func (s *State) MarkSent(profile, key string, at time.Time) {
	if s.Sent[profile] == nil {
		s.Sent[profile] = map[string]time.Time{}
	}
	s.Sent[profile][key] = at
}
