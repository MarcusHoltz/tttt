package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadMissingIsEmpty(t *testing.T) {
	st, err := Load(filepath.Join(t.TempDir(), "none.json"))
	if err != nil || st.Sent == nil || st.Broken == nil || !st.NVDCursor.IsZero() {
		t.Errorf("got %+v, %v", st, err)
	}
}

func TestLoadCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(path, []byte("{"), 0o644)
	if _, err := Load(path); err == nil {
		t.Error("corrupt state accepted")
	}
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "s.json")
	at := time.Date(2026, 11, 20, 1, 2, 3, 0, time.UTC)
	st, _ := Load(path)
	st.NVDCursor, st.NVDPolled = at, at
	st.MarkSent("shop", "kev:CVE-1", at)
	st.Broken["NVD"] = "HTTP 503"
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || !got.WasSent("shop", "kev:CVE-1") || got.WasSent("blog", "kev:CVE-1") ||
		!got.NVDCursor.Equal(at) || got.Broken["NVD"] != "HTTP 503" {
		t.Errorf("got %+v, %v", got, err)
	}
}
