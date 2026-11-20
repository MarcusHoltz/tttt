package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MarcusHoltz/message-me-cve/internal/check"
	"github.com/MarcusHoltz/message-me-cve/internal/notify"
)

func TestAnnotationsEscapeFeedText(t *testing.T) {
	res := &check.Result{Deliveries: []check.Delivery{{
		At:      time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC),
		Message: notify.Message{Title: "ACT NOW: php, 2", Body: "line\n::error::forged", Urgent: true},
		Results: []string{"telegram: delivered"},
		OK:      true,
	}}}
	var b bytes.Buffer
	writeAnnotations(&b, res)
	want := "::warning title=2026-11-20T00%3A00%3A00Z ACT NOW%3A php%2C 2::Delivery: telegram: delivered%0A%0Aline%0A::error::forged\n"
	if b.String() != want {
		t.Errorf("got  %q\nwant %q", b.String(), want)
	}
}

func TestLoadProfiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.com.txt"), []byte("php\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "empty.txt"), []byte("# nothing\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "notes.md"), []byte("php\n"), 0o644)
	ps, err := loadProfiles(dir)
	if err != nil || len(ps) != 2 {
		t.Fatalf("got %d profiles, %v", len(ps), err)
	}
	if ps[0].Name != "a.com" || ps[0].Err != nil || ps[1].Name != "empty" || ps[1].Err == nil {
		t.Errorf("got %+v", ps)
	}
	if _, err := loadProfiles(t.TempDir()); err == nil {
		t.Error("empty directory accepted")
	}
}

func TestSendersFromEnv(t *testing.T) {
	t.Setenv("NTFY_URL", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "1:a")
	t.Setenv("TELEGRAM_CHAT_ID", "")
	if _, err := sendersFromEnv(); err == nil || !strings.Contains(err.Error(), "together") {
		t.Errorf("token without chat ID: got %v", err)
	}
	t.Setenv("TELEGRAM_CHAT_ID", "42")
	t.Setenv("NTFY_URL", "https://ntfy.sh/x")
	s, err := sendersFromEnv()
	if err != nil || len(s) != 2 {
		t.Errorf("got %d senders, %v", len(s), err)
	}
}
