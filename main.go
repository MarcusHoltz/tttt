// Command message-me-cve checks watch lists against CISA KEV and NVD once,
// pushes alerts to ntfy and/or Telegram, and exits non-zero while anything
// is broken. Scheduling is left to the caller (the GitHub Actions workflow,
// started by an outside cron).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	exitOK     = 0
	exitBroken = 1 // something is failing; it was messaged
	exitUsage  = 2 // bad configuration; nothing ran
)

func main() { os.Exit(runMain()) }

func runMain() int {
	profilesDir := flag.String("profiles", "profiles", "directory of <name>.txt watch lists")
	statePath := flag.String("state", "state/state.json", "state file")
	dryRun := flag.Bool("dry-run", false, "print alerts instead of sending them; do not write state")
	testNotify := flag.Bool("test-notify", false, "send one test message to every channel and exit")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	senders, err := sendersFromEnv()
	if err == nil && len(senders) == 0 && !*dryRun {
		err = errors.New("no channel configured: set NTFY_URL, or TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID")
	}
	if err != nil {
		log.Error("configuration", "err", err)
		return exitUsage
	}

	if *testNotify {
		return sendTest(ctx, log, senders)
	}

	// Without watch lists or state nothing can be checked, and there is no
	// state to remember that this was already reported: message every run.
	fail := func(err error) int {
		log.Error("not covered", "err", err)
		msg := Message{Title: "message-me-cve: FAILED, you are not covered", Body: err.Error(), Urgent: true}
		if *dryRun {
			return exitBroken
		}
		for _, s := range senders {
			if err := s.Send(ctx, msg); err != nil {
				log.Error("send failed", "channel", s.Name(), "err", err)
			}
		}
		return exitBroken
	}
	profiles, err := loadProfiles(*profilesDir)
	if err != nil {
		return fail(err)
	}
	st, err := loadState(*statePath)
	if err != nil {
		return fail(fmt.Errorf("cannot read state: %w", err))
	}

	c := &Checker{
		Feeds:   NewFeedClient(strings.TrimSpace(os.Getenv("NVD_API_KEY")), log),
		Senders: senders,
		DryRun:  *dryRun,
		Log:     log,
	}
	now := time.Now().UTC()
	res := c.Run(ctx, now, profiles, st)

	if !*dryRun {
		if err := st.Save(*statePath); err != nil {
			res.Problems = append(res.Problems, "cannot save state: "+err.Error())
			fail(fmt.Errorf("cannot save state: %w", err))
		}
	}
	for _, p := range res.Profiles {
		log.Info("profile checked", "profile", p.Name, "words", p.Words, "new", p.New, "sent", p.Sent)
	}
	for _, p := range res.Problems {
		log.Error("problem", "err", p)
	}
	log.Info("run done", "nvd_polled", res.NVDPolled, "messages", len(res.Deliveries), "ok", res.OK())
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		reportToGitHub(now, res, log)
	}
	if !res.OK() {
		return exitBroken
	}
	return exitOK
}

func sendersFromEnv() ([]Sender, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	var out []Sender
	if u := strings.TrimSpace(os.Getenv("NTFY_URL")); u != "" {
		out = append(out, &Ntfy{URL: u, HTTP: client})
	}
	token := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	chat := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))
	switch {
	case token != "" && chat != "":
		out = append(out, &Telegram{Token: token, ChatID: chat,
			API: "https://api.telegram.org", HTTP: client, Gap: time.Second})
	case token != "" || chat != "":
		return nil, errors.New("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set together")
	}
	return out, nil
}

// loadProfiles reads every <dir>/<name>.txt as profile name. A list that
// cannot be read is returned with Err set, so the others are still checked.
func loadProfiles(dir string) ([]Profile, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil || len(paths) == 0 {
		return nil, fmt.Errorf("no watch lists (*.txt) in %s", dir)
	}
	var out []Profile
	for _, p := range paths {
		words, err := LoadWords(p)
		out = append(out, Profile{Name: strings.TrimSuffix(filepath.Base(p), ".txt"), Words: words, Err: err})
	}
	return out, nil
}

func sendTest(ctx context.Context, log *slog.Logger, senders []Sender) int {
	msg := Message{Title: "message-me-cve: test", Body: "Delivery works. Sent with -test-notify."}
	code := exitOK
	for _, s := range senders {
		if err := s.Send(ctx, msg); err != nil {
			log.Error("test message failed", "channel", s.Name(), "err", err)
			code = exitBroken
			continue
		}
		log.Info("test message delivered", "channel", s.Name())
	}
	return code
}
