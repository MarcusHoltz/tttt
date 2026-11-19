// message-me-cve: message me when something in my watch list is in trouble.
//
// Each run:
//  1. CISA KEV (actively exploited): entries whose vendor or product matches a
//     watch word -> "ACT NOW", urgent priority.
//  2. NVD: CRITICAL/HIGH CVEs published in the last 90 days and modified since
//     the last run whose affected-product list (CPE) names a watch word.
//     Severity is the highest CVSS from any source (NVD, the CVE's publisher,
//     CISA), so CVEs NVD has not scored yet are included. CVEs NVD has not
//     analyzed yet (no CPE) are matched on the product list in their CVE.org
//     record and marked as such.
//  3. Each CVE is messaged once, and only marked sent after delivery succeeded.
//  4. Unreachable feeds and message-me-cve's own failures are messaged once
//     when they start and once when they clear. The exit code is non-zero
//     while broken.
//
// Env: WATCH_FILE (watch.txt), STATE_FILE (state/state.json), NTFY_URL,
// TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, NVD_API_KEY, PROFILE (prefixes titles),
// PROFILES_DIR (check every <dir>/<name>.txt as profile name, one fetch),
// INTERVAL (e.g. "2h": loop forever; unset: run once and exit).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

var kevURLs = []string{
	"https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
	"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}

const (
	nvdURL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	userAgent     = "Mozilla/5.0 (compatible; message-me-cve)"
	nvdMaxWindow  = 119 * 24 * time.Hour // NVD rejects date ranges over 120 days
	nvdFirstRun   = 7 * 24 * time.Hour
	nvdMinGap     = 2 * time.Hour       // NVD: poll for changes no more than once every two hours
	nvdMaxAge     = 90 * 24 * time.Hour // older CVEs re-modified by NVD are not news
	nvdTimeFormat = "2006-01-02T15:04:05.000Z"
	maxSingle     = 5    // more new alerts than this in one run: send a combined list
	maxBody       = 3500 // ntfy turns bodies over 4096 bytes into attachments
	selfKey       = "message-me-cve itself"
)

var client = &http.Client{Timeout: 60 * time.Second}

var telegramAPI = "https://api.telegram.org"

// Telegram: "In a single chat, avoid sending more than one message per
// second" (Bots FAQ). All profiles send to the same chat in one run.
var (
	telegramGap  = time.Second
	telegramLast time.Time
)

type config struct {
	watchFile, stateFile, ntfyURL, nvdKey string
	tgToken, tgChat, profile              string
	nvdSleep                              time.Duration
}

type state struct {
	Sent     map[string]string `json:"sent"`
	NVDSince string            `json:"nvd_since"`
	// NVDPolled is when NVD was last requested, successful or not.
	NVDPolled string            `json:"nvd_polled,omitempty"`
	Broken    map[string]string `json:"broken"`
}

type alert struct {
	key, title, body, short string
	urgent                  bool
}

// feedError marks a feed that could not be read; it is reported through the
// broken-feed messages, not as a message-me-cve failure.
type feedError struct{ feed, msg string }

func (e *feedError) Error() string { return e.feed + ": " + e.msg }

func main() {
	cfg := config{
		watchFile: env("WATCH_FILE", "watch.txt"),
		stateFile: env("STATE_FILE", filepath.Join("state", "state.json")),
		ntfyURL:   strings.TrimSpace(os.Getenv("NTFY_URL")),
		nvdKey:    strings.TrimSpace(os.Getenv("NVD_API_KEY")),
		tgToken:   strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")),
		tgChat:    strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID")),
		profile:   strings.TrimSpace(os.Getenv("PROFILE")),
		nvdSleep:  7 * time.Second, // keyless limit: 5 requests / 30 s
	}
	if cfg.nvdKey != "" {
		cfg.nvdSleep = 700 * time.Millisecond
	}
	cfgs := []config{cfg}
	if dir := strings.TrimSpace(os.Getenv("PROFILES_DIR")); dir != "" {
		var err error
		if cfgs, err = profileConfigs(cfg, dir); err != nil {
			send(cfg, "message-me-cve: FAILED, you are not covered", err.Error(), true)
			os.Exit(1)
		}
	}
	interval := os.Getenv("INTERVAL")
	if interval == "" {
		if !runAll(cfgs) {
			os.Exit(1)
		}
		return
	}
	every, err := time.ParseDuration(interval)
	if err != nil || every < time.Minute {
		send(cfg, "message-me-cve: bad INTERVAL", fmt.Sprintf("INTERVAL=%q is not a duration of at least 1m (e.g. 1h). Not running.", interval), true)
		os.Exit(2)
	}
	for {
		runAll(cfgs)
		time.Sleep(every)
	}
}

// profileConfigs returns one config per <dir>/<name>.txt watch list, with
// state in <state dir>/<name>.json and alert titles prefixed [name].
func profileConfigs(base config, dir string) ([]config, error) {
	lists, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil || len(lists) == 0 {
		return nil, fmt.Errorf("PROFILES_DIR %s has no *.txt watch lists, nothing is being watched", dir)
	}
	var out []config
	for _, l := range lists {
		c := base
		c.profile = strings.TrimSuffix(filepath.Base(l), ".txt")
		c.watchFile = l
		c.stateFile = filepath.Join(filepath.Dir(base.stateFile), c.profile+".json")
		out = append(out, c)
	}
	return out, nil
}

// fetched holds one fetch of KEV and NVD, shared by every profile so NVD sees
// a single requestor (its guidance: poll changes at most every two hours).
type fetched struct {
	now    time.Time
	kev    []kevEntry
	kevErr error
	nvd    []nvdCVE
	nvdErr error
	// nvdSkipped: NVD was polled less than nvdMinGap ago, so this run did
	// not request it. Its window and broken state are left as they are.
	nvdSkipped bool

	// CVE.org lookups, cached for the run (failures too): profiles that
	// watch the same word would otherwise fetch the same record again.
	// cveOrg nil means cveOrgAffected.
	cveOrg      func(id string) ([]string, error)
	cveOrgCache map[string]cveOrgResult
}

type cveOrgResult struct {
	products []string
	err      error
}

func (f *fetched) affected(id string) ([]string, error) {
	if r, ok := f.cveOrgCache[id]; ok {
		return r.products, r.err
	}
	lookup := f.cveOrg
	if lookup == nil {
		lookup = cveOrgAffected
	}
	products, err := lookup(id)
	if f.cveOrgCache == nil {
		f.cveOrgCache = map[string]cveOrgResult{}
	}
	f.cveOrgCache[id] = cveOrgResult{products, err}
	return products, err
}

// report is one profile's result in one run, for the job summary, the state
// commit message and the log.
type report struct {
	profile        string
	words          int
	kevNew, nvdNew int // matches not sent before
	sent           int
	ok             bool
	status         string
}

// runAll fetches the feeds once and checks every profile against them.
// Returns false if anything was broken for any profile.
func runAll(cfgs []config) bool {
	now := time.Now().UTC()
	states := make([]*state, len(cfgs))
	stErrs := make([]error, len(cfgs))
	since := now
	for i, c := range cfgs {
		states[i], stErrs[i] = loadState(c.stateFile)
		if stErrs[i] == nil {
			if s := nvdSince(states[i], now); s.Before(since) {
				since = s
			}
		}
	}
	var f *fetched
	if last := lastNVDPoll(states, stErrs); nvdNotDue(last, now) {
		fmt.Printf("NVD not due: last polled %s, next poll from %s\n",
			last.Format(time.RFC3339), last.Add(nvdMinGap).Format(time.RFC3339))
		f = &fetched{now: now, nvdSkipped: true}
		f.kev, f.kevErr = fetchKEV()
	} else {
		f = fetchFeeds(cfgs[0], since, now)
	}
	ok := true
	var reps []report
	for i, c := range cfgs {
		rep := runOnce(c, states[i], stErrs[i], f)
		reps = append(reps, rep)
		ok = rep.ok && ok
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		writeSummary(now, reps)
		writeCommitMessage(reps)
	}
	return ok
}

// writeSummary adds one row per profile to the job summary, so every run
// shows each profile was checked, also when nothing was sent.
func writeSummary(now time.Time, reps []report) {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[job summary]", err)
		return
	}
	defer f.Close()
	fmt.Fprint(f, summaryTable(now, reps))
}

func summaryTable(now time.Time, reps []report) string {
	cell := strings.NewReplacer("|", `\|`, "\r", " ", "\n", " ")
	var b strings.Builder
	fmt.Fprintf(&b, "### %s profiles checked\n\n", now.Format(time.RFC3339))
	b.WriteString("| Profile | Words | New KEV | New NVD | Sent | Not sent | Status |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, r := range reps {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %s |\n",
			cell.Replace(r.profile), r.words, r.kevNew, r.nvdNew, r.sent,
			r.kevNew+r.nvdNew-r.sent, cell.Replace(r.status))
	}
	b.WriteString("\n")
	return b.String()
}

// writeCommitMessage leaves the state commit message in $RUNNER_TEMP for the
// workflow's Save state step. RUNNER_TEMP is emptied at the start of each job.
func writeCommitMessage(reps []report) {
	dir := os.Getenv("RUNNER_TEMP")
	if dir == "" {
		return
	}
	path := filepath.Join(dir, "message-me-cve-commit.txt")
	if err := os.WriteFile(path, []byte(commitMessage(reps)), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "[commit message]", err)
	}
}

// commitMessage names the profiles that sent alerts or failed in the subject,
// and lists every profile's counts in the body.
func commitMessage(reps []report) string {
	var sent, failed, body []string
	for _, r := range reps {
		if r.sent > 0 {
			sent = append(sent, fmt.Sprintf("%s (%d)", r.profile, r.sent))
		}
		if !r.ok {
			failed = append(failed, r.profile)
		}
		body = append(body, fmt.Sprintf("%s: new KEV %d, new NVD %d, sent %d, %s",
			r.profile, r.kevNew, r.nvdNew, r.sent, r.status))
	}
	var parts []string
	if len(sent) > 0 {
		parts = append(parts, "sent "+strings.Join(sent, ", "))
	}
	if len(failed) > 0 {
		parts = append(parts, "failed "+strings.Join(failed, ", "))
	}
	subject := "message-me-cve: nothing sent"
	if len(parts) > 0 {
		subject = "message-me-cve: " + strings.Join(parts, "; ")
	}
	return subject + "\n\n" + strings.Join(body, "\n") + "\n"
}

// lastNVDPoll returns the latest NVD request time across profiles, zero if
// none is recorded.
func lastNVDPoll(states []*state, stErrs []error) time.Time {
	var last time.Time
	for i, st := range states {
		if stErrs[i] != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339, st.NVDPolled); err == nil && t.After(last) {
			last = t
		}
	}
	return last
}

// nvdNotDue reports whether NVD was polled less than nvdMinGap before now.
// A poll time in the future is treated as bad data, not as recent.
func nvdNotDue(last, now time.Time) bool {
	d := now.Sub(last)
	return !last.IsZero() && d >= 0 && d < nvdMinGap
}

func nvdSince(st *state, now time.Time) time.Time {
	if t, err := time.Parse(time.RFC3339, st.NVDSince); err == nil {
		return t
	}
	return now.Add(-nvdFirstRun)
}

// fetchFeeds reads KEV, and NVD changes since `since` in windows of at most
// 119 days so a long outage leaves no gap.
func fetchFeeds(cfg config, since, now time.Time) *fetched {
	f := &fetched{now: now}
	f.kev, f.kevErr = fetchKEV()
	first := true
	for start := since.Add(-5 * time.Minute); start.Before(now); start = start.Add(nvdMaxWindow) {
		if !first {
			time.Sleep(cfg.nvdSleep)
		}
		first = false
		end := start.Add(nvdMaxWindow)
		if end.After(now) {
			end = now
		}
		cves, err := fetchNVD(cfg, start, end)
		if err != nil {
			f.nvd, f.nvdErr = nil, err
			break
		}
		f.nvd = append(f.nvd, cves...)
	}
	return f
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// runOnce runs one check and reports its own failure. rep.ok is false if
// anything was broken (feed down or message-me-cve error).
func runOnce(cfg config, st *state, stErr error, f *fetched) report {
	rep := report{profile: cfg.profile}
	var runErr error
	if stErr != nil {
		runErr = stErr
	} else {
		before := len(st.Sent)
		runErr = safeRun(cfg, st, f, &rep)
		rep.sent = len(st.Sent) - before
	}

	var feeds *feedErrors
	selfErr := runErr
	if errors.As(runErr, &feeds) {
		selfErr = nil
	}
	if stErr != nil {
		// No usable state, so no once-only bookkeeping: report every run.
		send(cfg, "message-me-cve: FAILED, you are not covered", stErr.Error(), true)
	} else {
		trackBroken(cfg, st, selfKey, selfErr)
		if err := saveState(cfg.stateFile, st); err != nil {
			send(cfg, "message-me-cve: FAILED, you are not covered", "cannot save state: "+err.Error(), true)
			runErr = err
		}
	}
	status := "ok"
	if f.nvdSkipped {
		status = "ok, NVD not due"
	}
	if runErr != nil {
		status = runErr.Error()
	}
	name := ""
	if cfg.profile != "" {
		name = " [" + cfg.profile + "]"
	}
	fmt.Printf("[%s]%s run done: new KEV %d, new NVD %d, sent %d, %s\n",
		time.Now().UTC().Format(time.RFC3339), name, rep.kevNew, rep.nvdNew, rep.sent, status)
	rep.ok, rep.status = runErr == nil, status
	return rep
}

func safeRun(cfg config, st *state, f *fetched, rep *report) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("crash: %v", r)
		}
	}()
	return run(cfg, st, f, rep)
}

type feedErrors struct{ list []error }

func (e *feedErrors) Error() string {
	parts := make([]string, len(e.list))
	for i, x := range e.list {
		parts[i] = x.Error()
	}
	return "not covered: " + strings.Join(parts, "; ")
}

func run(cfg config, st *state, f *fetched, rep *report) error {
	words, err := loadWords(cfg.watchFile)
	if err != nil {
		return err
	}
	rep.words = len(words)
	now := f.now
	var down []error
	undelivered := false

	// KEV
	kevErr := f.kevErr
	if kevErr == nil {
		var alerts []alert
		for _, v := range f.kev {
			if w := kevMatch(v, words); w != "" && st.Sent["kev:"+v.CveID] == "" {
				alerts = append(alerts, kevAlert(v, w))
			}
		}
		rep.kevNew = len(alerts)
		if !deliver(cfg, st, alerts, "ACT NOW: actively exploited", now) {
			undelivered = true
		}
	} else {
		down = append(down, kevErr)
	}
	trackBroken(cfg, st, "CISA KEV", kevErr)

	// NVD. The shared fetch starts at the oldest profile's window, so it
	// covers this one; CVEs this profile already sent are skipped. Not due
	// (polled under nvdMinGap ago): the window is kept and the next due run
	// covers it. A due run that finishes sets nvd_since and nvd_polled to the
	// same time; if they differ, the last check left work undone (NVD or
	// CVE.org down, alerts undelivered) and the run stays failed.
	if f.nvdSkipped {
		if st.NVDSince != st.NVDPolled {
			down = append(down, errors.New("last NVD check did not finish, retrying at the next NVD poll"))
		}
	} else {
		st.NVDPolled = now.Format(time.RFC3339)
		var cveOrgErr error
		nvdErr := func() error {
			if f.nvdErr != nil {
				return f.nvdErr
			}
			var alerts []alert
			for _, c := range f.nvd {
				if st.Sent["nvd:"+c.ID] != "" || st.Sent["kev:"+c.ID] != "" {
					continue
				}
				if sev, _ := c.severity(); sev != "CRITICAL" && sev != "HIGH" {
					continue
				}
				// Unparseable date: keep the CVE rather than drop it silently.
				if p, err := time.Parse("2006-01-02T15:04:05", c.Published); err == nil && now.Sub(p) > nvdMaxAge {
					continue
				}
				w, confirmed, err := nvdMatch(c, words, f.affected)
				if err != nil {
					// A CVE.org failure only blocks the CVE that needed it; the
					// window is kept below so that CVE is retried next run.
					cveOrgErr = err
					continue
				}
				if w != "" {
					alerts = append(alerts, nvdAlert(c, w, confirmed))
				}
			}
			alerts = dedupe(alerts)
			rep.nvdNew = len(alerts)
			if !deliver(cfg, st, alerts, "New CRITICAL/HIGH CVEs", now) {
				undelivered = true
				return nil // undelivered alerts stay unsent; keep the window so they retry
			}
			if cveOrgErr == nil {
				st.NVDSince = now.Format(time.RFC3339)
			}
			return nil
		}()
		if nvdErr != nil {
			down = append(down, nvdErr)
		}
		trackBroken(cfg, st, "NVD", nvdErr)
		// Without NVD data no CVE.org lookup ran, so its state is unknown.
		if nvdErr == nil {
			if cveOrgErr != nil {
				down = append(down, cveOrgErr)
			}
			trackBroken(cfg, st, "CVE.org", cveOrgErr)
		}
	}

	if undelivered {
		down = append(down, errors.New("could not deliver alerts, retrying next run"))
	}
	if len(down) > 0 {
		return &feedErrors{down}
	}
	return nil
}

// ---------- watch list / state ----------

func loadWords(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read watch list: %w", err)
	}
	var words []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		w, _, _ := strings.Cut(line, "#")
		w = strings.ToLower(strings.Join(strings.Fields(w), " "))
		if w != "" && !seen[w] {
			seen[w] = true
			words = append(words, w)
		}
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("watch list %s has no words, nothing is being watched", path)
	}
	return words, nil
}

func loadState(path string) (*state, error) {
	st := &state{}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("cannot read state: %w", err)
	}
	if err == nil {
		if err := json.Unmarshal(data, st); err != nil {
			return nil, fmt.Errorf("state file %s is corrupt (move it away to start fresh): %w", path, err)
		}
	}
	if st.Sent == nil {
		st.Sent = map[string]string{}
	}
	if st.Broken == nil {
		st.Broken = map[string]string{}
	}
	return st, nil
}

func saveState(path string, st *state) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// trackBroken messages once when something breaks and once when it recovers.
func trackBroken(cfg config, st *state, name string, err error) {
	_, was := st.Broken[name]
	switch {
	case err != nil && !was:
		body := fmt.Sprintf("%s is failing. You are NOT covered until this clears.\n%v", name, err)
		title := "message-me-cve: cannot check " + name
		if name == selfKey {
			title = "message-me-cve: FAILED, you are not covered"
		}
		if send(cfg, title, body, true) {
			st.Broken[name] = err.Error()
		}
	case err == nil && was:
		if send(cfg, "message-me-cve: "+name+" OK again", name+" is working again.", false) {
			delete(st.Broken, name)
		}
	}
}

// ---------- matching ----------

func isWordChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b >= 0x80
}

// containsWord reports whether w occurs in hay as a whole word.
func containsWord(hay, w string) bool {
	hay = strings.ToLower(hay)
	for i := 0; i < len(hay); {
		j := strings.Index(hay[i:], w)
		if j < 0 {
			return false
		}
		s, e := i+j, i+j+len(w)
		left := s == 0 || !isWordChar(hay[s-1])
		right := e == len(hay) || !isWordChar(hay[e])
		if left && right {
			return true
		}
		i = s + 1
	}
	return false
}

func kevMatch(v kevEntry, words []string) string {
	hay := v.VendorProject + " " + v.Product
	for _, w := range words {
		if containsWord(hay, w) {
			return w
		}
	}
	return ""
}

// nvdMatch returns the matching watch word and whether NVD has analyzed the CVE
// (confirmed). Unanalyzed CVEs whose description mentions a watch word are
// looked up in the CVE.org record, whose affected-product list is written by
// the CVE's publisher at release time.
func nvdMatch(c nvdCVE, words []string, affected func(id string) ([]string, error)) (string, bool, error) {
	analyzed := false
	for _, m := range c.cpeMatches() {
		if !m.Vulnerable {
			continue
		}
		analyzed = true
		p := strings.Split(strings.ToLower(m.Criteria), ":")
		if len(p) < 5 {
			continue
		}
		hay := strings.ReplaceAll(p[3]+" "+p[4], "_", " ") // vendor product
		for _, w := range words {
			if containsWord(hay, w) {
				return w, true, nil
			}
		}
	}
	if analyzed {
		return "", false, nil
	}
	mentioned := false
	for _, w := range words {
		mentioned = mentioned || containsWord(c.desc(), w)
	}
	if !mentioned {
		return "", false, nil
	}
	products, err := affected(c.ID)
	if err != nil {
		return "", false, err
	}
	for _, p := range products {
		for _, w := range words {
			if containsWord(p, w) {
				return w, false, nil
			}
		}
	}
	return "", false, nil
}

// cveOrgAffected returns "vendor product" for each product the CVE record lists.
func cveOrgAffected(id string) ([]string, error) {
	var rec struct {
		Containers struct {
			CNA struct {
				Affected []struct {
					Vendor  string `json:"vendor"`
					Product string `json:"product"`
				} `json:"affected"`
			} `json:"cna"`
		} `json:"containers"`
	}
	if err := getJSON("https://cveawg.mitre.org/api/cve/"+url.PathEscape(id), nil, &rec); err != nil {
		return nil, &feedError{"CVE.org", err.Error()}
	}
	var out []string
	for _, a := range rec.Containers.CNA.Affected {
		out = append(out, a.Vendor+" "+a.Product)
	}
	return out, nil
}

// ---------- delivery ----------

// deliver sends alerts and marks each sent only after delivery. Many alerts in
// one run (e.g. a newly added watch word with years of history) are sent as a
// combined list instead of one push each. Returns true if everything was sent.
func deliver(cfg config, st *state, alerts []alert, listTitle string, now time.Time) bool {
	if len(alerts) == 0 {
		return true
	}
	stamp := now.Format(time.RFC3339)
	ok := true
	if len(alerts) <= maxSingle {
		for _, a := range alerts {
			if send(cfg, a.title, a.body, a.urgent) {
				st.Sent[a.key] = stamp
			} else {
				ok = false
			}
		}
		return ok
	}
	urgent := false
	for _, a := range alerts {
		urgent = urgent || a.urgent
	}
	var chunk []alert
	size := 0
	flush := func(part int) {
		lines := make([]string, len(chunk))
		for i, a := range chunk {
			lines[i] = a.short
		}
		title := fmt.Sprintf("%s: %d matches (part %d)", listTitle, len(alerts), part)
		if send(cfg, title, strings.Join(lines, "\n"), urgent) {
			for _, a := range chunk {
				st.Sent[a.key] = stamp
			}
		} else {
			ok = false
		}
		chunk, size = nil, 0
	}
	part := 1
	for _, a := range alerts {
		if size+len(a.short)+1 > maxBody && len(chunk) > 0 {
			flush(part)
			part++
		}
		chunk = append(chunk, a)
		size += len(a.short) + 1
	}
	flush(part)
	return ok
}

// send delivers to every configured channel; false if any of them failed.
func send(cfg config, title, body string, urgent bool) bool {
	if cfg.profile != "" {
		title = "[" + cfg.profile + "] " + title
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		// Feed text is third-party; stop the runner treating a line of it
		// as a workflow command (e.g. a forged ::error:: annotation).
		tok := make([]byte, 16)
		rand.Read(tok)
		end := hex.EncodeToString(tok)
		fmt.Printf("::stop-commands::%s\n=== %s\n%s\n\n::%s::\n", end, title, body, end)
	} else {
		fmt.Printf("=== %s\n%s\n\n", title, body)
	}
	ok := true
	var delivery []string
	if cfg.ntfyURL != "" {
		r := sendNtfy(cfg, title, body, urgent)
		ok = r && ok
		delivery = append(delivery, "ntfy "+result(r))
	}
	if cfg.tgToken != "" {
		r := sendTelegram(cfg, title, body)
		ok = r && ok
		delivery = append(delivery, "telegram "+result(r))
	}
	if len(delivery) == 0 {
		delivery = append(delivery, "no channel configured")
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		recordInRun(time.Now().UTC(), title, body, urgent, ok, strings.Join(delivery, ", "))
	}
	return ok
}

func result(ok bool) string {
	if ok {
		return "delivered"
	}
	return "FAILED"
}

// recordInRun puts the message on the Actions run page: an annotation and a
// job summary entry, kept for the repo's log retention period.
func recordInRun(at time.Time, title, body string, urgent, ok bool, delivery string) {
	stamp := at.Format(time.RFC3339)
	level := "notice"
	if urgent {
		level = "warning"
	}
	if !ok {
		level = "error"
	}
	esc := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	prop := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	fmt.Printf("::%s title=%s::%s\n", level, prop.Replace(stamp+" "+title),
		esc.Replace("Delivery: "+delivery+"\n\n"+body))

	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[job summary]", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "### %s %s\n\nDelivery: %s\n\n````\n%s\n````\n\n", stamp, title, delivery, body)
}

func sendTelegram(cfg config, title, body string) bool {
	if cfg.tgChat == "" {
		fmt.Fprintln(os.Stderr, "[telegram send failed] TELEGRAM_CHAT_ID is not set")
		return false
	}
	form := url.Values{"chat_id": {cfg.tgChat}, "text": {title + "\n\n" + body}}
	req, err := http.NewRequest("POST", telegramAPI+"/bot"+cfg.tgToken+"/sendMessage", strings.NewReader(form.Encode()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "[telegram send failed] could not build request")
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	time.Sleep(time.Until(telegramLast.Add(telegramGap)))
	resp, err := client.Do(req)
	// Pace from the reply, not the request: Telegram has the message by now,
	// so the next one reaches it at least telegramGap later. Pacing from the
	// request let a faster second request arrive a few ms early.
	telegramLast = time.Now()
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL contains the bot token; keep it out of logs
		}
		fmt.Fprintln(os.Stderr, "[telegram send failed]", err)
		return false
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode >= 300 {
		fmt.Fprintln(os.Stderr, "[telegram send failed] HTTP", resp.StatusCode, string(reply))
		return false
	}
	return true
}

func sendNtfy(cfg config, title, body string, urgent bool) bool {
	req, err := http.NewRequest("POST", cfg.ntfyURL, strings.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "[send failed]", err)
		return false
	}
	req.Header.Set("Title", ascii(title))
	req.Header.Set("User-Agent", userAgent)
	if urgent {
		req.Header.Set("Priority", "urgent")
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[send failed]", err)
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		fmt.Fprintln(os.Stderr, "[send failed] HTTP", resp.StatusCode)
		return false
	}
	return true
}

func ascii(s string) string {
	b := []byte{}
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b = append(b, byte(r))
		} else {
			b = append(b, '?')
		}
	}
	return string(b)
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}

func dedupe(alerts []alert) []alert {
	seen := map[string]bool{}
	out := alerts[:0]
	for _, a := range alerts {
		if !seen[a.key] {
			seen[a.key] = true
			out = append(out, a)
		}
	}
	return out
}

// ---------- KEV ----------

type kevEntry struct {
	CveID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

func fetchKEV() ([]kevEntry, error) {
	var errs []string
	for _, u := range kevURLs {
		var feed struct {
			Vulnerabilities []kevEntry `json:"vulnerabilities"`
		}
		if err := getJSON(u, nil, &feed); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if len(feed.Vulnerabilities) == 0 {
			errs = append(errs, u+": empty catalog")
			continue
		}
		return feed.Vulnerabilities, nil
	}
	return nil, &feedError{"CISA KEV", strings.Join(errs, "; ")}
}

func kevAlert(v kevEntry, w string) alert {
	body := fmt.Sprintf("%s - %s %s\n%s\nActively exploited (on CISA KEV since %s). Ransomware use: %s\nAction: %s\n%s\nhttps://nvd.nist.gov/vuln/detail/%s",
		v.CveID, v.VendorProject, v.Product, v.VulnerabilityName, v.DateAdded,
		v.KnownRansomwareCampaignUse, cut(v.RequiredAction, 300), cut(v.ShortDescription, 400), v.CveID)
	return alert{
		key:    "kev:" + v.CveID,
		title:  fmt.Sprintf("ACT NOW [%s]: exploited %s %s", w, v.Product, v.CveID),
		body:   body,
		short:  fmt.Sprintf("%s [%s] %s %s, KEV since %s", v.CveID, w, v.VendorProject, v.Product, v.DateAdded),
		urgent: true,
	}
}

// ---------- NVD ----------

type cpeMatch struct {
	Vulnerable          bool   `json:"vulnerable"`
	Criteria            string `json:"criteria"`
	VersionEndExcluding string `json:"versionEndExcluding"`
}

type cvssMetric struct {
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V40 []cvssMetric `json:"cvssMetricV40"`
		V31 []cvssMetric `json:"cvssMetricV31"`
		V30 []cvssMetric `json:"cvssMetricV30"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CpeMatch []cpeMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

func (c nvdCVE) cpeMatches() []cpeMatch {
	var out []cpeMatch
	for _, conf := range c.Configurations {
		for _, n := range conf.Nodes {
			out = append(out, n.CpeMatch...)
		}
	}
	return out
}

func (c nvdCVE) desc() string {
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

// severity returns the highest CVSS v3.x severity and score from any source:
// NVD (Primary), the CVE's publisher or CISA (Secondary). NVD scores new CVEs
// days to weeks late, often never. No v3.x score: highest v4.0. None: "".
func (c nvdCVE) severity() (string, string) {
	for _, list := range [][]cvssMetric{slices.Concat(c.Metrics.V31, c.Metrics.V30), c.Metrics.V40} {
		if len(list) == 0 {
			continue
		}
		best := list[0].CvssData
		for _, m := range list[1:] {
			if m.CvssData.BaseScore > best.BaseScore {
				best = m.CvssData
			}
		}
		return strings.ToUpper(best.BaseSeverity), strconv.FormatFloat(best.BaseScore, 'f', 1, 64)
	}
	return "", "?"
}

// NVD outages are usually short. Retry for up to nvdRetryBudget before
// the failure reaches trackBroken and alerts.
var (
	nvdRetryBudget = 60 * time.Minute
	nvdRetryFirst  = 30 * time.Second
	nvdRetryCap    = 5 * time.Minute
)

func retryNVD(fn func() error) error {
	deadline := time.Now().Add(nvdRetryBudget)
	wait := nvdRetryFirst
	for {
		err := fn()
		if err == nil || time.Now().Add(wait).After(deadline) {
			return err
		}
		fmt.Fprintf(os.Stderr, "NVD error, retrying in %s: %v\n", wait, err)
		time.Sleep(wait)
		wait = min(wait*2, nvdRetryCap)
	}
}

// fetchNVD returns every CVE modified in [start, end]. No cvssV3Severity
// filter: it only checks NVD's own score, so it drops every CVE that only its
// publisher has scored yet. Severity is checked by the caller instead.
func fetchNVD(cfg config, start, end time.Time) ([]nvdCVE, error) {
	var out []nvdCVE
	headers := map[string]string{}
	if cfg.nvdKey != "" {
		headers["apiKey"] = cfg.nvdKey
	}
	for index := 0; ; {
		q := url.Values{
			"lastModStartDate": {start.Format(nvdTimeFormat)},
			"lastModEndDate":   {end.Format(nvdTimeFormat)},
			"resultsPerPage":   {"2000"},
			"startIndex":       {strconv.Itoa(index)},
		}
		var page struct {
			TotalResults    int `json:"totalResults"`
			Vulnerabilities []struct {
				CVE nvdCVE `json:"cve"`
			} `json:"vulnerabilities"`
		}
		if err := retryNVD(func() error {
			return getJSON(nvdURL+"?"+q.Encode(), headers, &page)
		}); err != nil {
			return nil, &feedError{"NVD", fmt.Sprintf("startIndex=%d: %v", index, err)}
		}
		for _, v := range page.Vulnerabilities {
			out = append(out, v.CVE)
		}
		index += len(page.Vulnerabilities)
		if len(page.Vulnerabilities) == 0 || index >= page.TotalResults {
			return out, nil
		}
		time.Sleep(cfg.nvdSleep)
	}
}

func nvdAlert(c nvdCVE, w string, confirmed bool) alert {
	severity, score := c.severity()
	fixes := map[string]bool{}
	for _, m := range c.cpeMatches() {
		if p := strings.Split(m.Criteria, ":"); m.Vulnerable && m.VersionEndExcluding != "" && len(p) > 4 {
			fixes[p[4]+" >= "+m.VersionEndExcluding] = true
		}
	}
	var fixList []string
	for f := range fixes {
		fixList = append(fixList, f)
	}
	sort.Strings(fixList)
	note := ""
	if !confirmed {
		note = " (NVD analysis pending; product match from the CVE.org record)"
	}
	fix := ""
	if len(fixList) > 0 {
		fix = "Fixed in: " + cut(strings.Join(fixList, ", "), 400) + "\n"
	}
	body := fmt.Sprintf("%s - %s %s%s\n%s%s\nhttps://nvd.nist.gov/vuln/detail/%s",
		c.ID, severity, score, note, fix, cut(c.desc(), 500), c.ID)
	return alert{
		key:   "nvd:" + c.ID,
		title: fmt.Sprintf("%s %s [%s]: %s", severity, score, w, c.ID),
		body:  body,
		short: fmt.Sprintf("%s [%s] %s %s: %s", c.ID, w, severity, score, cut(c.desc(), 120)),
	}
}

// ---------- HTTP ----------

func getJSON(u string, headers map[string]string, v any) error {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", strings.SplitN(u, "?", 2)[0], resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
