package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContainsWord(t *testing.T) {
	cases := []struct {
		hay, w string
		want   bool
	}{
		{"PHP Group PHP", "php", true},
		{"PHPMailer", "php", false},
		{"in /admin/login.php", "php", true},
		{"php-fpm crash", "php", true},
		{"Apache HTTP Server", "apache http server", true},
		{"openresty-nginx", "nginx", true},
		{"nginxplus", "nginx", false},
	}
	for _, c := range cases {
		if got := containsWord(c.hay, c.w); got != c.want {
			t.Errorf("containsWord(%q, %q) = %v, want %v", c.hay, c.w, got, c.want)
		}
	}
}

func cve(id, desc string, criteria ...string) nvdCVE {
	c := nvdCVE{ID: id}
	c.Descriptions = append(c.Descriptions, struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}{"en", desc})
	if len(criteria) > 0 {
		var ms []cpeMatch
		for _, cr := range criteria {
			ms = append(ms, cpeMatch{Vulnerable: true, Criteria: cr})
		}
		c.Configurations = append(c.Configurations, struct {
			Nodes []struct {
				CpeMatch []cpeMatch `json:"cpeMatch"`
			} `json:"nodes"`
		}{Nodes: []struct {
			CpeMatch []cpeMatch `json:"cpeMatch"`
		}{{CpeMatch: ms}}})
	}
	return c
}

func TestNVDMatch(t *testing.T) {
	words := []string{"php", "apache http server"}
	records := map[string][]string{
		"CVE-PHP":   {"PHP Group PHP"},
		"CVE-CRAFT": {"craftcms cms"},
	}
	lookups := 0
	affected := func(id string) ([]string, error) {
		lookups++
		if id == "CVE-DOWN" {
			return nil, errors.New("down")
		}
		return records[id], nil
	}
	cases := []struct {
		name      string
		c         nvdCVE
		word      string
		confirmed bool
		err       bool
	}{
		{"cpe product", cve("A", "x", "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"), "php", true, false},
		{"analyzed webapp", cve("B", "SQLi in login.php", "cpe:2.3:a:acme:shop:*:*:*:*:*:*:*:*"), "", false, false},
		{"multi-word product", cve("C", "x", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"), "apache http server", true, false},
		{"other apache product", cve("D", "x", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"), "", false, false},
		{"unanalyzed php itself", cve("CVE-PHP", "PHP 8.4 heap overflow"), "php", false, false},
		{"unanalyzed php app", cve("CVE-CRAFT", "Craft CMS lets users call static PHP callables"), "", false, false},
		{"unanalyzed record lookup fails", cve("CVE-DOWN", "PHP thing"), "", false, true},
	}
	for _, c := range cases {
		w, ok, err := nvdMatch(c.c, words, affected)
		if w != c.word || ok != c.confirmed || (err != nil) != c.err {
			t.Errorf("%s: got (%q, %v, %v), want (%q, %v, err=%v)", c.name, w, ok, err, c.word, c.confirmed, c.err)
		}
	}

	lookups = 0
	nvdMatch(cve("CVE-X", "nothing relevant"), words, affected)
	if lookups != 0 {
		t.Errorf("unanalyzed CVE not mentioning a watch word triggered %d lookups", lookups)
	}
}

func TestSeverity(t *testing.T) {
	cases := []struct {
		name, json, sev, score string
	}{
		// CVE-2026-121810 (NGINX HTTP/3) as NVD served it: F5's score only.
		{"publisher score only", `{"metrics":{"cvssMetricV31":[{"source":"f5sirt@f5.com","type":"Secondary","cvssData":{"baseScore":8.1,"baseSeverity":"HIGH"}}],"cvssMetricV40":[{"source":"f5sirt@f5.com","type":"Secondary","cvssData":{"baseScore":9.2,"baseSeverity":"CRITICAL"}}]}}`, "HIGH", "8.1"},
		{"highest of NVD and publisher", `{"metrics":{"cvssMetricV31":[{"type":"Secondary","cvssData":{"baseScore":5.3,"baseSeverity":"MEDIUM"}},{"type":"Primary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}`, "CRITICAL", "9.8"},
		{"v4.0 only", `{"metrics":{"cvssMetricV40":[{"cvssData":{"baseScore":8.7,"baseSeverity":"HIGH"}}]}}`, "HIGH", "8.7"},
		{"unscored", `{"metrics":{}}`, "", "?"},
	}
	for _, c := range cases {
		var v nvdCVE
		if err := json.Unmarshal([]byte(c.json), &v); err != nil {
			t.Fatal(err)
		}
		if sev, score := v.severity(); sev != c.sev || score != c.score {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", c.name, sev, score, c.sev, c.score)
		}
	}
}

func TestSendTelegram(t *testing.T) {
	var path, chat, text string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		path, chat, text = r.URL.Path, r.PostForm.Get("chat_id"), r.PostForm.Get("text")
		w.WriteHeader(status)
	}))
	defer srv.Close()
	telegramAPI = srv.URL

	cfg := config{tgToken: "123:abc", tgChat: "42"}
	if !send(cfg, "ACT NOW: php", "body", true) {
		t.Fatal("send failed against 200 server")
	}
	if path != "/bot123:abc/sendMessage" || chat != "42" || text != "ACT NOW: php\n\nbody" {
		t.Errorf("got path %q chat %q text %q", path, chat, text)
	}

	status = http.StatusBadRequest
	if send(cfg, "t", "b", false) {
		t.Error("send reported success on HTTP 400")
	}

	status = http.StatusOK
	if send(config{tgToken: "123:abc"}, "t", "b", false) {
		t.Error("send reported success without TELEGRAM_CHAT_ID")
	}
}

func TestRecordInRun(t *testing.T) {
	summary := filepath.Join(t.TempDir(), "summary.md")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	ok := send(config{}, "ACT NOW: php, 2 matches", "line1\nline2\n::error::forged", true)
	w.Close()
	os.Stdout = stdout
	out := make([]byte, 4096)
	n, _ := r.Read(out)

	if !ok {
		t.Fatal("send with no channels reported failure")
	}
	if !strings.Contains(string(out[:n]), "::warning title=") ||
		!strings.Contains(string(out[:n]), "ACT NOW%3A php%2C 2 matches::Delivery: no channel configured%0A%0Aline1%0Aline2%0A::error::forged\n") {
		t.Errorf("annotation not found in output:\n%s", out[:n])
	}
	o := string(out[:n])
	stop := strings.Index(o, "::stop-commands::")
	forged := strings.Index(o, "\n::error::forged\n")
	if stop < 0 || forged < stop {
		t.Fatalf("raw feed text printed outside stop-commands:\n%s", o)
	}
	end := o[stop+len("::stop-commands::") : stop+len("::stop-commands::")+32]
	if resume := strings.Index(o, "::"+end+"::"); resume < forged || resume > strings.Index(o, "::warning") {
		t.Errorf("commands not resumed between raw text and annotation:\n%s", o)
	}
	data, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ACT NOW: php, 2 matches\n\nDelivery: no channel configured\n\n````\nline1\nline2\n::error::forged\n````") {
		t.Errorf("summary:\n%s", data)
	}
}

func TestProfilePrefix(t *testing.T) {
	var text string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		text = r.PostForm.Get("text")
	}))
	defer srv.Close()
	telegramAPI = srv.URL
	send(config{tgToken: "1:a", tgChat: "1", profile: "business"}, "ACT NOW", "b", true)
	if text != "[business] ACT NOW\n\nb" {
		t.Errorf("text = %q", text)
	}
}

func TestRetryNVD(t *testing.T) {
	nvdRetryBudget, nvdRetryFirst, nvdRetryCap = time.Second, time.Millisecond, 5*time.Millisecond
	calls := 0
	err := retryNVD(func() error {
		calls++
		if calls < 3 {
			return errors.New("HTTP 503")
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Errorf("transient: err %v calls %d, want nil and 3", err, calls)
	}

	nvdRetryBudget = 50 * time.Millisecond
	calls = 0
	err = retryNVD(func() error { calls++; return errors.New("HTTP 503") })
	if err == nil || calls < 2 {
		t.Errorf("persistent: err %v calls %d, want error after retries", err, calls)
	}
}

func TestTelegramPacing(t *testing.T) {
	var at []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		at = append(at, time.Now())
	}))
	defer srv.Close()
	telegramAPI, telegramGap = srv.URL, 50*time.Millisecond
	defer func() { telegramGap = time.Second }()
	cfg := config{tgToken: "1:a", tgChat: "1"}
	send(cfg, "a", "b", false)
	send(cfg, "a", "b", false)
	if len(at) != 2 || at[1].Sub(at[0]) < 50*time.Millisecond {
		t.Errorf("second Telegram message not paced: %v", at)
	}
}

func TestProfileConfigs(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a.com.txt", "b.txt", "notes.md"} {
		os.WriteFile(filepath.Join(dir, n), []byte("php\n"), 0o644)
	}
	cfgs, err := profileConfigs(config{stateFile: filepath.Join("state", "state.json")}, dir)
	if err != nil || len(cfgs) != 2 {
		t.Fatalf("got %d configs, err %v; want 2", len(cfgs), err)
	}
	if c := cfgs[0]; c.profile != "a.com" || c.watchFile != filepath.Join(dir, "a.com.txt") || c.stateFile != filepath.Join("state", "a.com.json") {
		t.Errorf("got %+v", c)
	}
	if _, err := profileConfigs(config{}, t.TempDir()); err == nil {
		t.Error("empty PROFILES_DIR accepted")
	}
}

// One shared NVD fetch, checked per profile: severity from any source, 90-day
// published cutoff, unparseable dates kept, already-sent skipped.
func TestRunNVDFilters(t *testing.T) {
	now := time.Date(2026, 11, 18, 19, 0, 0, 0, time.UTC)
	mk := func(id, published string, score float64, sev string) nvdCVE {
		c := cve(id, "x", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")
		c.Published = published
		var m cvssMetric
		m.CvssData.BaseScore, m.CvssData.BaseSeverity = score, sev
		c.Metrics.V31 = []cvssMetric{m}
		return c
	}
	f := &fetched{now: now, nvd: []nvdCVE{
		mk("CVE-NEW-HIGH", "2026-11-18T16:18:00.357", 8.1, "HIGH"),
		mk("CVE-NEW-MEDIUM", "2026-11-18T16:18:00.357", 5.3, "MEDIUM"),
		mk("CVE-OLD-HIGH", "2016-05-05T01:59:00.000", 9.8, "CRITICAL"),
		mk("CVE-ODD-DATE", "18 Nov 2026", 9.8, "CRITICAL"),
		mk("CVE-SENT", "2026-11-18T16:18:00.357", 9.8, "CRITICAL"),
	}}
	watch := filepath.Join(t.TempDir(), "w.txt")
	os.WriteFile(watch, []byte("nginx\n"), 0o644)
	st := &state{Sent: map[string]string{"nvd:CVE-SENT": "x"}, Broken: map[string]string{}}
	var rep report
	if err := run(config{watchFile: watch}, st, f, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.words != 1 || rep.kevNew != 0 || rep.nvdNew != 2 {
		t.Errorf("report = %+v, want words 1, kevNew 0, nvdNew 2", rep)
	}
	for id, want := range map[string]bool{"CVE-NEW-HIGH": true, "CVE-ODD-DATE": true, "CVE-NEW-MEDIUM": false, "CVE-OLD-HIGH": false} {
		if got := st.Sent["nvd:"+id] != ""; got != want {
			t.Errorf("%s sent = %v, want %v", id, got, want)
		}
	}
	if st.NVDSince != now.Format(time.RFC3339) {
		t.Errorf("NVDSince = %q, want %q", st.NVDSince, now.Format(time.RFC3339))
	}
}

// A CVE.org outage holds back only the CVE that needed the lookup: analyzed
// CVEs are still sent, the failure is reported as CVE.org (not NVD), and the
// NVD window is kept so the held-back CVE is retried next run.
func TestRunCVEOrgOutage(t *testing.T) {
	now := time.Date(2026, 11, 18, 19, 0, 0, 0, time.UTC)
	mk := func(c nvdCVE) nvdCVE {
		c.Published = "2026-11-18T16:18:00.357"
		var m cvssMetric
		m.CvssData.BaseScore, m.CvssData.BaseSeverity = 8.1, "HIGH"
		c.Metrics.V31 = []cvssMetric{m}
		return c
	}
	f := &fetched{now: now, nvd: []nvdCVE{
		mk(cve("CVE-UNANALYZED", "nginx heap overflow")),
		mk(cve("CVE-ANALYZED", "x", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")),
	}, cveOrg: func(id string) ([]string, error) {
		return nil, &feedError{"CVE.org", "HTTP 503"}
	}}
	watch := filepath.Join(t.TempDir(), "w.txt")
	os.WriteFile(watch, []byte("nginx\n"), 0o644)
	st := &state{Sent: map[string]string{}, Broken: map[string]string{}, NVDSince: "2026-11-18T17:00:00Z"}
	var rep report
	err := run(config{watchFile: watch}, st, f, &rep)

	var feeds *feedErrors
	if !errors.As(err, &feeds) {
		t.Fatalf("err = %v, want a feed error", err)
	}
	if st.Sent["nvd:CVE-ANALYZED"] == "" || st.Sent["nvd:CVE-UNANALYZED"] != "" {
		t.Errorf("sent = %v, want only CVE-ANALYZED", st.Sent)
	}
	if _, ok := st.Broken["CVE.org"]; !ok {
		t.Errorf("broken = %v, want CVE.org", st.Broken)
	}
	if _, ok := st.Broken["NVD"]; ok {
		t.Errorf("broken = %v, NVD reported for a CVE.org failure", st.Broken)
	}
	if st.NVDSince != "2026-11-18T17:00:00Z" {
		t.Errorf("NVDSince advanced to %q during a CVE.org failure", st.NVDSince)
	}

	// CVE.org back: the held-back CVE is sent and CVE.org clears.
	f.cveOrg, f.cveOrgCache = func(id string) ([]string, error) { return []string{"F5 NGINX"}, nil }, nil
	if err := run(config{watchFile: watch}, st, f, &rep); err != nil {
		t.Fatal(err)
	}
	if st.Sent["nvd:CVE-UNANALYZED"] == "" {
		t.Error("held-back CVE not sent after CVE.org recovered")
	}
	if _, ok := st.Broken["CVE.org"]; ok || st.NVDSince != now.Format(time.RFC3339) {
		t.Errorf("after recovery: broken %v, NVDSince %q", st.Broken, st.NVDSince)
	}
}

// NVD is polled at most every nvdMinGap: zero and future poll times count as
// due, so missing or bad state never blocks NVD.
func TestNVDNotDue(t *testing.T) {
	now := time.Date(2026, 11, 19, 14, 41, 0, 0, time.UTC)
	for _, tc := range []struct {
		last time.Time
		want bool
	}{
		{time.Time{}, false},
		{now.Add(-time.Hour), true},
		{now.Add(-nvdMinGap + time.Second), true},
		{now.Add(-nvdMinGap), false},
		{now.Add(-9 * time.Hour), false},
		{now.Add(time.Hour), false},
	} {
		if got := nvdNotDue(tc.last, now); got != tc.want {
			t.Errorf("nvdNotDue(%s) = %v, want %v", tc.last, got, tc.want)
		}
	}
}

func TestLastNVDPoll(t *testing.T) {
	states := []*state{
		{NVDPolled: "2026-11-19T12:41:00Z"},
		{NVDPolled: "2026-11-19T14:41:00Z"}, // unreadable state file: ignored
		{NVDPolled: "garbage"},
		{NVDPolled: "2026-11-19T13:00:00Z"},
		{},
	}
	errs := []error{nil, errors.New("bad state"), nil, nil, nil}
	want := time.Date(2026, 11, 19, 13, 0, 0, 0, time.UTC)
	if got := lastNVDPoll(states, errs); !got.Equal(want) {
		t.Errorf("lastNVDPoll = %s, want %s", got, want)
	}
}

// A run where NVD is not due checks KEV only and leaves the NVD window, poll
// time and broken state untouched. It stays failed while the last NVD check
// is unfinished (exit code non-zero while broken). A due run records its
// poll time.
func TestRunNVDNotDue(t *testing.T) {
	now := time.Date(2026, 11, 19, 14, 41, 0, 0, time.UTC)
	watch := filepath.Join(t.TempDir(), "w.txt")
	os.WriteFile(watch, []byte("nginx\n"), 0o644)

	// Last check finished: not-due run is ok.
	done := &state{Sent: map[string]string{}, Broken: map[string]string{},
		NVDSince: "2026-11-19T13:41:00Z", NVDPolled: "2026-11-19T13:41:00Z"}
	var rep report
	if err := run(config{watchFile: watch}, done, &fetched{now: now, nvdSkipped: true}, &rep); err != nil {
		t.Errorf("not-due run after a finished NVD check: err = %v, want nil", err)
	}

	// Last check unfinished (NVD down at 13:41).
	st := &state{
		Sent:      map[string]string{},
		Broken:    map[string]string{"NVD": "2026-11-19T12:41:00Z"},
		NVDSince:  "2026-11-19T10:00:00Z",
		NVDPolled: "2026-11-19T13:41:00Z",
	}
	f := &fetched{now: now, nvdSkipped: true, kev: []kevEntry{
		{CveID: "CVE-KEV", VendorProject: "F5", Product: "nginx"},
	}}
	err := run(config{watchFile: watch}, st, f, &rep)
	var feeds *feedErrors
	if !errors.As(err, &feeds) {
		t.Errorf("not-due run while NVD check unfinished: err = %v, want a feed error", err)
	}
	if rep.kevNew != 1 || st.Sent["kev:CVE-KEV"] == "" {
		t.Errorf("KEV not checked on a not-due run: rep %+v, sent %v", rep, st.Sent)
	}
	if st.NVDSince != "2026-11-19T10:00:00Z" || st.NVDPolled != "2026-11-19T13:41:00Z" {
		t.Errorf("not-due run changed NVD state: since %q, polled %q", st.NVDSince, st.NVDPolled)
	}
	if _, ok := st.Broken["NVD"]; !ok {
		t.Errorf("not-due run cleared NVD broken state: %v", st.Broken)
	}

	f = &fetched{now: now}
	if err := run(config{watchFile: watch}, st, f, &rep); err != nil {
		t.Fatal(err)
	}
	if st.NVDPolled != now.Format(time.RFC3339) || st.NVDSince != now.Format(time.RFC3339) {
		t.Errorf("due run: polled %q, since %q, want both %s", st.NVDPolled, st.NVDSince, now.Format(time.RFC3339))
	}
	if _, ok := st.Broken["NVD"]; ok {
		t.Errorf("due run with NVD data did not clear NVD broken state: %v", st.Broken)
	}
}

// Profiles watching the same word share one CVE.org lookup per run, failed
// lookups included.
func TestCVEOrgCache(t *testing.T) {
	calls := map[string]int{}
	f := &fetched{cveOrg: func(id string) ([]string, error) {
		calls[id]++
		if id == "CVE-DOWN" {
			return nil, errors.New("down")
		}
		return []string{"PHP Group PHP"}, nil
	}}
	for i := 0; i < 3; i++ {
		if p, err := f.affected("CVE-UP"); err != nil || len(p) != 1 {
			t.Fatalf("CVE-UP: %v %v", p, err)
		}
		if _, err := f.affected("CVE-DOWN"); err == nil {
			t.Fatal("CVE-DOWN: cached failure lost")
		}
	}
	if calls["CVE-UP"] != 1 || calls["CVE-DOWN"] != 1 {
		t.Errorf("lookups = %v, want 1 each", calls)
	}
}

func TestSummaryTable(t *testing.T) {
	now := time.Date(2026, 11, 18, 19, 0, 0, 0, time.UTC)
	got := summaryTable(now, []report{
		{profile: "example.com", words: 11, kevNew: 2, nvdNew: 1, sent: 2, ok: false, status: "not covered: a|b\nc"},
		{profile: "example-project", words: 4, ok: true, status: "ok"},
	})
	for _, want := range []string{
		"### 2026-11-18T19:00:00Z profiles checked\n",
		"| example.com | 11 | 2 | 1 | 2 | 1 | not covered: a\\|b c |\n",
		"| example-project | 4 | 0 | 0 | 0 | 0 | ok |\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q:\n%s", want, got)
		}
	}
}

func TestCommitMessage(t *testing.T) {
	quiet := report{profile: "example-project", words: 4, ok: true, status: "ok"}
	cases := []struct {
		reps    []report
		subject string
	}{
		{[]report{quiet}, "message-me-cve: nothing sent"},
		{[]report{{profile: "a.com", kevNew: 2, sent: 2, ok: true, status: "ok"}, quiet}, "message-me-cve: sent a.com (2)"},
		{[]report{{profile: "a.com", nvdNew: 1, sent: 1, ok: false, status: "x"}, {profile: "b", ok: false, status: "y"}, quiet},
			"message-me-cve: sent a.com (1); failed a.com, b"},
	}
	for _, c := range cases {
		msg := commitMessage(c.reps)
		if subject, _, _ := strings.Cut(msg, "\n"); subject != c.subject {
			t.Errorf("subject = %q, want %q", subject, c.subject)
		}
		if !strings.Contains(msg, "\nexample-project: new KEV 0, new NVD 0, sent 0, ok\n") {
			t.Errorf("body missing quiet profile:\n%s", msg)
		}
	}
}
