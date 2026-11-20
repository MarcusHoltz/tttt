package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestSeverity(t *testing.T) {
	cases := []struct {
		name, json string
		sev        string
		score      float64
		ok         bool
	}{
		{"publisher 3.1 beats 4.0", `{"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.1,"baseSeverity":"HIGH"}}],"cvssMetricV40":[{"cvssData":{"baseScore":9.2,"baseSeverity":"CRITICAL"}}]}}`, "HIGH", 8.1, true},
		{"highest 3.x source", `{"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":5.3,"baseSeverity":"MEDIUM"}},{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}`, "CRITICAL", 9.8, true},
		{"4.0 only", `{"metrics":{"cvssMetricV40":[{"cvssData":{"baseScore":8.7,"baseSeverity":"HIGH"}}]}}`, "HIGH", 8.7, true},
		{"unscored", `{"metrics":{}}`, "", 0, false},
	}
	for _, c := range cases {
		var v CVE
		if err := json.Unmarshal([]byte(c.json), &v); err != nil {
			t.Fatal(err)
		}
		if sev, score, ok := v.Severity(); sev != c.sev || score != c.score || ok != c.ok {
			t.Errorf("%s: got (%q, %v, %v)", c.name, sev, score, ok)
		}
	}
}

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := NewClient("", nil)
	c.NVDURL, c.CVEOrgURL, c.KEVURLs = srv.URL+"/nvd", srv.URL+"/cve", []string{srv.URL + "/down", srv.URL + "/kev"}
	c.NVDPageDelay = 0
	c.NVDRetry = Backoff{Budget: time.Second, First: time.Millisecond, Max: time.Millisecond}
	return c
}

func TestNVDPagesAndWindows(t *testing.T) {
	var windows []string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		index, _ := strconv.Atoi(q.Get("startIndex"))
		if index == 0 {
			windows = append(windows, q.Get("lastModStartDate"))
		}
		// Two pages of one CVE each per window.
		fmt.Fprintf(w, `{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-%s-%d"}}]}`, q.Get("lastModStartDate")[:10], index)
	})
	end := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	start := end.Add(-200 * 24 * time.Hour) // needs two windows
	cves, err := c.NVD(context.Background(), start, end)
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 2 || len(cves) != 4 {
		t.Errorf("windows %v, %d CVEs; want 2 windows, 4 CVEs", windows, len(cves))
	}
}

func TestNVDRetriesThenFails(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, `{"totalResults":0,"vulnerabilities":[]}`)
	})
	now := time.Now()
	if _, err := c.NVD(context.Background(), now.Add(-time.Hour), now); err != nil || calls != 3 {
		t.Errorf("transient outage: err %v, calls %d; want nil, 3", err, calls)
	}

	c = testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	c.NVDRetry.Budget = 20 * time.Millisecond
	_, err := c.NVD(context.Background(), now.Add(-time.Hour), now)
	if fe, ok := err.(*Error); !ok || fe.Feed != "NVD" {
		t.Errorf("persistent outage: got %v, want *Error for NVD", err)
	}
}

func TestKEVFallback(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, `{"vulnerabilities":[{"cveID":"CVE-1","vendorProject":"PHP","product":"PHP"}]}`)
	})
	kev, err := c.KEV(context.Background())
	if err != nil || len(kev) != 1 || kev[0].CveID != "CVE-1" {
		t.Errorf("got %v, %v", kev, err)
	}
}

func TestAffected(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cve/CVE-2026-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `{"containers":{"cna":{"affected":[{"vendor":"F5","product":"NGINX Open Source"}]}}}`)
	})
	got, err := c.Affected(context.Background(), "CVE-2026-1")
	if err != nil || len(got) != 1 || got[0] != "F5 NGINX Open Source" {
		t.Errorf("got %q, %v", got, err)
	}
}
