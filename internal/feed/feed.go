// Package feed reads the public vulnerability feeds: CISA KEV, NVD and the
// CVE.org record API.
package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	nvdTimeFormat = "2006-01-02T15:04:05.000Z"
	// NVD rejects lastMod ranges over 120 days.
	nvdMaxWindow = 119 * 24 * time.Hour
	nvdPageSize  = 2000
)

// Error is a feed that could not be read.
type Error struct {
	Feed string
	Err  error
}

func (e *Error) Error() string { return e.Feed + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// HTTPError is a response other than 200 OK.
type HTTPError struct {
	URL    string // without the query
	Status int
}

func (e *HTTPError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.URL, e.Status) }

// transient reports whether a request may succeed if repeated: network
// errors, rate limiting and server errors. A 4xx means the request is wrong.
func transient(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status == http.StatusTooManyRequests || he.Status >= 500
	}
	return true
}

// Backoff bounds the retries of a failing NVD request.
type Backoff struct {
	Budget time.Duration // give up once the next wait would pass this
	First  time.Duration
	Max    time.Duration
}

// Client fetches the feeds. The zero value is not usable; use NewClient.
type Client struct {
	HTTP      *http.Client
	UserAgent string
	NVDKey    string
	// NVDPageDelay is the pause between NVD requests. NVD allows 5
	// requests per 30 s without an API key, 50 with one.
	NVDPageDelay time.Duration
	NVDRetry     Backoff
	Log          *slog.Logger

	KEVURLs   []string // tried in order
	NVDURL    string
	CVEOrgURL string // record URL is CVEOrgURL + "/" + id
}

// NewClient returns a Client for the public endpoints.
func NewClient(nvdKey string, log *slog.Logger) *Client {
	delay := 7 * time.Second
	if nvdKey != "" {
		delay = 700 * time.Millisecond
	}
	return &Client{
		HTTP:         &http.Client{Timeout: 60 * time.Second},
		UserAgent:    "message-me-cve (+https://github.com/MarcusHoltz/message-me-cve)",
		NVDKey:       nvdKey,
		NVDPageDelay: delay,
		// NVD outages are usually short; retry before reporting one.
		NVDRetry: Backoff{Budget: 60 * time.Minute, First: 30 * time.Second, Max: 5 * time.Minute},
		Log:      log,
		KEVURLs: []string{
			"https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
			"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		},
		NVDURL:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
		CVEOrgURL: "https://cveawg.mitre.org/api/cve",
	}
}

// KEV returns the CISA Known Exploited Vulnerabilities catalog, from the
// first URL that serves a non-empty one.
func (c *Client) KEV(ctx context.Context) ([]KEVEntry, error) {
	var errs []error
	for _, u := range c.KEVURLs {
		var catalog struct {
			Vulnerabilities []KEVEntry `json:"vulnerabilities"`
		}
		if err := c.getJSON(ctx, u, nil, &catalog); err != nil {
			errs = append(errs, err)
			continue
		}
		if len(catalog.Vulnerabilities) == 0 {
			errs = append(errs, fmt.Errorf("%s: empty catalog", u))
			continue
		}
		return catalog.Vulnerabilities, nil
	}
	return nil, &Error{"CISA KEV", errors.Join(errs...)}
}

// NVD returns every CVE NVD modified in [start, end], fetched in windows of
// at most 119 days so a long gap leaves no hole. Severity is not filtered
// here: NVD's cvssV3Severity filter only sees NVD's own score and would drop
// CVEs that only their publisher has scored.
func (c *Client) NVD(ctx context.Context, start, end time.Time) ([]CVE, error) {
	var out []CVE
	first := true
	for from := start; from.Before(end); from = from.Add(nvdMaxWindow) {
		to := from.Add(nvdMaxWindow)
		if to.After(end) {
			to = end
		}
		for index := 0; ; {
			if !first {
				if err := sleep(ctx, c.NVDPageDelay); err != nil {
					return nil, &Error{"NVD", err}
				}
			}
			first = false
			page, err := c.nvdPage(ctx, from, to, index)
			if err != nil {
				return nil, &Error{"NVD", fmt.Errorf("startIndex=%d: %w", index, err)}
			}
			for _, v := range page.Vulnerabilities {
				out = append(out, v.CVE)
			}
			index += len(page.Vulnerabilities)
			if len(page.Vulnerabilities) == 0 || index >= page.TotalResults {
				break
			}
		}
	}
	return out, nil
}

type nvdPage struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE CVE `json:"cve"`
	} `json:"vulnerabilities"`
}

func (c *Client) nvdPage(ctx context.Context, from, to time.Time, index int) (*nvdPage, error) {
	q := url.Values{
		"lastModStartDate": {from.UTC().Format(nvdTimeFormat)},
		"lastModEndDate":   {to.UTC().Format(nvdTimeFormat)},
		"resultsPerPage":   {strconv.Itoa(nvdPageSize)},
		"startIndex":       {strconv.Itoa(index)},
	}
	var headers map[string]string
	if c.NVDKey != "" {
		headers = map[string]string{"apiKey": c.NVDKey}
	}
	var page nvdPage
	err := c.retry(ctx, func() error {
		page = nvdPage{}
		return c.getJSON(ctx, c.NVDURL+"?"+q.Encode(), headers, &page)
	})
	return &page, err
}

// retry runs fn with exponential backoff until it succeeds, fails for good,
// the budget is spent or ctx is done.
func (c *Client) retry(ctx context.Context, fn func() error) error {
	deadline := time.Now().Add(c.NVDRetry.Budget)
	wait := c.NVDRetry.First
	for {
		err := fn()
		if err == nil || !transient(err) || time.Now().Add(wait).After(deadline) {
			return err
		}
		if c.Log != nil {
			c.Log.Warn("NVD request failed, retrying", "wait", wait, "err", err)
		}
		if err := sleep(ctx, wait); err != nil {
			return err
		}
		wait = min(wait*2, c.NVDRetry.Max)
	}
}

// Affected returns "vendor product" for each product listed in the CVE.org
// record. The CVE's publisher writes this list at release, often days before
// NVD analyzes the CVE.
func (c *Client) Affected(ctx context.Context, id string) ([]string, error) {
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
	if err := c.getJSON(ctx, c.CVEOrgURL+"/"+url.PathEscape(id), nil, &rec); err != nil {
		return nil, &Error{"CVE.org", err}
	}
	out := make([]string, 0, len(rec.Containers.CNA.Affected))
	for _, a := range rec.Containers.CNA.Affected {
		out = append(out, a.Vendor+" "+a.Product)
	}
	return out, nil
}

func (c *Client) getJSON(ctx context.Context, u string, headers map[string]string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &HTTPError{URL: strings.SplitN(u, "?", 2)[0], Status: resp.StatusCode}
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
