package feed

import (
	"cmp"
	"slices"
	"strings"
	"time"
)

// KEVEntry is one entry of the CISA KEV catalog.
type KEVEntry struct {
	CveID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

// CVE is the part of an NVD CVE record this program uses.
type CVE struct {
	ID             string          `json:"id"`
	Published      string          `json:"published"`
	Descriptions   []LangString    `json:"descriptions"`
	Metrics        Metrics         `json:"metrics"`
	Configurations []Configuration `json:"configurations"`
}

type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Metrics struct {
	V40 []CVSSMetric `json:"cvssMetricV40"`
	V31 []CVSSMetric `json:"cvssMetricV31"`
	V30 []CVSSMetric `json:"cvssMetricV30"`
}

type CVSSMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type Configuration struct {
	Nodes []struct {
		CPEMatch []CPEMatch `json:"cpeMatch"`
	} `json:"nodes"`
}

type CPEMatch struct {
	Vulnerable          bool   `json:"vulnerable"`
	Criteria            string `json:"criteria"` // cpe:2.3:part:vendor:product:...
	VersionEndExcluding string `json:"versionEndExcluding"`
}

// Description returns the English description.
func (c CVE) Description() string {
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

// CPEMatches returns every CPE match in every configuration.
func (c CVE) CPEMatches() []CPEMatch {
	var out []CPEMatch
	for _, conf := range c.Configurations {
		for _, n := range conf.Nodes {
			out = append(out, n.CPEMatch...)
		}
	}
	return out
}

// PublishedAt parses Published. NVD omits the zone; it is UTC.
func (c CVE) PublishedAt() (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05", c.Published)
}

// Severity returns the highest CVSS 3.x severity and score from any source
// NVD carries (NVD itself, the CVE's publisher, CISA): NVD often scores a new
// CVE weeks late. Without any 3.x score, the highest 4.0 score is used.
// ok is false when the CVE has no score at all.
func (c CVE) Severity() (severity string, score float64, ok bool) {
	for _, list := range [][]CVSSMetric{slices.Concat(c.Metrics.V31, c.Metrics.V30), c.Metrics.V40} {
		if len(list) == 0 {
			continue
		}
		best := slices.MaxFunc(list, func(a, b CVSSMetric) int {
			return cmp.Compare(a.CVSSData.BaseScore, b.CVSSData.BaseScore)
		})
		return strings.ToUpper(best.CVSSData.BaseSeverity), best.CVSSData.BaseScore, true
	}
	return "", 0, false
}
