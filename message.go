package main

import (
	"fmt"
	"slices"
	"strings"
)

// prefix names the profiles and watch words an alert is for:
// "[shop, blog] ACT NOW [php]: ...".
func (a *alert) prefix() string   { return "[" + strings.Join(a.profiles, ", ") + "] " }
func (a *alert) wordList() string { return strings.Join(a.words, ", ") }

func (a *alert) message() Message {
	if a.kev != nil {
		v := a.kev
		return Message{
			Title: fmt.Sprintf("%sACT NOW [%s]: exploited %s %s", a.prefix(), a.wordList(), v.Product, v.CveID),
			Body: fmt.Sprintf("%s - %s %s\n%s\nActively exploited (on CISA KEV since %s). Ransomware use: %s\nAction: %s\n%s\n%s",
				v.CveID, v.VendorProject, v.Product, v.VulnerabilityName, v.DateAdded,
				v.KnownRansomwareCampaignUse, cut(v.RequiredAction, 300), cut(v.ShortDescription, 400), nvdLink(v.CveID)),
			Urgent: true,
		}
	}
	c := a.cve
	sev, score, _ := c.Severity()
	note := ""
	if a.cveOrg {
		note = " (NVD analysis pending; product match from the CVE.org record)"
	}
	fix := ""
	if f := a.fixedIn(); f != "" {
		fix = "Fixed in: " + cut(f, 400) + "\n"
	}
	return Message{
		Title: fmt.Sprintf("%s%s %.1f [%s]: %s", a.prefix(), sev, score, a.wordList(), c.ID),
		Body: fmt.Sprintf("%s - %s %.1f%s\n%s%s\n%s",
			c.ID, sev, score, note, fix, cut(c.Description(), 500), nvdLink(c.ID)),
	}
}

// short is the alert's line in a combined list.
func (a *alert) short() string {
	if a.kev != nil {
		v := a.kev
		return fmt.Sprintf("%s%s [%s] %s %s, KEV since %s", a.prefix(), v.CveID, a.wordList(), v.VendorProject, v.Product, v.DateAdded)
	}
	sev, score, _ := a.cve.Severity()
	return fmt.Sprintf("%s%s [%s] %s %.1f: %s", a.prefix(), a.cve.ID, a.wordList(), sev, score, cut(a.cve.Description(), 120))
}

// fixedIn lists "product >= version" for every vulnerable range NVD gives
// an upper bound for.
func (a *alert) fixedIn() string {
	var fixes []string
	for _, m := range a.cve.CPEMatches() {
		p := strings.Split(m.Criteria, ":")
		if m.Vulnerable && m.VersionEndExcluding != "" && len(p) > 4 {
			fixes = append(fixes, p[4]+" >= "+m.VersionEndExcluding)
		}
	}
	slices.Sort(fixes)
	return strings.Join(slices.Compact(fixes), ", ")
}

func nvdLink(id string) string { return "https://nvd.nist.gov/vuln/detail/" + id }

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}
