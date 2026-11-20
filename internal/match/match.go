// Package match decides whether a feed entry concerns a watch list.
//
// Matching is on vendor and product names only, as whole words, never on
// descriptions: "php" must not match every web app whose description
// mentions a .php file.
package match

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/MarcusHoltz/message-me-cve/internal/feed"
)

// LoadWords reads a watch list: one word or phrase per line, "#" starts a
// comment, case and repeated spaces do not matter.
func LoadWords(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var words []string
	seen := map[string]bool{}
	for line := range strings.Lines(string(data)) {
		w, _, _ := strings.Cut(line, "#")
		w = strings.ToLower(strings.Join(strings.Fields(w), " "))
		if w != "" && !seen[w] {
			seen[w] = true
			words = append(words, w)
		}
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("%s has no words", path)
	}
	return words, nil
}

func isWordChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b >= 0x80
}

// ContainsWord reports whether the lower-case word w occurs in hay as a
// whole word, case-insensitively.
func ContainsWord(hay, w string) bool {
	hay = strings.ToLower(hay)
	for i := 0; i < len(hay); {
		j := strings.Index(hay[i:], w)
		if j < 0 {
			return false
		}
		s, e := i+j, i+j+len(w)
		if (s == 0 || !isWordChar(hay[s-1])) && (e == len(hay) || !isWordChar(hay[e])) {
			return true
		}
		i = s + 1
	}
	return false
}

func firstIn(hay string, words []string) string {
	for _, w := range words {
		if ContainsWord(hay, w) {
			return w
		}
	}
	return ""
}

// KEV returns the watch word naming the entry's vendor or product, or "".
func KEV(e feed.KEVEntry, words []string) string {
	return firstIn(e.VendorProject+" "+e.Product, words)
}

// AffectedFunc returns the "vendor product" list of a CVE's CVE.org record.
type AffectedFunc func(ctx context.Context, id string) ([]string, error)

// NVD returns the watch word naming a vulnerable product of c, and whether
// the match comes from NVD's own analysis (confirmed). CVEs NVD has not
// analyzed yet have no CPE list; for those whose description mentions a
// watch word, the product list in the CVE.org record is checked instead.
func NVD(ctx context.Context, c feed.CVE, words []string, affected AffectedFunc) (word string, confirmed bool, err error) {
	analyzed := false
	for _, m := range c.CPEMatches() {
		if !m.Vulnerable {
			continue
		}
		analyzed = true
		p := strings.Split(m.Criteria, ":")
		if len(p) < 5 {
			continue
		}
		if w := firstIn(strings.ReplaceAll(p[3]+" "+p[4], "_", " "), words); w != "" {
			return w, true, nil
		}
	}
	if analyzed || firstIn(c.Description(), words) == "" {
		return "", false, nil
	}
	products, err := affected(ctx, c.ID)
	if err != nil {
		return "", false, err
	}
	for _, p := range products {
		if w := firstIn(p, words); w != "" {
			return w, false, nil
		}
	}
	return "", false, nil
}
