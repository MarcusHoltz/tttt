package match

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/MarcusHoltz/message-me-cve/internal/feed"
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
		{"nginxplus nginx", "nginx", true}, // later whole-word hit
	}
	for _, c := range cases {
		if got := ContainsWord(c.hay, c.w); got != c.want {
			t.Errorf("ContainsWord(%q, %q) = %v, want %v", c.hay, c.w, got, c.want)
		}
	}
}

func TestLoadWords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.txt")
	os.WriteFile(path, []byte("# comment\nPHP\n  apache   http server # inline\nphp\n\n"), 0o644)
	got, err := LoadWords(path)
	if err != nil || !slices.Equal(got, []string{"php", "apache http server"}) {
		t.Errorf("got %q, %v", got, err)
	}
	os.WriteFile(path, []byte("# only comments\n"), 0o644)
	if _, err := LoadWords(path); err == nil {
		t.Error("empty list accepted")
	}
}

func cve(id, desc string, criteria ...string) feed.CVE {
	c := feed.CVE{ID: id, Descriptions: []feed.LangString{{Lang: "en", Value: desc}}}
	if len(criteria) > 0 {
		var conf feed.Configuration
		conf.Nodes = make([]struct {
			CPEMatch []feed.CPEMatch `json:"cpeMatch"`
		}, 1)
		for _, cr := range criteria {
			conf.Nodes[0].CPEMatch = append(conf.Nodes[0].CPEMatch, feed.CPEMatch{Vulnerable: true, Criteria: cr})
		}
		c.Configurations = []feed.Configuration{conf}
	}
	return c
}

func TestNVD(t *testing.T) {
	words := []string{"php", "apache http server"}
	records := map[string][]string{"CVE-PHP": {"PHP Group PHP"}, "CVE-CRAFT": {"craftcms cms"}}
	lookups := 0
	affected := func(_ context.Context, id string) ([]string, error) {
		lookups++
		if id == "CVE-DOWN" {
			return nil, errors.New("down")
		}
		return records[id], nil
	}
	cases := []struct {
		name      string
		c         feed.CVE
		word      string
		confirmed bool
		err       bool
	}{
		{"cpe product", cve("A", "x", "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"), "php", true, false},
		{"analyzed, other product", cve("B", "SQLi in login.php", "cpe:2.3:a:acme:shop:*:*:*:*:*:*:*:*"), "", false, false},
		{"underscore product", cve("C", "x", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"), "apache http server", true, false},
		{"unanalyzed, CVE.org confirms", cve("CVE-PHP", "PHP bug"), "php", false, false},
		{"unanalyzed, CVE.org other product", cve("CVE-CRAFT", "Craft uses PHP"), "", false, false},
		{"unanalyzed, not mentioned", cve("CVE-X", "unrelated"), "", false, false},
		{"unanalyzed, CVE.org down", cve("CVE-DOWN", "php thing"), "", false, true},
	}
	for _, c := range cases {
		w, confirmed, err := NVD(context.Background(), c.c, words, affected)
		if w != c.word || confirmed != c.confirmed || (err != nil) != c.err {
			t.Errorf("%s: got (%q, %v, %v), want (%q, %v, err=%v)", c.name, w, confirmed, err, c.word, c.confirmed, c.err)
		}
	}
	if lookups != 3 {
		t.Errorf("CVE.org lookups = %d, want 3 (only unanalyzed CVEs that mention a word)", lookups)
	}
}
