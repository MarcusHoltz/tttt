package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

// reportToGitHub puts the run on its Actions page: an annotation per message
// and a job summary with every message and a row per profile.
func reportToGitHub(now time.Time, res *Result, log *slog.Logger) {
	writeAnnotations(os.Stdout, res)
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Error("job summary", "err", err)
		return
	}
	defer f.Close()
	writeSummary(f, now, res)
}

// writeAnnotations emits one workflow command per message. Feed text is
// third-party, so it is escaped: a newline in it cannot start a forged
// workflow command.
func writeAnnotations(w io.Writer, res *Result) {
	data := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	prop := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	for _, d := range res.Deliveries {
		level := "notice"
		if d.Message.Urgent {
			level = "warning"
		}
		if !d.OK {
			level = "error"
		}
		fmt.Fprintf(w, "::%s title=%s::%s\n", level,
			prop.Replace(d.At.Format(time.RFC3339)+" "+d.Message.Title),
			data.Replace("Delivery: "+strings.Join(d.Results, "; ")+"\n\n"+d.Message.Body))
	}
}

func writeSummary(w io.Writer, now time.Time, res *Result) {
	cell := strings.NewReplacer("|", `\|`, "\r", " ", "\n", " ")
	nvd := "not due (polled under 2 h ago)"
	if res.NVDPolled {
		nvd = "polled"
	}
	status := "OK"
	if !res.OK() {
		status = "FAILING"
	}
	fmt.Fprintf(w, "### %s: %s\n\nNVD: %s\n\n", now.Format(time.RFC3339), status, nvd)
	fmt.Fprintln(w, "| Profile | Words | New | Sent |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, p := range res.Profiles {
		words := fmt.Sprint(p.Words)
		if p.ReadErr != nil {
			words = "unreadable: " + p.ReadErr.Error()
		}
		fmt.Fprintf(w, "| %s | %s | %d | %d |\n", cell.Replace(p.Name), cell.Replace(words), p.New, p.Sent)
	}
	for _, p := range res.Problems {
		fmt.Fprintf(w, "\n- **Problem:** %s", cell.Replace(p))
	}
	fmt.Fprintln(w)
	for _, d := range res.Deliveries {
		fmt.Fprintf(w, "\n#### %s %s\n\nDelivery: %s\n\n````\n%s\n````\n",
			d.At.Format(time.RFC3339), d.Message.Title, strings.Join(d.Results, "; "), d.Message.Body)
	}
}
