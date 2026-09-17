package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Report struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	Target     string    `json:"target"`
	StartedAt  time.Time `json:"started_at"`
	Duration   string    `json:"duration"`
	Stats      Stats     `json:"stats"`
	NoisyFiles []string  `json:"noisy_files,omitempty"`
	Findings   []Finding `json:"findings"`
}

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cCyan   = "\033[36m"
	cMag    = "\033[35m"
	cGreen  = "\033[32m"
)

type colorizer struct{ on bool }

func (c colorizer) wrap(code, s string) string {
	if !c.on {
		return s
	}
	return code + s + cReset
}

func sevColor(s Severity) string {
	switch s {
	case SevCritical:
		return cMag
	case SevHigh:
		return cRed
	case SevMedium:
		return cYellow
	case SevLow:
		return cBlue
	}
	return cDim
}

// WriteText renders a human-readable report.
func WriteText(w io.Writer, rep Report, color bool) {
	c := colorizer{on: color}

	fmt.Fprintf(w, "\n%s  %s\n", c.wrap(cBold+cCyan, "regbait"), c.wrap(cDim, "secret & entropy scan"))
	fmt.Fprintf(w, "  target   %s\n", rep.Target)
	fmt.Fprintf(w, "  scanned  %d files (%s) in %s\n",
		rep.Stats.FilesScanned, humanBytes(rep.Stats.BytesScanned), rep.Duration)
	fmt.Fprintf(w, "  skipped  %d   errors %d\n\n", rep.Stats.FilesSkipped, rep.Stats.Errors)

	if len(rep.Findings) == 0 {
		fmt.Fprintf(w, "  %s\n\n", c.wrap(cGreen, "No findings above the configured threshold."))
		return
	}

	var lastSev Severity = -1
	for _, f := range rep.Findings {
		if f.severity != lastSev {
			lastSev = f.severity
			bar := strings.Repeat("─", 68)
			fmt.Fprintf(w, "%s\n", c.wrap(cDim, bar))
			fmt.Fprintf(w, "%s\n", c.wrap(cBold+sevColor(f.severity), " "+f.Severity))
			fmt.Fprintf(w, "%s\n", c.wrap(cDim, bar))
		}
		fmt.Fprintf(w, "\n  %s  %s\n", c.wrap(cBold, f.RuleID), c.wrap(cDim, "["+f.FileKind+"]"))
		fmt.Fprintf(w, "  %s\n", f.Description)
		fmt.Fprintf(w, "  %s %s:%d:%d\n", c.wrap(cDim, "loc "), f.File, f.Line, f.Column)
		fmt.Fprintf(w, "  %s %s\n", c.wrap(cDim, "val "), c.wrap(sevColor(f.severity), f.Secret))
		fmt.Fprintf(w, "  %s entropy %.2f  charset %s  id %s",
			c.wrap(cDim, "meta"), f.Entropy, f.Charset, f.Fingerprint)
		if f.Origin != "" {
			fmt.Fprintf(w, "  via %s", f.Origin)
		}
		fmt.Fprintln(w)
		if f.Context != "" {
			fmt.Fprintf(w, "  %s %s\n", c.wrap(cDim, "ctx "), c.wrap(cDim, f.Context))
		}
	}

	// Summary tables.
	bySev := map[string]int{}
	byRule := map[string]int{}
	for _, f := range rep.Findings {
		bySev[f.Severity]++
		byRule[f.RuleID]++
	}
	fmt.Fprintf(w, "\n%s\n", c.wrap(cDim, strings.Repeat("═", 68)))
	fmt.Fprintf(w, "%s  ", c.wrap(cBold, "summary"))
	for _, s := range []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo} {
		if n := bySev[s.String()]; n > 0 {
			fmt.Fprintf(w, "%s ", c.wrap(sevColor(s), fmt.Sprintf("%s:%d", s.String(), n)))
		}
	}
	fmt.Fprintf(w, " total:%d\n", len(rep.Findings))

	type kv struct {
		k string
		v int
	}
	var rules []kv
	for k, v := range byRule {
		rules = append(rules, kv{k, v})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].v != rules[j].v {
			return rules[i].v > rules[j].v
		}
		return rules[i].k < rules[j].k
	})
	fmt.Fprintf(w, "%s\n", c.wrap(cBold, "top rules"))
	for i, r := range rules {
		if i >= 10 {
			break
		}
		fmt.Fprintf(w, "  %-34s %d\n", r.k, r.v)
	}
	if rep.Stats.NoiseSuppressed > 0 {
		fmt.Fprintf(w, "%s\n", c.wrap(cDim, fmt.Sprintf(
			"  (%d generic finding(s) suppressed as noise across %d high-noise file(s); "+
				"raise --max-generic-per-file or use --no-context-gate to see them)",
			rep.Stats.NoiseSuppressed, rep.Stats.NoisyFiles)))
		for i, f := range rep.NoisyFiles {
			if i >= 5 {
				fmt.Fprintf(w, "%s\n", c.wrap(cDim, fmt.Sprintf("    … and %d more", len(rep.NoisyFiles)-5)))
				break
			}
			fmt.Fprintf(w, "%s\n", c.wrap(cDim, "    high-noise: "+f))
		}
	}
	if rep.Stats.BaselineHidden > 0 {
		fmt.Fprintf(w, "%s\n", c.wrap(cDim,
			fmt.Sprintf("  (%d finding(s) suppressed by baseline)", rep.Stats.BaselineHidden)))
	}
	fmt.Fprintln(w)
}

func WriteJSON(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

func WriteCSV(w io.Writer, rep Report) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{
		"severity", "rule_id", "description", "file", "file_kind",
		"line", "column", "secret", "entropy", "charset", "origin", "fingerprint",
	}); err != nil {
		return err
	}
	for _, f := range rep.Findings {
		if err := cw.Write([]string{
			f.Severity, f.RuleID, f.Description, f.File, f.FileKind,
			strconv.Itoa(f.Line), strconv.Itoa(f.Column), f.Secret,
			strconv.FormatFloat(f.Entropy, 'f', 3, 64), f.Charset, f.Origin, f.Fingerprint,
		}); err != nil {
			return err
		}
	}
	return nil
}

// WriteSARIF emits SARIF 2.1.0 so findings drop into GitHub code scanning,
// DefectDojo, or any SARIF-aware triage UI.
func WriteSARIF(w io.Writer, rep Report) error {
	type sarifRule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription map[string]string `json:"shortDescription"`
		Properties       map[string]any    `json:"properties"`
	}
	ruleSet := map[string]sarifRule{}
	var results []map[string]any

	for _, f := range rep.Findings {
		if _, ok := ruleSet[f.RuleID]; !ok {
			ruleSet[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				Name:             f.RuleID,
				ShortDescription: map[string]string{"text": f.Description},
				Properties:       map[string]any{"tags": f.Tags, "security-severity": sarifScore(f.severity)},
			}
		}
		level := "warning"
		switch f.severity {
		case SevCritical, SevHigh:
			level = "error"
		case SevLow, SevInfo:
			level = "note"
		}
		results = append(results, map[string]any{
			"ruleId":              f.RuleID,
			"level":               level,
			"message":             map[string]string{"text": f.Description + " — " + f.Secret},
			"partialFingerprints": map[string]string{"regbait/v1": f.Fingerprint},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": f.File},
					"region": map[string]int{
						"startLine":   max(f.Line, 1),
						"startColumn": max(f.Column, 1),
					},
				},
			}},
		})
	}

	var rules []sarifRule
	for _, r := range ruleSet {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           rep.Tool,
					"version":        rep.Version,
					"informationUri": "https://example.invalid/regbait",
					"rules":          rules,
				},
			},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifScore(s Severity) string {
	switch s {
	case SevCritical:
		return "9.0"
	case SevHigh:
		return "7.5"
	case SevMedium:
		return "5.0"
	case SevLow:
		return "3.0"
	}
	return "1.0"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// LoadBaseline reads a previous JSON report and returns its fingerprints.
func LoadBaseline(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rep Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("%s: not a valid regbait JSON report: %w", path, err)
	}
	out := map[string]bool{}
	for _, f := range rep.Findings {
		out[f.Fingerprint] = true
	}
	return out, nil
}
