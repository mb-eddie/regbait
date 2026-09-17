package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const version = "1.0.0"

type stringSet []string

func (s *stringSet) String() string { return strings.Join(*s, ",") }
func (s *stringSet) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

func toSet(list []string, lower bool) map[string]bool {
	m := map[string]bool{}
	for _, v := range list {
		if lower {
			v = strings.ToLower(v)
		}
		m[v] = true
	}
	return m
}

func normExts(list []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range list {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if !strings.HasPrefix(v, ".") {
			v = "." + v
		}
		m[v] = true
	}
	return m
}

func usage() {
	fmt.Fprintf(os.Stderr, `regbait %s — secret hunting for decompiled APK trees

USAGE
  regbait [flags] <path>

  <path> is a directory (jadx/apktool output) or a single file.

COMMON
  regbait ./out
  regbait --redact --format json --out findings.json ./out
  regbait --min-severity high --binaries ./out
  regbait --no-entropy --only google-api-key,aws-access-key-id ./out
  regbait --baseline known.json ./out         # only show new findings

FLAGS
`, version)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
EXIT CODES
  0  no findings at or above --fail-on
  1  findings at or above --fail-on
  2  usage or runtime error

CUSTOM RULES (JSON)
  {"extend": true, "rules": [
    {"id":"acme-key","description":"ACME internal key",
     "regex":"\\bACME-[A-Z0-9]{24}\\b","severity":"critical",
     "keywords":["acme-"],"min_entropy":3.0}
  ]}
  Set "extend": false to replace the built-in ruleset entirely.
`)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "regbait: %v\n", err)
		os.Exit(2)
	}
}

func run() error {
	flag.Usage = usage

	var (
		format      = flag.String("format", "text", "output format: text, json, csv, sarif")
		outPath     = flag.String("out", "", "write output to this file instead of stdout")
		workers     = flag.Int("jobs", runtime.NumCPU()*2, "concurrent file workers")
		maxSize     = flag.Int64("max-size", 20<<20, "skip files larger than this many bytes (0 = no limit)")
		maxLine     = flag.Int("max-line", 64*1024, "window size for very long lines")
		minSevStr   = flag.String("min-severity", "low", "report findings at or above: info|low|medium|high|critical")
		failOnStr   = flag.String("fail-on", "high", "exit 1 if a finding at or above this severity exists; 'never' disables")
		redact      = flag.Bool("redact", false, "mask secret values in output (safe for sharing reports)")
		noEntropy   = flag.Bool("no-entropy", false, "disable the generic high-entropy detector")
		entB64      = flag.Float64("entropy-b64", 4.3, "min Shannon bits/char for base64/alnum strings")
		entHex      = flag.Float64("entropy-hex", 3.3, "min Shannon bits/char for hex strings")
		entLen      = flag.Int("entropy-min-len", 20, "min length for entropy candidates")
		decodeB64   = flag.Bool("decode-base64", false, "base64-decode long blobs and rescan the plaintext")
		binaries    = flag.Bool("binaries", false, "extract printable strings from .so/.dex/.bin and scan them")
		minStrLen   = flag.Int("min-string-len", 8, "min run length when extracting strings from binaries")
		rulesFile   = flag.String("rules", "", "path to a JSON rule pack")
		listRules   = flag.Bool("list-rules", false, "print the active ruleset and exit")
		baselineFn  = flag.String("baseline", "", "previous JSON report; suppress fingerprints it contains")
		noColor     = flag.Bool("no-color", false, "disable ANSI colour")
		contextLen  = flag.Int("context", 120, "characters of surrounding context to show")
		noCollapse  = flag.Bool("no-collapse", false, "keep generic findings even when a precise rule matched the same value")
		noContext   = flag.Bool("no-context-gate", false, "let generic detectors fire without a nearby credential keyword (very noisy on obfuscated code)")
		ctxWindow   = flag.Int("context-window", 3, "lines either side searched for a credential keyword")
		maxGenFile  = flag.Int("max-generic-per-file", 10, "drop all generic findings from a file exceeding this count (0 = no cap)")
		maxGenTotal = flag.Int("max-generic-total", 200, "global cap on generic findings, highest entropy kept (0 = no cap)")
		maxMem      = flag.Int64("max-in-memory", 16<<20, "files above this size stream without proximity context")
		verbose     = flag.Bool("verbose", false, "log scanned paths to stderr")
	)
	var onlyRules, skipRules, incExts, excExts, excDirs stringSet
	flag.Var(&onlyRules, "only", "comma-separated rule IDs to run exclusively")
	flag.Var(&skipRules, "skip", "comma-separated rule IDs to disable")
	flag.Var(&incExts, "ext", "only scan these extensions (e.g. xml,json,smali)")
	flag.Var(&excExts, "exclude-ext", "additional extensions to skip")
	flag.Var(&excDirs, "exclude-dir", "additional directory names to skip")
	excPathRe := flag.String("exclude-path", "", "regex; skip paths that match")
	incPathRe := flag.String("include-path", "", "regex; scan only paths that match")

	flag.Parse()

	// --- assemble ruleset ---
	specs := DefaultRules
	if *rulesFile != "" {
		custom, extend, err := LoadRuleFile(*rulesFile)
		if err != nil {
			return err
		}
		if extend {
			specs = append(append([]RuleSpec{}, DefaultRules...), custom...)
		} else {
			specs = custom
		}
	}
	rules, err := CompileRules(specs)
	if err != nil {
		return err
	}

	if *listRules {
		return printRules(rules, *format)
	}

	if flag.NArg() != 1 {
		usage()
		return fmt.Errorf("expected exactly one target path")
	}
	target := flag.Arg(0)
	abs, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return err
	}

	minSev, err := ParseSeverity(*minSevStr)
	if err != nil {
		return err
	}
	failOn := SevCritical + 1 // effectively "never"
	if !strings.EqualFold(*failOnStr, "never") {
		if failOn, err = ParseSeverity(*failOnStr); err != nil {
			return err
		}
	}

	var baseline map[string]bool
	if *baselineFn != "" {
		if baseline, err = LoadBaseline(*baselineFn); err != nil {
			return err
		}
	}

	excludeDirs := map[string]bool{}
	for k := range DefaultExcludeDirs {
		excludeDirs[k] = true
	}
	for k := range toSet(excDirs, false) {
		excludeDirs[k] = true
	}
	excludeExts := map[string]bool{}
	for k := range DefaultExcludeExts {
		excludeExts[k] = true
	}
	for k := range normExts(excExts) {
		excludeExts[k] = true
	}

	cfg := Config{
		Root:              abs,
		Rules:             rules,
		Workers:           *workers,
		MaxFileSize:       *maxSize,
		MaxLineLen:        *maxLine,
		MinSeverity:       minSev,
		Redact:            *redact,
		EntropyScan:       !*noEntropy,
		EntropyMinB64:     *entB64,
		EntropyMinHex:     *entHex,
		EntropyMinLen:     *entLen,
		RequireContext:    !*noContext,
		ContextWindow:     *ctxWindow,
		MaxGenericPerFile: *maxGenFile,
		MaxGenericTotal:   *maxGenTotal,
		MaxInMemory:       *maxMem,
		DecodeBase64:      *decodeB64,
		ScanBinaries:      *binaries,
		MinStringLen:      *minStrLen,
		IncludeExts:       normExts(incExts),
		ExcludeExts:       excludeExts,
		ExcludeDirs:       excludeDirs,
		OnlyRules:         toSet(onlyRules, false),
		SkipRules:         toSet(skipRules, false),
		Baseline:          baseline,
		ContextChars:      *contextLen,
		CollapseGeneric:   !*noCollapse,
		Verbose:           *verbose,
	}
	if *excPathRe != "" {
		if cfg.ExcludePathRe, err = regexp.Compile(*excPathRe); err != nil {
			return fmt.Errorf("--exclude-path: %w", err)
		}
	}
	if *incPathRe != "" {
		if cfg.IncludePathRe, err = regexp.Compile(*incPathRe); err != nil {
			return fmt.Errorf("--include-path: %w", err)
		}
	}
	if *verbose {
		cfg.Progress = func(p string) { fmt.Fprintln(os.Stderr, "scan:", p) }
	}
	// A single-file target still works: scan its parent but restrict to it.
	if !fi.IsDir() {
		cfg.Root = filepath.Dir(abs)
		base := regexp.QuoteMeta(filepath.Base(abs))
		cfg.IncludePathRe = regexp.MustCompile(base + `$`)
		cfg.IncludeExts = nil
	}

	for _, id := range onlyRules {
		if !hasRule(rules, id) {
			return fmt.Errorf("--only: unknown rule %q (see --list-rules)", id)
		}
	}
	for _, id := range skipRules {
		if !hasRule(rules, id) {
			return fmt.Errorf("--skip: unknown rule %q (see --list-rules)", id)
		}
	}

	start := time.Now()
	sc := NewScanner(cfg)
	findings, stats, errs := sc.Run()
	elapsed := time.Since(start)

	rep := Report{
		Tool: "regbait", Version: version, Target: abs,
		StartedAt: start, Duration: elapsed.Round(time.Millisecond).String(),
		Stats: stats, Findings: findings, NoisyFiles: sc.NoisyFiles(),
	}
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}

	out := os.Stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	bw := bufio.NewWriter(out)
	defer bw.Flush()

	color := !*noColor && *outPath == "" && isTTY(os.Stdout)
	switch strings.ToLower(*format) {
	case "text":
		WriteText(bw, rep, color)
	case "json":
		if err := WriteJSON(bw, rep); err != nil {
			return err
		}
	case "csv":
		if err := WriteCSV(bw, rep); err != nil {
			return err
		}
	case "sarif":
		if err := WriteSARIF(bw, rep); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown --format %q", *format)
	}
	bw.Flush()

	if *verbose {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "warn:", e)
		}
	}

	for _, f := range findings {
		if f.severity >= failOn {
			os.Exit(1)
		}
	}
	return nil
}

func hasRule(rules []*Rule, id string) bool {
	for _, r := range rules {
		if r.Spec.ID == id {
			return true
		}
	}
	return false
}

func printRules(rules []*Rule, format string) error {
	if strings.EqualFold(format, "json") {
		specs := make([]RuleSpec, 0, len(rules))
		for _, r := range rules {
			specs = append(specs, r.Spec)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(specs)
	}
	fmt.Printf("%d active rules\n\n", len(rules))
	fmt.Printf("%-9s %-32s %s\n", "SEVERITY", "ID", "DESCRIPTION")
	for _, r := range rules {
		fmt.Printf("%-9s %-32s %s\n", r.severity, r.Spec.ID, r.Spec.Description)
	}
	fmt.Printf("%-9s %-32s %s\n", "LOW/MED", "high-entropy-string", "Generic entropy detector (--no-entropy to disable)")
	return nil
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
