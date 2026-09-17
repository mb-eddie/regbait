package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
)

// Finding is one reported secret candidate.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	severity    Severity `json:"-"`
	File        string   `json:"file"`
	FileKind    string   `json:"file_kind"`
	Line        int      `json:"line"`
	Column      int      `json:"column"`
	Secret      string   `json:"secret"`
	Entropy     float64  `json:"entropy"`
	Charset     string   `json:"charset"`
	Context     string   `json:"context"`
	Tags        []string `json:"tags,omitempty"`
	Origin      string   `json:"origin,omitempty"` // "base64-decoded", "binary-strings"
	Fingerprint string   `json:"fingerprint"`
}

// Config holds every knob the scanner exposes.
type Config struct {
	Root        string
	Rules       []*Rule
	Workers     int
	MaxFileSize int64
	MaxInMemory int64 // above this, stream without proximity context
	MaxLineLen  int
	MinSeverity Severity
	Redact      bool

	// Generic high-entropy detector.
	EntropyScan    bool
	EntropyMinB64  float64
	EntropyMinHex  float64
	EntropyMinLen  int
	RequireContext bool // generic detectors need a credential keyword nearby
	ContextWindow  int  // how many lines either side count as "nearby"

	// Noise control. Obfuscated code produces thousands of genuinely
	// high-entropy strings; these caps stop a report from being unreadable.
	MaxGenericPerFile int
	MaxGenericTotal   int
	CollapseGeneric   bool

	DecodeBase64 bool
	ScanBinaries bool
	MinStringLen int

	IncludeExts   map[string]bool
	ExcludeExts   map[string]bool
	ExcludeDirs   map[string]bool
	ExcludePathRe *regexp.Regexp
	IncludePathRe *regexp.Regexp
	OnlyRules     map[string]bool
	SkipRules     map[string]bool
	Baseline      map[string]bool

	ContextChars int
	Verbose      bool
	Progress     func(path string)
}

type Stats struct {
	FilesSeen       int64 `json:"files_seen"`
	FilesScanned    int64 `json:"files_scanned"`
	FilesSkipped    int64 `json:"files_skipped"`
	BytesScanned    int64 `json:"bytes_scanned"`
	Errors          int64 `json:"errors"`
	Findings        int64 `json:"findings"`
	Deduped         int64 `json:"deduped"`
	BaselineHidden  int64 `json:"baseline_hidden"`
	NoiseSuppressed int64 `json:"noise_suppressed"`
	NoisyFiles      int64 `json:"noisy_files"`
}

type Scanner struct {
	cfg   Config
	stats Stats

	mu         sync.Mutex
	findings   []Finding
	seen       map[string]bool
	errs       []error
	noisyFiles []string
}

func NewScanner(cfg Config) *Scanner {
	if cfg.Workers <= 0 {
		cfg.Workers = 8
	}
	if cfg.MaxLineLen <= 0 {
		cfg.MaxLineLen = 64 * 1024
	}
	if cfg.MaxInMemory <= 0 {
		cfg.MaxInMemory = 16 << 20
	}
	if cfg.ContextChars <= 0 {
		cfg.ContextChars = 120
	}
	if cfg.MinStringLen <= 0 {
		cfg.MinStringLen = 8
	}
	if cfg.ContextWindow <= 0 {
		cfg.ContextWindow = 3
	}
	return &Scanner{cfg: cfg, seen: map[string]bool{}}
}

var DefaultExcludeDirs = map[string]bool{
	".git": true, ".svn": true, ".hg": true, "node_modules": true,
	"__pycache__": true, ".gradle": true, ".idea": true,
}

var DefaultExcludeExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".bmp": true, ".ico": true, ".ttf": true, ".otf": true, ".woff": true,
	".woff2": true, ".mp3": true, ".mp4": true, ".ogg": true, ".wav": true,
	".m4a": true, ".avi": true, ".mov": true, ".zip": true, ".gz": true,
	".7z": true, ".rar": true, ".pdf": true, ".psd": true, ".svg": true,
}

var binaryExts = map[string]bool{
	".so": true, ".dex": true, ".bin": true, ".dat": true, ".arsc": true,
	".odex": true, ".vdex": true, ".jar": true, ".a": true, ".o": true,
}

// ---------------------------------------------------------------------------
// Proximity context
// ---------------------------------------------------------------------------

// reCredKeyword marks a line as credential-adjacent. This is the single most
// effective false-positive filter: an obfuscated identifier and a real API key
// look identical to an entropy test, but only one of them sits next to a field
// called "apiKey" or a call to setRequestProperty("Authorization", ...).
var reCredKeyword = regexp.MustCompile(`(api[_\-]?key|apikey|\bsecret|\btoken|passw(or)?d|passwd|credential|\bbearer\b|authoriz|private[_\-]?key|access[_\-]?key|client[_\-]?secret|\bsigning\b|\bhmac\b|\bsignature\b|\bencrypt|\bdecrypt|\bcipher\b|keystore|\boauth\b|refresh[_\-]?token|session[_\-]?key|x-api|auth[_\-]?header|license[_\-]?key)`)

// credLiterals are the lowercase substrings that every pattern in
// reCredKeyword necessarily contains. A line lacking all of them cannot match,
// so it is rejected without touching the regex engine.
var credLiterals = []string{
	"key", "secret", "token", "pass", "auth", "cred", "crypt",
	"cipher", "sign", "hmac", "oauth", "bearer", "licen", "x-api",
}

func anyCredLiteral(lower string) bool {
	for _, lit := range credLiterals {
		if strings.Contains(lower, lit) {
			return true
		}
	}
	return false
}

// fileCtx caches per-file line data so proximity lookups are cheap.
type fileCtx struct {
	lines  []string
	lower  []string // lowered once, reused by keyword scan and rule prefilter
	hasKw  []bool
	built  bool
	window int
}

// lowerAt returns the lowercased form of line i, computing it once.
func (fc *fileCtx) lowerAt(i int) string {
	if fc == nil || i < 0 || i >= len(fc.lines) {
		return ""
	}
	if fc.lower == nil {
		fc.lower = make([]string, len(fc.lines))
		for j, l := range fc.lines {
			fc.lower[j] = strings.ToLower(l)
		}
	}
	return fc.lower[i]
}

func newFileCtx(lines []string, window int) *fileCtx {
	return &fileCtx{lines: lines, window: window}
}

func (fc *fileCtx) build() {
	if fc.built {
		return
	}
	fc.hasKw = make([]bool, len(fc.lines))
	for i := range fc.lines {
		l := fc.lowerAt(i)
		if len(l) > 1<<20 { // keyword lines are rarely enormous blobs
			l = l[:1<<20]
		}
		// Two-stage: a handful of SIMD-backed substring checks reject the
		// overwhelming majority of lines, so the precise word-bounded
		// alternation only runs on plausible candidates.
		if !anyCredLiteral(l) {
			continue
		}
		fc.hasKw[i] = reCredKeyword.MatchString(l)
	}
	fc.built = true
}

// keywordNear reports whether a credential keyword appears within the
// configured window of line index i (0-based).
func (fc *fileCtx) keywordNear(i int) bool {
	if fc == nil || len(fc.lines) == 0 {
		return false
	}
	fc.build()
	lo := i - fc.window
	if lo < 0 {
		lo = 0
	}
	hi := i + fc.window
	if hi >= len(fc.hasKw) {
		hi = len(fc.hasKw) - 1
	}
	for j := lo; j <= hi; j++ {
		if fc.hasKw[j] {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Walk and dispatch
// ---------------------------------------------------------------------------

func (s *Scanner) Run() ([]Finding, Stats, []error) {
	paths := make(chan string, 512)
	var wg sync.WaitGroup

	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range paths {
				if err := s.scanFile(p); err != nil {
					atomic.AddInt64(&s.stats.Errors, 1)
					s.mu.Lock()
					if len(s.errs) < 100 {
						s.errs = append(s.errs, err)
					}
					s.mu.Unlock()
				}
			}
		}()
	}

	walkErr := filepath.WalkDir(s.cfg.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			atomic.AddInt64(&s.stats.Errors, 1)
			return nil // unreadable dirs are common in extracted APKs
		}
		if d.IsDir() {
			if path != s.cfg.Root && s.cfg.ExcludeDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinks, sockets, devices
		}
		atomic.AddInt64(&s.stats.FilesSeen, 1)
		if !s.shouldScan(path) {
			atomic.AddInt64(&s.stats.FilesSkipped, 1)
			return nil
		}
		paths <- path
		return nil
	})

	close(paths)
	wg.Wait()

	if walkErr != nil {
		s.errs = append(s.errs, walkErr)
	}

	if s.cfg.CollapseGeneric {
		s.collapseGeneric()
	}
	s.suppressNoise()

	sort.Slice(s.findings, func(i, j int) bool {
		a, b := s.findings[i], s.findings[j]
		if a.severity != b.severity {
			return a.severity > b.severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
	s.stats.Findings = int64(len(s.findings))
	return s.findings, s.stats, s.errs
}

func (s *Scanner) shouldScan(path string) bool {
	if s.cfg.ExcludePathRe != nil && s.cfg.ExcludePathRe.MatchString(path) {
		return false
	}
	if s.cfg.IncludePathRe != nil && !s.cfg.IncludePathRe.MatchString(path) {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if len(s.cfg.IncludeExts) > 0 {
		return s.cfg.IncludeExts[ext]
	}
	if s.cfg.ExcludeExts[ext] {
		return false
	}
	if binaryExts[ext] && !s.cfg.ScanBinaries {
		return false
	}
	return true
}

func (s *Scanner) scanFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if s.cfg.MaxFileSize > 0 && fi.Size() > s.cfg.MaxFileSize {
		atomic.AddInt64(&s.stats.FilesSkipped, 1)
		return nil
	}
	if fi.Size() == 0 {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	head := make([]byte, 512)
	n, err := f.Read(head)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	binary := bytes.IndexByte(head[:n], 0) >= 0
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if s.cfg.Progress != nil {
		s.cfg.Progress(path)
	}
	atomic.AddInt64(&s.stats.FilesScanned, 1)
	atomic.AddInt64(&s.stats.BytesScanned, fi.Size())

	rel := s.rel(path)
	kind := classifyFile(rel)

	if binary {
		if !s.cfg.ScanBinaries {
			return nil
		}
		return s.scanBinary(f, rel, kind)
	}
	return s.scanText(f, fi.Size(), rel, kind)
}

func (s *Scanner) rel(path string) string {
	if r, err := filepath.Rel(s.cfg.Root, path); err == nil {
		return r
	}
	return path
}

// scanText reads the file whole when it fits in memory so proximity context is
// available in both directions; oversized files fall back to streaming, where
// generic detectors are skipped because context is unavailable.
func (s *Scanner) scanText(r io.Reader, size int64, rel, kind string) error {
	if size <= s.cfg.MaxInMemory {
		data, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
		fc := newFileCtx(lines, s.cfg.ContextWindow)
		for i, line := range lines {
			s.scanLongLine(line, rel, kind, i+1, "", fc, i)
		}
		return nil
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		s.scanLongLine(sc.Text(), rel, kind, lineNo, "", nil, 0)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("%s: line exceeds 8MB, scan truncated", rel)
		}
		return fmt.Errorf("%s: %w", rel, err)
	}
	return nil
}

// scanLongLine splits oversized lines (minified JS, single-line JSON, packed
// smali) into overlapping windows so no match straddles a boundary.
func (s *Scanner) scanLongLine(line, rel, kind string, lineNo int, origin string, fc *fileCtx, idx int) {
	const overlap = 1024
	max := s.cfg.MaxLineLen
	if len(line) <= max {
		s.scanLine(line, rel, kind, lineNo, 0, origin, fc, idx)
		return
	}
	for off := 0; off < len(line); off += max - overlap {
		end := off + max
		if end > len(line) {
			end = len(line)
		}
		s.scanLine(line[off:end], rel, kind, lineNo, off, origin, fc, idx)
		if end == len(line) {
			break
		}
	}
}

// scanBinary extracts printable runs and scans them as pseudo-lines, keeping
// them in a fileCtx so proximity context still works across nearby strings.
func (s *Scanner) scanBinary(r io.Reader, rel, kind string) error {
	br := bufio.NewReaderSize(r, 128*1024)
	var buf []byte
	var strs []string
	flush := func() {
		if len(buf) >= s.cfg.MinStringLen {
			strs = append(strs, string(buf))
		}
		buf = buf[:0]
	}
	for {
		b, err := br.ReadByte()
		if err != nil {
			flush()
			if !errors.Is(err, io.EOF) {
				return err
			}
			break
		}
		if b >= 0x20 && b < 0x7f {
			buf = append(buf, b)
			if len(buf) > 8192 {
				flush()
			}
		} else {
			flush()
		}
	}
	fc := newFileCtx(strs, s.cfg.ContextWindow)
	for i, str := range strs {
		s.scanLongLine(str, rel, kind, i+1, "binary-strings", fc, i)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

func (s *Scanner) scanLine(line, rel, kind string, lineNo, colOffset int, origin string, fc *fileCtx, idx int) {
	if line == "" {
		return
	}
	// Reuse the cached lowered line when the whole line is being scanned;
	// windowed slices and decoded payloads need their own.
	var lower string
	if fc != nil && idx < len(fc.lines) && len(line) == len(fc.lines[idx]) && origin == "" {
		lower = fc.lowerAt(idx)
	} else {
		lower = strings.ToLower(line)
	}

	for _, rule := range s.cfg.Rules {
		if len(s.cfg.OnlyRules) > 0 && !s.cfg.OnlyRules[rule.Spec.ID] {
			continue
		}
		if s.cfg.SkipRules[rule.Spec.ID] {
			continue
		}
		if !rule.appliesTo(rel) || !rule.prefilter(lower) {
			continue
		}
		// Context-hungry rules bail out before the regex engine runs.
		if rule.Spec.RequireContext && s.cfg.RequireContext && !fc.keywordNear(idx) {
			continue
		}
		for _, loc := range rule.re.FindAllStringSubmatchIndex(line, 20) {
			gi := rule.Spec.SecretGroup * 2
			if gi+1 >= len(loc) || loc[gi] < 0 {
				gi = 0
			}
			secret := strings.TrimSpace(line[loc[gi]:loc[gi+1]])
			if secret == "" {
				continue
			}
			if rule.Spec.MinLength > 0 && len(secret) < rule.Spec.MinLength {
				continue
			}
			if rule.allowed(secret) {
				continue
			}
			ent := ShannonEntropy(secret)
			if rule.Spec.MinEntropy > 0 && ent < rule.Spec.MinEntropy {
				continue
			}
			s.record(Finding{
				RuleID:      rule.Spec.ID,
				Description: rule.Spec.Description,
				severity:    rule.severity,
				File:        rel,
				FileKind:    kind,
				Line:        lineNo,
				Column:      colOffset + loc[gi] + 1,
				Secret:      secret,
				Entropy:     ent,
				Charset:     ClassifyCharset(secret).String(),
				Context:     s.snippet(line, loc[gi], loc[gi+1]),
				Tags:        rule.Spec.Tags,
				Origin:      origin,
			})
		}
	}

	if s.cfg.EntropyScan {
		s.entropyScan(line, rel, kind, lineNo, colOffset, origin, fc, idx)
	}
	if s.cfg.DecodeBase64 && origin == "" {
		s.decodeAndRescan(line, rel, kind, lineNo, fc, idx)
	}
}

// Candidate extraction: the generic detector only inspects quoted literals,
// XML text nodes and properties values, never raw code tokens.
var (
	reStringLiteral = regexp.MustCompile(`"([^"\n\\]{8,1000})"|'([^'\n\\]{8,1000})'`)
	reXMLText       = regexp.MustCompile(`>([^<>\n]{8,1000})<`)
	rePropsValue    = regexp.MustCompile(`(?m)^[A-Za-z0-9_.\-]+\s*[=:]\s*(\S{8,})\s*$`)
)

func (s *Scanner) candidates(line, kind string) [][2]int {
	var out [][2]int
	add := func(m []int, groups ...int) {
		for _, g := range groups {
			if m[g*2] >= 0 {
				out = append(out, [2]int{m[g*2], m[g*2+1]})
			}
		}
	}
	for _, m := range reStringLiteral.FindAllStringSubmatchIndex(line, 64) {
		add(m, 1, 2)
	}
	switch kind {
	case "xml", "manifest", "resources":
		for _, m := range reXMLText.FindAllStringSubmatchIndex(line, 64) {
			add(m, 1)
		}
	case "config":
		for _, m := range rePropsValue.FindAllStringSubmatchIndex(line, 8) {
			add(m, 1)
		}
	}
	return out
}

func (s *Scanner) entropyScan(line, rel, kind string, lineNo, colOffset int, origin string, fc *fileCtx, idx int) {
	// The gate that makes entropy scanning usable on obfuscated code.
	if s.cfg.RequireContext && !fc.keywordNear(idx) {
		return
	}
	for _, c := range s.candidates(line, kind) {
		val := line[c[0]:c[1]]
		if len(val) < s.cfg.EntropyMinLen || LooksLikeNoise(val) {
			continue
		}
		cs := ClassifyCharset(val)
		ent := ShannonEntropy(val)

		var threshold float64
		sev := SevLow
		switch cs {
		case CharsetHex:
			if IsUUID(val) {
				continue
			}
			threshold = s.cfg.EntropyMinHex
		case CharsetBase64, CharsetAlnum:
			threshold = s.cfg.EntropyMinB64
			sev = SevMedium
		default:
			continue
		}
		if ent < threshold || NormalizedEntropy(val) < 0.72 {
			continue
		}
		s.record(Finding{
			RuleID:      "high-entropy-string",
			Description: fmt.Sprintf("High-entropy %s string near credential keywords (%.2f bits/char)", cs, ent),
			severity:    sev,
			File:        rel,
			FileKind:    kind,
			Line:        lineNo,
			Column:      colOffset + c[0] + 1,
			Secret:      val,
			Entropy:     ent,
			Charset:     cs.String(),
			Context:     s.snippet(line, c[0], c[1]),
			Tags:        []string{"entropy"},
			Origin:      origin,
		})
	}
}

var reB64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)

// decodeAndRescan base64-decodes long blobs one level deep and re-runs the
// rules on anything that decodes to printable text, catching the common
// "hide the key behind base64" pattern.
func (s *Scanner) decodeAndRescan(line, rel, kind string, lineNo int, fc *fileCtx, idx int) {
	for _, m := range reB64Blob.FindAllString(line, 8) {
		if len(m) > 4096 {
			continue
		}
		dec, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(m, "="))
		if err != nil {
			continue
		}
		if !isMostlyPrintable(dec) {
			continue
		}
		s.scanLongLine(string(dec), rel, kind, lineNo, "base64-decoded", fc, idx)
	}
}

func isMostlyPrintable(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	ok := 0
	for _, c := range b {
		if c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			ok++
		}
	}
	return float64(ok)/float64(len(b)) > 0.9
}

func (s *Scanner) snippet(line string, start, end int) string {
	pad := s.cfg.ContextChars / 2
	lo := start - pad
	if lo < 0 {
		lo = 0
	}
	hi := end + pad
	if hi > len(line) {
		hi = len(line)
	}
	out := strings.TrimSpace(line[lo:hi])
	out = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return '.'
		}
		return r
	}, out)
	if lo > 0 {
		out = "\u2026" + out
	}
	if hi < len(line) {
		out += "\u2026"
	}
	return out
}

// fingerprint is stable across line-number changes so baselines survive edits.
func fingerprint(f Finding) string {
	h := sha256.Sum256([]byte(f.RuleID + "\x00" + f.File + "\x00" + f.Secret))
	return hex.EncodeToString(h[:8])
}

func (s *Scanner) record(f Finding) {
	f.Severity = f.severity.String()
	f.Fingerprint = fingerprint(f)
	if f.severity < s.cfg.MinSeverity {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.Baseline[f.Fingerprint] {
		s.stats.BaselineHidden++
		return
	}
	key := fmt.Sprintf("%s|%s|%d|%s", f.RuleID, f.File, f.Line, f.Secret)
	if s.seen[key] {
		s.stats.Deduped++
		return
	}
	s.seen[key] = true

	if s.cfg.Redact {
		f.Secret = Redact(f.Secret)
		f.Context = "" // context would leak what redaction just removed
	}
	s.findings = append(s.findings, f)
}

// ---------------------------------------------------------------------------
// Post-processing
// ---------------------------------------------------------------------------

// genericTier rules are broad nets. A precise rule matching the same value at
// the same place makes the generic hit pure noise.
var genericTier = map[string]bool{
	"high-entropy-string":        true,
	"generic-assigned-secret":    true,
	"smali-const-string-secret":  true,
	"android-strings-xml-secret": true,
	"hardcoded-iv-or-key-bytes":  true,
}

func (s *Scanner) collapseGeneric() {
	type loc struct {
		file string
		line int
	}
	specific := map[loc][]string{}
	for _, f := range s.findings {
		if !genericTier[f.RuleID] {
			k := loc{f.File, f.Line}
			specific[k] = append(specific[k], f.Secret)
		}
	}
	if len(specific) == 0 {
		return
	}
	kept := s.findings[:0]
	for _, f := range s.findings {
		if genericTier[f.RuleID] {
			drop := false
			for _, sec := range specific[loc{f.File, f.Line}] {
				// Overlap either way: the generic match may be the whole
				// literal or an inner capture of the precise one.
				if strings.Contains(sec, f.Secret) || strings.Contains(f.Secret, sec) {
					drop = true
					break
				}
			}
			if drop {
				s.stats.Deduped++
				continue
			}
		}
		kept = append(kept, f)
	}
	s.findings = kept
}

// suppressNoise enforces per-file and global budgets on generic findings.
// A file emitting dozens of high-entropy strings is obfuscated, not leaky, and
// listing all of them buries the findings that matter.
func (s *Scanner) suppressNoise() {
	if s.cfg.MaxGenericPerFile <= 0 && s.cfg.MaxGenericTotal <= 0 {
		return
	}
	perFile := map[string]int{}
	for _, f := range s.findings {
		if genericTier[f.RuleID] {
			perFile[f.File]++
		}
	}
	noisy := map[string]bool{}
	if s.cfg.MaxGenericPerFile > 0 {
		for file, n := range perFile {
			if n > s.cfg.MaxGenericPerFile {
				noisy[file] = true
			}
		}
	}

	kept := make([]Finding, 0, len(s.findings))
	var generics []Finding
	for _, f := range s.findings {
		if genericTier[f.RuleID] {
			if noisy[f.File] {
				s.stats.NoiseSuppressed++
				continue
			}
			generics = append(generics, f)
			continue
		}
		kept = append(kept, f)
	}
	for file := range noisy {
		s.noisyFiles = append(s.noisyFiles, file)
	}
	s.stats.NoisyFiles = int64(len(noisy))

	// Global budget: keep the highest-entropy generics, drop the tail.
	if s.cfg.MaxGenericTotal > 0 && len(generics) > s.cfg.MaxGenericTotal {
		sort.Slice(generics, func(i, j int) bool { return generics[i].Entropy > generics[j].Entropy })
		s.stats.NoiseSuppressed += int64(len(generics) - s.cfg.MaxGenericTotal)
		generics = generics[:s.cfg.MaxGenericTotal]
	}
	s.findings = append(kept, generics...)
	sort.Strings(s.noisyFiles)
}

// NoisyFiles returns files whose generic findings were suppressed wholesale.
func (s *Scanner) NoisyFiles() []string { return s.noisyFiles }

// Redact keeps enough of a secret to correlate findings without printing it.
func Redact(s string) string {
	n := len(s)
	if n <= 8 {
		return strings.Repeat("*", n)
	}
	keep := 4
	if n > 40 {
		keep = 6
	}
	return s[:keep] + strings.Repeat("*", 8) + s[n-2:] + fmt.Sprintf("(len=%d)", n)
}

// classifyFile tags a path with its role inside a decompiled APK so findings
// can be triaged by where they live.
func classifyFile(rel string) string {
	l := strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(l)
	ext := filepath.Ext(l)

	switch {
	case base == "androidmanifest.xml":
		return "manifest"
	case strings.Contains(l, "/values") && ext == ".xml":
		return "resources"
	case ext == ".smali":
		return "smali"
	case ext == ".java":
		return "java"
	case ext == ".kt":
		return "kotlin"
	case ext == ".xml":
		return "xml"
	case ext == ".json":
		return "json"
	case ext == ".properties", ext == ".env", ext == ".cfg", ext == ".ini",
		ext == ".yaml", ext == ".yml", ext == ".toml", ext == ".gradle":
		return "config"
	case ext == ".js", ext == ".ts", ext == ".jsx":
		return "javascript"
	case ext == ".html", ext == ".htm":
		return "html"
	case strings.HasPrefix(l, "assets/"), strings.Contains(l, "/assets/"):
		return "asset"
	case ext == ".so":
		return "native"
	case ext == ".dex":
		return "dex"
	}
	return "other"
}
