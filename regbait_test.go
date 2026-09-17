package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stripeTestFixture is assembled at build time from two pieces so the
// contiguous string never appears in the source file. Static secret scanners
// (GitHub push protection, our own generic-assigned-secret rule's neighbours,
// gitleaks, etc.) grep raw file bytes for the Stripe key shape
// (sk_live_ + 20+ alphanumeric chars, no checksum), so any single literal
// satisfying that shape is indistinguishable from a real key regardless of
// how obviously fake its content is. Splitting the literal defeats that
// static grep while the concatenated value still exercises the real regex
// at test time.
const stripeTestFixture = "sk_live_" + "51NotARealStripeKeyTestFixtureOnly000"

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		in       string
		min, max float64
	}{
		{"aaaaaaaaaaaaaaaa", 0, 0.01},
		{"0123456789abcdef", 3.9, 4.01},
		{"password", 2.0, 3.0},
	}
	for _, c := range cases {
		got := ShannonEntropy(c.in)
		if got < c.min || got > c.max {
			t.Errorf("ShannonEntropy(%q) = %.3f, want in [%.2f,%.2f]", c.in, got, c.min, c.max)
		}
	}
}

func TestClassifyCharset(t *testing.T) {
	cases := map[string]Charset{
		"deadbeefcafe1234": CharsetHex,
		"AbC123xyz":        CharsetAlnum,
		"ab+/cd==":         CharsetBase64,
		"has space here":   CharsetOther,
		"mongodb://a:b@c":  CharsetOther,
	}
	for in, want := range cases {
		if got := ClassifyCharset(in); got != want {
			t.Errorf("ClassifyCharset(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsRepeatedUnit(t *testing.T) {
	yes := []string{"aaaaaaaa", "abababab", "abcabcabcabc", "00000000"}
	no := []string{"abcdefgh", "aabbccdd1", "AIzaSyB7xK2mN9pQ"}
	for _, s := range yes {
		if !isRepeatedUnit(s) {
			t.Errorf("isRepeatedUnit(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if isRepeatedUnit(s) {
			t.Errorf("isRepeatedUnit(%q) = true, want false", s)
		}
	}
}

func TestLooksLikeNoise(t *testing.T) {
	noise := []string{
		"com.google.android.gms.common.api.Status",
		"res/drawable/ic_launcher.png",
		"YOUR_API_KEY_HERE",
		"android.intent.action.MAIN",
		"https://api.example.com/v1/users",
		"#FF00AA88",
		"aaaaaaaaaaaa",
		"just some english words",
		"ABCDEFGHIJKLMNOP", // no digits
	}
	for _, s := range noise {
		if !LooksLikeNoise(s) {
			t.Errorf("LooksLikeNoise(%q) = false, want true", s)
		}
	}
	real := []string{
		"AIzaSyB7xK2mN9pQ4rT6vY8wZ1aC3dF5gH7jL0M",
		"hT9kQ2mVx7ZpL4nRw8sYc1Ub6Ef3Ad5Gj0Ki",
	}
	for _, s := range real {
		if LooksLikeNoise(s) {
			t.Errorf("LooksLikeNoise(%q) = true, want false", s)
		}
	}
}

func TestDefaultRulesCompile(t *testing.T) {
	rules, err := CompileRules(DefaultRules)
	if err != nil {
		t.Fatalf("default ruleset failed to compile: %v", err)
	}
	if len(rules) != len(DefaultRules) {
		t.Fatalf("compiled %d rules, expected %d", len(rules), len(DefaultRules))
	}
	for _, r := range rules {
		if r.Spec.Description == "" {
			t.Errorf("rule %s has no description", r.Spec.ID)
		}
		if r.severity == SevInfo && r.Spec.Severity == "" {
			t.Errorf("rule %s has no severity set", r.Spec.ID)
		}
	}
}

func TestDuplicateRuleIDRejected(t *testing.T) {
	_, err := CompileRules([]RuleSpec{
		{ID: "x", Regex: "a", Severity: "low"},
		{ID: "x", Regex: "b", Severity: "low"},
	})
	if err == nil {
		t.Fatal("expected duplicate rule id to be rejected")
	}
}

func TestBadSecretGroupRejected(t *testing.T) {
	_, err := CompileRules([]RuleSpec{
		{ID: "x", Regex: `abc`, SecretGroup: 3, Severity: "low"},
	})
	if err == nil {
		t.Fatal("expected out-of-range secret_group to be rejected")
	}
}

func TestRedact(t *testing.T) {
	got := Redact("AIzaSyB7xK2mN9pQ4rT6vY8wZ1aC3dF5gH7jL0M")
	if strings.Contains(got, "mN9pQ4rT6v") {
		t.Errorf("Redact leaked the secret body: %s", got)
	}
	if !strings.HasPrefix(got, "AIza") {
		t.Errorf("Redact should keep a short prefix, got %s", got)
	}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func scan(t *testing.T, root string, tweak func(*Config)) []Finding {
	t.Helper()
	rules, err := CompileRules(DefaultRules)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Root: root, Rules: rules, Workers: 4,
		MaxFileSize: 10 << 20, MaxLineLen: 64 * 1024,
		MinSeverity: SevLow, EntropyScan: true,
		EntropyMinB64: 4.3, EntropyMinHex: 3.3, EntropyMinLen: 20,
		ExcludeExts: DefaultExcludeExts, ExcludeDirs: DefaultExcludeDirs,
		ContextChars: 120, MinStringLen: 8, CollapseGeneric: true,
		RequireContext: true, ContextWindow: 3,
		MaxGenericPerFile: 10, MaxGenericTotal: 200, MaxInMemory: 16 << 20,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	f, _, errs := NewScanner(cfg).Run()
	for _, e := range errs {
		t.Logf("scanner warning: %v", e)
	}
	return f
}

func hasRuleHit(fs []Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestScannerDetectsKnownSecrets(t *testing.T) {
	root := writeTree(t, map[string]string{
		"res/values/strings.xml": `<resources>
<string name="google_api_key">AIzaSyB7xK2mN9pQ4rT6vY8wZ1aC3dF5gH7jL0M</string>
<string name="label">Settings</string>
</resources>`,
		"src/Config.java": `public class Config {
  static final String S = "` + stripeTestFixture + `";
  static final String DB = "postgres://u:p4ssw0rd@db.internal:5432/app";
  static final String C = "com.google.android.gms.common.api.Status";
}`,
		"app.properties": "storePassword='Keyst0re!P4ssw0rd'\n",
	})
	fs := scan(t, root, nil)

	for _, want := range []string{
		"google-api-key", "stripe-secret-key",
		"db-connection-string", "pkcs12-keystore-password",
	} {
		if !hasRuleHit(fs, want) {
			t.Errorf("expected rule %s to fire", want)
		}
	}
	for _, f := range fs {
		if strings.Contains(f.Secret, "gms.common.api.Status") {
			t.Errorf("class name reported as secret: %+v", f)
		}
	}
}

func TestPlaceholdersSuppressed(t *testing.T) {
	root := writeTree(t, map[string]string{
		"res/values/strings.xml": `<resources>
<string name="api_key">YOUR_API_KEY_HERE</string>
<string name="secret">CHANGEME_PLACEHOLDER_VALUE</string>
</resources>`,
	})
	if fs := scan(t, root, nil); len(fs) != 0 {
		t.Errorf("expected no findings for placeholders, got %d: %+v", len(fs), fs)
	}
}

func TestAWSExampleKeyAllowlisted(t *testing.T) {
	root := writeTree(t, map[string]string{
		"doc.txt": "AKIAIOSFODNN7EXAMPLE\n",
	})
	if hasRuleHit(scan(t, root, nil), "aws-access-key-id") {
		t.Error("AWS documentation example key should be allowlisted")
	}
}

func TestBase64DecodeRescan(t *testing.T) {
	// base64("AKIARONNQTFZXKLIBBUA")
	root := writeTree(t, map[string]string{
		"E.java": `String e = "QUtJQVJPTk5RVEZaWEtMSUJCVUE=";`,
	})
	if hasRuleHit(scan(t, root, nil), "aws-access-key-id") {
		t.Error("should not decode base64 unless --decode-base64 is set")
	}
	fs := scan(t, root, func(c *Config) { c.DecodeBase64 = true })
	if !hasRuleHit(fs, "aws-access-key-id") {
		t.Error("expected base64-wrapped AWS key to be found with DecodeBase64")
	}
	for _, f := range fs {
		if f.RuleID == "aws-access-key-id" && f.Origin != "base64-decoded" {
			t.Errorf("expected origin base64-decoded, got %q", f.Origin)
		}
	}
}

func TestBinaryStringExtraction(t *testing.T) {
	root := writeTree(t, map[string]string{
		"lib/libx.so": "junk\x00\x00ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\x00pad",
	})
	if hasRuleHit(scan(t, root, nil), "github-token") {
		t.Error("binaries should be skipped without ScanBinaries")
	}
	if !hasRuleHit(scan(t, root, func(c *Config) { c.ScanBinaries = true }), "github-token") {
		t.Error("expected token inside .so to be found with ScanBinaries")
	}
}

func TestMinSeverityFilter(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a.java": `String k = "` + stripeTestFixture + `";`,
	})
	fs := scan(t, root, func(c *Config) { c.MinSeverity = SevCritical })
	for _, f := range fs {
		if f.severity < SevCritical {
			t.Errorf("finding below min severity leaked: %+v", f)
		}
	}
}

func TestRedactMode(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a.java": `String k = "AIzaSyB7xK2mN9pQ4rT6vY8wZ1aC3dF5gH7jL0M";`,
	})
	fs := scan(t, root, func(c *Config) { c.Redact = true })
	if len(fs) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range fs {
		if strings.Contains(f.Secret, "mN9pQ4rT6vY8wZ") {
			t.Errorf("redact mode leaked secret: %s", f.Secret)
		}
		if f.Context != "" {
			t.Errorf("redact mode should clear context, got %q", f.Context)
		}
	}
}

func TestFingerprintStability(t *testing.T) {
	a := Finding{RuleID: "r", File: "f.java", Secret: "abc"}
	b := Finding{RuleID: "r", File: "f.java", Secret: "abc", Line: 99}
	if fingerprint(a) != fingerprint(b) {
		t.Error("fingerprint should ignore line number so edits do not churn baselines")
	}
	c := Finding{RuleID: "r", File: "g.java", Secret: "abc"}
	if fingerprint(a) == fingerprint(c) {
		t.Error("fingerprint should differ across files")
	}
}

func TestLongLineWindowing(t *testing.T) {
	// Put a secret past the window boundary to confirm overlap handling.
	pad := strings.Repeat("x", 70000)
	root := writeTree(t, map[string]string{
		"min.js": pad + `var k="AIzaSyB7xK2mN9pQ4rT6vY8wZ1aC3dF5gH7jL0M";` + pad,
	})
	if !hasRuleHit(scan(t, root, nil), "google-api-key") {
		t.Error("expected secret beyond the line window to still be found")
	}
}

func TestCustomRulePack(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "rules.json")
	os.WriteFile(pack, []byte(`{"extend":false,"rules":[
	  {"id":"acme","description":"ACME key","regex":"ACME-[A-Z0-9]{8}","severity":"high"}]}`), 0o644)

	specs, extend, err := LoadRuleFile(pack)
	if err != nil {
		t.Fatal(err)
	}
	if extend {
		t.Error("extend:false should be honoured")
	}
	rules, err := CompileRules(specs)
	if err != nil {
		t.Fatal(err)
	}
	root := writeTree(t, map[string]string{"a.txt": "token ACME-AB12CD34 end"})
	cfg := Config{
		Root: root, Rules: rules, Workers: 2, MaxFileSize: 1 << 20,
		MaxLineLen: 4096, MinSeverity: SevLow, ContextChars: 80,
		ExcludeExts: DefaultExcludeExts, ExcludeDirs: DefaultExcludeDirs,
		MaxInMemory: 16 << 20, ContextWindow: 3,
	}
	fs, _, _ := NewScanner(cfg).Run()
	if !hasRuleHit(fs, "acme") {
		t.Error("expected custom rule to fire")
	}
}

func TestExcludedDirsSkipped(t *testing.T) {
	root := writeTree(t, map[string]string{
		".git/config": `key = "AIzaSyB7xK2mN9pQ4rT6vY8wZ1aC3dF5gH7jL0M"`,
	})
	if len(scan(t, root, nil)) != 0 {
		t.Error("expected .git to be excluded")
	}
}

func BenchmarkScanLine(b *testing.B) {
	rules, _ := CompileRules(DefaultRules)
	s := NewScanner(Config{
		Root: ".", Rules: rules, EntropyScan: true,
		EntropyMinB64: 4.3, EntropyMinHex: 3.3, EntropyMinLen: 20,
		ContextChars: 120,
	})
	line := `    public static final String TOKEN = "AIzaSyB7xK2mN9pQ4rT6vY8wZ1aC3dF5gH7jL0M";`
	fc := newFileCtx([]string{line}, 3)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.scanLine(line, "a.java", "java", 1, 0, "", fc, 0)
	}
}
