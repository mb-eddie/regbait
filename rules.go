package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	}
	return "INFO"
}

func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SevCritical, nil
	case "HIGH":
		return SevHigh, nil
	case "MEDIUM", "MED":
		return SevMedium, nil
	case "LOW":
		return SevLow, nil
	case "INFO", "":
		return SevInfo, nil
	}
	return SevInfo, fmt.Errorf("unknown severity %q", s)
}

// RuleSpec is the serialisable form of a rule, used for the built-in table and
// for user-supplied JSON rule packs.
type RuleSpec struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Regex       string   `json:"regex"`
	SecretGroup int      `json:"secret_group,omitempty"` // capture group holding the secret; 0 = whole match
	Keywords    []string `json:"keywords,omitempty"`     // cheap substring prefilter (case-insensitive)
	MinEntropy  float64  `json:"min_entropy,omitempty"`  // Shannon bits/char on the secret group
	MinLength   int      `json:"min_length,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Allowlist   []string `json:"allowlist,omitempty"`    // regexes; a hit suppresses the finding
	PathInclude string   `json:"path_include,omitempty"` // only run on paths matching this regex
	PathExclude string   `json:"path_exclude,omitempty"`
	// RequireContext makes the rule fire only when a credential keyword
	// appears within the proximity window. Essential for broad rules run
	// against obfuscated code.
	RequireContext bool     `json:"require_context,omitempty"`
	Tags           []string `json:"tags,omitempty"`
}

type Rule struct {
	Spec        RuleSpec
	re          *regexp.Regexp
	allow       []*regexp.Regexp
	pathInclude *regexp.Regexp
	pathExclude *regexp.Regexp
	keywords    []string
	severity    Severity
}

func (r *Rule) ID() string { return r.Spec.ID }

// CompileRules validates and compiles a set of specs.
func CompileRules(specs []RuleSpec) ([]*Rule, error) {
	seen := map[string]bool{}
	out := make([]*Rule, 0, len(specs))
	for i, s := range specs {
		if s.ID == "" {
			return nil, fmt.Errorf("rule #%d: missing id", i)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("duplicate rule id %q", s.ID)
		}
		seen[s.ID] = true

		re, err := regexp.Compile(s.Regex)
		if err != nil {
			return nil, fmt.Errorf("rule %s: bad regex: %w", s.ID, err)
		}
		if s.SecretGroup > re.NumSubexp() {
			return nil, fmt.Errorf("rule %s: secret_group %d but regex has %d groups",
				s.ID, s.SecretGroup, re.NumSubexp())
		}
		sev, err := ParseSeverity(s.Severity)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", s.ID, err)
		}
		r := &Rule{Spec: s, re: re, severity: sev}
		for _, a := range s.Allowlist {
			ar, err := regexp.Compile(a)
			if err != nil {
				return nil, fmt.Errorf("rule %s: bad allowlist regex %q: %w", s.ID, a, err)
			}
			r.allow = append(r.allow, ar)
		}
		if s.PathInclude != "" {
			if r.pathInclude, err = regexp.Compile(s.PathInclude); err != nil {
				return nil, fmt.Errorf("rule %s: bad path_include: %w", s.ID, err)
			}
		}
		if s.PathExclude != "" {
			if r.pathExclude, err = regexp.Compile(s.PathExclude); err != nil {
				return nil, fmt.Errorf("rule %s: bad path_exclude: %w", s.ID, err)
			}
		}
		for _, k := range s.Keywords {
			r.keywords = append(r.keywords, strings.ToLower(k))
		}
		out = append(out, r)
	}
	return out, nil
}

// appliesTo reports whether the rule should run against this file path.
func (r *Rule) appliesTo(path string) bool {
	if r.pathInclude != nil && !r.pathInclude.MatchString(path) {
		return false
	}
	if r.pathExclude != nil && r.pathExclude.MatchString(path) {
		return false
	}
	return true
}

// prefilter is the cheap substring gate run before the regex engine. Rules with
// no keywords always pass.
func (r *Rule) prefilter(lowerLine string) bool {
	if len(r.keywords) == 0 {
		return true
	}
	for _, k := range r.keywords {
		if strings.Contains(lowerLine, k) {
			return true
		}
	}
	return false
}

func (r *Rule) allowed(secret string) bool {
	for _, a := range r.allow {
		if a.MatchString(secret) {
			return true
		}
	}
	return false
}

// LoadRuleFile reads a JSON rule pack: either a bare array of RuleSpec or an
// object of the form {"rules": [...], "extend": true}.
func LoadRuleFile(path string) ([]RuleSpec, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	var arr []RuleSpec
	if err := json.Unmarshal(b, &arr); err == nil {
		return arr, true, nil
	}
	var wrapper struct {
		Extend *bool      `json:"extend"`
		Rules  []RuleSpec `json:"rules"`
	}
	if err := json.Unmarshal(b, &wrapper); err != nil {
		return nil, false, fmt.Errorf("%s: not a valid rule pack: %w", path, err)
	}
	extend := true
	if wrapper.Extend != nil {
		extend = *wrapper.Extend
	}
	return wrapper.Rules, extend, nil
}

// commonPlaceholder suppresses obvious non-secrets across every rule.
const commonPlaceholder = `(?i)(your[_-]?|example|sample|placeholder|dummy|xxxxx|change[_-]?me|insert[_-]?|test[_-]?key|fake|abcdef1234|1234567890abcdef)`

// DefaultRules is the built-in ruleset. Ordering is irrelevant; every rule runs.
var DefaultRules = []RuleSpec{
	// ---------- Google / Firebase (very common in APKs) ----------
	{
		ID: "google-api-key", Description: "Google API key (Maps, Places, Firebase, YouTube)",
		Regex: `\bAIza[0-9A-Za-z_\-]{35}\b`, Severity: "high",
		Keywords: []string{"aiza"}, Tags: []string{"google", "android"},
		Allowlist: []string{commonPlaceholder},
	},
	{
		ID: "gcp-oauth-client-secret", Description: "Google OAuth client secret",
		Regex: `\bGOCSPX-[A-Za-z0-9_\-]{28}\b`, Severity: "critical",
		Keywords: []string{"gocspx"}, Tags: []string{"google"},
	},
	{
		ID: "gcp-service-account", Description: "GCP service account JSON key material",
		Regex: `"type"\s*:\s*"service_account"`, Severity: "critical",
		Keywords: []string{"service_account"}, Tags: []string{"google"},
	},
	{
		ID: "firebase-database-url", Description: "Firebase Realtime Database URL (check for open rules)",
		Regex:    `\bhttps://[a-z0-9][a-z0-9\-]{2,}\.(firebaseio\.com|firebasedatabase\.app)\b`,
		Severity: "medium", Keywords: []string{"firebaseio", "firebasedatabase"}, Tags: []string{"google"},
	},
	{
		ID: "firebase-cloud-messaging-key", Description: "FCM server key (allows arbitrary push to all users)",
		Regex: `\bAAAA[A-Za-z0-9_\-]{7}:APA91b[A-Za-z0-9_\-]{100,}`, Severity: "critical",
		Keywords: []string{"apa91b"}, Tags: []string{"google", "android"},
	},

	// ---------- AWS ----------
	{
		ID: "aws-access-key-id", Description: "AWS access key ID",
		Regex: `\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b`, SecretGroup: 1,
		Severity: "high", Keywords: []string{"akia", "asia", "abia", "acca", "a3t"}, Tags: []string{"aws"},
		Allowlist: []string{`^AKIAIOSFODNN7EXAMPLE$`},
	},
	{
		ID: "aws-secret-access-key", Description: "AWS secret access key (keyword-anchored)",
		Regex:       `(?i)aws[_.\-]?(?:secret|sec)[_.\-]?(?:access)?[_.\-]?key[^\n]{0,20}?['"]([A-Za-z0-9/+=]{40})['"]`,
		SecretGroup: 1, MinEntropy: 3.5, Severity: "critical",
		Keywords: []string{"aws"}, Tags: []string{"aws"},
		Allowlist: []string{`^wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY$`, commonPlaceholder},
	},
	{
		ID: "aws-session-token", Description: "AWS session token",
		Regex:       `(?i)aws[_.\-]?session[_.\-]?token[^\n]{0,20}?['"]([A-Za-z0-9/+=]{100,})['"]`,
		SecretGroup: 1, MinEntropy: 4.0, Severity: "high", Keywords: []string{"aws"}, Tags: []string{"aws"},
	},

	// ---------- Azure ----------
	{
		ID: "azure-storage-connection-string", Description: "Azure Storage connection string with AccountKey",
		Regex:    `DefaultEndpointsProtocol=https?;[^\n"']*AccountKey=[A-Za-z0-9+/=]{60,}`,
		Severity: "critical", Keywords: []string{"accountkey"}, Tags: []string{"azure"},
	},
	{
		ID: "azure-sas-token", Description: "Azure shared access signature",
		Regex:    `\bsig=[A-Za-z0-9%/+=]{40,}&?[^\n"']*se=\d{4}-\d{2}-\d{2}`,
		Severity: "high", Keywords: []string{"sig="}, Tags: []string{"azure"},
	},

	// ---------- Source control / CI ----------
	{
		ID: "github-token", Description: "GitHub token (PAT, OAuth, app, refresh)",
		Regex: `\b(gh[pousr]_[A-Za-z0-9]{36,255})\b`, SecretGroup: 1, Severity: "critical",
		Keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, Tags: []string{"vcs"},
	},
	{
		ID: "github-fine-grained-pat", Description: "GitHub fine-grained personal access token",
		Regex: `\bgithub_pat_[A-Za-z0-9_]{60,}\b`, Severity: "critical",
		Keywords: []string{"github_pat_"}, Tags: []string{"vcs"},
	},
	{
		ID: "gitlab-token", Description: "GitLab personal / runner token",
		Regex: `\b(glpat-[A-Za-z0-9_\-]{20,}|GR1348941[A-Za-z0-9_\-]{20,})\b`, SecretGroup: 1,
		Severity: "critical", Keywords: []string{"glpat-", "gr1348941"}, Tags: []string{"vcs"},
	},
	{
		ID: "npm-token", Description: "npm access token",
		Regex: `\bnpm_[A-Za-z0-9]{36}\b`, Severity: "high", Keywords: []string{"npm_"}, Tags: []string{"ci"},
	},

	// ---------- Payments ----------
	{
		ID: "stripe-secret-key", Description: "Stripe secret or restricted key",
		Regex: `\b([rs]k_(?:live|test)_[A-Za-z0-9]{20,})\b`, SecretGroup: 1, Severity: "critical",
		Keywords: []string{"sk_live", "sk_test", "rk_live", "rk_test"}, Tags: []string{"payments"},
	},
	{
		ID: "square-token", Description: "Square access or OAuth secret",
		Regex: `\b(sq0(?:atp|csp|idp)-[A-Za-z0-9_\-]{22,43}|EAAA[A-Za-z0-9_\-]{60,})\b`, SecretGroup: 1,
		Severity: "critical", Keywords: []string{"sq0atp", "sq0csp", "sq0idp", "eaaa"}, Tags: []string{"payments"},
	},
	{
		ID: "paypal-braintree-token", Description: "Braintree / PayPal access token",
		Regex:    `\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}\b`,
		Severity: "critical", Keywords: []string{"access_token$"}, Tags: []string{"payments"},
	},

	// ---------- Messaging / comms ----------
	{
		ID: "slack-token", Description: "Slack API token",
		Regex: `\b(xox[abposr]-[A-Za-z0-9\-]{10,})\b`, SecretGroup: 1, Severity: "critical",
		Keywords: []string{"xoxb-", "xoxa-", "xoxp-", "xoxo-", "xoxs-", "xoxr-"}, Tags: []string{"saas"},
	},
	{
		ID: "slack-webhook", Description: "Slack incoming webhook URL",
		Regex:    `https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}`,
		Severity: "high", Keywords: []string{"hooks.slack.com"}, Tags: []string{"saas"},
	},
	{
		ID: "discord-bot-token", Description: "Discord bot token",
		Regex:    `\b[MNO][A-Za-z\d_\-]{23,26}\.[A-Za-z\d_\-]{6}\.[A-Za-z\d_\-]{27,}\b`,
		Severity: "high", Keywords: []string{"discord", "bot "}, Tags: []string{"saas"},
	},
	{
		ID: "discord-webhook", Description: "Discord webhook URL",
		Regex:    `https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,}`,
		Severity: "high", Keywords: []string{"discord"}, Tags: []string{"saas"},
	},
	{
		ID: "telegram-bot-token", Description: "Telegram bot token",
		Regex: `\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b`, Severity: "high",
		Keywords: []string{":aa"}, Tags: []string{"saas"},
	},
	{
		ID: "twilio-api-key", Description: "Twilio account SID or API key SID",
		Regex: `\b((?:AC|SK)[0-9a-fA-F]{32})\b`, SecretGroup: 1, Severity: "high",
		Keywords: []string{"twilio", "ac", "sk"}, Tags: []string{"saas"},
		Allowlist: []string{commonPlaceholder},
	},
	{
		ID: "sendgrid-api-key", Description: "SendGrid API key",
		Regex: `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`, Severity: "critical",
		Keywords: []string{"sg."}, Tags: []string{"saas"},
	},
	{
		ID: "mailgun-api-key", Description: "Mailgun API key",
		Regex: `\bkey-[0-9a-zA-Z]{32}\b`, Severity: "high", Keywords: []string{"key-"}, Tags: []string{"saas"},
	},
	{
		ID: "mailchimp-api-key", Description: "Mailchimp API key",
		Regex: `\b[0-9a-f]{32}-us[0-9]{1,2}\b`, Severity: "high",
		Keywords: []string{"-us"}, Tags: []string{"saas"},
	},

	// ---------- AI / LLM providers ----------
	{
		ID: "openai-api-key", Description: "OpenAI API key",
		Regex:       `\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{48})\b`,
		SecretGroup: 1, Severity: "critical", Keywords: []string{"sk-"}, Tags: []string{"ai"},
	},
	{
		ID: "anthropic-api-key", Description: "Anthropic API key",
		Regex: `\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{80,}\b`, Severity: "critical",
		Keywords: []string{"sk-ant-"}, Tags: []string{"ai"},
	},
	{
		ID: "huggingface-token", Description: "Hugging Face access token",
		Regex: `\bhf_[A-Za-z0-9]{34,}\b`, Severity: "high", Keywords: []string{"hf_"}, Tags: []string{"ai"},
	},

	// ---------- Mobile-analytics / backend SDKs common in APKs ----------
	{
		ID: "algolia-admin-key", Description: "Algolia admin API key (keyword-anchored)",
		Regex:       `(?i)algolia[_.\-]?(?:admin|api)?[_.\-]?key[^\n]{0,20}?['"]([a-f0-9]{32})['"]`,
		SecretGroup: 1, Severity: "high", Keywords: []string{"algolia"}, Tags: []string{"saas"},
	},
	{
		ID: "branch-io-key", Description: "Branch.io live key",
		Regex: `\bkey_live_[A-Za-z0-9]{32}\b`, Severity: "medium",
		Keywords: []string{"key_live_"}, Tags: []string{"android"},
	},
	{
		ID: "pusher-key", Description: "Pusher app secret (keyword-anchored)",
		Regex:       `(?i)pusher[_.\-]?(?:app)?[_.\-]?secret[^\n]{0,20}?['"]([a-f0-9]{20,32})['"]`,
		SecretGroup: 1, Severity: "high", Keywords: []string{"pusher"}, Tags: []string{"saas"},
	},
	{
		ID: "cloudinary-url", Description: "Cloudinary URL with embedded API secret",
		Regex: `cloudinary://[0-9]{10,}:[A-Za-z0-9_\-]{20,}@[a-z0-9_\-]+`, Severity: "critical",
		Keywords: []string{"cloudinary://"}, Tags: []string{"saas"},
	},
	{
		ID: "facebook-app-secret", Description: "Facebook app secret (keyword-anchored)",
		Regex:       `(?i)facebook[_.\-]?(?:app)?[_.\-]?secret[^\n]{0,20}?['"]([a-f0-9]{32})['"]`,
		SecretGroup: 1, Severity: "critical", Keywords: []string{"facebook"}, Tags: []string{"android"},
	},
	{
		ID: "facebook-access-token", Description: "Facebook Graph access token",
		Regex: `\bEAACEdEose0cBA[0-9A-Za-z]+\b`, Severity: "high",
		Keywords: []string{"eaacededose", "eaaced"}, Tags: []string{"saas"},
	},

	// ---------- Generic credential material ----------
	{
		ID: "private-key-block", Description: "PEM private key block",
		Regex: `-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----`, Severity: "critical",
		Keywords: []string{"private key"}, Tags: []string{"crypto"},
	},
	{
		ID: "pkcs12-keystore-password", Description: "Keystore / signing password in build config",
		Regex:       `(?i)(?:store|key)Password\s*[:=]\s*['"]([^'"\n]{4,})['"]`,
		SecretGroup: 1, Severity: "high", Keywords: []string{"password"},
		PathInclude: `(?i)(\.gradle|\.properties|\.cfg|\.ini|\.env)$`, Tags: []string{"android"},
		Allowlist: []string{commonPlaceholder},
	},
	{
		ID: "jwt", Description: "JSON Web Token",
		Regex:    `\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`,
		Severity: "high", Keywords: []string{"eyj"}, Tags: []string{"auth"},
	},
	{
		ID: "basic-auth-url", Description: "Credentials embedded in a URL",
		Regex:    `\b[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://[^\s:@/"']{1,64}:[^\s:@/"']{3,64}@[a-zA-Z0-9.\-]{3,}`,
		Severity: "critical", Keywords: []string{"://"}, Tags: []string{"auth"},
		Allowlist: []string{`(?i)://[^:]*:(password|pass|pwd|secret|token|xxx+|\*+|changeme)@`},
	},
	{
		ID: "db-connection-string", Description: "Database connection string with credentials",
		Regex:    `\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql|jdbc:[a-z]+)://[^\s:@/"']+:[^\s:@/"']+@`,
		Severity: "critical", Keywords: []string{"mongodb", "postgres", "mysql://", "redis://", "amqp://", "jdbc:"},
		Tags: []string{"db"},
	},
	{
		ID: "authorization-header", Description: "Hardcoded Authorization header value",
		Regex:       `(?i)['"]?authorization['"]?\s*[:=,]\s*['"](?:Basic|Bearer|Token)\s+([A-Za-z0-9_\-+/=.]{16,})['"]`,
		SecretGroup: 1, MinEntropy: 3.0, Severity: "high", Keywords: []string{"authorization"},
		RequireContext: true,
		Tags:           []string{"auth"}, Allowlist: []string{commonPlaceholder},
	},
	{
		ID: "generic-assigned-secret", Description: "Secret-like value assigned to a sensitive identifier",
		Regex:       `(?i)\b([a-z0-9_.\-]{0,24}(?:api[_.\-]?key|apikey|secret|token|passwd|password|credential|client[_.\-]?secret|private[_.\-]?key|auth[_.\-]?key|access[_.\-]?key|session[_.\-]?key|encryption[_.\-]?key))['"]?\s*(?:[:=]|=>|,)\s*['"]([^'"\n]{10,120})['"]`,
		SecretGroup: 2, MinEntropy: 3.2, MinLength: 10, Severity: "medium",
		Keywords:       []string{"key", "secret", "token", "password", "passwd", "credential", "auth"},
		RequireContext: true,
		Tags:           []string{"generic"},
		Allowlist: []string{
			commonPlaceholder,
			`^[A-Za-z0-9_.\-]+\.(png|jpg|xml|json|java|kt|so|txt|html?)$`,
			`^(true|false|null|none|nil|undefined|enabled|disabled)$`,
			`^\d+$`,
			`^(android|com|org|io|net)\.[a-z0-9_.]+$`,
			`^@(string|id|drawable|style|color)/`,
		},
	},
	{
		ID: "android-strings-xml-secret", Description: "Secret-named value in Android string resources",
		Regex:       `(?i)<string\s+name="([a-z0-9_]*(?:api[_-]?key|secret|token|password|client[_-]?id|app[_-]?key)[a-z0-9_]*)"[^>]*>([^<]{8,})</string>`,
		SecretGroup: 2, MinEntropy: 2.8, Severity: "high",
		PathInclude: `(?i)(strings\.xml|values[^/]*/.*\.xml)$`,
		Keywords:    []string{"<string"}, Tags: []string{"android"},
		Allowlist: []string{commonPlaceholder, `^@`},
	},
	{
		ID: "smali-const-string-secret", Description: "Secret assigned into a sensitive-looking smali field",
		Regex:       `(?i)const-string\s+[vp]\d+,\s+"([A-Za-z0-9+/=_\-]{20,})"`,
		SecretGroup: 1, MinEntropy: 4.0, MinLength: 20, Severity: "low",
		RequireContext: true,
		PathInclude:    `\.smali$`, Keywords: []string{"const-string"}, Tags: []string{"android"},
		Allowlist: []string{commonPlaceholder, `^[a-z]+(\.[a-z0-9_]+){2,}$`},
	},
	{
		ID: "hardcoded-iv-or-key-bytes", Description: "Hardcoded crypto key/IV literal",
		Regex:       `(?i)\b(?:secret|iv|key)(?:Spec|Bytes|Material)?\s*[:=]\s*['"]([A-Za-z0-9+/=]{16,64})['"]`,
		SecretGroup: 1, MinEntropy: 3.0, Severity: "medium",
		RequireContext: true,
		Keywords:       []string{"secretkey", "ivspec", "keyspec", "iv =", "iv=", "key ="}, Tags: []string{"crypto"},
	},
}
