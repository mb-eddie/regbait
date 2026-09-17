# regbait

Secret hunting for decompiled APK trees. Pure Go, zero dependencies, single binary.

Point it at jadx or apktool output and it walks the whole tree, applies 45 provider-specific
rules plus a context-gated entropy detector, and ranks what it finds by severity.

```
go build -o regbait .
./regbait ./jadx-out
```

## Why the entropy detector is gated

Plain entropy scanning does not work on Android. ProGuard/R8 identifiers, resource hashes and
obfuscated string tables are *genuinely* high-entropy — they are indistinguishable from a real
API key by any statistical test. On a 240k-line smali tree containing exactly one planted
secret, an ungated scanner produced **107,808 findings**. The same tree with proximity gating
produces **1**.

The gate: a generic high-entropy candidate is only reported if a credential keyword
(`apiKey`, `secret`, `Authorization`, `keystore`, `hmac`, …) appears within N lines of it.
Real secrets live next to the code that uses them; obfuscated garbage does not. Precise
rules (`AIza…`, `ghp_…`, `sk_live_…`) are never gated — they are specific enough on their own.

Two further backstops: any file emitting more than `--max-generic-per-file` generic findings is
treated as obfuscated and its generic hits are dropped wholesale, and a global
`--max-generic-total` budget keeps only the highest-entropy remainder.

## What it detects

**Cloud / infra** — Google API keys, GCP OAuth secrets, service-account JSON, Firebase DB URLs,
FCM server keys, AWS access keys + secret keys + session tokens, Azure storage connection
strings and SAS tokens.

**Source control / CI** — GitHub PATs (classic + fine-grained), GitLab tokens, npm tokens.

**Payments** — Stripe, Square, Braintree/PayPal.

**Comms / SaaS** — Slack tokens and webhooks, Discord bot tokens and webhooks, Telegram,
Twilio, SendGrid, Mailgun, Mailchimp, Algolia, Pusher, Branch.io, Cloudinary, Facebook.

**AI providers** — OpenAI, Anthropic, Hugging Face.

**Generic credential material** — PEM private key blocks, JWTs, credentials embedded in URLs,
DB connection strings, hardcoded `Authorization` headers, keystore/signing passwords in
`.gradle`/`.properties`, hardcoded crypto keys and IVs.

**Android-specific** — secret-named values in `strings.xml`, `const-string` literals assigned
into credential-named smali fields.

## Usage

```bash
regbait ./out                                     # standard scan
regbait --redact --format json --out f.json ./out # safe to share
regbait --min-severity high ./out                 # only what matters
regbait --binaries ./out                          # also scan .so/.dex strings
regbait --decode-base64 ./out                     # unwrap base64-hidden keys
regbait --baseline known.json ./out               # only show new findings
regbait --only google-api-key,aws-access-key-id ./out
regbait --list-rules
```

Formats: `text` (default), `json`, `csv`, `sarif`. SARIF drops straight into GitHub code
scanning or DefectDojo.

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`), `2` error.
Use `--fail-on never` to always exit 0.

### Tuning noise

| Flag | Default | Effect |
|---|---|---|
| `--context-window` | 3 | Lines either side searched for a credential keyword |
| `--no-context-gate` | off | Report every high-entropy string. Expect thousands on obfuscated code |
| `--max-generic-per-file` | 10 | Files above this have generic findings dropped entirely |
| `--max-generic-total` | 200 | Global cap, highest entropy kept |
| `--entropy-b64` / `--entropy-hex` | 4.3 / 3.3 | Shannon bits-per-char thresholds |
| `--no-collapse` | off | Keep generic hits even when a precise rule matched the same value |
| `--no-entropy` | off | Rules only |

If you suspect something was suppressed, the report tells you how much and from which files.
Re-run those with `--include-path` and `--no-context-gate`.

### Custom rules

```json
{"extend": true, "rules": [
  {"id": "acme-key",
   "description": "ACME internal key",
   "regex": "\\bACME-[A-Z0-9]{24}\\b",
   "severity": "critical",
   "keywords": ["acme-"],
   "min_entropy": 3.0,
   "require_context": false,
   "path_include": "\\.(java|smali|xml)$",
   "allowlist": ["(?i)example|test"]}
]}
```

`regbait --rules pack.json ./out`. Set `"extend": false` to replace the built-ins entirely.

Fields: `regex` (RE2 — **no lookarounds or backreferences**), `secret_group` (capture group
holding the secret, default 0), `keywords` (cheap substring prefilter), `min_entropy`,
`min_length`, `severity`, `allowlist`, `path_include`, `path_exclude`, `require_context`, `tags`.

## Design notes

- **Two-stage keyword matching.** A handful of SIMD-backed `strings.Contains` checks reject
  most lines before the word-bounded alternation runs. This alone took the 240k-line scan from
  6.0s to 1.2s.
- **Fingerprints ignore line numbers** (`sha256(rule|file|secret)`), so baselines survive
  edits above the finding.
- **Long lines are windowed with overlap**, so a key in minified JS or packed smali is still
  found at any offset.
- **Cross-rule collapsing.** When a precise rule and a generic one match the same value at the
  same place, only the precise one is reported.
- Files are read whole when under `--max-in-memory` (16 MB) so proximity context works in both
  directions; larger files stream with generic detectors off.
- Binaries are scanned by extracting printable runs, which are kept adjacent so proximity
  context still applies.

## Testing

```
go test ./...            # unit + integration
go test -race ./...
go test -bench=. ./...
```

Covers entropy maths, noise heuristics, rule compilation (including rejection of duplicate IDs
and out-of-range capture groups), placeholder suppression, the AWS documentation-key allowlist,
base64 unwrapping, binary extraction, redaction, long-line windowing, custom rule packs and
baseline behaviour.

## Scope

This finds *hardcoded* secrets in static output. It does not attempt runtime extraction,
native-code decompilation, or validation that a key is live — and you should not test keys
against provider APIs on engagements without authorisation covering that.

Findings are candidates, not conclusions. Triage top-down: `CRITICAL` provider-specific hits
first, generic entropy hits last.
