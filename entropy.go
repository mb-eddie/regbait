package main

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// ShannonEntropy returns the Shannon entropy of s in bits per character.
// Reference points for random data: hex ~4.0, base64 ~6.0, printable ASCII ~6.5.
// Short strings cannot reach the theoretical maximum because entropy is bounded
// by log2(len(s)), so callers should also enforce a minimum length.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	n := 0
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
		n++
	}
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// NormalizedEntropy scales entropy against the maximum achievable for a string
// of this length, which removes the length bias from raw Shannon entropy.
func NormalizedEntropy(s string) float64 {
	if len(s) < 2 {
		return 0
	}
	max := math.Log2(float64(len(s)))
	if max == 0 {
		return 0
	}
	return ShannonEntropy(s) / max
}

type Charset int

const (
	CharsetOther Charset = iota
	CharsetHex
	CharsetBase64
	CharsetAlnum
)

func (c Charset) String() string {
	switch c {
	case CharsetHex:
		return "hex"
	case CharsetBase64:
		return "base64"
	case CharsetAlnum:
		return "alnum"
	}
	return "other"
}

// ClassifyCharset reports the tightest character class that contains s.
func ClassifyCharset(s string) Charset {
	hex, b64, alnum := true, true, true
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		isAlnum := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isB64 := isAlnum || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
		if !isHex {
			hex = false
		}
		if !isAlnum {
			alnum = false
		}
		if !isB64 {
			b64 = false
		}
	}
	switch {
	case hex:
		return CharsetHex
	case alnum:
		return CharsetAlnum
	case b64:
		return CharsetBase64
	}
	return CharsetOther
}

// --- noise heuristics -------------------------------------------------------

var (
	// com.example.foo.Bar — Java/Kotlin package or class reference.
	reClassName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_$]*(\.[A-Za-z][A-Za-z0-9_$]*){2,}$`)
	// res/drawable/icon.png, /system/lib/libc.so, a.b.c/d
	reFilePath = regexp.MustCompile(`(?i)^[A-Za-z0-9_./$-]+\.(png|jpe?g|webp|gif|svg|xml|json|java|kt|smali|dex|so|ttf|otf|html?|js|css|txt|properties|pro|md|yml|yaml|cfg|ini|dat|bin|arsc|mp[34]|ogg|wav)$`)
	// android.intent.action.VIEW style constants
	reDottedConst = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+){2,}$`)
	// #AARRGGBB / 0xDEADBEEF literals
	reColorOrHexLit = regexp.MustCompile(`^(#|0[xX])[0-9a-fA-F]+$`)
	// Template placeholders: ${FOO}, {{foo}}, %s, <your-key>
	rePlaceholder = regexp.MustCompile(`(?i)(\$\{|\{\{|%[sdv]|<[a-z_-]+>|\bYOUR[_-]|\bINSERT[_-]|\bREPLACE[_-]|XXXX|\.\.\.|EXAMPLE|SAMPLE|PLACEHOLDER|DUMMY|CHANGE[_-]?ME|TODO|FAKE|NOT[_-]?A[_-]?REAL|TEST[_-]?KEY|DEADBEEF)`)
	// Anything with whitespace or many spaces is prose, not a key.
	reHasSpace = regexp.MustCompile(`\s`)
	// Android resource identifiers used heavily in smali.
	reResID = regexp.MustCompile(`^(R\$?[a-z]+|@(id|string|drawable|style|color|layout|dimen|attr)/.*)$`)
	// UUID — usually an identifier, not a secret, unless keyword context says so.
	reUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// LooksLikeNoise applies cheap structural heuristics to reject the string
// literals that dominate decompiled Android output. It deliberately errs toward
// rejecting: rule-based matches bypass this, only the generic entropy detector
// relies on it.
func LooksLikeNoise(s string) bool {
	if len(s) < 8 {
		return true
	}
	if reHasSpace.MatchString(s) {
		return true
	}
	if rePlaceholder.MatchString(s) {
		return true
	}
	if isRepeatedUnit(s) {
		return true
	}
	if reClassName.MatchString(s) || reDottedConst.MatchString(s) {
		return true
	}
	if reFilePath.MatchString(s) {
		return true
	}
	if reColorOrHexLit.MatchString(s) {
		return true
	}
	if reResID.MatchString(s) {
		return true
	}
	// A URL with no embedded credentials is an endpoint, not a secret.
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if !strings.Contains(s[8:], "@") {
			return true
		}
	}
	// Mostly punctuation or non-ASCII is almost never a credential.
	printable := 0
	for _, r := range s {
		if r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			printable++
		}
	}
	if float64(printable)/float64(len([]rune(s))) < 0.7 {
		return true
	}
	// Needs at least one digit and one letter; pure-word strings are English.
	hasDigit, hasAlpha := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			hasDigit = true
		} else if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasAlpha = true
		}
	}
	return !(hasDigit && hasAlpha)
}

// isRepeatedUnit reports whether s is a short unit repeated at least four
// times (aaaaaa, 010101, abcabcabcabc). RE2 has no backreferences, so this
// replaces the `^(.{1,4}?)\1{3,}$` pattern a PCRE engine would use.
func isRepeatedUnit(s string) bool {
	for unit := 1; unit <= 4 && unit*4 <= len(s); unit++ {
		if len(s)%unit != 0 {
			continue
		}
		if len(s)/unit < 4 {
			continue
		}
		ok := true
		for i := unit; i < len(s) && ok; i++ {
			if s[i] != s[i%unit] {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// IsUUID is exported separately so rules can opt in to UUID-shaped secrets
// (Heroku, some Azure keys) while the generic detector skips them.
func IsUUID(s string) bool { return reUUID.MatchString(s) }
