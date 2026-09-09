// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package redact removes credentials from a message before the agent sees it.
//
// This is the connector's job and not the skill's, for two reasons. It must
// hold even when the model has been talked into something, and a deterministic
// filter is auditable in a way that a sentence in a prompt is not.
//
// The attack it defeats is not persuasion, it is arithmetic: trigger a
// password reset on some service, wait for the mail to land, then get the
// agent to read the code out. Nothing about that requires the agent to
// misbehave, so nothing about the defence can depend on it behaving.
//
// The rule is to replace, never to delete. An agent handed a blank body will
// try to work out what the message was; an agent handed
// "[one-time code removed]" knows it was a login mail and moves on.
package redact

import (
	"fmt"
	"regexp"
	"strings"
)

// Result is the cleaned text and what was taken out of it.
type Result struct {
	Text  string
	Count int
	Kinds []string
}

type rule struct {
	name        string
	re          *regexp.Regexp
	replacement string
	// group is the submatch to replace; 0 means the whole match.
	group int
}

var rules = []rule{
	// A one-time code, named as such by the words around it. Anchoring on the
	// LABEL rather than on "a number of 6 digits" is what keeps invoice
	// totals, phone numbers and years out of the filter.
	// The code itself is matched CASE-SENSITIVELY, with (?-i:…) inside an
	// otherwise case-insensitive rule. Without that the alphanumeric branch
	// matches any lowercase word, so "Ihr Bestätigungscode lautet 220044"
	// redacted the word "lautet" and left the code standing.
	//
	// The gap between label and code allows the small filler verbs, because
	// "your verification code is 483920" is the ordinary phrasing and a
	// separator class of non-alphanumerics never reaches past the "is".
	{
		name:        "one-time-code",
		re:          regexp.MustCompile(`(?i)\b(?:one[- ]?time (?:code|password|passcode|pin)|verification code|security code|confirmation code|auth(?:entication)? code|access code|login code|OTP|2FA code|code de v[ée]rification|code de s[ée]curit[ée]|code d'acc[èe]s|code de connexion|Best[äa]tigungscode|Sicherheitscode|c[oó]digo de verificaci[oó]n)\b(?:\s+(?:is|ist|est|lautet|es|sind|sera))?[\s:=.\-]{0,4}((?-i:[0-9]{4,10}|[0-9A-Z]{4,10}))`),
		replacement: "[one-time code removed]",
		group:       1,
	},
	// A bare "code:" with an explicit separator. Word-bounded, so "postcode:"
	// and "barcode:" do not match.
	{
		name:        "one-time-code",
		re:          regexp.MustCompile(`(?i)\bcode\b\s*[:=]\s*((?-i:[0-9]{4,10}|[0-9A-Z]{4,10}))`),
		replacement: "[one-time code removed]",
		group:       1,
	},
	// The same thing the other way round: the code first, the label after.
	{
		name:        "one-time-code",
		re:          regexp.MustCompile(`(?i)\b([0-9]{4,8})\s+(?:is your|est votre|ist Ihr|es tu)\b[^.\n]{0,40}\b(?:code|password|passcode|pin|mot de passe)\b`),
		replacement: "[one-time code removed]",
		group:       1,
	},
	// A password quoted in the body. Rare, and catastrophic when it happens.
	{
		name:        "password",
		re:          regexp.MustCompile(`(?i)\b(?:password|passwort|mot de passe|contrase[ñn]a)\b\s*[:=]\s*(\S{6,64})`),
		replacement: "[password removed]",
		group:       1,
	},
	// A reset or magic link. Matched on the PATH, so an ordinary link to the
	// same host survives: the dangerous thing is the token in the URL, and
	// the path is what says the URL carries one.
	{
		name:        "auth-link",
		re:          regexp.MustCompile(`(?i)https?://[^\s<>"']*\b(?:reset[-_]?password|password[-_]?reset|forgot[-_]?password|set[-_]?password|magic[-_]?link|verify[-_]?email|email[-_]?verif\w*|confirm[-_]?email|activate[-_]?account|one[-_]?time[-_]?login|passwordless|signin[-_]?link|login[-_]?link|auth[/_-]callback|reinitialiser[-_]?mot[-_]?de[-_]?passe)\b[^\s<>"']*`),
		replacement: "[login link removed]",
	},
	// A one-click ACCOUNT ACTION link.
	//
	// Found by running a real inbox through the connector, not by thinking
	// about it: a Google security alert carries
	// accounts.google.com/AccountDisavow?adt=<token>, which takes an
	// irreversible action on the account in one click and which none of the
	// rules above matched. The dangerous links are not only the ones that log
	// you in; they are the ones that DO something.
	{
		name: "account-action-link",
		// No leading \b: the verb is often glued to another word in a path,
		// as in /AccountDisavow, so a word boundary before it never matches.
		re:          regexp.MustCompile(`(?i)https?://[^\s<>"']*(?:disavow|remove[-_]?account|close[-_]?account|delete[-_]?account|deactivate|revoke[-_]?(?:access|session|token|device)|report[-_]?(?:fraud|abuse)|confirm[-_]?(?:transfer|payment|transaction)|approve[-_]?(?:device|login|request))[^\s<>"']*`),
		replacement: "[account action link removed]",
	},
	// A URL carrying something that looks like a bearer token, whatever the
	// path says. Bounded to long high-entropy-ish values so ordinary query
	// strings are left alone.
	{
		name:        "token-link",
		re:          regexp.MustCompile(`(?i)https?://[^\s<>"']*[?&](?:token|access_token|id_token|auth|key|secret|otp|code|nonce|signature|sig|adt|confirmation)=[A-Za-z0-9._~+/=-]{20,}[^\s<>"']*`),
		replacement: "[link with a token removed]",
	},
	// Bearer tokens and API keys pasted into a body.
	{
		name:        "bearer",
		re:          regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}`),
		replacement: "[token removed]",
	},
	{
		name:        "api-key",
		re:          regexp.MustCompile(`\b(?:sk|pk|rk|api|ghp|gho|ghs|ghu|xoxb|xoxp|AKIA)[-_][A-Za-z0-9]{16,}\b`),
		replacement: "[api key removed]",
	},
	// A private key block. If one of these is ever in a mailbox the day is
	// already bad, but it must not also reach a model.
	{
		name:        "private-key",
		re:          regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
		replacement: "[private key removed]",
	},
}

// Apply strips credentials from body text.
//
// It is intentionally not clever. A classifier belongs after this, catching
// what patterns miss, but the deterministic pass runs first and alone is
// enough for the common shapes, and it can be read and argued with.
func Apply(s string) Result {
	if s == "" {
		return Result{}
	}
	seen := map[string]bool{}
	count := 0

	for _, r := range rules {
		s = replaceGroup(s, r, func() { count++; seen[r.name] = true })
	}

	kinds := make([]string, 0, len(seen))
	for k := range seen {
		kinds = append(kinds, k)
	}
	// Stable order so a digest or a test does not depend on map iteration.
	for i := 0; i < len(kinds); i++ {
		for j := i + 1; j < len(kinds); j++ {
			if kinds[j] < kinds[i] {
				kinds[i], kinds[j] = kinds[j], kinds[i]
			}
		}
	}
	return Result{Text: s, Count: count, Kinds: kinds}
}

// replaceGroup replaces either the whole match or one submatch, so a rule can
// keep the words around a code ("Your verification code is [removed]") while
// removing only the code. Losing the surrounding sentence would tell the agent
// less, not more.
func replaceGroup(s string, r rule, onHit func()) string {
	locs := r.re.FindAllStringSubmatchIndex(s, -1)
	if locs == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range locs {
		start, end := m[0], m[1]
		if r.group > 0 && len(m) > 2*r.group+1 && m[2*r.group] >= 0 {
			start, end = m[2*r.group], m[2*r.group+1]
		}
		if start < last {
			continue // overlapping match already handled
		}
		b.WriteString(s[last:start])
		b.WriteString(r.replacement)
		last = end
		onHit()
	}
	b.WriteString(s[last:])
	return b.String()
}

// Summary is a one-line note for the agent, so a redacted message reads as a
// login mail rather than as a message with a hole in it.
func (r Result) Summary() string {
	if r.Count == 0 {
		return ""
	}
	return fmt.Sprintf("[%d credential(s) removed by the connector before this reached the agent: %s]",
		r.Count, strings.Join(r.Kinds, ", "))
}
