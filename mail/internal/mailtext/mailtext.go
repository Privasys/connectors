// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package mailtext turns one fetched MIME part into the sender's own words.
//
// Every rule here was learned by running the spike against a real mailbox of
// 11,000 sent messages, and the comments say which, because each one looks
// like a detail and is worth a measurable slice of the corpus.
package mailtext

import (
	"bytes"
	"encoding/base64"
	"html"
	"io"
	"mime/quotedprintable"
	"regexp"
	"strings"

	"github.com/emersion/go-message/charset"
)

// Decode transfer-decodes a part and converts its charset.
//
// Neither step is optional. Quoted-printable leaves "=20" and "=C3=A9" all
// over French mail, in text whose whole purpose is to show how someone writes.
func Decode(raw []byte, encoding, charsetName string) string {
	var r io.Reader = bytes.NewReader(raw)
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, r)
	}
	decoded, err := io.ReadAll(r)
	if err != nil && len(decoded) == 0 {
		return ""
	}
	cs := strings.ToLower(strings.TrimSpace(charsetName))
	if cs != "" && cs != "utf-8" && cs != "utf8" && cs != "us-ascii" && cs != "ascii" {
		if cr, err := charset.Reader(cs, bytes.NewReader(decoded)); err == nil {
			if converted, err := io.ReadAll(cr); err == nil {
				decoded = converted
			}
		}
	}
	return string(decoded)
}

var (
	htmlBreak = regexp.MustCompile(`(?i)<(?:br|/p|/div|/tr|/li|/h[1-6])\b[^>]*>`)
	// Enumerated rather than back-referenced: Go's regexp is RE2, which has no
	// backreferences, so `<(script|style)…</\1>` does not compile.
	htmlDrop    = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>|<head\b[^>]*>.*?</head>`)
	htmlTag     = regexp.MustCompile(`(?s)<[^>]*>`)
	trailingWSp = regexp.MustCompile(`(?m)[ \t]+$`)
	blankRuns   = regexp.MustCompile(`\n{3,}`)
)

// HTMLToText is deliberately small. A style corpus and a triage summary need
// the words and the shape of the paragraphs, not a faithful render, and a full
// parser here would be a dependency with its own failure modes for no gain.
//
// It is not optional either: 25 of 200 real sent messages had no plain-text
// part at all, so a plain-only reader silently drops an eighth of a mailbox,
// and not a random eighth — whatever the user writes from an HTML-only client.
func HTMLToText(s string) string {
	s = htmlDrop.ReplaceAllString(s, "")
	s = htmlBreak.ReplaceAllString(s, "\n")
	s = htmlTag.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = strings.ReplaceAll(s, " ", " ")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = trailingWSp.ReplaceAllString(s, "")
	return strings.TrimSpace(blankRuns.ReplaceAllString(s, "\n\n"))
}

var (
	quoteLine = regexp.MustCompile(`(?m)^\s*>`)
	// Anchored on the TERMINATOR, not on the whole line.
	//
	// The first version required "On <=120 chars> wrote:" on a single line and
	// missed 26 of 178 real messages, because the attribution wraps:
	//   On Mon, 8 Sep 2026 at 14:32, Some Person
	//   <someone@a-long-domain.example> wrote:
	// Too long for the bound, and split so "On" and "wrote:" are not even on
	// the same line.
	attribEnd  = regexp.MustCompile(`(?mi)^.*(?:\bwrote:|\ba écrit\s*:|\bschrieb:|\bha escrito:|\bha scritto:)\s*$`)
	forwardSep = regexp.MustCompile(`(?mi)^\s*(?:-{2,}\s*(?:Original Message|Forwarded message|Message d'origine|Ursprüngliche Nachricht)|_{5,}|-{5,})`)
	sigSep     = regexp.MustCompile(`(?m)^-- $`)
)

// OwnText keeps only what the sender typed: everything before the first quoted
// history, with the signature block removed.
//
// An empty result is a legitimate answer, not a failure. 22 of 200 real sent
// messages came back empty and 20 of those were forwards sent with no comment
// added, so 89% of a mailbox carries the sender's own words and 11% does not.
func OwnText(body string) string {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	cut := len(body)

	if loc := attribEnd.FindStringIndex(body); loc != nil {
		// Cut from the start of the attribution's PARAGRAPH, so a wrapped
		// attribution goes whole rather than leaving its first line behind.
		if p := paragraphStart(body, loc[0]); p < cut {
			cut = p
		}
	}
	for _, re := range []*regexp.Regexp{forwardSep, quoteLine} {
		if loc := re.FindStringIndex(body); loc != nil && loc[0] < cut {
			cut = loc[0]
		}
	}
	text := body[:cut]
	if loc := sigSep.FindStringIndex(text); loc != nil {
		text = text[:loc[0]]
	}
	return strings.TrimSpace(blankRuns.ReplaceAllString(text, "\n\n"))
}

func paragraphStart(s string, at int) int {
	if at <= 0 || at > len(s) {
		return 0
	}
	if i := strings.LastIndex(s[:at], "\n\n"); i >= 0 {
		return i + 1
	}
	if i := strings.LastIndex(s[:at], "\n"); i >= 0 {
		return i + 1
	}
	return 0
}

// Snippet is the one-line preview a listing shows.
func Snippet(text string, max int) string {
	f := strings.Join(strings.Fields(strings.ReplaceAll(text, "\n", " ")), " ")
	if len(f) <= max {
		return f
	}
	cut := max
	if i := strings.LastIndex(f[:max], " "); i > max/2 {
		cut = i
	}
	return strings.TrimSpace(f[:cut]) + "…"
}

// The marker may sit anywhere in the local part, not just at the start: a
// real listing turned up CloudPlatform-noreply.com, which an anchored
// pattern reported as repliable. Bounded by a separator so an ordinary name
// containing one of these strings is not caught.
var noReply = regexp.MustCompile(`(?i)(?:^|[._+-])(?:no[-_.]?reply|do[-_.]?not[-_.]?reply|noreply|donotreply|bounce|mailer[-_.]?daemon|postmaster|notifications?|alerts?|automated?|auto[-_.]?confirm|nepasrepondre|ne[-_.]?pas[-_.]?repondre)\b`)

// Repliable reports whether a human reads that address.
//
// This exists because of a real incident, not a hypothetical: the first draft
// the spike ever produced was a reply to a Google security alert from
// no-reply@accounts.google.com. Drafting to an address nobody reads wastes the
// user's attention and makes the agent look stupid, which is its own cost.
func Repliable(addr string) bool {
	at := strings.IndexByte(addr, '@')
	if at <= 0 {
		return false
	}
	return !noReply.MatchString(addr[:at])
}
