// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package vtt reads WebVTT, the one format every meeting platform can hand
// a transcript over in, and turns it into speaker-attributed text.
//
// Two dialects matter. Microsoft Teams names the speaker with a voice tag,
// `<v Jane Doe>text</v>`, as the WebVTT specification has it. Zoom writes
// the speaker into the cue text as a prefix, `Jane Doe: text`. Both are
// read here, so a connector never has to know which platform produced the
// file to say who said what.
//
// The text an agent reads is merged: consecutive cues by the same speaker
// become one paragraph, timed at the first cue, because a transcript cut
// into three-second lines is three times as many tokens for no more
// meaning.
package vtt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// Cue is one timed line of the transcript.
type Cue struct {
	// ID is the optional identifier line above the timing, empty when the
	// file has none.
	ID    string
	Start time.Duration
	End   time.Duration
	// Speaker is who said it, when the file says; empty otherwise.
	Speaker string
	Text    string
}

// Transcript is the parsed file.
type Transcript struct {
	Cues []Cue
}

// ErrNotVTT is a file that does not start with the WEBVTT signature.
var ErrNotVTT = errors.New("not a WebVTT file: it does not begin with WEBVTT")

// maxBytes bounds what is parsed. A transcript of a day-long meeting is
// well under a megabyte; anything larger is not a transcript.
const maxBytes = 16 << 20

var (
	timingRe = regexp.MustCompile(`^\s*(\S+)\s+-->\s+(\S+)(?:\s.*)?$`)
	voiceRe  = regexp.MustCompile(`^<v(?:\.[^\s>]*)?\s+([^>]*)>`)
	tagRe    = regexp.MustCompile(`<[^>]*>`)
	// A Zoom-style speaker prefix: a short run of name characters, then a
	// colon and a space. Bounded so a sentence with a colon in it is not
	// mistaken for a speaker.
	prefixRe = regexp.MustCompile(`^([^:\n]{1,64}?):\s+(.*)$`)
)

// Parse reads a WebVTT document.
func Parse(r io.Reader) (*Transcript, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, fmt.Errorf("the transcript is larger than %d bytes", maxBytes)
	}
	return ParseBytes(raw)
}

// ParseBytes reads a WebVTT document held in memory.
func ParseBytes(raw []byte) (*Transcript, error) {
	text := strings.TrimPrefix(string(raw), "\xef\xbb\xbf")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	if !strings.HasPrefix(text, "WEBVTT") {
		return nil, ErrNotVTT
	}

	t := &Transcript{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64<<10), maxBytes)

	// The header block runs to the first blank line; everything after is
	// blocks separated by blank lines. A block whose first or second line
	// is a timing is a cue; NOTE, STYLE and REGION blocks are skipped.
	var block []string
	inHeader := true
	flush := func() {
		if len(block) > 0 && !inHeader {
			if c, ok := cueOf(block); ok {
				t.Cues = append(t.Cues, c)
			}
		}
		block = block[:0]
		inHeader = false
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		block = append(block, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return t, nil
}

// cueOf reads one block as a cue, or reports that it is not one.
func cueOf(lines []string) (Cue, bool) {
	var c Cue
	i := 0
	if !timingRe.MatchString(lines[0]) {
		if len(lines) < 2 || !timingRe.MatchString(lines[1]) {
			return Cue{}, false
		}
		c.ID = strings.TrimSpace(lines[0])
		i = 1
	}
	m := timingRe.FindStringSubmatch(lines[i])
	start, err1 := parseTimestamp(m[1])
	end, err2 := parseTimestamp(m[2])
	if err1 != nil || err2 != nil {
		return Cue{}, false
	}
	c.Start, c.End = start, end

	body := strings.Join(lines[i+1:], "\n")
	if v := voiceRe.FindStringSubmatch(body); v != nil {
		c.Speaker = strings.TrimSpace(v[1])
	}
	body = tagRe.ReplaceAllString(body, "")
	body = strings.TrimSpace(unescape(body))
	if c.Speaker == "" {
		if p := prefixRe.FindStringSubmatch(body); p != nil && looksLikeName(p[1]) {
			c.Speaker, body = strings.TrimSpace(p[1]), strings.TrimSpace(p[2])
		}
	}
	c.Text = body
	return c, true
}

// looksLikeName refuses a speaker prefix that reads like the start of a
// sentence or a URL: a scheme, or a label with no letter in it.
func looksLikeName(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "http") || strings.Contains(s, "/") {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r > 127 {
			return true
		}
	}
	return false
}

func unescape(s string) string {
	return strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&nbsp;", " ", "&quot;", `"`).Replace(s)
}

// parseTimestamp reads hh:mm:ss.mmm or mm:ss.mmm.
func parseTimestamp(s string) (time.Duration, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, fmt.Errorf("bad timestamp %q", s)
	}
	var h, m int
	var sec float64
	var err error
	if len(parts) == 3 {
		if _, err = fmt.Sscanf(parts[0], "%d", &h); err != nil {
			return 0, fmt.Errorf("bad timestamp %q", s)
		}
		parts = parts[1:]
	}
	if _, err = fmt.Sscanf(parts[0], "%d", &m); err != nil {
		return 0, fmt.Errorf("bad timestamp %q", s)
	}
	if _, err = fmt.Sscanf(strings.Replace(parts[1], ",", ".", 1), "%f", &sec); err != nil {
		return 0, fmt.Errorf("bad timestamp %q", s)
	}
	return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(sec*float64(time.Second)), nil
}

// Speakers lists who spoke, in order of first appearance. A cue without a
// speaker contributes nothing.
func (t *Transcript) Speakers() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range t.Cues {
		if c.Speaker == "" || seen[c.Speaker] {
			continue
		}
		seen[c.Speaker] = true
		out = append(out, c.Speaker)
	}
	return out
}

// Duration is the end of the last cue.
func (t *Transcript) Duration() time.Duration {
	var d time.Duration
	for _, c := range t.Cues {
		if c.End > d {
			d = c.End
		}
	}
	return d
}

// Paragraph is a run of consecutive cues by one speaker.
type Paragraph struct {
	Start   time.Duration
	Speaker string
	Text    string
}

// Paragraphs merges consecutive cues by the same speaker. A cue with no
// speaker joins the paragraph before it when that one has none either, and
// otherwise starts a paragraph of its own, so an unattributed line is never
// put into someone's mouth.
func (t *Transcript) Paragraphs() []Paragraph {
	var out []Paragraph
	for _, c := range t.Cues {
		if c.Text == "" {
			continue
		}
		if n := len(out); n > 0 && out[n-1].Speaker == c.Speaker {
			out[n-1].Text += " " + c.Text
			continue
		}
		out = append(out, Paragraph{Start: c.Start, Speaker: c.Speaker, Text: c.Text})
	}
	return out
}

// Text is the transcript as an agent reads it: one line per paragraph,
// `[hh:mm:ss] Speaker: text`, the speaker omitted when unknown.
func (t *Transcript) Text() string {
	var b strings.Builder
	for _, p := range t.Paragraphs() {
		b.WriteString("[" + Clock(p.Start) + "] ")
		if p.Speaker != "" {
			b.WriteString(p.Speaker + ": ")
		}
		b.WriteString(p.Text)
		b.WriteString("\n")
	}
	return b.String()
}

// Clock formats an offset as hh:mm:ss.
func Clock(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d / time.Hour)
	m := int(d/time.Minute) % 60
	s := int(d/time.Second) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}
