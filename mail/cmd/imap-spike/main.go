// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// imap-spike answers the questions the inbox-agent plan (§6 spike 2) needs
// answered against a real Gmail mailbox before the IMAP driver is written:
//
//	probe   Can we connect, and what do the folders look like?
//	sent    Can we read the user's own outbound text, cleanly enough to learn
//	        a writing style from it? (plan §4, the style corpus)
//	draft   Does a draft written with APPEND thread correctly in the Gmail UI,
//	        and does our marker header survive the round trip?
//	label   Can a label be applied without any Gmail-specific extension?
//	        (CREATE + COPY: Gmail renders an IMAP folder as a label, so this
//	        is ordinary IMAP that happens to do the Gmail thing.)
//	verify  Re-read what draft wrote and report what actually persisted.
//
// It is a throwaway harness that will become the seed of the driver. It never
// deletes mail, never sends, and never prints the password.
//
// Credentials come from a JSON file OUTSIDE this repository, so that no secret
// is ever pasted into a terminal, a transcript, or a commit:
//
//	{"host":"imap.gmail.com:993","user":"you@gmail.com","password":"<app password>"}
//
// Path from $MAIL_SPIKE_CREDS, else ./mail-spike-creds.json.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"mime/quotedprintable"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/charset"
)

const (
	markerHeader = "X-Privasys-Draft"
	labelName    = "Privasys/needs-reply"
)

type creds struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
}

func loadCreds() (creds, error) {
	path := os.Getenv("MAIL_SPIKE_CREDS")
	if path == "" {
		path = "mail-spike-creds.json"
	}
	var c creds
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("read %s: %w (create it, or set MAIL_SPIKE_CREDS)", path, err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Host == "" {
		c.Host = "imap.gmail.com:993"
	}
	if c.User == "" || c.Password == "" {
		return c, fmt.Errorf("%s: user and password are both required", path)
	}
	return c, nil
}

func dial(c creds) (*imapclient.Client, error) {
	host := c.Host
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	cl, err := imapclient.DialTLS(c.Host, &imapclient.Options{
		TLSConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
	})
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", c.Host, err)
	}
	if err := cl.Login(c.User, c.Password).Wait(); err != nil {
		cl.Close()
		return nil, fmt.Errorf("login as %s: %w (for Gmail this must be an App Password, with 2-Step Verification on)", c.User, err)
	}
	return cl, nil
}

// ---------------------------------------------------------------- probe

func probe(cl *imapclient.Client) error {
	boxes, err := cl.List("", "*", nil).Collect()
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	fmt.Printf("%d mailboxes\n", len(boxes))
	var sent, drafts string
	for _, b := range boxes {
		var attrs []string
		for _, a := range b.Attrs {
			attrs = append(attrs, string(a))
			switch a {
			case imap.MailboxAttrSent:
				sent = b.Mailbox
			case imap.MailboxAttrDrafts:
				drafts = b.Mailbox
			}
		}
		fmt.Printf("  %-34s %s\n", b.Mailbox, strings.Join(attrs, ","))
	}
	fmt.Printf("\nSPECIAL-USE  \\Sent=%q  \\Drafts=%q\n", sent, drafts)
	if sent == "" || drafts == "" {
		fmt.Println("NOTE: a server without SPECIAL-USE needs the folder names configured per account.")
	}
	for _, name := range []string{"INBOX", sent, drafts} {
		if name == "" {
			continue
		}
		mbox, err := cl.Select(name, &imap.SelectOptions{ReadOnly: true}).Wait()
		if err != nil {
			fmt.Printf("  select %-24s ERROR %v\n", name, err)
			continue
		}
		fmt.Printf("  select %-24s %d messages\n", name, mbox.NumMessages)
	}
	return nil
}

// ---------------------------------------------------------------- sent

var (
	quoteLine = regexp.MustCompile(`(?m)^\s*>`)
	// The attribution line is matched by its ENDING, not its whole shape.
	// The first version required "On <=120 chars> wrote:" on one line, and
	// missed 26 of 178 real messages, because a real one reads
	//   On Mon, 8 Sep 2026 at 14:32, Some Person
	//   <someone@a-long-domain.example> wrote:
	// — too long for the bound, and wrapped across two lines so "On" and
	// "wrote:" are not even on the same one. Anchor on the terminator and then
	// walk back to the start of its paragraph.
	attribEnd  = regexp.MustCompile(`(?mi)^.*(\bwrote:|\ba écrit\s*:)\s*$`)
	forwardSep = regexp.MustCompile(`(?mi)^\s*(-{2,}\s*(Original Message|Forwarded message|Message d'origine)|_{5,})`)
)

// paragraphStart walks back from an offset to the start of its paragraph, so
// cutting removes a wrapped attribution line whole rather than leaving its
// first half behind.
func paragraphStart(s string, at int) int {
	if i := strings.LastIndex(s[:at], "\n\n"); i >= 0 {
		return i + 1
	}
	if i := strings.LastIndex(s[:at], "\n"); i >= 0 {
		return i + 1
	}
	return 0
}

// decodePart turns one fetched MIME leaf into text: transfer-decoded, then
// charset-converted. Both matter for a style corpus and neither is optional —
// quoted-printable would leave "=20" and "=C3=A9" all over French mail, which
// is precisely the writing we are trying to learn.
func decodePart(raw []byte, encoding, charsetName string) string {
	var r io.Reader = bytes.NewReader(raw)
	switch strings.ToLower(encoding) {
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, r)
	}
	decoded, err := io.ReadAll(r)
	if err != nil && len(decoded) == 0 {
		return ""
	}
	if charsetName != "" && !strings.EqualFold(charsetName, "utf-8") && !strings.EqualFold(charsetName, "us-ascii") {
		if cr, err := charset.Reader(charsetName, bytes.NewReader(decoded)); err == nil {
			if converted, err := io.ReadAll(cr); err == nil {
				decoded = converted
			}
		}
	}
	return string(decoded)
}

// ownText keeps only what the sender actually typed: everything before the
// first quote marker, with the signature block removed. Deliberately crude —
// the spike's question is whether the RESULT is good enough to learn a voice
// from, and that is a judgement to make on real output, not in advance.
func ownText(body string) string {
	cut := len(body)
	if loc := attribEnd.FindStringIndex(body); loc != nil {
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
	if i := strings.Index(text, "\n-- \n"); i >= 0 {
		text = text[:i]
	}
	return strings.TrimSpace(text)
}

// conn is a client that can be replaced under its holder. Long reads against
// a real mailbox lose the connection (see the note in sent), and every layer
// above has to keep working across that, so the reconnect lives here rather
// than being a special case inside one command.
type conn struct {
	creds   creds
	cl      *imapclient.Client
	box     string // re-selected after a reconnect
	redials int
}

func (cn *conn) reconnect() error {
	if cn.cl != nil {
		_ = cn.cl.Close()
	}
	cl, err := dial(cn.creds)
	if err != nil {
		return err
	}
	cn.cl = cl
	cn.redials++
	if cn.box != "" {
		if _, err := cl.Select(cn.box, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
			return fmt.Errorf("re-select %s: %w", cn.box, err)
		}
	}
	return nil
}

// fetchRange fetches lo..hi, reconnecting and retrying once. It reports
// whether the retry was needed so the caller can tell a dropped connection
// (retry succeeds) from a message the server will not serve (retry fails too).
func (cn *conn) fetchRange(lo, hi uint32, opts *imap.FetchOptions) ([]*imapclient.FetchMessageBuffer, error) {
	set := imap.SeqSetNum()
	set.AddRange(lo, hi)
	msgs, err := cn.cl.Fetch(set, opts).Collect()
	if err == nil {
		return msgs, nil
	}
	if rerr := cn.reconnect(); rerr != nil {
		return nil, fmt.Errorf("%w; reconnect failed: %v", err, rerr)
	}
	set2 := imap.SeqSetNum()
	set2.AddRange(lo, hi)
	return cn.cl.Fetch(set2, opts).Collect()
}

func sent(cn *conn, limit, batch, prefixBytes int, outDir string) error {
	name, err := specialUse(cn.cl, imap.MailboxAttrSent, "[Gmail]/Sent Mail")
	if err != nil {
		return err
	}
	mbox, err := cn.cl.Select(name, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return fmt.Errorf("select %s: %w", name, err)
	}
	if mbox.NumMessages == 0 {
		return fmt.Errorf("%s is empty", name)
	}
	cn.box = name
	from := uint32(1)
	if int(mbox.NumMessages) > limit {
		from = mbox.NumMessages - uint32(limit) + 1
	}
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o700); err != nil {
			return err
		}
	}

	// TWO PHASE, and the reason is worth keeping.
	//
	// The first cut asked for BODY.PEEK[TEXT]<0.16384> and one message in 200
	// refused to come back at all, twice, even alone: seq 11008, "unexpected
	// EOF". The obvious theory was size. It was wrong — inspect showed a
	// 2,382-byte message, multipart/mixed wrapping a multipart/alternative
	// plus a text/vcard. What is special is the SHAPE, not the size: TEXT is a
	// SYNTHETIC section that Gmail assembles from parts it stores separately,
	// and on this shape the literal it announces does not match the bytes it
	// then sends, so the client waits for data that never arrives.
	//
	// So: never ask for TEXT. Phase 1 fetches BODYSTRUCTURE (cheap, no body),
	// phase 2 fetches only the first non-attachment text/plain LEAF, which is
	// a real stored part rather than something reassembled. That is faster,
	// avoids the bug, and is more correct anyway — TEXT would have handed us
	// MIME boundaries and the base64 of every other part to strip by hand.
	//
	// Messages in a batch usually share a part path, so phase 2 groups by path
	// and issues one FETCH per distinct path: two or three, not twenty-five.
	metaOpts := &imap.FetchOptions{
		UID:           true,
		Envelope:      true,
		RFC822Size:    true,
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
	}

	var fetched, kept, empty, chars, skipped, noText, htmlOnly int
	for lo := from; lo <= mbox.NumMessages; lo += uint32(batch) {
		hi := lo + uint32(batch) - 1
		if hi > mbox.NumMessages {
			hi = mbox.NumMessages
		}
		metas, err := cn.fetchRange(lo, hi, metaOpts)
		if err != nil {
			fmt.Printf("  %d..%d  metadata failed: %v\n", lo, hi, err)
			continue
		}

		// Group this batch by the part path we want from each message.
		type want struct {
			seq      uint32
			meta     *imapclient.FetchMessageBuffer
			encoding string
			charset  string
			isHTML   bool
		}
		byPath := map[string][]want{}
		seqOf := map[*imapclient.FetchMessageBuffer]uint32{}
		for i, m := range metas {
			seqOf[m] = lo + uint32(i)
		}
		for _, m := range metas {
			if m.BodyStructure == nil {
				noText++
				continue
			}
			path, isHTML := textPartPath(m.BodyStructure)
			if path == nil {
				noText++
				continue
			}
			if isHTML {
				htmlOnly++
			}
			enc, cs := partEncoding(m.BodyStructure, path)
			key := pathKey(path)
			byPath[key] = append(byPath[key], want{seq: seqOf[m], meta: m, encoding: enc, charset: cs, isHTML: isHTML})
		}

		for key, ws := range byPath {
			set := imap.SeqSetNum()
			for _, w := range ws {
				set.AddNum(w.seq)
			}
			opts := &imap.FetchOptions{
				UID: true,
				BodySection: []*imap.FetchItemBodySection{{
					Part:    parsePathKey(key),
					Peek:    true,
					Partial: &imap.SectionPartial{Offset: 0, Size: int64(prefixBytes)},
				}},
			}
			bodies, err := cn.cl.Fetch(set, opts).Collect()
			if err != nil {
				// One bad message must never cost the batch, so drop to one at
				// a time and name whatever still refuses.
				if rerr := cn.reconnect(); rerr != nil {
					return fmt.Errorf("part %s: %w; reconnect: %v", key, err, rerr)
				}
				bodies = nil
				for _, w := range ws {
					one := imap.SeqSetNum()
					one.AddNum(w.seq)
					b, e := cn.cl.Fetch(one, opts).Collect()
					if e != nil {
						skipped++
						fmt.Printf("    seq %d part %s SKIPPED: %v\n", w.seq, key, e)
						continue
					}
					bodies = append(bodies, b...)
				}
			}
			byUID := map[imap.UID]*imapclient.FetchMessageBuffer{}
			for _, b := range bodies {
				byUID[b.UID] = b
			}
			for _, w := range ws {
				b, ok := byUID[w.meta.UID]
				if !ok {
					continue
				}
				var raw []byte
				for _, s := range b.BodySection {
					raw = s.Bytes
					break
				}
				body := decodePart(raw, w.encoding, w.charset)
				if w.isHTML {
					body = htmlToText(body)
				}
				text := ownText(body)
				fetched++
				if text == "" {
					empty++
					// Keep the raw body of an empty result so the cause is
					// inspectable. 22 of 200 came back empty and guessing why
					// from aggregate counts is how a heuristic stays broken.
					if outDir != "" {
						writeCorpus(filepath.Join(outDir, "_empty"), w.meta, body)
					}
					continue
				}
				kept++
				chars += len(text)
				if outDir != "" {
					writeCorpus(outDir, w.meta, text)
				}
			}
		}
		fmt.Printf("  %d..%d  meta %d  paths %d  usable %d  empty %d\n", lo, hi, len(metas), len(byPath), kept, empty)
	}

	fmt.Printf("\nmailbox %s: %d messages, bodies read %d (%d-byte prefixes of the text/plain LEAF, batches of %d)\n",
		name, mbox.NumMessages, fetched, prefixBytes, batch)
	fmt.Printf("usable %d, empty after stripping %d, no text/plain part %d, skipped %d, reconnects %d\n",
		kept, empty, noText, skipped, cn.redials)
	if kept > 0 {
		fmt.Printf("mean own-text length %d chars (~%d tokens)\n", chars/kept, chars/kept/4)
		fmt.Printf("corpus for %d messages ~ %d chars ~ %d k tokens\n", kept, chars, chars/4/1000)
		fmt.Printf("extrapolated to 1000 messages ~ %d k tokens\n", (chars/kept)*1000/4/1000)
	}
	if outDir != "" {
		fmt.Printf("written to %s (0600, delete when the spike is done)\n", outDir)
	}
	return nil
}

// specialUse resolves a mailbox by its SPECIAL-USE attribute, so no Gmail
// folder name is ever hard-coded.
func specialUse(cl *imapclient.Client, attr imap.MailboxAttr, fallback string) (string, error) {
	boxes, err := cl.List("", "*", &imap.ListOptions{SelectSpecialUse: true, ReturnSpecialUse: true}).Collect()
	if err != nil {
		return "", fmt.Errorf("list special-use: %w", err)
	}
	for _, b := range boxes {
		for _, a := range b.Attrs {
			if a == attr {
				return b.Mailbox, nil
			}
		}
	}
	fmt.Printf("no %s special-use; falling back to %q\n", attr, fallback)
	return fallback, nil
}

func pathKey(path []int) string {
	var ss []string
	for _, p := range path {
		ss = append(ss, fmt.Sprint(p))
	}
	return strings.Join(ss, ".")
}

func parsePathKey(key string) []int {
	var out []int
	for _, s := range strings.Split(key, ".") {
		var n int
		fmt.Sscanf(s, "%d", &n)
		out = append(out, n)
	}
	return out
}

// partEncoding returns the transfer encoding and charset of the part at path.
func partEncoding(bs imap.BodyStructure, path []int) (string, string) {
	var enc, cs string
	bs.Walk(func(p []int, part imap.BodyStructure) bool {
		if pathKey(p) != pathKey(path) {
			return true
		}
		if sp, ok := part.(*imap.BodyStructureSinglePart); ok {
			enc = sp.Encoding
			cs = sp.Params["charset"]
		}
		return false
	})
	return enc, cs
}

func writeCorpus(outDir string, m *imapclient.FetchMessageBuffer, text string) {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return
	}
	subj, to, date := "", "", ""
	if m.Envelope != nil {
		subj = m.Envelope.Subject
		date = m.Envelope.Date.Format(time.RFC3339)
		if len(m.Envelope.To) > 0 {
			to = m.Envelope.To[0].Addr()
		}
	}
	doc := fmt.Sprintf("---\nuid: %d\ndate: %s\nto: %s\nsubject: %s\n---\n\n%s\n",
		m.UID, date, to, strings.ReplaceAll(subj, "\n", " "), text)
	_ = os.WriteFile(filepath.Join(outDir, fmt.Sprintf("%06d.md", m.UID)), []byte(doc), 0o600)
}

// ---------------------------------------------------------------- labels

// labels answers "where did the label go" with evidence rather than a theory.
// Three separate facts get conflated by "it's gone": the mailbox no longer
// exists, it exists but is empty, or it exists and holds the message and Gmail
// is simply not showing it in the sidebar. Each has a different fix.
func labels(cn *conn, want string) error {
	boxes, err := cn.cl.List("", "*", nil).Collect()
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	fmt.Printf("%d mailboxes visible over IMAP:\n", len(boxes))
	found := false
	for _, b := range boxes {
		mark := "  "
		if strings.EqualFold(b.Mailbox, want) {
			mark = ">>"
			found = true
		}
		fmt.Printf("%s %s\n", mark, b.Mailbox)
	}
	fmt.Println()
	if !found {
		fmt.Printf("VERDICT: %q does NOT exist over IMAP any more.\n", want)
		fmt.Println("  Gmail removed it. The likeliest cause is that the label was left")
		fmt.Println("  empty: a COPY that did not actually land leaves an empty label,")
		fmt.Println("  and Gmail prunes those. Re-run `label`, then this, in that order,")
		fmt.Println("  without touching the Gmail UI in between.")
		return nil
	}
	mbox, err := cn.cl.Select(want, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return fmt.Errorf("select %s: %w", want, err)
	}
	cn.box = want
	fmt.Printf("VERDICT: %q EXISTS over IMAP and holds %d message(s).\n", want, mbox.NumMessages)
	if mbox.NumMessages == 0 {
		fmt.Println("  Empty, so the COPY did not land. That is the thing to fix.")
		return nil
	}
	set := imap.SeqSetNum()
	set.AddRange(1, mbox.NumMessages)
	msgs, err := cn.cl.Fetch(set, &imap.FetchOptions{UID: true, Envelope: true}).Collect()
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	for _, m := range msgs {
		subj := ""
		if m.Envelope != nil {
			subj = m.Envelope.Subject
		}
		fmt.Printf("  uid %d  %q\n", m.UID, subj)
	}
	fmt.Println("\n  The label is applied. If Gmail's sidebar does not show it, that is")
	fmt.Println("  a per-label display setting in Gmail (Settings > Labels > Show in")
	fmt.Println("  label list), not something IMAP did wrong.")
	return nil
}

// ---------------------------------------------------------------- inspect

// inspect asks for everything ABOUT a message and nothing OF it: envelope,
// total size, and the MIME tree. All cheap for the server, so it answers "why
// will this one message not come back" without touching the body that is
// failing.
func inspect(cn *conn, box string, seq uint32) error {
	if box == "" {
		box = "[Gmail]/Sent Mail"
	}
	if _, err := cn.cl.Select(box, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		return fmt.Errorf("select %s: %w", box, err)
	}
	cn.box = box
	set := imap.SeqSetNum()
	set.AddNum(seq)
	msgs, err := cn.cl.Fetch(set, &imap.FetchOptions{
		UID:           true,
		Envelope:      true,
		RFC822Size:    true,
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
	}).Collect()
	if err != nil {
		return fmt.Errorf("fetch metadata for seq %d: %w (even the metadata will not come back)", seq, err)
	}
	if len(msgs) == 0 {
		return fmt.Errorf("seq %d not found in %s", seq, box)
	}
	m := msgs[0]
	fmt.Printf("seq %d uid %d\n", seq, m.UID)
	if m.Envelope != nil {
		fmt.Printf("  date    %s\n", m.Envelope.Date)
		fmt.Printf("  subject %q\n", m.Envelope.Subject)
		if len(m.Envelope.To) > 0 {
			fmt.Printf("  to      %s\n", m.Envelope.To[0].Addr())
		}
	}
	fmt.Printf("  SIZE    %d bytes (%.1f MB)\n", m.RFC822Size, float64(m.RFC822Size)/(1024*1024))
	if m.BodyStructure == nil {
		fmt.Println("  no BODYSTRUCTURE returned")
		return nil
	}
	fmt.Println("  MIME tree:")
	m.BodyStructure.Walk(func(path []int, part imap.BodyStructure) bool {
		label := "."
		if len(path) > 0 {
			var ss []string
			for _, p := range path {
				ss = append(ss, fmt.Sprint(p))
			}
			label = strings.Join(ss, ".")
		}
		size := ""
		if sp, ok := part.(*imap.BodyStructureSinglePart); ok {
			size = fmt.Sprintf("  %d bytes  encoding=%s", sp.Size, sp.Encoding)
		}
		fmt.Printf("    [%-6s] %-28s%s\n", label, part.MediaType(), size)
		return true
	})
	path, isHTML := textPartPath(m.BodyStructure)
	kind := "text/plain"
	if isHTML {
		kind = "text/html (no plain part)"
	}
	fmt.Printf("\npart the driver would read: %v  (%s)\n", path, kind)
	return nil
}

// textPartPath finds the leaf we actually want: the first non-attachment
// text/plain, falling back to text/html. Fetching a LEAF avoids the synthetic
// BODY[TEXT] section entirely, which is what the 11008 failure was about.
//
// The html fallback is not a nicety. On the first two-phase run, 25 of 200
// sent messages had no text/plain part at all, so a plain-only rule silently
// drops an eighth of the corpus — and those are not random messages, they are
// whatever the user writes from a client that sends html only.
func textPartPath(bs imap.BodyStructure) (path []int, isHTML bool) {
	var plain, html []int
	bs.Walk(func(p []int, part imap.BodyStructure) bool {
		sp, ok := part.(*imap.BodyStructureSinglePart)
		if !ok {
			return true
		}
		if d := part.Disposition(); d != nil && strings.EqualFold(d.Value, "attachment") {
			return true
		}
		if !strings.EqualFold(sp.Type, "text") {
			return true
		}
		switch {
		case strings.EqualFold(sp.Subtype, "plain") && plain == nil:
			plain = append([]int(nil), p...)
		case strings.EqualFold(sp.Subtype, "html") && html == nil:
			html = append([]int(nil), p...)
		}
		return true
	})
	if plain != nil {
		return plain, false
	}
	return html, html != nil
}

var (
	htmlTag     = regexp.MustCompile(`(?s)<(script|style)\b.*?</(script|style)>|<[^>]*>`)
	htmlBreak   = regexp.MustCompile(`(?i)<(br|/p|/div|/tr)\b[^>]*>`)
	blankRuns   = regexp.MustCompile(`\n{3,}`)
	trailingWSp = regexp.MustCompile(`(?m)[ \t]+$`)
)

// htmlToText is deliberately small. A style corpus needs the words and the
// shape of the paragraphs, not a faithful render, and a full html parser here
// would be a dependency carrying its own failure modes for no gain.
func htmlToText(s string) string {
	s = htmlBreak.ReplaceAllString(s, "\n")
	s = htmlTag.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = strings.ReplaceAll(s, " ", " ")
	s = trailingWSp.ReplaceAllString(s, "")
	return blankRuns.ReplaceAllString(s, "\n\n")
}

// ---------------------------------------------------------------- draft

func draft(cn *conn, dryRun bool) error {
	cl := cn.cl
	mbox, err := cl.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return fmt.Errorf("select INBOX: %w", err)
	}
	if mbox.NumMessages == 0 {
		return fmt.Errorf("INBOX is empty, nothing to reply to")
	}
	set := imap.SeqSetNum()
	set.AddNum(mbox.NumMessages)
	msgs, err := cl.Fetch(set, &imap.FetchOptions{UID: true, Envelope: true}).Collect()
	if err != nil || len(msgs) == 0 {
		return fmt.Errorf("fetch newest: %w", err)
	}
	env := msgs[0].Envelope
	if env == nil {
		return fmt.Errorf("newest message has no envelope")
	}
	fmt.Printf("replying to: %q\n", env.Subject)
	fmt.Printf("  message-id: %s\n", env.MessageID)
	if env.MessageID == "" {
		fmt.Println("  WARNING: no Message-ID, so this reply cannot be threaded by any client")
	}

	to := ""
	if len(env.From) > 0 {
		to = env.From[0].Addr()
	}
	subject := env.Subject
	if !strings.HasPrefix(strings.ToLower(subject), "re:") {
		subject = "Re: " + subject
	}
	runID := time.Now().UTC().Format("20060102T150405Z")
	// RFC 5322 threading: References = the parent's own References chain (which
	// IMAP surfaces as the envelope In-Reply-To list) followed by the parent.
	refs := env.MessageID
	if len(env.InReplyTo) > 0 {
		refs = strings.Join(env.InReplyTo, " ") + " " + env.MessageID
	}

	var b strings.Builder
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "In-Reply-To: %s\r\n", env.MessageID)
	fmt.Fprintf(&b, "References: %s\r\n", refs)
	fmt.Fprintf(&b, "%s: %s\r\n", markerHeader, runID)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&b, "\r\n")
	fmt.Fprintf(&b, "This is a Privasys connector spike draft. It was never sent.\r\n")
	fmt.Fprintf(&b, "Run %s. Delete it.\r\n", runID)
	raw := []byte(b.String())

	fmt.Printf("\ndraft to %s, marker %s=%s, %d bytes\n", to, markerHeader, runID, len(raw))
	if dryRun {
		fmt.Println("\n--- dry run, nothing written; message follows ---")
		fmt.Println(string(raw))
		return nil
	}

	target := draftsMailbox(cl)
	fmt.Printf("APPEND to %q with \\Draft\n", target)
	app := cl.Append(target, int64(len(raw)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagDraft},
		Time:  time.Now(),
	})
	if _, err := app.Write(raw); err != nil {
		return fmt.Errorf("append write: %w", err)
	}
	if err := app.Close(); err != nil {
		return fmt.Errorf("append close: %w", err)
	}
	data, err := app.Wait()
	if err != nil {
		return fmt.Errorf("append: %w", err)
	}
	if data != nil && data.UID > 0 {
		fmt.Printf("APPENDUID uid=%d uidvalidity=%d\n", data.UID, data.UIDValidity)
	} else {
		fmt.Println("no APPENDUID returned; find it by marker header instead")
	}
	// Read it straight back, in this same run. The first attempt checked the
	// header in a LATER invocation, by which time the draft was gone — Gmail
	// re-creates a draft under a new UID when its own UI touches one, so a
	// human looking at it in between destroys the evidence. Verifying inside
	// the same run removes that race and answers the header question cleanly.
	if data != nil && data.UID > 0 {
		if err := dumpHeaders(cn, target, data.UID); err != nil {
			fmt.Printf("immediate read-back failed: %v\n", err)
		}
	}

	fmt.Printf("\nNOW CHECK IN THE GMAIL WEB UI:\n")
	fmt.Printf("  1. does the draft appear INSIDE the thread %q, not as a separate one?\n", env.Subject)
	fmt.Printf("  2. is the recipient prefilled as %s?\n", to)
	fmt.Printf("\n(The UID above stops being valid as soon as Gmail's UI touches\n")
	fmt.Println("the draft, so it is not a durable handle. Thread-level idempotence,")
	fmt.Println("recorded on the user's own Drive, is what the design should rely on.)")
	return nil
}

func draftsMailbox(cl *imapclient.Client) string {
	boxes, err := cl.List("", "*", &imap.ListOptions{SelectSpecialUse: true, ReturnSpecialUse: true}).Collect()
	if err == nil {
		for _, b := range boxes {
			for _, a := range b.Attrs {
				if a == imap.MailboxAttrDrafts {
					return b.Mailbox
				}
			}
		}
	}
	return "[Gmail]/Drafts"
}

// ---------------------------------------------------------------- verify

func verify(cn *conn, marker string, uid uint) error {
	cl := cn.cl
	target := draftsMailbox(cl)
	if _, err := cl.Select(target, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		return fmt.Errorf("select %s: %w", target, err)
	}
	crit := &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: markerHeader, Value: marker}}}
	res, err := cl.Search(crit, nil).Wait()
	if err != nil {
		return fmt.Errorf("search: %w", err)
	}
	nums := res.AllSeqNums()
	fmt.Printf("SEARCH HEADER %s %q in %s: %d hit(s)\n", markerHeader, marker, target, len(nums))
	if len(nums) == 0 {
		// A zero result conflates two very different facts: the server threw
		// our header away, or the server kept it and simply cannot search it.
		// Gmail's IMAP SEARCH is known not to index arbitrary X- headers, so
		// read the message back by its APPENDUID and look.
		fmt.Println("\nSEARCH found nothing. That does not yet mean the header is gone:")
		fmt.Println("Gmail's IMAP SEARCH does not index arbitrary X- headers.")
		if uid == 0 {
			fmt.Println("Re-run with -uid <the APPENDUID that draft printed> to settle it.")
			return nil
		}
		return dumpHeaders(cn, target, imap.UID(uid))
	}
	set := imap.SeqSetNum(nums...)
	msgs, err := cl.Fetch(set, &imap.FetchOptions{
		UID:      true,
		Envelope: true,
		BodySection: []*imap.FetchItemBodySection{
			{Specifier: imap.PartSpecifierHeader},
		},
	}).Collect()
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	for _, m := range msgs {
		fmt.Printf("\nuid=%d subject=%q\n", m.UID, m.Envelope.Subject)
		for _, b := range m.BodySection {
			for _, line := range strings.Split(string(b.Bytes), "\r\n") {
				l := strings.ToLower(line)
				if strings.HasPrefix(l, "in-reply-to:") || strings.HasPrefix(l, "references:") ||
					strings.HasPrefix(l, strings.ToLower(markerHeader)+":") {
					fmt.Printf("  %s\n", line)
				}
			}
		}
	}
	fmt.Println("\nVERDICT: marker header survives APPEND and is searchable.")
	return nil
}

// ---------------------------------------------------------------- label

func label(cl *imapclient.Client, name string) error {
	// Gmail renders an IMAP mailbox as a label, and COPY applies it. So this
	// is ordinary IMAP: no X-GM-LABELS, no Gmail-only code path in the driver.
	if err := cl.Create(name, nil).Wait(); err != nil {
		fmt.Printf("CREATE %q: %v (already exists is fine)\n", name, err)
	} else {
		fmt.Printf("CREATE %q ok\n", name)
	}
	mbox, err := cl.Select("INBOX", nil).Wait()
	if err != nil {
		return fmt.Errorf("select INBOX: %w", err)
	}
	if mbox.NumMessages == 0 {
		return fmt.Errorf("INBOX is empty")
	}
	set := imap.SeqSetNum()
	set.AddNum(mbox.NumMessages)
	msgs, err := cl.Fetch(set, &imap.FetchOptions{UID: true, Envelope: true}).Collect()
	if err != nil || len(msgs) == 0 {
		return fmt.Errorf("fetch newest: %w", err)
	}
	fmt.Printf("labelling newest INBOX message %q (uid %d)\n", msgs[0].Envelope.Subject, msgs[0].UID)
	uidSet := imap.UIDSetNum(msgs[0].UID)
	data, err := cl.Copy(uidSet, name).Wait()
	if err != nil {
		return fmt.Errorf("copy to %s: %w", name, err)
	}
	if data != nil {
		fmt.Printf("COPYUID %v -> %v\n", data.SourceUIDs, data.DestUIDs)
	}
	fmt.Printf("\nNOW CHECK IN THE GMAIL WEB UI: does that message show the label %q,\n", name)
	fmt.Println("and is it STILL in the inbox (a label, not a move)?")
	return nil
}

// ---------------------------------------------------------------- main

func main() {
	limit := flag.Int("limit", 200, "sent: how many recent messages to read")
	out := flag.String("out", "", "sent: directory to write the corpus into (omit to only measure)")
	batchSize := flag.Int("batch", 25, "sent: messages per FETCH command")
	prefix := flag.Int("prefix", 16384, "sent: bytes of each body to fetch (own text is at the top; attachments are never pulled)")
	marker := flag.String("marker", "", "verify: the run id printed by draft")
	labelFlag := flag.String("label", labelName, "label: the label to create and apply")
	seq := flag.Uint("seq", 0, "inspect: sequence number to describe")
	uidFlag := flag.Uint("uid", 0, "verify: read this UID back directly (the APPENDUID draft printed)")
	box := flag.String("box", "", "inspect: mailbox (default the Sent folder)")
	dryRun := flag.Bool("dry-run", false, "draft: build the message and print it, write nothing")
	// Go's flag package stops parsing at the first non-flag argument, so
	// "imap-spike verify -marker X" silently dropped -marker and then
	// complained that it was missing. Lift the command out of the argument
	// list first, so it may appear before OR after the flags. Every hint this
	// tool prints puts it first, which was the order that did not work.
	cmd, rest := "", []string(nil)
	for _, a := range os.Args[1:] {
		if cmd == "" && !strings.HasPrefix(a, "-") && isCommand(a) {
			cmd = a
			continue
		}
		rest = append(rest, a)
	}
	if err := flag.CommandLine.Parse(rest); err != nil {
		os.Exit(2)
	}

	if cmd == "" {
		fmt.Fprintln(os.Stderr, "usage: imap-spike [flags] probe|sent|inspect|draft|verify|label|labels")
		fmt.Fprintln(os.Stderr, "\ncredentials: $MAIL_SPIKE_CREDS or ./mail-spike-creds.json")
		fmt.Fprintln(os.Stderr, `  {"host":"imap.gmail.com:993","user":"…","password":"<app password>"}`)
		os.Exit(2)
	}

	c, err := loadCreds()
	if err != nil {
		fmt.Fprintln(os.Stderr, "credentials:", err)
		os.Exit(1)
	}
	cl, err := dial(c)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// The client is held behind conn so a command that loses the connection
	// can replace it, and the deferred logout still closes the live one.
	cn := &conn{creds: c, cl: cl}
	defer func() {
		if cn.cl != nil {
			_ = cn.cl.Logout().Wait()
			_ = cn.cl.Close()
		}
	}()
	fmt.Printf("connected to %s as %s\n\n", c.Host, c.User)

	switch cmd {
	case "probe":
		err = probe(cn.cl)
	case "sent":
		err = sent(cn, *limit, *batchSize, *prefix, *out)
	case "draft":
		err = draft(cn, *dryRun)
	case "verify":
		if *marker == "" {
			err = fmt.Errorf("verify needs -marker <run id from draft>")
		} else {
			err = verify(cn, *marker, *uidFlag)
		}
	case "inspect":
		if *seq == 0 {
			err = fmt.Errorf("inspect needs -seq <sequence number>")
		} else {
			err = inspect(cn, *box, uint32(*seq))
		}
	case "label":
		err = label(cn.cl, *labelFlag)
	case "labels":
		err = labels(cn, *labelFlag)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nERROR:", err)
		os.Exit(1)
	}
}

// isCommand reports whether a bare argument names a subcommand, so the
// command can be lifted out of the argument list wherever the user put it.
func isCommand(s string) bool {
	switch s {
	case "probe", "sent", "inspect", "draft", "verify", "label", "labels":
		return true
	}
	return false
}

// dumpHeaders reads one message back by UID and prints its headers, which is
// the only way to tell "the server discarded our header" from "the server kept
// it but will not search it". The difference decides whether a marker header
// can be a durable handle on our own drafts at all.
func dumpHeaders(cn *conn, box string, uid imap.UID) error {
	// SELECT the mailbox first. Without this the fetch runs against whatever
	// was selected last, which in the draft path is INBOX — so a UID that had
	// just been created in Drafts came back "no longer there", and I read that
	// as Gmail recycling draft UIDs. It was looking in the wrong folder.
	if _, err := cn.cl.Select(box, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		return fmt.Errorf("select %s: %w", box, err)
	}
	cn.box = box
	set := imap.UIDSetNum(uid)
	msgs, err := cn.cl.Fetch(set, &imap.FetchOptions{
		UID:      true,
		Envelope: true,
		BodySection: []*imap.FetchItemBodySection{
			{Specifier: imap.PartSpecifierHeader, Peek: true},
		},
	}).Collect()
	if err != nil {
		return fmt.Errorf("fetch uid %d in %s: %w", uid, box, err)
	}
	if len(msgs) == 0 {
		fmt.Printf("uid %d is no longer in %s (deleted, or UIDVALIDITY changed)\n", uid, box)
		return nil
	}
	var raw string
	for _, b := range msgs[0].BodySection {
		raw = string(b.Bytes)
		break
	}
	fmt.Printf("\nheaders of uid %d in %s:\n", uid, box)
	found := false
	for _, line := range strings.Split(raw, "\r\n") {
		l := strings.ToLower(line)
		switch {
		case strings.HasPrefix(l, strings.ToLower(markerHeader)+":"):
			found = true
			fmt.Printf("  >> %s\n", line)
		case strings.HasPrefix(l, "in-reply-to:"), strings.HasPrefix(l, "references:"),
			strings.HasPrefix(l, "subject:"), strings.HasPrefix(l, "to:"), strings.HasPrefix(l, "message-id:"):
			fmt.Printf("     %s\n", line)
		}
	}
	fmt.Println()
	if found {
		fmt.Println("VERDICT: the header SURVIVED the round trip; Gmail simply will not SEARCH it.")
		fmt.Println("  So a marker header is fine as a RECORD, but not as a lookup key.")
		fmt.Println("  Address our own drafts by the APPENDUID we were handed and stored.")
	} else {
		fmt.Println("VERDICT: the header was DISCARDED by the server.")
		fmt.Println("  Identify our drafts by the stored APPENDUID, with In-Reply-To as the fallback.")
	}
	return nil
}
