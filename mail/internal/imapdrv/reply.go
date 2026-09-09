// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package imapdrv

import (
	"fmt"
	"mime"
	"strings"
	"time"

	"github.com/Privasys/connectors/mail/internal/mail"
)

// buildReply renders a draft as RFC 5322.
//
// The threading headers are the whole reason a draft written over IMAP is
// useful: with In-Reply-To and References set, the draft appears INSIDE the
// original conversation in the provider's own interface, so the user reads and
// sends it where they already work. Confirmed by eye against Gmail. Without
// them it lands as an orphan thread, which is worse than not drafting at all.
func buildReply(from string, parent mail.Message, d mail.Draft) []byte {
	to := parent.From.Addr
	if to == "" {
		to = addrList(parent.To).first()
	}

	subject := parent.Subject
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(subject)), "re:") {
		subject = "Re: " + subject
	}

	// In-Reply-To names the PARENT; References is the chain root followed by
	// the parent. They are different ids and conflating them produced a
	// References header that listed the same id twice, which is why the
	// domain type carries both.
	parentID := bracket(parent.MessageID)
	rootID := bracket(parent.ThreadID)
	refs := parentID
	if rootID != "" && rootID != parentID {
		refs = rootID + " " + parentID
	}

	var b strings.Builder
	writeHeader(&b, "From", from)
	writeHeader(&b, "To", to)
	for _, cc := range d.CC {
		writeHeader(&b, "Cc", cc.Addr)
	}
	writeHeader(&b, "Subject", encodeWord(subject))
	if parentID != "" {
		writeHeader(&b, "In-Reply-To", parentID)
		writeHeader(&b, "References", strings.TrimSpace(refs))
	}
	writeHeader(&b, "Date", time.Now().Format(time.RFC1123Z))
	writeHeader(&b, "MIME-Version", "1.0")
	writeHeader(&b, "Content-Type", "text/plain; charset=utf-8")
	writeHeader(&b, "Content-Transfer-Encoding", "8bit")
	b.WriteString("\r\n")
	b.WriteString(normaliseCRLF(d.Body))
	if !strings.HasSuffix(d.Body, "\n") {
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

// bracket wraps a bare Message-ID in angle brackets.
//
// The envelope hands ids back bare, and a Message-ID without brackets in
// In-Reply-To is ignored by most clients, so the draft would silently fail to
// thread: the one thing this whole file exists to achieve.
func bracket(raw string) string {
	id := strings.TrimSpace(raw)
	if id == "" {
		return ""
	}
	if !strings.HasPrefix(id, "<") {
		id = "<" + id
	}
	if !strings.HasSuffix(id, ">") {
		id = id + ">"
	}
	return id
}

// writeHeader folds nothing and escapes newlines out of the value, because a
// header value carrying CRLF is header injection, and the values here come
// from mail somebody else wrote.
func writeHeader(b *strings.Builder, k, v string) {
	v = strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
	fmt.Fprintf(b, "%s: %s\r\n", k, strings.TrimSpace(v))
}

func encodeWord(s string) string {
	for _, r := range s {
		if r > 127 {
			return mime.QEncoding.Encode("utf-8", s)
		}
	}
	return s
}

func normaliseCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

type addrList []mail.Address

func (a addrList) first() string {
	if len(a) == 0 {
		return ""
	}
	return a[0].Addr
}
