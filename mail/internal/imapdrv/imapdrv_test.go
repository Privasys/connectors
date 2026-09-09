// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package imapdrv

import (
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/Privasys/connectors/mail/internal/mail"
)

func TestIDRoundTrip(t *testing.T) {
	in := msgID{Folder: "[Gmail]/Sent Mail", UIDValidity: 6, UID: 119526}
	got, err := decodeID(encodeID(in))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != in {
		t.Errorf("round trip lost data: %+v -> %+v", in, got)
	}
	// An id is opaque to the agent, so it must not leak the folder in the
	// clear or invite anyone to construct one by hand.
	if strings.Contains(encodeID(in), "Gmail") {
		t.Error("the encoded id should not be readable")
	}
}

func TestIDRejectsRubbish(t *testing.T) {
	for _, s := range []string{"", "!!!!", "YWJj", "YQBiAGM="} {
		if _, err := decodeID(s); err == nil {
			t.Errorf("decodeID(%q) should have failed", s)
		}
	}
}

// A stale id must be detectable. When a mailbox is recreated its UID validity
// changes and old UIDs point at different messages, so reading one without
// checking would return the wrong mail silently.
func TestIDCarriesUIDValidity(t *testing.T) {
	a := decodeMust(t, encodeID(msgID{"INBOX", 1, 42}))
	b := decodeMust(t, encodeID(msgID{"INBOX", 2, 42}))
	if a.UIDValidity == b.UIDValidity {
		t.Fatal("uid validity is not encoded")
	}
}

func decodeMust(t *testing.T, s string) msgID {
	t.Helper()
	m, err := decodeID(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return m
}

// The part chooser is where an eighth of a real mailbox is won or lost.
func TestTextPartPrefersPlainThenHTML(t *testing.T) {
	plain := &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Encoding: "quoted-printable", Params: map[string]string{"charset": "utf-8"}}
	html := &imap.BodyStructureSinglePart{Type: "text", Subtype: "html", Encoding: "base64", Params: map[string]string{"charset": "iso-8859-1"}}
	pdf := &imap.BodyStructureSinglePart{Type: "application", Subtype: "pdf"}

	t.Run("prefers plain", func(t *testing.T) {
		bs := &imap.BodyStructureMultiPart{Subtype: "alternative", Children: []imap.BodyStructure{plain, html}}
		path, isHTML, enc, cs := textPart(bs)
		if isHTML || pathKey(path) != "1" || enc != "quoted-printable" || cs != "utf-8" {
			t.Errorf("want the plain leaf, got path=%v html=%v enc=%q cs=%q", path, isHTML, enc, cs)
		}
	})

	t.Run("falls back to html", func(t *testing.T) {
		bs := &imap.BodyStructureMultiPart{Subtype: "alternative", Children: []imap.BodyStructure{pdf, html}}
		path, isHTML, enc, cs := textPart(bs)
		if !isHTML || pathKey(path) != "2" || enc != "base64" || cs != "iso-8859-1" {
			t.Errorf("want the html leaf, got path=%v html=%v enc=%q cs=%q", path, isHTML, enc, cs)
		}
	})

	t.Run("no text at all", func(t *testing.T) {
		bs := &imap.BodyStructureMultiPart{Subtype: "mixed", Children: []imap.BodyStructure{pdf}}
		if path, _, _, _ := textPart(bs); path != nil {
			t.Errorf("want no path, got %v", path)
		}
	})

	// The shape that broke the spike: multipart/mixed wrapping a
	// multipart/alternative plus a vCard, 2 KB in total. Nothing about it is
	// large; asking for BODY[TEXT] on it hangs, and reading the leaf works.
	t.Run("the shape that hung BODY[TEXT]", func(t *testing.T) {
		vcard := &imap.BodyStructureSinglePart{Type: "text", Subtype: "vcard", Encoding: "base64"}
		bs := &imap.BodyStructureMultiPart{Subtype: "mixed", Children: []imap.BodyStructure{
			&imap.BodyStructureMultiPart{Subtype: "alternative", Children: []imap.BodyStructure{plain, html}},
			vcard,
		}}
		path, isHTML, _, _ := textPart(bs)
		if isHTML || pathKey(path) != "1.1" {
			t.Errorf("want the nested plain leaf 1.1, got %v (html=%v)", pathKey(path), isHTML)
		}
	})
}

func TestAttachmentsListedNotFetched(t *testing.T) {
	bs := &imap.BodyStructureMultiPart{Subtype: "mixed", Children: []imap.BodyStructure{
		&imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"},
		&imap.BodyStructureSinglePart{
			Type: "application", Subtype: "pdf", Size: 900000,
			Extended: &imap.BodyStructureSinglePartExt{
				Disposition: &imap.BodyStructureDisposition{
					Value: "attachment", Params: map[string]string{"filename": "invoice.pdf"},
				},
			},
		},
	}}
	got := attachments(bs)
	if len(got) != 1 || got[0].Name != "invoice.pdf" || got[0].Size != 900000 || got[0].Type != "application/pdf" {
		t.Fatalf("attachment not described correctly: %+v", got)
	}
	// And the text part chooser must not offer the attachment as the body.
	if path, _, _, _ := textPart(bs); pathKey(path) != "1" {
		t.Errorf("body should be the text leaf, got %v", pathKey(path))
	}
}

// Threading is the entire value of drafting over IMAP, so the headers that
// achieve it are pinned here.
func TestBuildReplyThreads(t *testing.T) {
	parent := mail.Message{Header: mail.Header{
		From:      mail.Address{Addr: "alice@example.com"},
		Subject:   "Contract review",
		ThreadID:  "abc123@mail.example.com",
		MessageID: "abc123@mail.example.com",
		Date:      time.Now(),
		Repliable: true,
	}}
	raw := string(buildReply("me@example.org", parent, mail.Draft{Body: "Yes, that works.\n"}))

	for _, want := range []string{
		"To: alice@example.com\r\n",
		"Subject: Re: Contract review\r\n",
		"In-Reply-To: <abc123@mail.example.com>\r\n",
		"References: <abc123@mail.example.com>\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n",
		"\r\n\r\nYes, that works.\r\n",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("missing %q in:\n%s", want, raw)
		}
	}
}

// A Message-ID without angle brackets is ignored by most clients, so the draft
// silently fails to thread: the one thing the function exists to do.
func TestBuildReplyBracketsMessageID(t *testing.T) {
	parent := mail.Message{Header: mail.Header{From: mail.Address{Addr: "a@b.example"}, ThreadID: "bare@id", MessageID: "bare@id"}}
	raw := string(buildReply("me@example.org", parent, mail.Draft{Body: "hi"}))
	if !strings.Contains(raw, "In-Reply-To: <bare@id>") {
		t.Errorf("Message-ID not bracketed:\n%s", raw)
	}
}

func TestBuildReplyKeepsExistingRePrefix(t *testing.T) {
	parent := mail.Message{Header: mail.Header{From: mail.Address{Addr: "a@b.example"}, Subject: "Re: already"}}
	raw := string(buildReply("me@example.org", parent, mail.Draft{Body: "x"}))
	if strings.Contains(raw, "Re: Re:") {
		t.Errorf("subject double-prefixed:\n%s", raw)
	}
}

// Header values come from mail somebody else wrote, so a newline in one is
// header injection and must not survive.
func TestBuildReplyRefusesHeaderInjection(t *testing.T) {
	parent := mail.Message{Header: mail.Header{
		From:    mail.Address{Addr: "evil@example.com"},
		Subject: "hello\r\nBcc: victim@example.com",
	}}
	raw := string(buildReply("me@example.org", parent, mail.Draft{Body: "x"}))
	if strings.Contains(raw, "Bcc:") && strings.Contains(raw, "\r\nBcc:") {
		t.Errorf("header injection survived:\n%s", raw)
	}
	if strings.Count(raw, "Subject:") != 1 {
		t.Errorf("subject split into two headers:\n%s", raw)
	}
}

func TestBuildReplyEncodesNonASCIISubject(t *testing.T) {
	parent := mail.Message{Header: mail.Header{From: mail.Address{Addr: "a@b.example"}, Subject: "Réunion café"}}
	raw := string(buildReply("me@example.org", parent, mail.Draft{Body: "x"}))
	if strings.Contains(raw, "Réunion") {
		t.Errorf("non-ASCII subject was not encoded:\n%s", raw)
	}
	if !strings.Contains(raw, "=?utf-8?q?") && !strings.Contains(raw, "=?UTF-8?q?") {
		t.Errorf("expected an encoded word:\n%s", raw)
	}
}
