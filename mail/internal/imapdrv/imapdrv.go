// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package imapdrv implements mail.Driver over IMAP.
//
// IMAP is the first driver, and for a while the only one that matters,
// because it is the only mailbox path with no vendor standing in front of it.
// A draft written here threads correctly in Gmail's own interface and a label
// applied here shows in Gmail's own sidebar, both proved against a real
// mailbox, so the connector can serve a real user with no API key, no OAuth
// verification and no annual security assessment.
//
// Everything unusual in this file is load-bearing and the comments say why.
// The short version: never ask for BODY[TEXT], always be able to skip a
// message, and re-select before you read by UID.
package imapdrv

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/Privasys/connectors/mail/internal/mail"
	"github.com/Privasys/connectors/mail/internal/mailtext"
	"github.com/Privasys/connectors/mail/internal/redact"
)

const (
	// defaultBodyBytes bounds one body fetch. A reply's own words are at the
	// top, so this is generous for the purpose and never pulls an attachment.
	defaultBodyBytes = 16 << 10

	// fetchBatch is how many messages one FETCH covers. Small enough that a
	// failure costs one batch, large enough that a 200-message listing is
	// eight round trips rather than two hundred.
	fetchBatch = 25

	snippetLen = 160
)

// Config is one mailbox.
type Config struct {
	Host     string // host:port, e.g. imap.gmail.com:993
	User     string
	Password string // app password today; XOAUTH2 when the OAuth drivers land

	// OwnDomains lets a caller tell colleagues from customers. Passed in
	// rather than guessed, because a hardcoded list is wrong for everyone
	// except whoever wrote it.
	OwnDomains []string
}

// Driver is a live IMAP mailbox. Safe for concurrent use: IMAP is a stateful
// single-conversation protocol, so calls are serialised on one mutex rather
// than pretending otherwise.
type Driver struct {
	cfg Config

	mu      sync.Mutex
	cl      *imapclient.Client
	sel     string // currently selected mailbox
	redials int

	folders struct {
		once   sync.Once
		inbox  string
		sent   string
		drafts string
	}
}

var _ mail.Driver = (*Driver)(nil)

// Open connects and authenticates.
func Open(cfg Config) (*Driver, error) {
	d := &Driver{cfg: cfg}
	if err := d.connect(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Driver) connect() error {
	host := d.cfg.Host
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	cl, err := imapclient.DialTLS(d.cfg.Host, &imapclient.Options{
		TLSConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
	})
	if err != nil {
		return fmt.Errorf("dial %s: %w", d.cfg.Host, err)
	}
	if err := cl.Login(d.cfg.User, d.cfg.Password).Wait(); err != nil {
		cl.Close()
		return fmt.Errorf("login as %s: %w", d.cfg.User, err)
	}
	d.cl = cl
	d.sel = ""
	return nil
}

// reconnect replaces a dead client. Long reads against a real mailbox do lose
// the connection, and every layer above has to keep working across that.
func (d *Driver) reconnect() error {
	if d.cl != nil {
		_ = d.cl.Close()
		d.cl = nil
	}
	if err := d.connect(); err != nil {
		return err
	}
	d.redials++
	return nil
}

func (d *Driver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cl == nil {
		return nil
	}
	_ = d.cl.Logout().Wait()
	err := d.cl.Close()
	d.cl = nil
	return err
}

// ---------------------------------------------------------------- folders

// resolveFolders finds the special-use mailboxes once.
//
// Never hard-code "[Gmail]/Sent Mail": SPECIAL-USE is what tells you, and the
// answer differs per provider and per account. An account may also publish
// only some of its folders over IMAP, so absence is normal and gets a
// fallback rather than an error.
func (d *Driver) resolveFolders() {
	d.folders.once.Do(func() {
		d.folders.inbox = "INBOX"
		d.folders.sent = "[Gmail]/Sent Mail"
		d.folders.drafts = "[Gmail]/Drafts"
		boxes, err := d.cl.List("", "*", &imap.ListOptions{
			SelectSpecialUse: true, ReturnSpecialUse: true,
		}).Collect()
		if err != nil {
			return
		}
		for _, b := range boxes {
			for _, a := range b.Attrs {
				switch a {
				case imap.MailboxAttrSent:
					d.folders.sent = b.Mailbox
				case imap.MailboxAttrDrafts:
					d.folders.drafts = b.Mailbox
				}
			}
		}
	})
}

func (d *Driver) selectBox(name string, readOnly bool) (*imap.SelectData, error) {
	sd, err := d.cl.Select(name, &imap.SelectOptions{ReadOnly: readOnly}).Wait()
	if err != nil {
		if rerr := d.reconnect(); rerr != nil {
			return nil, fmt.Errorf("select %s: %w (reconnect: %v)", name, err, rerr)
		}
		sd, err = d.cl.Select(name, &imap.SelectOptions{ReadOnly: readOnly}).Wait()
		if err != nil {
			return nil, fmt.Errorf("select %s: %w", name, err)
		}
	}
	d.sel = name
	return sd, nil
}

// ---------------------------------------------------------------- ids

// An id names a message by mailbox, UID validity and UID. It is opaque to the
// agent on purpose: it is a coordinate, not something to reason about, and
// encoding the UID validity is what makes a stale id detectable rather than a
// silent read of the wrong message after a mailbox is recreated.
type msgID struct {
	Folder      string
	UIDValidity uint32
	UID         imap.UID
}

func encodeID(m msgID) string {
	raw := fmt.Sprintf("%s\x00%d\x00%d", m.Folder, m.UIDValidity, uint32(m.UID))
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeID(s string) (msgID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return msgID{}, fmt.Errorf("%w: malformed id", mail.ErrNotFound)
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 {
		return msgID{}, fmt.Errorf("%w: malformed id", mail.ErrNotFound)
	}
	v, err1 := strconv.ParseUint(parts[1], 10, 32)
	u, err2 := strconv.ParseUint(parts[2], 10, 32)
	if err1 != nil || err2 != nil {
		return msgID{}, fmt.Errorf("%w: malformed id", mail.ErrNotFound)
	}
	return msgID{Folder: parts[0], UIDValidity: uint32(v), UID: imap.UID(u)}, nil
}

// ---------------------------------------------------------------- fetching

// textPart picks the leaf to read: the first non-attachment text/plain,
// falling back to text/html.
//
// The fallback is not a nicety. 25 of 200 real sent messages had no plain-text
// part at all, so a plain-only reader silently drops an eighth of a mailbox,
// and not a random eighth: whatever the user writes from an HTML-only client.
func textPart(bs imap.BodyStructure) (path []int, isHTML bool, enc, charset string) {
	var plain, html []int
	var pEnc, pCs, hEnc, hCs string
	bs.Walk(func(p []int, part imap.BodyStructure) bool {
		sp, ok := part.(*imap.BodyStructureSinglePart)
		if !ok {
			return true
		}
		if disp := part.Disposition(); disp != nil && strings.EqualFold(disp.Value, "attachment") {
			return true
		}
		if !strings.EqualFold(sp.Type, "text") {
			return true
		}
		switch {
		case strings.EqualFold(sp.Subtype, "plain") && plain == nil:
			plain = append([]int(nil), p...)
			pEnc, pCs = sp.Encoding, sp.Params["charset"]
		case strings.EqualFold(sp.Subtype, "html") && html == nil:
			html = append([]int(nil), p...)
			hEnc, hCs = sp.Encoding, sp.Params["charset"]
		}
		return true
	})
	if plain != nil {
		return plain, false, pEnc, pCs
	}
	return html, html != nil, hEnc, hCs
}

func attachments(bs imap.BodyStructure) []mail.Attachment {
	var out []mail.Attachment
	bs.Walk(func(p []int, part imap.BodyStructure) bool {
		sp, ok := part.(*imap.BodyStructureSinglePart)
		if !ok {
			return true
		}
		disp := part.Disposition()
		name := ""
		if disp != nil {
			name = disp.Params["filename"]
		}
		if name == "" {
			name = sp.Params["name"]
		}
		isAttach := disp != nil && strings.EqualFold(disp.Value, "attachment")
		if !isAttach && name == "" {
			return true
		}
		out = append(out, mail.Attachment{
			Name: name, Type: sp.MediaType(), Size: int64(sp.Size), Part: pathKey(p),
		})
		return true
	})
	return out
}

func pathKey(p []int) string {
	ss := make([]string, len(p))
	for i, n := range p {
		ss[i] = strconv.Itoa(n)
	}
	return strings.Join(ss, ".")
}

// metaOptions asks for everything ABOUT a message and nothing OF it. Cheap for
// the server, and enough to build a listing.
func metaOptions() *imap.FetchOptions {
	return &imap.FetchOptions{
		UID:           true,
		Flags:         true,
		Envelope:      true,
		RFC822Size:    true,
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
	}
}

// fetchMeta fetches metadata for a range, reconnecting once and then dropping
// to one message at a time.
//
// The per-message fallback is what makes a real mailbox readable at all: one
// message in 200 will not come back, twice, even alone, and a run that dies on
// it has read nothing.
func (d *Driver) fetchMeta(lo, hi uint32) ([]*imapclient.FetchMessageBuffer, []uint32) {
	set := imap.SeqSetNum()
	set.AddRange(lo, hi)
	msgs, err := d.cl.Fetch(set, metaOptions()).Collect()
	if err == nil {
		return msgs, nil
	}
	if rerr := d.reconnect(); rerr != nil {
		return nil, seqRange(lo, hi)
	}
	if _, err := d.selectBox(d.sel, true); err != nil {
		return nil, seqRange(lo, hi)
	}
	var out []*imapclient.FetchMessageBuffer
	var bad []uint32
	for n := lo; n <= hi; n++ {
		one := imap.SeqSetNum()
		one.AddNum(n)
		m, err := d.cl.Fetch(one, metaOptions()).Collect()
		if err != nil {
			bad = append(bad, n)
			continue
		}
		out = append(out, m...)
	}
	return out, bad
}

func seqRange(lo, hi uint32) []uint32 {
	out := make([]uint32, 0, hi-lo+1)
	for n := lo; n <= hi; n++ {
		out = append(out, n)
	}
	return out
}

// fetchBody reads one message's text leaf.
//
// NEVER BODY[TEXT]. That is a synthetic section the server assembles from
// parts it stores separately, and on some shapes the literal it announces does
// not match the bytes it sends, so the client waits for data that never
// arrives. A real 2 KB message with a multipart/alternative and a vCard was
// enough to hang it. A leaf is a stored part, cheaper and more correct: TEXT
// would also hand back MIME boundaries and the base64 of every other part.
func (d *Driver) fetchBody(uid imap.UID, bs imap.BodyStructure, maxBytes int) (string, bool) {
	path, isHTML, enc, cs := textPart(bs)
	if path == nil {
		return "", false
	}
	if maxBytes <= 0 {
		maxBytes = defaultBodyBytes
	}
	opts := &imap.FetchOptions{
		UID: true,
		BodySection: []*imap.FetchItemBodySection{{
			Part:    path,
			Peek:    true, // reading must never mark the user's mail as read
			Partial: &imap.SectionPartial{Offset: 0, Size: int64(maxBytes)},
		}},
	}
	msgs, err := d.cl.Fetch(imap.UIDSetNum(uid), opts).Collect()
	if err != nil || len(msgs) == 0 {
		return "", false
	}
	var raw []byte
	for _, s := range msgs[0].BodySection {
		raw = s.Bytes
		break
	}
	body := mailtext.Decode(raw, enc, cs)
	if isHTML {
		body = mailtext.HTMLToText(body)
	}
	return body, len(raw) >= maxBytes
}

// ---------------------------------------------------------------- mapping

func addr(a imap.Address) mail.Address {
	return mail.Address{Name: a.Name, Addr: a.Addr()}
}

func addrs(in []imap.Address) []mail.Address {
	out := make([]mail.Address, 0, len(in))
	for _, a := range in {
		out = append(out, addr(a))
	}
	return out
}

func (d *Driver) header(folder string, uidValidity uint32, m *imapclient.FetchMessageBuffer) mail.Header {
	h := mail.Header{
		ID: encodeID(msgID{Folder: folder, UIDValidity: uidValidity, UID: m.UID}),
	}
	if m.Envelope != nil {
		h.Date = m.Envelope.Date
		h.Subject = m.Envelope.Subject
		if len(m.Envelope.From) > 0 {
			h.From = addr(m.Envelope.From[0])
		}
		h.To = addrs(m.Envelope.To)
		h.Cc = addrs(m.Envelope.Cc)
		h.ThreadID = threadID(m.Envelope)
		h.MessageID = m.Envelope.MessageID
	}
	h.Unread = true
	for _, f := range m.Flags {
		if f == imap.FlagSeen {
			h.Unread = false
		}
	}
	if m.BodyStructure != nil {
		h.HasAttach = len(attachments(m.BodyStructure)) > 0
	}
	h.Repliable = mailtext.Repliable(h.From.Addr)
	return h
}

// threadID is the root Message-ID of the conversation.
//
// IMAP has no thread concept, so the root of the References chain is the
// closest honest equivalent, and it is stable across providers in a way a
// vendor thread id is not.
func threadID(e *imap.Envelope) string {
	if len(e.InReplyTo) > 0 && e.InReplyTo[0] != "" {
		return e.InReplyTo[0]
	}
	return e.MessageID
}

// ---------------------------------------------------------------- Driver

func (d *Driver) List(ctx context.Context, o mail.ListOptions) (mail.Page, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.resolveFolders()

	folder := o.Folder
	if folder == "" {
		folder = d.folders.inbox
	}
	sd, err := d.selectBox(folder, true)
	if err != nil {
		return mail.Page{}, err
	}
	if sd.NumMessages == 0 {
		return mail.Page{}, nil
	}
	limit := o.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	// Newest first, and always from a bounded recent window: the mailboxes
	// this runs against hold tens of thousands of messages, so there is no
	// "list everything" and a triage run never scans a folder.
	hi := sd.NumMessages
	if o.Cursor != "" {
		if c, err := strconv.ParseUint(o.Cursor, 10, 32); err == nil && uint32(c) < hi {
			hi = uint32(c)
		}
	}
	lo := uint32(1)
	if hi > uint32(limit) {
		lo = hi - uint32(limit) + 1
	}

	var page mail.Page
	for start := lo; start <= hi; start += fetchBatch {
		end := start + fetchBatch - 1
		if end > hi {
			end = hi
		}
		msgs, bad := d.fetchMeta(start, end)
		for _, n := range bad {
			page.Unreadable = append(page.Unreadable, fmt.Sprintf("seq:%d", n))
		}
		for _, m := range msgs {
			h := d.header(folder, sd.UIDValidity, m)
			if o.UnreadOnly && !h.Unread {
				continue
			}
			if !o.Since.IsZero() && h.Date.Before(o.Since) {
				continue
			}
			page.Headers = append(page.Headers, h)
		}
	}
	sort.Slice(page.Headers, func(i, j int) bool {
		return page.Headers[i].Date.After(page.Headers[j].Date)
	})
	if lo > 1 {
		page.Cursor = strconv.FormatUint(uint64(lo-1), 10)
	}
	return page, nil
}

func (d *Driver) Get(ctx context.Context, id string, maxBytes int) (mail.Message, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.get(id, maxBytes)
}

func (d *Driver) get(id string, maxBytes int) (mail.Message, error) {
	mid, err := decodeID(id)
	if err != nil {
		return mail.Message{}, err
	}
	// SELECT before reading by UID. Without this the fetch runs against
	// whatever was selected last, and a UID that exists comes back "not
	// found", which reads exactly like the message having been deleted.
	sd, err := d.selectBox(mid.Folder, true)
	if err != nil {
		return mail.Message{}, err
	}
	if sd.UIDValidity != mid.UIDValidity {
		return mail.Message{}, fmt.Errorf("%w: the mailbox was recreated since this id was issued", mail.ErrNotFound)
	}
	msgs, err := d.cl.Fetch(imap.UIDSetNum(mid.UID), metaOptions()).Collect()
	if err != nil {
		return mail.Message{}, fmt.Errorf("%w: %v", mail.ErrUnreadable, err)
	}
	if len(msgs) == 0 {
		return mail.Message{}, mail.ErrNotFound
	}
	m := msgs[0]
	out := mail.Message{Header: d.header(mid.Folder, sd.UIDValidity, m)}
	if m.BodyStructure != nil {
		out.Attachments = attachments(m.BodyStructure)
		out.HasAttach = len(out.Attachments) > 0
		body, truncated := d.fetchBody(mid.UID, m.BodyStructure, maxBytes)
		out.Truncated = truncated
		clean := redact.Apply(mailtext.OwnText(body))
		out.Text = clean.Text
		out.Redactions = clean.Count
		if s := clean.Summary(); s != "" {
			out.Text = s + "\n\n" + out.Text
		}
		out.Snippet = mailtext.Snippet(out.Text, snippetLen)
	}
	return out, nil
}

func (d *Driver) Thread(ctx context.Context, id string, maxBytes int) ([]mail.Message, error) {
	root, err := d.Get(ctx, id, maxBytes)
	if err != nil {
		return nil, err
	}
	if root.ThreadID == "" {
		return []mail.Message{root}, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	mid, _ := decodeID(id)
	sd, err := d.selectBox(mid.Folder, true)
	if err != nil {
		return []mail.Message{root}, nil
	}
	// Best effort by design. Gmail's IMAP SEARCH does not index every header,
	// so a partial thread is an expected outcome, not a failure: return what
	// came back rather than an error the agent cannot act on.
	crit := &imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{
		{Header: []imap.SearchCriteriaHeaderField{{Key: "References", Value: root.ThreadID}}},
		{Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: root.ThreadID}}},
	}}}
	res, err := d.cl.UIDSearch(crit, nil).Wait()
	if err != nil {
		return []mail.Message{root}, nil
	}
	uids := res.AllUIDs()
	out := []mail.Message{root}
	for _, u := range uids {
		if u == mid.UID {
			continue
		}
		m, err := d.get(encodeID(msgID{Folder: mid.Folder, UIDValidity: sd.UIDValidity, UID: u}), maxBytes)
		if err != nil {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Date.Before(out[j].Date) })
	return out, nil
}

func (d *Driver) Search(ctx context.Context, query string, o mail.ListOptions) (mail.Page, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.resolveFolders()

	folder := o.Folder
	if folder == "" {
		folder = d.folders.inbox
	}
	sd, err := d.selectBox(folder, true)
	if err != nil {
		return mail.Page{}, err
	}
	// The PROVIDER's search, not ours. It indexes years of mail and we hold
	// none of it, which is the whole point of not mirroring the mailbox.
	crit := &imap.SearchCriteria{Text: []string{query}}
	if !o.Since.IsZero() {
		crit.Since = o.Since
	}
	res, err := d.cl.UIDSearch(crit, nil).Wait()
	if err != nil {
		return mail.Page{}, fmt.Errorf("search: %w", err)
	}
	uids := res.AllUIDs()
	limit := o.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if len(uids) > limit {
		uids = uids[len(uids)-limit:] // newest
	}
	var page mail.Page
	for _, u := range uids {
		msgs, err := d.cl.Fetch(imap.UIDSetNum(u), metaOptions()).Collect()
		if err != nil || len(msgs) == 0 {
			page.Unreadable = append(page.Unreadable, encodeID(msgID{folder, sd.UIDValidity, u}))
			continue
		}
		page.Headers = append(page.Headers, d.header(folder, sd.UIDValidity, msgs[0]))
	}
	sort.Slice(page.Headers, func(i, j int) bool {
		return page.Headers[i].Date.After(page.Headers[j].Date)
	})
	return page, nil
}

func (d *Driver) Sent(ctx context.Context, limit int, since time.Time) ([]mail.Message, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.resolveFolders()

	sd, err := d.selectBox(d.folders.sent, true)
	if err != nil {
		return nil, err
	}
	if sd.NumMessages == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	lo := uint32(1)
	if sd.NumMessages > uint32(limit) {
		lo = sd.NumMessages - uint32(limit) + 1
	}

	var out []mail.Message
	for start := lo; start <= sd.NumMessages; start += fetchBatch {
		end := start + fetchBatch - 1
		if end > sd.NumMessages {
			end = sd.NumMessages
		}
		msgs, _ := d.fetchMeta(start, end)
		for _, m := range msgs {
			if m.BodyStructure == nil {
				continue
			}
			h := d.header(d.folders.sent, sd.UIDValidity, m)
			if !since.IsZero() && h.Date.Before(since) {
				continue
			}
			body, _ := d.fetchBody(m.UID, m.BodyStructure, defaultBodyBytes)
			text := mailtext.OwnText(body)
			if text == "" {
				// Legitimately empty: a forward sent with nothing added. About
				// one message in nine. Not an error, just not a sample.
				continue
			}
			clean := redact.Apply(text)
			out = append(out, mail.Message{Header: h, Text: clean.Text, Redactions: clean.Count})
		}
	}
	return out, nil
}

func (d *Driver) SetLabels(ctx context.Context, id string, add, remove []string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	mid, err := decodeID(id)
	if err != nil {
		return err
	}
	if _, err := d.selectBox(mid.Folder, false); err != nil {
		return err
	}
	// A label is a mailbox, and COPY applies it. Gmail renders an IMAP
	// mailbox as a label and leaves the message in the inbox, so this is
	// ordinary IMAP that happens to do the Gmail thing: no X-GM-LABELS, and
	// one code path for every provider.
	for _, name := range add {
		if name == "" {
			continue
		}
		if err := d.cl.Create(name, nil).Wait(); err != nil {
			// Already exists is the common case and not an error.
			_ = err
		}
		if _, err := d.cl.Copy(imap.UIDSetNum(mid.UID), name).Wait(); err != nil {
			return fmt.Errorf("apply label %q: %w", name, err)
		}
	}
	// Removing a label means deleting the message from that mailbox, which is
	// a different and more dangerous operation than adding one. Left unbuilt
	// until something needs it, because a bug here deletes mail.
	if len(remove) > 0 {
		return fmt.Errorf("removing labels is not implemented: it means expunging from a mailbox, and nothing needs it yet")
	}
	return nil
}

func (d *Driver) MarkRead(ctx context.Context, id string, read bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	mid, err := decodeID(id)
	if err != nil {
		return err
	}
	if _, err := d.selectBox(mid.Folder, false); err != nil {
		return err
	}
	op := imap.StoreFlagsAdd
	if !read {
		op = imap.StoreFlagsDel
	}
	cmd := d.cl.Store(imap.UIDSetNum(mid.UID), &imap.StoreFlags{
		Op: op, Silent: true, Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	if _, err := cmd.Collect(); err != nil {
		return fmt.Errorf("set \\Seen: %w", err)
	}
	return nil
}

func (d *Driver) CreateDraft(ctx context.Context, dr mail.Draft) (mail.DraftRef, error) {
	parent, err := d.Get(ctx, dr.ReplyTo, 0)
	if err != nil {
		return mail.DraftRef{}, fmt.Errorf("the message being replied to: %w", err)
	}
	if !parent.Repliable {
		// A no-reply sender. Refused here rather than left to the skill,
		// because the very first draft the spike produced was a reply to a
		// Google security alert and nothing in the agent stopped it.
		return mail.DraftRef{}, fmt.Errorf("%s is not a repliable address", parent.From.Addr)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.resolveFolders()

	raw := buildReply(d.cfg.User, parent, dr)
	app := d.cl.Append(d.folders.drafts, int64(len(raw)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagDraft},
		Time:  time.Now(),
	})
	if _, err := app.Write(raw); err != nil {
		return mail.DraftRef{}, fmt.Errorf("write draft: %w", err)
	}
	if err := app.Close(); err != nil {
		return mail.DraftRef{}, fmt.Errorf("finish draft: %w", err)
	}
	data, err := app.Wait()
	if err != nil {
		return mail.DraftRef{}, fmt.Errorf("store draft: %w", err)
	}
	ref := mail.DraftRef{ThreadID: parent.ThreadID}
	if data != nil && data.UID > 0 {
		ref.ID = encodeID(msgID{Folder: d.folders.drafts, UIDValidity: data.UIDValidity, UID: data.UID})
	}
	return ref, nil
}

func (d *Driver) DeleteDraft(ctx context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	mid, err := decodeID(id)
	if err != nil {
		return err
	}
	if !strings.EqualFold(mid.Folder, d.folders.drafts) {
		// Only ever a draft. This method must not become a way to delete mail.
		return fmt.Errorf("refusing to delete a message outside the Drafts folder")
	}
	if _, err := d.selectBox(mid.Folder, false); err != nil {
		return err
	}
	cmd := d.cl.Store(imap.UIDSetNum(mid.UID), &imap.StoreFlags{
		Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	if _, err := cmd.Collect(); err != nil {
		return fmt.Errorf("flag draft deleted: %w", err)
	}
	if err := d.cl.UIDExpunge(imap.UIDSetNum(mid.UID)).Close(); err != nil {
		return fmt.Errorf("expunge draft: %w", err)
	}
	return nil
}

// Changes waits on the mailbox's own event source.
//
// IDLE is what makes the whole product affordable: a quiet mailbox costs an
// open connection and nothing else, no polling, no model calls, no credits.
func (d *Driver) Changes(ctx context.Context, since string, wait time.Duration) ([]mail.Change, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.resolveFolders()

	sd, err := d.selectBox(d.folders.inbox, true)
	if err != nil {
		return nil, since, err
	}
	last := sd.NumMessages
	if since != "" {
		if v, err := strconv.ParseUint(since, 10, 32); err == nil {
			last = uint32(v)
		}
	}
	// Anything that arrived while we were away, before waiting for more.
	if sd.NumMessages > last {
		return d.arrivals(last, sd), strconv.FormatUint(uint64(sd.NumMessages), 10), nil
	}
	if wait <= 0 {
		return nil, strconv.FormatUint(uint64(sd.NumMessages), 10), nil
	}

	arrived := make(chan uint32, 1)
	d.cl.Close() // detach the current handler-less client
	d.cl = nil   //
	if err := d.connectWithHandler(arrived); err != nil {
		return nil, since, err
	}
	if _, err := d.selectBox(d.folders.inbox, true); err != nil {
		return nil, since, err
	}
	idle, err := d.cl.Idle()
	if err != nil {
		return nil, since, fmt.Errorf("idle: %w", err)
	}
	var now uint32
	select {
	case n := <-arrived:
		now = n
	case <-time.After(wait):
	case <-ctx.Done():
	}
	_ = idle.Close()
	_ = idle.Wait()

	if now <= last {
		return nil, strconv.FormatUint(uint64(last), 10), nil
	}
	sd2, err := d.selectBox(d.folders.inbox, true)
	if err != nil {
		return nil, since, err
	}
	return d.arrivals(last, sd2), strconv.FormatUint(uint64(sd2.NumMessages), 10), nil
}

func (d *Driver) connectWithHandler(arrived chan<- uint32) error {
	host := d.cfg.Host
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	cl, err := imapclient.DialTLS(d.cfg.Host, &imapclient.Options{
		TLSConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			Mailbox: func(data *imapclient.UnilateralDataMailbox) {
				if data != nil && data.NumMessages != nil {
					select {
					case arrived <- *data.NumMessages:
					default:
					}
				}
			},
		},
	})
	if err != nil {
		return fmt.Errorf("dial %s: %w", d.cfg.Host, err)
	}
	if err := cl.Login(d.cfg.User, d.cfg.Password).Wait(); err != nil {
		cl.Close()
		return fmt.Errorf("login as %s: %w", d.cfg.User, err)
	}
	d.cl = cl
	d.sel = ""
	return nil
}

func (d *Driver) arrivals(from uint32, sd *imap.SelectData) []mail.Change {
	var out []mail.Change
	lo := from + 1
	if lo < 1 {
		lo = 1
	}
	for start := lo; start <= sd.NumMessages; start += fetchBatch {
		end := start + fetchBatch - 1
		if end > sd.NumMessages {
			end = sd.NumMessages
		}
		msgs, _ := d.fetchMeta(start, end)
		for _, m := range msgs {
			out = append(out, mail.Change{
				ID:   encodeID(msgID{Folder: d.folders.inbox, UIDValidity: sd.UIDValidity, UID: m.UID}),
				Kind: "arrived",
			})
		}
	}
	return out
}
