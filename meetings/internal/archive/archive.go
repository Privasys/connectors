// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package archive keeps a transcript in the holder's own Drive.
//
// This is the one place a connector writes anything durable, and the reason
// is rule 2 of the connectors README: a transcript has no durable home.
// Zoom's retention ages recordings out, Teams' too, and a transcript is a
// document, the highest-value knowledge the holder's assistant will ever
// have. So it goes where the holder's documents live, under the holder's
// keys, in a folder this app declared and the holder approved on their
// device. The connector's own disk never sees it, and the holder withdraws
// the folder in Drive whenever they like: archiving then stops, and nothing
// else breaks.
package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/connectors/meetings/internal/meet"
	"github.com/Privasys/connectors/sdk/broker"
	"github.com/Privasys/connectors/sdk/drive"
	"github.com/Privasys/connectors/sdk/vtt"
)

// Resource is the manifest name of the folder this connector declares.
const Resource = "archive"

// ErrNotConfigured is a deployment with no Drive to archive into.
var ErrNotConfigured = errors.New("this deployment has no Drive configured, so transcripts cannot be kept here")

// NeedsFolder is the holder's folder not being usable: never approved,
// declined, or withdrawn in Drive. Reason is the sentence for the agent.
type NeedsFolder struct {
	Reason string
	// Withdrawn says Drive refused a folder the runtime still reports
	// approved.
	Withdrawn bool
}

func (e *NeedsFolder) Error() string { return e.Reason }

// Status is what account() and the setup route say about the folder.
type Status struct {
	Configured bool   `json:"configured"`
	Approved   bool   `json:"approved"`
	Declined   bool   `json:"declined,omitempty"`
	Withdrawn  bool   `json:"withdrawn,omitempty"`
	Path       string `json:"path,omitempty"`
}

// Saved is where a transcript landed.
type Saved struct {
	Folder       string `json:"folder"`
	MarkdownPath string `json:"markdown_path"`
	VTTPath      string `json:"vtt_path"`
	MarkdownNode string `json:"markdown_node"`
	VTTNode      string `json:"vtt_node"`
	// Updated says the files existed and were replaced: the same meeting
	// saved twice.
	Updated bool `json:"updated"`
	// Indexed says Drive accepted the mark that makes the Markdown part of
	// the holder's searchable memory; Indexing says what Drive answered.
	Indexed  bool   `json:"indexed"`
	Indexing string `json:"indexing"`
}

// Archive is what the connector needs from the place transcripts are kept.
type Archive interface {
	Status(ctx context.Context, sub string) (Status, error)
	// Prerequisite asks the runtime for the folder when the holder has not
	// approved it, or withdrew it, and returns what the wallet needs to
	// complete the ask; nil when nothing is needed or nothing can be asked.
	Prerequisite(ctx context.Context, sub string) []map[string]string
	Save(ctx context.Context, sub string, m meet.Meeting, t *vtt.Transcript, raw []byte) (Saved, error)
}

// None is the archive of a deployment that has none.
type None struct{}

func (None) Status(context.Context, string) (Status, error) { return Status{}, nil }
func (None) Prerequisite(context.Context, string) []map[string]string {
	return nil
}
func (None) Save(context.Context, string, meet.Meeting, *vtt.Transcript, []byte) (Saved, error) {
	return Saved{}, ErrNotConfigured
}

// Drive keeps transcripts in each holder's Drive through the attested leg.
type Drive struct {
	broker *broker.Client
	drive  *drive.Client
	now    func() time.Time

	mu        sync.Mutex
	withdrawn map[string]bool
}

// NewDrive builds the archive over the runtime broker and the Drive client.
func NewDrive(b *broker.Client, d *drive.Client) *Drive {
	return &Drive{broker: b, drive: d, now: time.Now, withdrawn: map[string]bool{}}
}

func (a *Drive) isWithdrawn(sub string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.withdrawn[sub]
}

func (a *Drive) setWithdrawn(sub string, v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if v {
		a.withdrawn[sub] = true
	} else {
		delete(a.withdrawn, sub)
	}
}

// Status reads the runtime's record, and remembers what Drive said last:
// a folder withdrawn in Drive is still "approved" to the runtime.
func (a *Drive) Status(ctx context.Context, sub string) (Status, error) {
	st, err := a.broker.Status(ctx, sub)
	if err != nil {
		return Status{Configured: true}, err
	}
	out := Status{Configured: true, Approved: st.Approved, Declined: st.Declined, Path: st.Path()}
	if out.Approved && a.isWithdrawn(sub) {
		out.Approved, out.Withdrawn = false, true
	}
	return out, nil
}

// Prerequisite lists the folder ask for the wallet: a first ask when the
// holder has not approved, a retry when Drive said the folder is gone.
// Nothing for a holder who declined: asking again after a refusal is how a
// consent prompt becomes spam.
func (a *Drive) Prerequisite(ctx context.Context, sub string) []map[string]string {
	retry := a.isWithdrawn(sub)
	if !retry {
		st, err := a.broker.Status(ctx, sub)
		if err != nil || st.Approved || st.Declined {
			return nil
		}
	}
	ask, err := a.broker.Ask(ctx, sub, retry)
	if err != nil || !ask.Pending() {
		return nil
	}
	return []map[string]string{ask.Prerequisite()}
}

// folder is the holder's approved folder, or the sentence for the agent.
func (a *Drive) folder(ctx context.Context, sub string) (drive.Folder, error) {
	st, err := a.broker.Status(ctx, sub)
	if err != nil {
		return drive.Folder{}, err
	}
	f, err := drive.FolderOf(st)
	switch {
	case errors.Is(err, broker.ErrDeclined):
		return drive.Folder{}, &NeedsFolder{Reason: "the user declined the Meeting transcripts folder in their Drive, so transcripts cannot be kept there. " +
			"Only they can change that: they approve the folder on their device, which their wallet asks for when the transcripts access is next approved with ask_again"}
	case errors.Is(err, broker.ErrNotApproved):
		return drive.Folder{}, &NeedsFolder{Reason: "the user has not approved the Meeting transcripts folder in their Drive, so there is nowhere to keep this. " +
			"They approve the folder on their device: their wallet asks for it when the transcripts access is next approved with ask_again. " +
			"Do not call request_access for a storage.folder resource of this service; the folder is this service's own ask, not the assistant's"}
	case err != nil:
		return drive.Folder{}, err
	}
	if a.isWithdrawn(sub) {
		return drive.Folder{}, withdrawn()
	}
	return f, nil
}

func withdrawn() *NeedsFolder {
	return &NeedsFolder{Withdrawn: true, Reason: "the user withdrew the Meeting transcripts folder in their Drive, so archiving has stopped; reading transcripts still works. " +
		"Only they can restore it: they approve the folder again on their device, which their wallet asks for when the transcripts access is next approved with ask_again"}
}

// Save writes the Markdown and the raw WebVTT, and asks Drive to index the
// Markdown. The same meeting saved twice lands on the same two files.
func (a *Drive) Save(ctx context.Context, sub string, m meet.Meeting, t *vtt.Transcript, raw []byte) (Saved, error) {
	f, err := a.folder(ctx, sub)
	if err != nil {
		return Saved{}, err
	}
	stem, updated, err := a.stemFor(ctx, f, m)
	if err != nil {
		return Saved{}, a.mapErr(sub, err)
	}
	mdPath, vttPath := stem+".md", stem+".vtt"
	md, err := a.drive.Write(ctx, f, mdPath, Markdown(m, t, a.now()), "text/markdown")
	if err != nil {
		return Saved{}, a.mapErr(sub, err)
	}
	vt, err := a.drive.Write(ctx, f, vttPath, raw, "text/vtt")
	if err != nil {
		return Saved{}, a.mapErr(sub, err)
	}
	a.setWithdrawn(sub, false)
	out := Saved{
		Folder: f.Path, MarkdownPath: join(f.Path, mdPath), VTTPath: join(f.Path, vttPath),
		MarkdownNode: md.ID, VTTNode: vt.ID, Updated: updated,
	}
	switch ierr := a.drive.SetIndexing(ctx, f, md.ID, true); {
	case ierr == nil:
		out.Indexed = true
		out.Indexing = "Drive will index the Markdown, so it becomes searchable in the user's Drive"
	case errors.Is(ierr, drive.ErrHolderOnly):
		out.Indexing = "Drive lets only the user make an app's folder searchable: the transcript is kept but not indexed until they enable search on the Meeting transcripts folder in Drive"
	default:
		out.Indexing = "Drive did not accept the indexing mark: " + ierr.Error()
	}
	return out, nil
}

// mapErr turns Drive's withdrawal into the sentence, and remembers it so
// the setup route asks for the folder again.
func (a *Drive) mapErr(sub string, err error) error {
	if errors.Is(err, drive.ErrWithdrawn) {
		a.setWithdrawn(sub, true)
		return withdrawn()
	}
	return err
}

// stemFor is the file name without its extension, and whether a file for
// this meeting is already there. A different meeting that happens to share
// the date and the title gets a suffix rather than overwriting it.
func (a *Drive) stemFor(ctx context.Context, f drive.Folder, m meet.Meeting) (string, bool, error) {
	stem := Stem(m)
	n, found, err := a.drive.Stat(ctx, f, stem+".md")
	if err != nil {
		return "", false, err
	}
	if !found {
		return stem, false, nil
	}
	existing, ok, err := a.drive.Read(ctx, f, n.ID)
	if err != nil {
		return "", false, err
	}
	if !ok || meetingIDOf(existing) == "" || meetingIDOf(existing) == m.ID {
		return stem, true, nil
	}
	stem += " (" + shortID(m.ID) + ")"
	_, found, err = a.drive.Stat(ctx, f, stem+".md")
	if err != nil {
		return "", false, err
	}
	return stem, found, nil
}

func join(folder, path string) string {
	if folder == "" {
		return path
	}
	return strings.TrimRight(folder, "/") + "/" + path
}

// ---------------------------------------------------------------- the files

var (
	unsafeRe = regexp.MustCompile(`[\x00-\x1f/\\:*?"<>|]+`)
	spaceRe  = regexp.MustCompile(`\s+`)
	metaRe   = regexp.MustCompile(`(?m)^meeting_id: "(.*)"$`)
)

// Stem is `<date> <title>`, safe as a file name on every platform, the
// title trimmed to a length a listing can show.
func Stem(m meet.Meeting) string {
	title := spaceRe.ReplaceAllString(unsafeRe.ReplaceAllString(m.Title, " "), " ")
	title = strings.Trim(strings.TrimSpace(title), ". ")
	if r := []rune(title); len(r) > 80 {
		title = strings.TrimSpace(string(r[:80]))
	}
	if title == "" {
		title = "Meeting"
	}
	date := "undated"
	if !m.Start.IsZero() {
		date = m.Start.UTC().Format("2006-01-02")
	}
	return date + " " + title
}

func shortID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:4])
}

// meetingIDOf reads the meeting id out of a saved file's front matter.
func meetingIDOf(md []byte) string {
	m := metaRe.FindSubmatch(md)
	if m == nil {
		return ""
	}
	id, err := strconv.Unquote(`"` + string(m[1]) + `"`)
	if err != nil {
		return ""
	}
	return id
}

// Markdown is the saved document: front matter with what the provider said
// about the meeting, then the speaker-attributed text.
func Markdown(m meet.Meeting, t *vtt.Transcript, savedAt time.Time) []byte {
	var b bytes.Buffer
	b.WriteString("---\n")
	fmt.Fprintf(&b, "title: %s\n", strconv.Quote(m.Title))
	fmt.Fprintf(&b, "provider: %s\n", m.Provider)
	fmt.Fprintf(&b, "meeting_id: %s\n", strconv.Quote(m.ID))
	if !m.Start.IsZero() {
		fmt.Fprintf(&b, "start: %s\n", m.Start.UTC().Format(time.RFC3339))
	}
	if !m.End.IsZero() {
		fmt.Fprintf(&b, "end: %s\n", m.End.UTC().Format(time.RFC3339))
	}
	if m.Organiser != nil {
		fmt.Fprintf(&b, "organiser: %s\n", strconv.Quote(personText(*m.Organiser)))
	}
	if people := Participants(m, t); len(people) > 0 {
		b.WriteString("participants:\n")
		for _, p := range people {
			fmt.Fprintf(&b, "  - %s\n", strconv.Quote(p))
		}
	}
	if t != nil && t.Duration() > 0 {
		fmt.Fprintf(&b, "duration: %s\n", vtt.Clock(t.Duration()))
	}
	fmt.Fprintf(&b, "saved: %s\n", savedAt.UTC().Format(time.RFC3339))
	b.WriteString("---\n\n")
	title := m.Title
	if title == "" {
		title = "Meeting"
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	if t != nil {
		b.WriteString(t.Text())
	}
	return b.Bytes()
}

// Participants is everyone known to have been there: the provider's list,
// and whoever spoke in the transcript, names first, sorted, deduplicated.
func Participants(m meet.Meeting, t *vtt.Transcript) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[strings.ToLower(s)] {
			return
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	for _, p := range m.Participants {
		add(personText(p))
	}
	if t != nil {
		for _, s := range t.Speakers() {
			add(s)
		}
	}
	sort.Strings(out)
	return out
}

func personText(p meet.Person) string {
	switch {
	case p.Name != "" && p.Address != "":
		return p.Name + " <" + p.Address + ">"
	case p.Name != "":
		return p.Name
	}
	return p.Address
}
