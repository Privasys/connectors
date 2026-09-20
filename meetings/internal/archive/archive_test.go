// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package archive

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/meetings/internal/meet"
	"github.com/Privasys/connectors/sdk/broker/brokertest"
	"github.com/Privasys/connectors/sdk/drive/drivetest"
	"github.com/Privasys/connectors/sdk/vtt"
)

const sampleVTT = "WEBVTT\n\n00:00:00.500 --> 00:00:02.000\n<v Alice Smith>Hello</v>\n\n00:00:02.100 --> 00:00:04.000\n<v Bob Jones>Hi Alice</v>\n"

var savedAt = time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)

func meeting(id, title string) meet.Meeting {
	return meet.Meeting{
		ID: id, Provider: meet.ProviderZoom, Title: title,
		Start: time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC), End: time.Date(2026, 9, 10, 9, 30, 0, 0, time.UTC),
		Organiser:     &meet.Person{Address: "host@example.org"},
		Participants:  []meet.Person{{Name: "Carol", Address: "carol@example.org"}},
		HasTranscript: true,
	}
}

func rig(t *testing.T) (*drivetest.Fake, *Drive) {
	t.Helper()
	b := brokertest.New(t, Resource)
	d := drivetest.New(t, b)
	a := NewDrive(b.Client(), d.Client(t))
	a.now = func() time.Time { return savedAt }
	return d, a
}

func parsed(t *testing.T) *vtt.Transcript {
	t.Helper()
	tr, err := vtt.ParseBytes([]byte(sampleVTT))
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestStemAndMarkdown(t *testing.T) {
	m := meeting("abc+def==", `Q3: plan / "review" <draft>`)
	if got := Stem(m); got != "2026-09-10 Q3 plan review draft" {
		t.Errorf("stem: %q", got)
	}
	if got := Stem(meet.Meeting{ID: "x"}); got != "undated Meeting" {
		t.Errorf("empty stem: %q", got)
	}
	long := meeting("x", strings.Repeat("word ", 40))
	if r := []rune(Stem(long)); len(r) > 92 {
		t.Errorf("a long title is trimmed: %d", len(r))
	}
	md := string(Markdown(m, parsed(t), savedAt))
	for _, want := range []string{
		"---\ntitle: \"Q3: plan / \\\"review\\\" <draft>\"\n", "provider: zoom\n", "meeting_id: \"abc+def==\"\n",
		"start: 2026-09-10T09:00:00Z\n", "end: 2026-09-10T09:30:00Z\n", "organiser: \"host@example.org\"\n",
		"participants:\n  - \"Alice Smith\"\n  - \"Bob Jones\"\n  - \"Carol <carol@example.org>\"\n",
		"duration: 00:00:04\n", "saved: 2026-09-20T10:00:00Z\n---\n\n# Q3: plan / \"review\" <draft>\n\n",
		"[00:00:00] Alice Smith: Hello\n[00:00:02] Bob Jones: Hi Alice\n",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
	if meetingIDOf([]byte(md)) != "abc+def==" {
		t.Errorf("meeting id read back: %q", meetingIDOf([]byte(md)))
	}
}

func TestSaveIsIdempotentAndReportsIndexing(t *testing.T) {
	d, a := rig(t)
	d.Approve("u1")
	ctx := context.Background()

	saved, err := a.Save(ctx, "u1", meeting("m-1", "Weekly sync"), parsed(t), []byte(sampleVTT))
	if err != nil {
		t.Fatal(err)
	}
	if saved.Folder != "AppData/Meeting transcripts" || saved.MarkdownPath != "AppData/Meeting transcripts/2026-09-10 Weekly sync.md" ||
		saved.VTTPath != "AppData/Meeting transcripts/2026-09-10 Weekly sync.vtt" || saved.Updated {
		t.Errorf("saved: %+v", saved)
	}
	if saved.Indexed || !strings.Contains(saved.Indexing, "only the user") {
		t.Errorf("Drive refuses an app's indexing mark today, and the answer says so: %+v", saved)
	}
	files := d.Files()
	if len(files) != 2 || string(files["2026-09-10 Weekly sync.vtt"].Content) != sampleVTT {
		t.Fatalf("files: %v", files)
	}
	if !strings.Contains(string(files["2026-09-10 Weekly sync.md"].Content), "meeting_id: \"m-1\"") {
		t.Errorf("markdown: %s", files["2026-09-10 Weekly sync.md"].Content)
	}

	// The same meeting again: the same two files, replaced.
	again, err := a.Save(ctx, "u1", meeting("m-1", "Weekly sync"), parsed(t), []byte(sampleVTT+"\n"))
	if err != nil || !again.Updated || again.MarkdownNode != saved.MarkdownNode || again.VTTNode != saved.VTTNode {
		t.Fatalf("second save: %+v %v", again, err)
	}
	if files := d.Files(); len(files) != 2 || files["2026-09-10 Weekly sync.md"].Rev != 2 {
		t.Errorf("files after the second save: %v", files)
	}

	// A different meeting with the same date and title gets its own files.
	other, err := a.Save(ctx, "u1", meeting("m-2", "Weekly sync"), parsed(t), []byte(sampleVTT))
	if err != nil || other.Updated || !strings.HasSuffix(other.MarkdownPath, ").md") || other.MarkdownNode == saved.MarkdownNode {
		t.Fatalf("collision: %+v %v", other, err)
	}
	if len(d.Files()) != 4 {
		t.Errorf("files after the collision: %v", d.Files())
	}

	// And when Drive takes the mark, it is reported.
	d.IndexingAllowed = true
	marked, err := a.Save(ctx, "u1", meeting("m-1", "Weekly sync"), parsed(t), []byte(sampleVTT))
	if err != nil || !marked.Indexed {
		t.Errorf("indexed: %+v %v", marked, err)
	}
}

func TestFolderNotApprovedDeclinedAndWithdrawn(t *testing.T) {
	d, a := rig(t)
	ctx := context.Background()
	m := meeting("m-1", "Weekly sync")

	var needs *NeedsFolder
	_, err := a.Save(ctx, "u1", m, parsed(t), []byte(sampleVTT))
	if !errors.As(err, &needs) || needs.Withdrawn || !strings.Contains(err.Error(), "has not approved") {
		t.Fatalf("not approved: %v", err)
	}
	st, _ := a.Status(ctx, "u1")
	if !st.Configured || st.Approved {
		t.Errorf("status: %+v", st)
	}
	// The setup route asks for the folder once.
	if p := a.Prerequisite(ctx, "u1"); len(p) != 1 || p[0]["nonce"] != "nonce-u1" || p[0]["app_host"] != "meetings.apps.example" {
		t.Errorf("prerequisite: %v", p)
	}

	d.Broker.Decline("u2")
	_, err = a.Save(ctx, "u2", m, parsed(t), []byte(sampleVTT))
	if !errors.As(err, &needs) || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("declined: %v", err)
	}
	if p := a.Prerequisite(ctx, "u2"); p != nil {
		t.Errorf("a decline is not asked again on its own: %v", p)
	}

	d.Approve("u1")
	if p := a.Prerequisite(ctx, "u1"); p != nil {
		t.Errorf("approved: nothing to ask: %v", p)
	}
	if _, err := a.Save(ctx, "u1", m, parsed(t), []byte(sampleVTT)); err != nil {
		t.Fatal(err)
	}

	// Withdrawn in Drive: the broker still says approved, Drive says 401,
	// the archive remembers and asks again with retry.
	d.Withdraw()
	_, err = a.Save(ctx, "u1", m, parsed(t), []byte(sampleVTT))
	if !errors.As(err, &needs) || !needs.Withdrawn {
		t.Fatalf("withdrawn: %v", err)
	}
	st, _ = a.Status(ctx, "u1")
	if st.Approved || !st.Withdrawn {
		t.Errorf("status after withdrawal: %+v", st)
	}
	asksBefore := len(d.Broker.Asks())
	if p := a.Prerequisite(ctx, "u1"); len(p) != 1 {
		t.Errorf("prerequisite after withdrawal: %v", p)
	}
	asks := d.Broker.Asks()
	if len(asks) != asksBefore+1 || !asks[len(asks)-1].Retry {
		t.Errorf("the ask after a withdrawal is a retry: %+v", asks)
	}
	_, err = a.Save(ctx, "u1", m, parsed(t), []byte(sampleVTT))
	if !errors.As(err, &needs) || !needs.Withdrawn {
		t.Fatalf("still withdrawn: %v", err)
	}
}

func TestNone(t *testing.T) {
	var a Archive = None{}
	if _, err := a.Save(context.Background(), "u", meet.Meeting{}, nil, nil); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("none: %v", err)
	}
	if st, _ := a.Status(context.Background(), "u"); st.Configured {
		t.Errorf("none status: %+v", st)
	}
	if a.Prerequisite(context.Background(), "u") != nil {
		t.Error("none asks nothing")
	}
}
