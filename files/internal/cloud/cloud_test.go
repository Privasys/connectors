// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cloud

import (
	"errors"
	"strings"
	"testing"
)

func TestIDs(t *testing.T) {
	id := EncodeID("b!drive", "01ITEM", `"{x},3"`)
	drive, item, etag, err := DecodeID(id)
	if err != nil || drive != "b!drive" || item != "01ITEM" || etag != `"{x},3"` {
		t.Fatalf("round trip: %q %q %q %v", drive, item, etag, err)
	}
	for _, bad := range []string{"", "not base64!", EncodeID("d", "", "e"), "MgBkAGkAZQ"} {
		if _, _, _, err := DecodeID(bad); !errors.Is(err, ErrBadID) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestCleanFolderAndName(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "runs": "runs", "runs/today": "runs today", " a / b ": "a b", `a\b`: "a b",
	} {
		segs, err := CleanFolder(in)
		if err != nil || strings.Join(segs, " ") != want {
			t.Errorf("CleanFolder(%q) = %v %v", in, segs, err)
		}
	}
	for _, bad := range []string{"/abs", "..", "a/../b", "./a", ".hidden", "a//b", "a/", strings.Repeat("x/", 9), "a:b", "con?"} {
		if _, err := CleanFolder(bad); !errors.Is(err, ErrBadFolder) {
			t.Errorf("CleanFolder(%q) should be refused: %v", bad, err)
		}
	}
	for in, want := range map[string]string{
		"notes": "notes.md text/markdown", "a.txt": "a.txt text/plain", "Data.CSV": "Data.CSV text/csv",
		"x.json": "x.json application/json", "  r.markdown ": "r.markdown text/markdown",
	} {
		name, mime, err := CleanName(in)
		if err != nil || name+" "+mime != want {
			t.Errorf("CleanName(%q) = %q %q %v", in, name, mime, err)
		}
	}
	for _, bad := range []string{"", "a/b.md", "../x.md", ".env", "x.exe", "x.docx", "a\x00.md", strings.Repeat("x", 200) + ".md"} {
		if _, _, err := CleanName(bad); !errors.Is(err, ErrBadName) {
			t.Errorf("CleanName(%q) should be refused: %v", bad, err)
		}
	}
}

func TestUniqueName(t *testing.T) {
	taken := map[string]bool{"notes.md": true, "notes (2).md": true, "plain": true}
	is := func(n string) bool { return taken[n] }
	for in, want := range map[string]string{"notes.md": "notes (3).md", "other.md": "other.md", "plain": "plain (2)"} {
		if got := UniqueName(in, is); got != want {
			t.Errorf("UniqueName(%q) = %q, want %q", in, got, want)
		}
	}
}
