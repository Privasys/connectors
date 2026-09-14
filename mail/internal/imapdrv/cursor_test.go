// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package imapdrv

import (
	"testing"

	"github.com/emersion/go-imap/v2"
)

func TestUIDCursorRoundTripsWithinOneValidity(t *testing.T) {
	c := uidCursor(77, 1234)
	got, ok := parseUIDCursor(c, 77)
	if !ok || got != 1234 {
		t.Fatalf("parse(%q) = %d,%v want 1234,true", c, got, ok)
	}
}

func TestUIDCursorFromAnotherIncarnationIsStale(t *testing.T) {
	if _, ok := parseUIDCursor(uidCursor(77, 1234), 78); ok {
		t.Fatal("a cursor from a recreated mailbox must not be read as a position in the new one")
	}
}

func TestCountCursorsOfEarlierReleasesAreIgnored(t *testing.T) {
	for _, c := range []string{"", "1222", "uid:", "uid:77", "uid:77:0", "uid:x:1"} {
		if _, ok := parseUIDCursor(c, 77); ok {
			t.Fatalf("%q must not parse as a UID cursor", c)
		}
	}
}

func TestPageOfUIDsWalksNewestFirstBelowTheCursor(t *testing.T) {
	all := []imap.UID{3, 9, 1, 7, 5}
	page, lowest, more := pageOfUIDs(all, 0, 2)
	if len(page) != 2 || page[0] != 9 || page[1] != 7 || lowest != 7 || !more {
		t.Fatalf("first page = %v lowest=%d more=%v", page, lowest, more)
	}
	page, lowest, more = pageOfUIDs(all, lowest, 2)
	if len(page) != 2 || page[0] != 5 || page[1] != 3 || lowest != 3 || !more {
		t.Fatalf("second page = %v lowest=%d more=%v", page, lowest, more)
	}
	page, lowest, more = pageOfUIDs(all, lowest, 2)
	if len(page) != 1 || page[0] != 1 || lowest != 1 || more {
		t.Fatalf("last page = %v lowest=%d more=%v", page, lowest, more)
	}
}
