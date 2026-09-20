// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package drive_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Privasys/connectors/sdk/broker"
	"github.com/Privasys/connectors/sdk/broker/brokertest"
	"github.com/Privasys/connectors/sdk/drive"
	"github.com/Privasys/connectors/sdk/drive/drivetest"
)

func rig(t *testing.T) (*drivetest.Fake, *drive.Client, drive.Folder) {
	t.Helper()
	b := brokertest.New(t, "archive")
	d := drivetest.New(t, b)
	d.Approve("u1")
	st, err := b.Client().Status(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	f, err := drive.FolderOf(st)
	if err != nil {
		t.Fatal(err)
	}
	return d, d.Client(t), f
}

func TestFolderOf(t *testing.T) {
	if _, err := drive.FolderOf(broker.Status{}); !errors.Is(err, broker.ErrNotApproved) {
		t.Errorf("not approved: %v", err)
	}
	if _, err := drive.FolderOf(broker.Status{Declined: true}); !errors.Is(err, broker.ErrDeclined) {
		t.Errorf("declined: %v", err)
	}
	if _, err := drive.FolderOf(broker.Status{Approved: true}); err == nil {
		t.Error("an approval with no coordinates was accepted")
	}
	f, err := drive.FolderOf(broker.Status{Approved: true, CapabilityID: "c", ServiceResult: map[string]string{"tenant_id": "t", "node_id": "n", "path": "AppData/X"}})
	if err != nil || f.TenantID != "t" || f.NodeID != "n" || f.Path != "AppData/X" || f.CapabilityID != "c" {
		t.Errorf("folder: %+v %v", f, err)
	}
}

func TestNewRefusesHalfAClient(t *testing.T) {
	b := brokertest.New(t, "archive")
	if _, err := drive.New("", nil, nil); err == nil {
		t.Error("no host")
	}
	if _, err := drive.New("drive.example", nil, b.Client()); err == nil {
		t.Error("no transport: a default client would not verify the peer")
	}
}

// Write by path with parents created, stat, read by node id, and the same
// path written again is the same node at a new revision.
func TestWriteStatReadAndIdempotence(t *testing.T) {
	d, c, f := rig(t)
	ctx := context.Background()

	if _, found, err := c.Stat(ctx, f, "2026/notes.md"); err != nil || found {
		t.Fatalf("stat before: %v %v", found, err)
	}
	n, err := c.Write(ctx, f, "2026/notes.md", []byte("# one"), "text/markdown")
	if err != nil || n.ID == "" || n.Rev != 1 {
		t.Fatalf("write: %+v %v", n, err)
	}
	st, found, err := c.Stat(ctx, f, "2026/notes.md")
	if err != nil || !found || st.ID != n.ID || !st.IsFile() {
		t.Fatalf("stat after: %+v %v %v", st, found, err)
	}
	data, found, err := c.Read(ctx, f, n.ID)
	if err != nil || !found || string(data) != "# one" {
		t.Fatalf("read: %q %v %v", data, found, err)
	}
	again, err := c.Write(ctx, f, "2026/notes.md", []byte("# two"), "text/markdown")
	if err != nil || again.ID != n.ID || again.Rev != 2 {
		t.Fatalf("rewrite: %+v %v", again, err)
	}
	if files := d.Files(); len(files) != 1 || string(files["notes.md"].Content) != "# two" {
		t.Fatalf("files: %+v", files)
	}
	if _, found, err := c.Read(ctx, f, "nope"); err != nil || found {
		t.Errorf("read missing: %v %v", found, err)
	}
	// Every request carried a fresh proof, signed by the broker.
	if d.Proofs() < 5 || d.Broker.Signed() < 5 {
		t.Errorf("proofs=%d signed=%d", d.Proofs(), d.Broker.Signed())
	}
}

func TestMkdirAndIndexing(t *testing.T) {
	d, c, f := rig(t)
	ctx := context.Background()
	n, err := c.Mkdir(ctx, f, "", "2027")
	if err != nil || n.Kind != "folder" || n.Name != "2027" {
		t.Fatalf("mkdir: %+v %v", n, err)
	}
	if _, err := c.Mkdir(ctx, f, "", "2027"); err == nil {
		t.Error("a second mkdir of the same name should be Drive's conflict")
	}
	file, _ := c.Write(ctx, f, "2027/a.md", []byte("a"), "text/markdown")

	// Drive lets only the holder mark a node searchable.
	if err := c.SetIndexing(ctx, f, file.ID, true); !errors.Is(err, drive.ErrHolderOnly) {
		t.Errorf("indexing as an app: %v", err)
	}
	d.IndexingAllowed = true
	if err := c.SetIndexing(ctx, f, file.ID, true); err != nil {
		t.Errorf("indexing when allowed: %v", err)
	}
	if !d.Files()["a.md"].Indexed {
		t.Error("the mark did not land")
	}
	if err := c.SetIndexing(ctx, f, "nope", true); !errors.Is(err, drive.ErrNotFound) {
		t.Errorf("indexing a missing node: %v", err)
	}
}

// A folder withdrawn in Drive surfaces as ErrWithdrawn on every call, while
// the broker still says approved.
func TestWithdrawnFolder(t *testing.T) {
	d, c, f := rig(t)
	ctx := context.Background()
	d.Withdraw()
	if _, _, err := c.Stat(ctx, f, "x"); !errors.Is(err, drive.ErrWithdrawn) {
		t.Errorf("stat: %v", err)
	}
	if _, err := c.Write(ctx, f, "x", []byte("x"), ""); !errors.Is(err, drive.ErrWithdrawn) {
		t.Errorf("write: %v", err)
	}
	if _, _, err := c.Read(ctx, f, "x"); !errors.Is(err, drive.ErrWithdrawn) {
		t.Errorf("read: %v", err)
	}
	if err := c.SetIndexing(ctx, f, "x", true); !errors.Is(err, drive.ErrWithdrawn) {
		t.Errorf("indexing: %v", err)
	}
}
