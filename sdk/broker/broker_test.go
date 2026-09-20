// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package broker_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/Privasys/connectors/sdk/broker"
	"github.com/Privasys/connectors/sdk/broker/brokertest"
)

func TestStatusAskAndSign(t *testing.T) {
	f := brokertest.New(t, "archive")
	c := f.Client()
	ctx := context.Background()

	st, err := c.Status(ctx, "u1")
	if err != nil || st.Approved || st.Declined {
		t.Fatalf("before approval: %+v %v", st, err)
	}

	// A holder who has not approved yet gets a push, and the ask carries
	// what a wallet needs to complete it as a prerequisite.
	ask, err := c.Ask(ctx, "u1", false)
	if err != nil || !ask.Pending() || ask.Status != "pending" {
		t.Fatalf("ask: %+v %v", ask, err)
	}
	if p := ask.Prerequisite(); p["app_host"] != "meetings.apps.example" || p["nonce"] != "nonce-u1" {
		t.Errorf("prerequisite: %v", p)
	}

	f.Approve("u1", "t-1", "n-1", "AppData/Meeting transcripts")
	st, err = c.Status(ctx, "u1")
	if err != nil || !st.Approved || st.TenantID() != "t-1" || st.NodeID() != "n-1" || st.Path() != "AppData/Meeting transcripts" {
		t.Fatalf("after approval: %+v %v", st, err)
	}
	if st.CapabilityID != "cap-u1" {
		t.Errorf("capability id: %q", st.CapabilityID)
	}
	ask, err = c.Ask(ctx, "u1", false)
	if err != nil || ask.Pending() || ask.Status != "already_granted" {
		t.Fatalf("ask after approval: %+v %v", ask, err)
	}

	// A decline sticks unless the retry is explicit.
	f.Decline("u2")
	ask, _ = c.Ask(ctx, "u2", false)
	if ask.Status != "declined" || ask.Pending() {
		t.Errorf("declined: %+v", ask)
	}
	ask, _ = c.Ask(ctx, "u2", true)
	if !ask.Pending() {
		t.Errorf("retry: %+v", ask)
	}
	if asks := f.Asks(); len(asks) != 4 || !asks[3].Retry {
		t.Errorf("asks recorded: %+v", asks)
	}

	sig, pub, err := c.Sign(ctx, []byte("payload"))
	if err != nil || pub != f.PublicB64() {
		t.Fatalf("sign: %v %q", err, pub)
	}
	if !ed25519.Verify(f.Public, []byte("payload"), sig) {
		t.Error("the signature does not verify with the key the broker named")
	}
}

func TestNewWithoutTheRuntime(t *testing.T) {
	t.Setenv("PRIVASYS_MANAGER_URL", "")
	t.Setenv("PRIVASYS_RUNTIME_URL", "")
	t.Setenv("PRIVASYS_CONTAINER_TOKEN", "")
	t.Setenv("PRIVASYS_APP_TOKEN", "")
	if _, err := broker.New("archive"); err != broker.ErrUnavailable {
		t.Errorf("off the platform: %v", err)
	}
	t.Setenv("PRIVASYS_MANAGER_URL", "http://127.0.0.1:1")
	t.Setenv("PRIVASYS_CONTAINER_TOKEN", "x")
	if _, err := broker.New("archive"); err != nil {
		t.Errorf("on the platform: %v", err)
	}
}
