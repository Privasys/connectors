// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package imapdrv

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// The initial response is the one Google documents, byte for byte: the
// address, the bearer, ^A between and two ^A at the end. Base64 is the IMAP
// layer's, so the client hands over the raw string.
func TestXoauth2InitialResponse(t *testing.T) {
	mech, ir, err := newXoauth2Client("someuser@example.com", "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg").Start()
	if err != nil || mech != "XOAUTH2" {
		t.Fatalf("mechanism: %q %v", mech, err)
	}
	want := "user=someuser@example.com\x01auth=Bearer ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg\x01\x01"
	if string(ir) != want {
		t.Fatalf("initial response:\n got %q\nwant %q", ir, want)
	}
	// Google's own worked example, once the IMAP layer has base64-encoded it.
	if got := base64.StdEncoding.EncodeToString(ir); got != "dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5LnZGOWRmdDRxbVRjMk52YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ==" {
		t.Fatalf("base64 form differs from Google's example: %s", got)
	}
}

// A challenge only ever means a refusal. It is reported as ErrLogin with the
// server's status, so a caller trying several servers for one address stops
// here as it does for a wrong password, and the exchange is not continued.
func TestXoauth2ChallengeIsARefusal(t *testing.T) {
	c := newXoauth2Client("me@example.com", "expired")
	_, _, _ = c.Start()
	_, err := c.Next([]byte(`{"status":"401","schemes":"bearer","scope":"https://mail.google.com/"}`))
	if !errors.Is(err, ErrLogin) {
		t.Fatalf("a challenge must be the server refusing the credential: %v", err)
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "https://mail.google.com/") {
		t.Fatalf("the status and the wanted scope should be in the error: %v", err)
	}
	// An unparseable challenge is still a refusal, not a crash.
	c = newXoauth2Client("me@example.com", "expired")
	if _, err := c.Next([]byte("not json")); !errors.Is(err, ErrLogin) {
		t.Fatalf("rubbish challenge: %v", err)
	}
}

// The token source is asked at the dial, so a reconnect after an hour gets a
// token that is still live rather than the one the mailbox was opened with;
// and the token source failing is not the mailbox refusing.
func TestLoginAsksTheTokenSourceAtEachDial(t *testing.T) {
	calls := 0
	d := &Driver{cfg: Config{User: "me@example.com", Token: func(context.Context) (string, error) {
		calls++
		return "", errors.New("the token endpoint is down")
	}}}
	err := d.login(nil) // never reaches the client: the token fails first
	if err == nil || errors.Is(err, ErrLogin) || !strings.Contains(err.Error(), "token endpoint is down") {
		t.Fatalf("a token source failure is its own error, not ErrLogin: %v", err)
	}
	_ = d.login(nil)
	if calls != 2 {
		t.Fatalf("the token source is asked at every dial, got %d calls", calls)
	}
}
