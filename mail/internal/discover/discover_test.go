// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package discover

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDomainOfAnAddress(t *testing.T) {
	for in, want := range map[string]string{
		"Me@Example.COM": "example.com", "  me@gmail.com ": "gmail.com",
		"Bertrand <b@x.org>": "x.org", "nothing": "", "trailing@": "",
	} {
		if got := Domain(in); got != want {
			t.Errorf("Domain(%q) = %q, want %q", in, got, want)
		}
	}
}

// A well-known provider is answered from the table alone: no DNS, no HTTP,
// and no plain guesses that would only make a wrong password slower to
// report.
func TestWellKnownProviderNeedsNoLookup(t *testing.T) {
	r := &Resolver{
		LookupSRV: func(context.Context, string, string, string) ([]*net.SRV, error) {
			t.Fatal("DNS was asked for a well-known provider")
			return nil, nil
		},
	}
	got := r.Candidates(context.Background(), "someone@gmail.com")
	if len(got) != 1 || got[0] != "imap.gmail.com:993" {
		t.Fatalf("candidates = %v", got)
	}
}

// An unknown domain is resolved in order: the DNS record, the autoconfig
// database, then the two guesses, without duplicates.
func TestUnknownDomainWalksTheLayers(t *testing.T) {
	ispdb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/example.org") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`<clientConfig version="1.1"><emailProvider id="example.org">
  <incomingServer type="imap"><hostname>imap.example.org</hostname><port>993</port><socketType>SSL</socketType></incomingServer>
  <incomingServer type="imap"><hostname>plain.example.org</hostname><port>143</port><socketType>STARTTLS</socketType></incomingServer>
  <incomingServer type="pop3"><hostname>pop.example.org</hostname><port>995</port><socketType>SSL</socketType></incomingServer>
</emailProvider></clientConfig>`))
	}))
	defer ispdb.Close()
	r := &Resolver{
		LookupSRV: func(_ context.Context, service, proto, name string) ([]*net.SRV, error) {
			if service != "imaps" || proto != "tcp" || name != "example.org" {
				t.Fatalf("unexpected lookup %s %s %s", service, proto, name)
			}
			return []*net.SRV{{Target: "mx.example.org.", Port: 993, Priority: 10}, {Target: "imap.example.org.", Port: 993, Priority: 20}}, nil
		},
		HTTP:           ispdb.Client(),
		AutoconfigBase: ispdb.URL,
	}
	got := r.Candidates(context.Background(), "me@example.org")
	want := []string{"mx.example.org:993", "imap.example.org:993", "mail.example.org:993"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}

// A domain nobody knows still gets the two guesses, so a self-hosted
// mailbox at the conventional name needs no question either.
func TestUnknownDomainStillGetsTheGuesses(t *testing.T) {
	r := &Resolver{}
	got := r.Candidates(context.Background(), "me@nowhere.test")
	if len(got) != 2 || got[0] != "imap.nowhere.test:993" || got[1] != "mail.nowhere.test:993" {
		t.Fatalf("candidates = %v", got)
	}
	if r.Candidates(context.Background(), "no-domain") != nil {
		t.Fatal("an address without a domain has no candidates")
	}
}
