// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package discover

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKnownProvidersNeedNoNetwork(t *testing.T) {
	r := &Resolver{} // no network at all
	got := r.Candidates(context.Background(), "Someone <someone@icloud.com>")
	if len(got) != 1 || got[0] != "https://caldav.icloud.com/" {
		t.Fatalf("iCloud: %v", got)
	}
	if got := r.Candidates(context.Background(), "no-domain"); got != nil {
		t.Fatalf("an address without a domain has no candidates: %v", got)
	}
}

func TestSRVWellKnownAndGuesses(t *testing.T) {
	wk := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/caldav" {
			http.Redirect(w, r, "https://dav.example.org/principals/", http.StatusMovedPermanently)
			return
		}
		http.NotFound(w, r)
	}))
	defer wk.Close()
	client := wk.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// Point every host at the test server, whose certificate is not for it.
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, wk.Listener.Addr().String())
	}
	r := &Resolver{
		LookupSRV: func(_ context.Context, service, proto, name string) ([]*net.SRV, error) {
			if service != "caldavs" || name != "example.org" {
				return nil, errors.New("no record")
			}
			return []*net.SRV{
				{Target: "backup.example.org.", Port: 8443, Priority: 20},
				{Target: "cal.example.org.", Port: 443, Priority: 10},
			}, nil
		},
		LookupTXT: func(context.Context, string) ([]string, error) { return []string{"path=/dav/"}, nil },
		HTTP:      client,
	}
	got := r.Candidates(context.Background(), "me@example.org")
	want := []string{
		"https://cal.example.org/dav/",
		"https://backup.example.org:8443/dav/",
		"https://dav.example.org/principals/",
		"https://caldav.example.org/",
		"https://example.org/",
	}
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidates = %v, want %v", got, want)
		}
	}
}

func TestGoogleEndpoint(t *testing.T) {
	if got := GoogleEndpoint(" Me@Gmail.com "); got != "https://apidata.googleusercontent.com/caldav/v2/me@gmail.com/user" {
		t.Fatalf("GoogleEndpoint = %q", got)
	}
}
