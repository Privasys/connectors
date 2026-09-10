// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package attested

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	rc "enclave-os-mini/clients/go/ratls"
)

const peerApp = "cf7a0d585468416884c341ebe0ce4025"

// A transport with no pinned identity would accept any enclave that answers
// the name, which defeats the point of attesting at all.
func TestNewRefusesWithoutAPinnedIdentity(t *testing.T) {
	for _, c := range []struct{ host, app string }{
		{"", peerApp},
		{"drive.example", ""},
		{"drive.example", "not-hex"},
		{"drive.example", "cf7a0d58"},
	} {
		if _, err := New(c.host, c.app, ""); err == nil {
			t.Errorf("New(%q, %q) should have been refused", c.host, c.app)
		}
	}
	if _, err := New("Drive.Example", "CF7A0D58-5468-4168-84C3-41EBE0CE4025", ""); err != nil {
		t.Errorf("a valid pin was refused: %v", err)
	}
}

// This leg carries a mailbox credential, so it must never fall back to plain
// HTTP and must never be talked into dialling somewhere else.
func TestRoundTripRefusesWrongSchemeOrHost(t *testing.T) {
	tr, err := New("drive.example", peerApp, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"http://drive.example/x", "https://evil.example/x"} {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		if _, err := tr.RoundTrip(req); err == nil {
			t.Errorf("%s should have been refused", url)
		}
	}
}

// The identity check is the whole point, so each way it can fail is pinned.
func TestCheckIdentity(t *testing.T) {
	appBytes := []byte{
		0xcf, 0x7a, 0x0d, 0x58, 0x54, 0x68, 0x41, 0x68,
		0x84, 0xc3, 0x41, 0xeb, 0xe0, 0xce, 0x40, 0x25,
	}
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	digestHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	withOids := func(oids ...rc.OidExtension) rc.CertInfo {
		return rc.CertInfo{CustomOids: oids}
	}

	t.Run("matching app id passes", func(t *testing.T) {
		tr, _ := New("drive.example", peerApp, "")
		if err := tr.checkIdentity(withOids(
			rc.OidExtension{OID: rc.OidWorkloadAppID, Value: appBytes},
		)); err != nil {
			t.Fatalf("a matching peer was refused: %v", err)
		}
	})

	t.Run("no app id at all is refused", func(t *testing.T) {
		tr, _ := New("drive.example", peerApp, "")
		if err := tr.checkIdentity(withOids()); err == nil {
			t.Fatal("a certificate with no app id was accepted")
		}
	})

	t.Run("a different app is refused", func(t *testing.T) {
		other := make([]byte, 16)
		tr, _ := New("drive.example", peerApp, "")
		err := tr.checkIdentity(withOids(rc.OidExtension{OID: rc.OidWorkloadAppID, Value: other}))
		if err == nil {
			t.Fatal("a different app was accepted")
		}
		if !strings.Contains(err.Error(), "configured to trust") {
			t.Errorf("the refusal should name what was expected: %v", err)
		}
	})

	t.Run("digest pin holds and can be omitted", func(t *testing.T) {
		pinned, _ := New("drive.example", peerApp, digestHex)
		ok := withOids(
			rc.OidExtension{OID: rc.OidWorkloadAppID, Value: appBytes},
			rc.OidExtension{OID: rc.OidWorkloadCodeHash, Value: digest},
		)
		if err := pinned.checkIdentity(ok); err != nil {
			t.Fatalf("the pinned build was refused: %v", err)
		}
		wrong := withOids(
			rc.OidExtension{OID: rc.OidWorkloadAppID, Value: appBytes},
			rc.OidExtension{OID: rc.OidWorkloadCodeHash, Value: make([]byte, 32)},
		)
		if err := pinned.checkIdentity(wrong); err == nil {
			t.Fatal("a different build passed a digest pin")
		}
		// A missing digest must not silently satisfy a pin.
		if err := pinned.checkIdentity(withOids(
			rc.OidExtension{OID: rc.OidWorkloadAppID, Value: appBytes},
		)); err == nil {
			t.Fatal("a peer with no digest satisfied a digest pin")
		}
		// Unpinned accepts any build of the right app.
		unpinned, _ := New("drive.example", peerApp, "")
		if err := unpinned.checkIdentity(wrong); err != nil {
			t.Fatalf("an unpinned transport refused a valid app: %v", err)
		}
	})
}

func TestNormaliseAppID(t *testing.T) {
	want := "cf7a0d585468416884c341ebe0ce4025"
	for _, in := range []string{
		want, strings.ToUpper(want), "app:" + want, "cf7a0d58-5468-4168-84c3-41ebe0ce4025",
	} {
		if got := normaliseAppID(in); got != want {
			t.Errorf("normaliseAppID(%q) = %q", in, got)
		}
	}
	for _, bad := range []string{"", "zz7a0d585468416884c341ebe0ce4025", "cf7a", "app:"} {
		if got := normaliseAppID(bad); got != "" {
			t.Errorf("normaliseAppID(%q) = %q, want empty", bad, got)
		}
	}
}
