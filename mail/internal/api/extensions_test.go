// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/connectors/mail/internal/config"
)

func extensions(t *testing.T, s *Server) []extensionEntry {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/attestation-extensions", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	var got []extensionEntry
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the runtime parses this as a JSON array: %v (%s)", err, w.Body)
	}
	return got
}

// Before configure there is nothing to claim, and an empty array is the
// correct answer rather than an error: the runtime fetches this at issuance,
// which happens before an operator has configured anything.
func TestExtensionsEmptyBeforeConfigure(t *testing.T) {
	s, _ := newTestServer(t)
	s.SetConfigurable("/tmp/x", nil, config.Config{}, false)
	if got := extensions(t, s); len(got) != 0 {
		t.Fatalf("want no claims before configure, got %+v", got)
	}
}

func TestExtensionsPublishTheConfigDigest(t *testing.T) {
	s, _ := newTestServer(t)
	cfg := config.Config{DriveHost: "drive.example", DriveAppID: "02104572ca2f41e8ae2d24c0294e6f5e"}
	s.SetConfigurable("/tmp/x", nil, cfg, true)

	got := extensions(t, s)
	byOID := map[string]string{}
	for _, e := range got {
		byOID[e.OID] = e.Value
	}
	if _, ok := byOID[oidConfigDigest]; !ok {
		t.Fatalf("no config digest in %+v", got)
	}

	// Every value must be valid DER, because the runtime puts it into a
	// certificate verbatim: raw bytes would produce a leaf nothing can parse.
	for oid, v := range byOID {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("%s is not base64: %v", oid, err)
		}
		var out []byte
		if rest, err := asn1.Unmarshal(raw, &out); err != nil || len(rest) != 0 {
			t.Fatalf("%s is not a DER OCTET STRING: %v", oid, err)
		}
	}

	// The peer's identity must not appear in the clear: a certificate
	// extension is visible to anyone who opens a connection.
	body, _ := json.Marshal(got)
	for _, secretish := range []string{"drive.example", "02104572ca2f41e8ae2d24c0294e6f5e"} {
		if strings.Contains(string(body), secretish) {
			t.Errorf("%q is published in the clear: %s", secretish, body)
		}
	}
}

// The digest must actually distinguish configurations, or it says nothing.
func TestConfigDigestChangesWithTheConfiguration(t *testing.T) {
	digestFor := func(c config.Config) string {
		s, _ := newTestServer(t)
		s.SetConfigurable("/tmp/x", nil, c, true)
		for _, e := range extensions(t, s) {
			if e.OID == oidConfigDigest {
				return e.Value
			}
		}
		t.Fatal("no digest")
		return ""
	}
	base := config.Config{DriveHost: "a.example", DriveAppID: "02104572ca2f41e8ae2d24c0294e6f5e"}
	other := config.Config{DriveHost: "b.example", DriveAppID: "02104572ca2f41e8ae2d24c0294e6f5e"}
	pinned := base
	pinned.DriveDigest = strings.Repeat("a", 64)

	if digestFor(base) == digestFor(other) {
		t.Error("a different host produced the same digest")
	}
	if digestFor(base) == digestFor(pinned) {
		t.Error("pinning a build produced the same digest")
	}
	if digestFor(base) != digestFor(base) {
		t.Error("the digest is not stable for the same configuration")
	}
}

// Whether the peer's build is pinned changes what a verifier may conclude, so
// it is published rather than left to the log.
func TestPeerPinnedFlag(t *testing.T) {
	flagFor := func(digest string) byte {
		s, _ := newTestServer(t)
		s.SetConfigurable("/tmp/x", nil, config.Config{
			DriveHost: "a.example", DriveAppID: "02104572ca2f41e8ae2d24c0294e6f5e", DriveDigest: digest,
		}, true)
		for _, e := range extensions(t, s) {
			if e.OID == oidPeerPinned {
				raw, _ := base64.StdEncoding.DecodeString(e.Value)
				var out []byte
				_, _ = asn1.Unmarshal(raw, &out)
				if len(out) == 1 {
					return out[0]
				}
			}
		}
		t.Fatal("no pinned flag")
		return 9
	}
	if flagFor("") != 0 {
		t.Error("unpinned should publish 0")
	}
	if flagFor(strings.Repeat("a", 64)) != 1 {
		t.Error("pinned should publish 1")
	}
}

// The arc matters: the runtime drops anything a container declares outside
// 5.4, because identity is stamped by the measured manager and never
// self-declared.
func TestOnlyAppDefinedArcIsUsed(t *testing.T) {
	for _, oid := range []string{oidConfigDigest, oidPeerPinned} {
		if !strings.HasPrefix(oid, "1.3.6.1.4.1.65230.5.4.") {
			t.Errorf("%s is outside the app-defined arc and would be dropped", oid)
		}
	}
}
