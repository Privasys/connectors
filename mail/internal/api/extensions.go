// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

// The app-defined extension arc. The runtime stamps identity itself and drops
// anything an app declares outside 5.4, so this is the only place a service
// can put its own claims into its certificate.
const oidConfigDigest = "1.3.6.1.4.1.65230.5.4.1"

// extensionEntry is the runtime's shape: an OID and a base64 DER value.
type extensionEntry struct {
	OID   string `json:"oid"`
	Value string `json:"value"`
}

// extensionsRoute publishes what this service wants folded into its RA-TLS
// leaf, which the runtime fetches at certificate issuance.
//
// Without it, "this connector was configured to trust issuer X" is a claim in
// a log that only the operator can read. With it, the claim is in the
// certificate, so anyone who attests this service can check what it was told,
// not merely that it was told something. That is the difference between a
// configuration and a configuration you can verify, and it is the whole point
// of configure-then-freeze.
//
// Only facts about the configuration go here. No holder is named, no
// credential is involved, and nothing here varies per request: a certificate
// extension that moved with traffic would leak what the service is doing to
// anyone who can open a connection.
func (s *Server) extensionsRoute(m *http.ServeMux) {
	m.HandleFunc("GET /.well-known/attestation-extensions", func(w http.ResponseWriter, r *http.Request) {
		entries := []extensionEntry{}

		if s.cfg != nil {
			s.cfg.mu.RLock()
			cur, set := s.cfg.current, s.cfg.set
			s.cfg.mu.RUnlock()

			if set {
				// A digest rather than the values: the certificate says WHICH
				// configuration is in force, and an operator who knows the
				// settings can prove it matches.
				//
				// The IDENTITY PROVIDER is the whole configuration now, and it
				// is the claim worth attesting: which issuer is trusted decides
				// whose approval can hand a mailbox over. There is no storage
				// peer any more, so there is nothing else to digest and no
				// "peer build pinned" bit to publish beside it.
				//
				// NUL-separated so no combination of values can be rearranged
				// into the same digest as another.
				sum := sha256.Sum256([]byte(strings.Join([]string{
					cur.IdpIssuer, cur.IdpAudience,
				}, "\x00")))
				entries = append(entries, extensionEntry{
					OID:   oidConfigDigest,
					Value: derOctetString(sum[:]),
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	})
}

// derOctetString wraps bytes as a DER OCTET STRING, which is what the runtime
// expects: the value is placed into the certificate verbatim, so it has to be
// a valid DER encoding rather than raw bytes.
func derOctetString(b []byte) string {
	der, err := asn1.Marshal(b)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(der)
}
