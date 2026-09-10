// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package attested carries the connector's one outbound platform call, to
// Drive, over a verified RA-TLS channel.
//
// It exists because ordinary TLS would not do. The enclave gateway refuses
// plaintext app traffic, so the call would not arrive; and even if it did,
// server-auth TLS proves only that something answered the name, while this
// leg carries a holder's mailbox credential. RA-TLS terminates at the peer
// enclave itself, and the peer's quote is bound to THIS handshake, so a
// replayed certificate or an intercepted session cannot pass.
//
// Deliberately narrower than the harness's transport, which fronts a whole
// tool fleet. This connector has exactly one peer, so there is no dependency
// set to walk and no per-host table: one expected app id, one expected
// workload digest, both pinned by configuration, both fail-closed.
package attested

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	rc "enclave-os-mini/clients/go/ratls"
)

// Transport is an http.RoundTripper that dials one attested peer.
type Transport struct {
	// Host is the only peer this transport will talk to. A request for any
	// other host is refused rather than dialled: a connector with one
	// dependency should not be a general-purpose client, and a control plane
	// that started pointing it elsewhere must not be able to move its traffic.
	Host string

	// ExpectedAppID pins WHO the peer is (OID 4.1), as 32 lowercase hex.
	// Identity rather than measurement, so an ordinary release of the peer
	// does not break the leg.
	ExpectedAppID string

	// ExpectedDigest optionally pins WHAT the peer runs (OID 3.2). Set it
	// when a specific build has been admitted; leaving it empty accepts any
	// build of the pinned app.
	ExpectedDigest string

	Timeout time.Duration

	getClientCert  func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	clientEvidence rc.ClientEvidenceSource

	once sync.Once
	pool *http.Transport
}

// New builds the transport from the runtime's environment.
//
// The mutual leg (this connector proving what IT is to Drive) comes from the
// manager, which mints the identity and quotes it per connection. Off the
// platform those are absent and the dial stays server-auth only, which is why
// the caller must still refuse to run in production without them.
func New(host, expectedAppID, expectedDigest string) (*Transport, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, errors.New("an attested transport needs the peer's hostname")
	}
	appID := normaliseAppID(expectedAppID)
	if appID == "" {
		return nil, errors.New(
			"an attested transport needs the peer's app id: without it the dial would " +
				"accept any enclave that answers the name")
	}
	t := &Transport{
		Host:           host,
		ExpectedAppID:  appID,
		ExpectedDigest: strings.ToLower(strings.TrimSpace(expectedDigest)),
		Timeout:        20 * time.Second,
	}
	if mgr := os.Getenv("PRIVASYS_MANAGER_URL"); mgr != "" {
		id := rc.NewEgressIdentity(mgr, os.Getenv("PRIVASYS_CONTAINER_TOKEN"))
		t.getClientCert = id.GetClientCertificate
		t.clientEvidence = id.ClientEvidence
	}
	return t, nil
}

// Mutual reports whether this transport can prove what it is to the peer.
// Drive's strict attested-caller check only engages when it can, so a
// deployment that reports false is one where the grant is enforced by key
// alone.
func (t *Transport) Mutual() bool { return t.getClientCert != nil }

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("attested: refusing a %s request; this leg carries a credential", req.URL.Scheme)
	}
	if !strings.EqualFold(req.URL.Hostname(), t.Host) {
		return nil, fmt.Errorf("attested: this transport dials %s only, not %s", t.Host, req.URL.Hostname())
	}
	t.once.Do(func() {
		t.pool = &http.Transport{
			DialTLSContext: t.dialVerified,
			// h2 is never negotiated: the RA-TLS dial advertises the splice
			// marker and http/1.1 only.
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     90 * time.Second,
		}
	})
	return t.pool.RoundTrip(req)
}

// CloseIdleConnections drops pooled channels, so a re-verification happens on
// the next dial.
func (t *Transport) CloseIdleConnections() {
	if t.pool != nil {
		t.pool.CloseIdleConnections()
	}
}

// dialVerified does one attested dial and refuses everything it cannot prove.
//
// Verification happens BEFORE the connection is handed to the pool, so no
// byte of a credential can be written to a channel whose far end has not been
// checked. Requests then multiplex over that verified channel until it idles
// out, which is the same verify-once-per-channel argument the platform's
// other pooled attested legs make.
func (t *Transport) dialVerified(_ context.Context, _ string, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host, portStr = addr, "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 443
	}

	// A fresh challenge per connection: the peer must bind its quote to THIS
	// handshake, so a replayed quote or an intercepted session cannot pass.
	cli, err := rc.Connect(host, port, &rc.Options{
		ServerName:           host,
		Timeout:              t.Timeout,
		GetClientCertificate: t.getClientCert,
		ClientEvidence:       t.clientEvidence,
	})
	if err != nil {
		return nil, fmt.Errorf("attested: connect %s: %w", host, err)
	}

	tee := rc.TeeTypeSGX
	if ev := cli.Evidence(); ev != nil && strings.HasPrefix(ev.TEE, "tdx") {
		tee = rc.TeeTypeTDX
	}
	info, verr := cli.VerifyCertificate(&rc.VerificationPolicy{TEE: tee})
	if verr != nil {
		cli.Close()
		return nil, fmt.Errorf(
			"attested: %s failed attestation, refusing to send a credential: %w", host, verr)
	}

	if err := t.checkIdentity(info); err != nil {
		cli.Close()
		return nil, err
	}
	return cli.Conn(), nil
}

// checkIdentity holds the peer to what was pinned.
func (t *Transport) checkIdentity(info rc.CertInfo) error {
	appID, digest := "", ""
	for _, ext := range info.CustomOids {
		switch ext.OID {
		case rc.OidWorkloadAppID:
			// The app id is a 16-byte UUID in the certificate. Accept the
			// hex of those bytes, and also a text form, because both
			// spellings appear across the estate and refusing the wrong one
			// would look exactly like an identity mismatch.
			appID = normaliseAppID(fmt.Sprintf("%x", ext.Value))
			if appID == "" {
				appID = normaliseAppID(string(ext.Value))
			}
		case rc.OidWorkloadCodeHash:
			digest = strings.ToLower(fmt.Sprintf("%x", ext.Value))
		}
	}
	if appID == "" {
		return errors.New("attested: the peer's certificate carries no app id, so it cannot be the app we pinned")
	}
	if appID != t.ExpectedAppID {
		return fmt.Errorf(
			"attested: %s is app %s, but this connector was configured to trust %s; refusing",
			t.Host, appID, t.ExpectedAppID)
	}
	if t.ExpectedDigest != "" && !strings.EqualFold(digest, t.ExpectedDigest) {
		return fmt.Errorf(
			"attested: %s runs build %s but %s was admitted; refusing (the peer changed since it was pinned)",
			t.Host, orUnset(digest), t.ExpectedDigest)
	}
	return nil
}

func normaliseAppID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "app:")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return ""
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return ""
		}
	}
	return s
}

func orUnset(v string) string {
	if v == "" {
		return "(no workload digest)"
	}
	return v
}
