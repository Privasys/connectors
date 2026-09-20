// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package caller reads who a tool call is FOR and which app is making it.
// Neither is the holder (see package holder): the holder decides, the caller
// acts.
//
// The acting user is asserted by the platform, never by the caller. It
// arrives as X-Privasys-On-Behalf-Of on a leg the runtime has already
// authenticated. An app that could name its own subject could read anyone's
// data, so a request without one is refused rather than defaulted.
//
// The calling app is the identity the runtime verified from the mutual RA-TLS
// client certificate, set inside the trusted boundary and stripped from
// anything arriving off it. Getting the header name wrong fails CLOSED: an
// unrecognised header means no verified peer, which means no access, which is
// the right direction to be wrong in.
package caller

import (
	"net/http"
	"strings"

	"github.com/Privasys/connectors/sdk/grant"
)

// SubjectHeader is how the attested runtime names the acting user.
const SubjectHeader = "X-Privasys-On-Behalf-Of"

// PeerAppHeader carries the app id the RUNTIME verified from the mutual RA-TLS
// client certificate. PeerVerifiedHeader is accepted as the older spelling.
const (
	PeerAppHeader      = "X-Privasys-Peer-App-Id"
	PeerVerifiedHeader = "X-Privasys-Peer-Verified"
)

// ActingUser returns the user this call acts for, or "" when the platform
// asserted none.
func ActingUser(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get(SubjectHeader))
}

// App returns the calling app's canonical subject ("app:<32 hex>"), or "" if
// the runtime did not vouch for one. A bare "true" is a vouch with no identity
// in it, which is not enough to pick a capability.
func App(r *http.Request) string {
	for _, h := range []string{PeerAppHeader, PeerVerifiedHeader} {
		v := strings.TrimSpace(r.Header.Get(h))
		if v == "" || strings.EqualFold(v, "true") {
			continue
		}
		if s, err := grant.NormaliseSubject(v); err == nil {
			return s
		}
	}
	return ""
}
