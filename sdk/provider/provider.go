// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package provider tells, from an address alone, who hosts the account it
// names and therefore how a holder can connect it: a sign-in at Google or
// Microsoft, or a password for a provider we reach directly.
//
// Every connector asks for the address FIRST and only then draws the second
// step, because the address decides everything: which server, which
// authorisation, and whether the account can be connected at all. Asking the
// holder to pick a provider would ask them something the domain already
// says, and would let them pick one that cannot hold their account.
//
// Three layers, cheapest first: the providers' own domains by name, then
// the domain's MX records (a custom domain at Google Workspace or Microsoft
// 365 points its mail there), then nothing, which means "somewhere else".
package provider

import (
	"context"
	"net"
	"strings"
	"time"
)

// Provider is who hosts an account.
type Provider string

const (
	Google    Provider = "google"
	Microsoft Provider = "microsoft"
	// Other is any provider we reach directly, with a credential the holder
	// types, or one we cannot reach at all: the caller decides which.
	Other Provider = "other"
)

// Name is the provider as a button names it.
func (p Provider) Name() string {
	switch p {
	case Google:
		return "Google"
	case Microsoft:
		return "Microsoft"
	}
	return ""
}

var googleDomains = map[string]bool{"gmail.com": true, "googlemail.com": true}

var microsoftDomains = map[string]bool{
	"outlook.com": true, "hotmail.com": true, "live.com": true, "msn.com": true,
	"outlook.fr": true, "hotmail.fr": true, "outlook.de": true, "hotmail.de": true,
	"outlook.co.uk": true, "hotmail.co.uk": true, "outlook.es": true, "hotmail.es": true,
	"outlook.it": true, "hotmail.it": true, "live.fr": true, "live.co.uk": true, "live.de": true,
}

// Resolver looks a domain up. LookupMX is replaceable so tests never touch
// DNS; nil means the well-known table alone.
type Resolver struct {
	LookupMX func(ctx context.Context, domain string) ([]*net.MX, error)
}

// Default resolves through the system resolver.
func Default() *Resolver {
	return &Resolver{LookupMX: net.DefaultResolver.LookupMX}
}

// Domain is the lower-cased part after the last "@", or "" for an address
// without one.
func Domain(address string) string {
	address = strings.ToLower(strings.TrimSpace(address))
	at := strings.LastIndex(address, "@")
	if at < 0 || at == len(address)-1 {
		return ""
	}
	return address[at+1:]
}

// Of says who hosts the address. The MX lookup is bounded to three seconds
// and a failure is Other: a slow resolver must not hold the holder's
// approval screen, and "somewhere else" is the honest answer for a domain
// we could not read.
func (r *Resolver) Of(ctx context.Context, address string) Provider {
	domain := Domain(address)
	if domain == "" {
		return Other
	}
	if googleDomains[domain] {
		return Google
	}
	if microsoftDomains[domain] {
		return Microsoft
	}
	if r == nil || r.LookupMX == nil {
		return Other
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	mxs, err := r.LookupMX(ctx, domain)
	if err != nil {
		return Other
	}
	for _, mx := range mxs {
		host := strings.ToLower(strings.TrimSuffix(mx.Host, "."))
		switch {
		case strings.HasSuffix(host, ".google.com"), strings.HasSuffix(host, ".googlemail.com"):
			return Google
		case strings.HasSuffix(host, ".mail.protection.outlook.com"), strings.HasSuffix(host, ".outlook.com"):
			return Microsoft
		}
	}
	return Other
}
