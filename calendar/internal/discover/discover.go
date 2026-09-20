// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package discover finds an account's CalDAV server from its address, so the
// holder is asked for the address and the password and, in the common case,
// nothing else. Three layers, cheapest first: the big providers by name, the
// records RFC 6764 says a client should look up (`_caldavs._tcp` SRV with its
// TXT path, then `/.well-known/caldav`), then two plain guesses. Every
// candidate is an https context URL; the caller proves each in turn.
//
// It also tells a Google account from the rest: Google's CalDAV endpoint
// takes a bearer, not a password, so the wallet must draw a sign-in button
// rather than a password field, and it has to know which before it draws.
package discover

import (
	"context"
	"net"
	"net/http"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"
)

// wellKnown maps a mail domain to its CalDAV context URL. Aliases of one
// provider share an entry; the list is what the first users are likely to
// have and grows as the long tail shows itself.
var wellKnown = map[string]string{
	"icloud.com": "https://caldav.icloud.com/", "me.com": "https://caldav.icloud.com/", "mac.com": "https://caldav.icloud.com/",
	"fastmail.com": "https://caldav.fastmail.com/", "fastmail.fm": "https://caldav.fastmail.com/",
	"yahoo.com": "https://caldav.calendar.yahoo.com/", "ymail.com": "https://caldav.calendar.yahoo.com/",
	"aol.com": "https://caldav.aol.com/",
	"gmx.com": "https://caldav.gmx.net/", "gmx.net": "https://caldav.gmx.net/", "gmx.de": "https://caldav.gmx.net/",
	"web.de":      "https://caldav.web.de/",
	"mailbox.org": "https://dav.mailbox.org/",
	"posteo.de":   "https://posteo.de:8443/",
	"yandex.com":  "https://caldav.yandex.ru/", "yandex.ru": "https://caldav.yandex.ru/",
}

// googleDomains are Google's own; a custom domain whose mail is at Google is
// found through its MX records.
var googleDomains = map[string]bool{"gmail.com": true, "googlemail.com": true}

// GoogleEndpoint is the CalDAV principal for a Google account, which takes
// a bearer with the calendar scope.
func GoogleEndpoint(address string) string {
	return "https://apidata.googleusercontent.com/caldav/v2/" + strings.ToLower(strings.TrimSpace(address)) + "/user"
}

// GoogleScope is what the bearer must carry.
const GoogleScope = "https://www.googleapis.com/auth/calendar"

// Resolver is the piece of the network a test can replace.
type Resolver struct {
	LookupSRV func(ctx context.Context, service, proto, name string) ([]*net.SRV, error)
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	LookupMX  func(ctx context.Context, name string) ([]*net.MX, error)
	// HTTP is used for the well-known redirect and must not follow it.
	HTTP *http.Client
}

// Default is the production resolver.
var Default = &Resolver{
	LookupSRV: func(ctx context.Context, service, proto, name string) ([]*net.SRV, error) {
		_, addrs, err := net.DefaultResolver.LookupSRV(ctx, service, proto, name)
		return addrs, err
	},
	LookupTXT: net.DefaultResolver.LookupTXT,
	LookupMX:  net.DefaultResolver.LookupMX,
	HTTP: &http.Client{
		Timeout: 5 * time.Second,
		// The well-known path answers with a redirect to the real context
		// URL, and that redirect IS the answer: following it would turn a
		// PROPFIND into a GET somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	},
}

// Domain returns the mail domain of an address, lower-cased, or "" when the
// address has none.
func Domain(address string) string {
	addr, err := mail.ParseAddress(strings.TrimSpace(address))
	s := strings.TrimSpace(address)
	if err == nil {
		s = addr.Address
	}
	at := strings.LastIndex(s, "@")
	if at < 0 || at == len(s)-1 {
		return ""
	}
	return strings.ToLower(s[at+1:])
}

// IsGoogle reports whether the address's mail is at Google: one of Google's
// own domains, or a domain whose MX records point there.
func (r *Resolver) IsGoogle(ctx context.Context, address string) bool {
	domain := Domain(address)
	if domain == "" {
		return false
	}
	if googleDomains[domain] {
		return true
	}
	if _, known := wellKnown[domain]; known || r.LookupMX == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	mxs, err := r.LookupMX(ctx, domain)
	if err != nil {
		return false
	}
	for _, mx := range mxs {
		host := strings.ToLower(strings.TrimSuffix(mx.Host, "."))
		if strings.HasSuffix(host, ".google.com") || strings.HasSuffix(host, ".googlemail.com") {
			return true
		}
	}
	return false
}

// Candidates returns the CalDAV context URLs to try for an address, best
// first, no duplicates: the well-known provider, then the SRV record with its
// TXT path, then the well-known redirect, then `https://caldav.<domain>/`
// and `https://<domain>/`. Never empty for an address with a domain; empty
// for an address without one.
func (r *Resolver) Candidates(ctx context.Context, address string) []string {
	domain := Domain(address)
	if domain == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	if known, ok := wellKnown[domain]; ok {
		add(known)
		return out // a known provider is the answer; the rest would only slow a wrong password down
	}
	for _, u := range r.srv(ctx, domain) {
		add(u)
	}
	add(r.wellKnownRedirect(ctx, domain))
	add("https://caldav." + domain + "/")
	add("https://" + domain + "/")
	return out
}

// srv reads RFC 6764's `_caldavs._tcp.<domain>`, best priority first, with
// the path from the matching TXT record when there is one.
func (r *Resolver) srv(ctx context.Context, domain string) []string {
	if r.LookupSRV == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := r.LookupSRV(ctx, "caldavs", "tcp", domain)
	if err != nil {
		return nil
	}
	sort.SliceStable(addrs, func(i, j int) bool {
		if addrs[i].Priority != addrs[j].Priority {
			return addrs[i].Priority < addrs[j].Priority
		}
		return addrs[i].Weight > addrs[j].Weight
	})
	path := "/.well-known/caldav"
	if r.LookupTXT != nil {
		if txts, err := r.LookupTXT(ctx, "_caldavs._tcp."+domain); err == nil {
			for _, t := range txts {
				if strings.HasPrefix(t, "path=") && strings.TrimPrefix(t, "path=") != "" {
					path = strings.TrimPrefix(t, "path=")
				}
			}
		}
	}
	var out []string
	for _, a := range addrs {
		target := strings.TrimSuffix(a.Target, ".")
		if target == "" || target == "." || a.Port == 0 {
			continue // "." means the service is not offered
		}
		host := target
		if a.Port != 443 {
			host = net.JoinHostPort(target, strconv.Itoa(int(a.Port)))
		}
		out = append(out, "https://"+host+path)
	}
	return out
}

// wellKnownRedirect asks `https://<domain>/.well-known/caldav` where the
// server lives. The answer is the redirect, not the page.
func (r *Resolver) wellKnownRedirect(ctx context.Context, domain string) string {
	if r.HTTP == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/.well-known/caldav", nil)
	if err != nil {
		return ""
	}
	res, err := r.HTTP.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode < 300 || res.StatusCode > 399 {
		return ""
	}
	loc, err := res.Location()
	if err != nil || loc.Scheme != "https" {
		return ""
	}
	return loc.String()
}
