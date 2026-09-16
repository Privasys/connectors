// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package discover finds a mailbox's IMAP server from its address, so the
// holder is asked for the address and the password and, in the common case,
// nothing else (Bertrand, 2026-09-16: "ask the email first, infer the
// endpoint from the hostname and only ask for the endpoint if we don't have
// it"). Three layers, cheapest first: the big providers by name, the DNS
// record mail clients look up (RFC 6186 `_imaps._tcp`), and the autoconfig
// database Thunderbird uses for the long tail, then two plain guesses. Every
// candidate is `host:port` for implicit TLS; the caller proves each in turn.
package discover

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"sort"
	"strings"
	"time"
)

// wellKnown maps a mail domain to its IMAP server. Aliases of one provider
// share an entry; the list is what the first users are likely to have and
// grows as the long tail shows itself.
var wellKnown = map[string]string{
	"gmail.com": "imap.gmail.com:993", "googlemail.com": "imap.gmail.com:993",
	"outlook.com": "outlook.office365.com:993", "hotmail.com": "outlook.office365.com:993",
	"live.com": "outlook.office365.com:993", "msn.com": "outlook.office365.com:993",
	"outlook.fr": "outlook.office365.com:993", "hotmail.fr": "outlook.office365.com:993",
	"yahoo.com": "imap.mail.yahoo.com:993", "ymail.com": "imap.mail.yahoo.com:993",
	"yahoo.fr": "imap.mail.yahoo.com:993", "rocketmail.com": "imap.mail.yahoo.com:993",
	"icloud.com": "imap.mail.me.com:993", "me.com": "imap.mail.me.com:993", "mac.com": "imap.mail.me.com:993",
	"aol.com":      "imap.aol.com:993",
	"fastmail.com": "imap.fastmail.com:993", "fastmail.fm": "imap.fastmail.com:993",
	"zoho.com": "imap.zoho.com:993", "zohomail.com": "imap.zoho.com:993",
	"yandex.com": "imap.yandex.com:993", "yandex.ru": "imap.yandex.ru:993",
	"gmx.com": "imap.gmx.com:993", "gmx.net": "imap.gmx.net:993", "gmx.de": "imap.gmx.net:993",
	"web.de": "imap.web.de:993", "t-online.de": "secureimap.t-online.de:993",
	"mail.com":  "imap.mail.com:993",
	"orange.fr": "imap.orange.fr:993", "wanadoo.fr": "imap.orange.fr:993",
	"free.fr": "imap.free.fr:993", "sfr.fr": "imap.sfr.fr:993", "neuf.fr": "imap.sfr.fr:993",
	"laposte.net": "imap.laposte.net:993", "bbox.fr": "imap.bbox.fr:993",
	"comcast.net": "imap.comcast.net:993", "btinternet.com": "mail.btinternet.com:993",
	"proton.me": "127.0.0.1:1143", "protonmail.com": "127.0.0.1:1143", // Proton needs its Bridge; the guess makes the refusal say so
}

// Resolver is the piece of the network a test can replace.
type Resolver struct {
	LookupSRV func(ctx context.Context, service, proto, name string) ([]*net.SRV, error)
	HTTP      *http.Client
	// AutoconfigBase is the ISPDB root; the request is <base>/<domain>.
	AutoconfigBase string
}

// Default is the production resolver.
var Default = &Resolver{
	LookupSRV: func(ctx context.Context, service, proto, name string) ([]*net.SRV, error) {
		_, addrs, err := net.DefaultResolver.LookupSRV(ctx, service, proto, name)
		return addrs, err
	},
	HTTP:           &http.Client{Timeout: 5 * time.Second},
	AutoconfigBase: "https://autoconfig.thunderbird.net/v1.1",
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

// Candidates returns the IMAP servers to try for an address, best first, no
// duplicates: the well-known provider, then the DNS record, then autoconfig,
// then `imap.<domain>` and `mail.<domain>`. Never empty for an address with
// a domain; empty for an address without one.
func (r *Resolver) Candidates(ctx context.Context, address string) []string {
	domain := Domain(address)
	if domain == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(hostport string) {
		hostport = strings.ToLower(strings.TrimSpace(hostport))
		if hostport == "" || seen[hostport] {
			return
		}
		seen[hostport] = true
		out = append(out, hostport)
	}
	if known, ok := wellKnown[domain]; ok {
		add(known)
		return out // a known provider is the answer; the rest would only slow a wrong password down
	}
	for _, h := range r.srv(ctx, domain) {
		add(h)
	}
	for _, h := range r.autoconfig(ctx, domain) {
		add(h)
	}
	add("imap." + domain + ":993")
	add("mail." + domain + ":993")
	return out
}

// srv reads RFC 6186's `_imaps._tcp.<domain>`, best priority first.
func (r *Resolver) srv(ctx context.Context, domain string) []string {
	if r.LookupSRV == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := r.LookupSRV(ctx, "imaps", "tcp", domain)
	if err != nil {
		return nil
	}
	sort.SliceStable(addrs, func(i, j int) bool {
		if addrs[i].Priority != addrs[j].Priority {
			return addrs[i].Priority < addrs[j].Priority
		}
		return addrs[i].Weight > addrs[j].Weight
	})
	var out []string
	for _, a := range addrs {
		target := strings.TrimSuffix(a.Target, ".")
		if target == "" || target == "." || a.Port == 0 {
			continue // RFC 6186: "." means the service is not offered
		}
		out = append(out, fmt.Sprintf("%s:%d", target, a.Port))
	}
	return out
}

// autoconfigXML is the part of Thunderbird's autoconfig document that names
// IMAP servers.
type autoconfigXML struct {
	Providers []struct {
		Incoming []struct {
			Type       string `xml:"type,attr"`
			Hostname   string `xml:"hostname"`
			Port       int    `xml:"port"`
			SocketType string `xml:"socketType"`
		} `xml:"incomingServer"`
	} `xml:"emailProvider"`
}

// autoconfig asks the ISPDB for the domain's IMAP servers over implicit TLS.
func (r *Resolver) autoconfig(ctx context.Context, domain string) []string {
	if r.HTTP == nil || r.AutoconfigBase == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.AutoconfigBase+"/"+domain, nil)
	if err != nil {
		return nil
	}
	res, err := r.HTTP.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 256<<10))
	if err != nil {
		return nil
	}
	return parseAutoconfig(body)
}

// parseAutoconfig extracts the IMAP-over-TLS servers of an autoconfig document.
func parseAutoconfig(body []byte) []string {
	var doc autoconfigXML
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var out []string
	for _, p := range doc.Providers {
		for _, in := range p.Incoming {
			if !strings.EqualFold(in.Type, "imap") || !strings.EqualFold(in.SocketType, "SSL") {
				continue
			}
			port := in.Port
			if port == 0 {
				port = 993
			}
			if h := strings.TrimSpace(in.Hostname); h != "" {
				out = append(out, fmt.Sprintf("%s:%d", h, port))
			}
		}
	}
	return out
}
