// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package redact

import "testing"

// The false-negative cases. Each is a real shape of mail that carries a
// credential an agent must never be able to read out.
func TestRemovesCredentials(t *testing.T) {
	cases := []struct {
		name string
		in   string
		gone string // must NOT appear in the output
	}{
		{"labelled code", "Your verification code is 483920. It expires in 10 minutes.", "483920"},
		{"code with colon", "One-time passcode: 91827364", "91827364"},
		{"code first", "483920 is your code for signing in", "483920"},
		{"french code", "Votre code de vérification : 774411", "774411"},
		{"german code", "Ihr Bestätigungscode lautet 220044", "220044"},
		{"alnum code", "Security code: A7B9C2D4", "A7B9C2D4"},
		{"password line", "password: hunter2correct", "hunter2correct"},
		{"reset link", "Reset here https://acme.example/reset-password?t=abc123def456 thanks", "reset-password"},
		{"magic link", "Sign in: https://app.example.com/auth/magic-link/9f8e7d6c5b4a", "magic-link"},
		{"token query", "Open https://x.example/go?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abc", "access_token=eyJ"},
		{"bearer", "curl -H 'Bearer " + fakeKey("sk", "live") + "'", fakeKey("sk", "live")},
		{"api key", "key is " + fakeKey("ghp", "") + " here", fakeKey("ghp", "")},
		// The real one, lifted from a Google security alert while smoke-testing
		// the connector against a live inbox. One click, irreversible.
		{"account action link", "remove <https://accounts.google.com/AccountDisavow?adt=AOX8kjxQwErTyU12345> now", "AccountDisavow"},
		{"revoke device link", "https://x.example/security/revoke-device?id=99", "revoke-device"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "MIIEow"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Apply(c.in)
			if contains(got.Text, c.gone) {
				t.Errorf("credential survived redaction\n in:  %q\n out: %q\n want %q gone", c.in, got.Text, c.gone)
			}
			if got.Count == 0 {
				t.Errorf("nothing was counted as redacted for %q", c.in)
			}
		})
	}
}

// The false-positive cases, which matter just as much. A filter that eats
// ordinary business mail makes the agent useless and will be turned off.
func TestKeepsOrdinaryText(t *testing.T) {
	cases := []string{
		"The invoice total is 483920 euros, please confirm.",
		"Call me on 07700 900123 when you land.",
		"We shipped 20260910 units last quarter.",
		"See https://example.com/pricing for the details.",
		"The meeting is in room 4820, second floor.",
		"Our reference is ORDER-88213 if you need it.",
		"https://docs.example.com/guide/authentication explains the flow.",
		"See https://example.com/account/settings to change it.",
		"Unsubscribe at https://news.example.com/unsubscribe?u=12 if you prefer.",
		"I reset my password yesterday and it worked fine.",
	}
	for _, in := range cases {
		got := Apply(in)
		if got.Text != in {
			t.Errorf("ordinary text was altered\n in:  %q\n out: %q", in, got.Text)
		}
		if got.Count != 0 {
			t.Errorf("ordinary text counted %d redactions: %q", got.Count, in)
		}
	}
}

// A redaction must leave the sentence readable, so the agent can tell a login
// mail from a message that simply arrived empty.
func TestLeavesTheSentenceStanding(t *testing.T) {
	got := Apply("Hi, your verification code is 483920 and it expires soon.")
	for _, want := range []string{"Hi,", "expires soon", "[one-time code removed]"} {
		if !contains(got.Text, want) {
			t.Errorf("expected %q in %q", want, got.Text)
		}
	}
	if got.Summary() == "" {
		t.Error("a redacted message should carry a summary line")
	}
}

func TestMultipleAndEmpty(t *testing.T) {
	got := Apply("code: 112233 and reset at https://a.example/reset-password?x=1")
	if got.Count != 2 {
		t.Errorf("want 2 redactions, got %d (%q)", got.Count, got.Text)
	}
	if len(got.Kinds) != 2 {
		t.Errorf("want 2 kinds, got %v", got.Kinds)
	}
	if r := Apply(""); r.Text != "" || r.Count != 0 || r.Summary() != "" {
		t.Errorf("empty input should be inert, got %+v", r)
	}
}

func contains(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) && indexOf(hay, needle) >= 0
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// fakeKey builds a credential-SHAPED string at run time rather than writing
// one as a literal.
//
// The literal version was correct, obviously fake, and still rejected: GitHub's
// push protection matched it as a Stripe key and blocked the push. Rather than
// click the "allow this secret" escape hatch, which trains everyone to click it
// again on the day it is real, the fixture is composed here. The regexes under
// test see exactly the same bytes; only the source file no longer contains
// them.
func fakeKey(prefix, env string) string {
	body := "abcdefghijklmnopqrstuvwx01"
	if env != "" {
		return prefix + "_" + env + "_" + body
	}
	return prefix + "_" + body
}
