// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mailtext

import "testing"

// The wrapped attribution. This one case was 26 of 178 real messages, and the
// obvious regex misses all of them.
func TestOwnTextCutsWrappedAttribution(t *testing.T) {
	body := "Yes, that works for me.\n\nThanks,\nB\n\nOn Mon, 8 Sep 2026 at 14:32, Some Person\n<someone@a-very-long-domain.example> wrote:\n> the original question\n> spanning lines\n"
	got := OwnText(body)
	for _, bad := range []string{"On Mon", "wrote:", "original question", "someone@"} {
		if contains(got, bad) {
			t.Errorf("quoted history survived (%q)\ngot: %q", bad, got)
		}
	}
	if !contains(got, "Yes, that works for me.") {
		t.Errorf("own words were lost\ngot: %q", got)
	}
}

func TestOwnTextCutsFrenchAttribution(t *testing.T) {
	body := "Bonjour, c'est noté.\n\nLe lun. 8 sept. 2026 à 14:32, Quelqu'un\n<a@b.example> a écrit :\n> question\n"
	got := OwnText(body)
	if contains(got, "a écrit") || contains(got, "question") {
		t.Errorf("French attribution survived: %q", got)
	}
	if !contains(got, "c'est noté") {
		t.Errorf("own words lost: %q", got)
	}
}

func TestOwnTextCutsQuotesForwardsAndSignature(t *testing.T) {
	cases := map[string]string{
		"plain quote": "My answer.\n\n> their words\n",
		"forward":     "See below.\n\n---------- Forwarded message ----------\nFrom: x\n",
		"signature":   "Short reply.\n\n-- \nBertrand\nCEO\n",
		"underscore":  "Noted.\n\n_______________\nFrom: someone\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			got := OwnText(body)
			for _, bad := range []string{"their words", "Forwarded", "CEO", "From: someone"} {
				if contains(got, bad) {
					t.Errorf("%s: %q survived in %q", name, bad, got)
				}
			}
			if got == "" {
				t.Errorf("%s: own words were lost entirely", name)
			}
		})
	}
}

// A bare forward is legitimately empty. It must not be treated as a failure,
// because 20 of 200 real messages are exactly this.
func TestOwnTextEmptyForBareForward(t *testing.T) {
	if got := OwnText("---------- Forwarded message ----------\nFrom: a\nTo: b\n"); got != "" {
		t.Errorf("a bare forward should yield no own text, got %q", got)
	}
}

func TestDecodeQuotedPrintableAndCharset(t *testing.T) {
	if got := Decode([]byte("Bonjour =C3=A0 tous=20!"), "quoted-printable", "utf-8"); got != "Bonjour à tous !" {
		t.Errorf("quoted-printable not decoded: %q", got)
	}
	if got := Decode([]byte("SGVsbG8gd29ybGQ="), "base64", "utf-8"); got != "Hello world" {
		t.Errorf("base64 not decoded: %q", got)
	}
	// latin-1 'é' is 0xE9; without conversion this is invalid UTF-8.
	if got := Decode([]byte{'c', 'a', 'f', 0xE9}, "", "iso-8859-1"); got != "café" {
		t.Errorf("charset not converted: %q", got)
	}
	if got := Decode([]byte("plain"), "7bit", ""); got != "plain" {
		t.Errorf("plain text mangled: %q", got)
	}
}

func TestHTMLToText(t *testing.T) {
	in := `<html><head><style>p{color:red}</style></head><body><p>First line</p><div>Second&nbsp;line</div><script>alert(1)</script><a href="https://x.example">link</a></body></html>`
	got := HTMLToText(in)
	for _, bad := range []string{"<", ">", "color:red", "alert(1)"} {
		if contains(got, bad) {
			t.Errorf("markup survived (%q): %q", bad, got)
		}
	}
	for _, want := range []string{"First line", "Second line", "link"} {
		if !contains(got, want) {
			t.Errorf("text lost (%q): %q", want, got)
		}
	}
}

func TestRepliable(t *testing.T) {
	unrepliable := []string{
		"no-reply@accounts.google.com", "noreply@x.example", "do-not-reply@bank.example",
		"donotreply@x.example", "mailer-daemon@x.example", "notifications@github.example",
		"ne-pas-repondre@fr.example", "postmaster@x.example",
		// Found by running the real inbox through the listing: an anchored
		// pattern called this one repliable.
		"CloudPlatform-noreply@google.com", "github.no-reply@example.com",
	}
	for _, a := range unrepliable {
		if Repliable(a) {
			t.Errorf("%s should not be repliable", a)
		}
	}
	for _, a := range []string{"alice@example.com", "b.foing@example.fr", "replies@example.com", "andrew@x.example", "reply.all@example.com"} {
		if !Repliable(a) {
			t.Errorf("%s should be repliable", a)
		}
	}
	if Repliable("not-an-address") {
		t.Error("a malformed address is not repliable")
	}
}

func TestSnippet(t *testing.T) {
	if got := Snippet("one   two\nthree", 100); got != "one two three" {
		t.Errorf("whitespace not normalised: %q", got)
	}
	got := Snippet("the quick brown fox jumps over the lazy dog", 20)
	if len([]rune(got)) > 21 || !contains(got, "…") {
		t.Errorf("not truncated on a word boundary: %q", got)
	}
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
