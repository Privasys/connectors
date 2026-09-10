// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package holder

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// issuer is a stand-in identity provider: it publishes a key set and mints
// tokens with it, so the tests exercise the real signature path rather than a
// stub that always agrees.
type issuer struct {
	key    *rsa.PrivateKey
	server *httptest.Server
	url    string
	// wrongIssuer makes discovery claim to be somebody else, which is the
	// shape of a redirect that hands over the wrong key set.
	wrongIssuer bool
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss := &issuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		name := iss.url
		if iss.wrongIssuer {
			name = "https://somewhere.else.example"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": name, "jwks_uri": iss.url + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := key.Public().(*rsa.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	})
	iss.server = httptest.NewServer(mux)
	iss.url = iss.server.URL
	t.Cleanup(iss.server.Close)
	return iss
}

func (i *issuer) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	seg := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := seg(map[string]string{"alg": "RS256", "kid": "k1", "typ": "at+jwt"}) + "." + seg(claims)
	sum := digest(crypto.SHA256, []byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum)
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// verifier points a JWKS verifier at the test issuer.
func (i *issuer) verifier(audience string) *JWKS {
	return NewJWKS(i.url, audience)
}

func goodClaims(url string) map[string]any {
	return map[string]any{
		"iss": url, "aud": "privasys-platform", "sub": "user-1",
		"email": "someone@example.com", "exp": time.Now().Add(time.Hour).Unix(),
	}
}

func TestVerifiesARealSignatureAndReturnsTheSubject(t *testing.T) {
	iss := newIssuer(t)
	id, err := iss.verifier("privasys-platform").Verify(context.Background(), iss.token(t, goodClaims(iss.url)))
	if err != nil {
		t.Fatal(err)
	}
	if id.Sub != "user-1" || id.Email != "someone@example.com" {
		t.Fatalf("identity: %+v", id)
	}
}

// Each of these is a way a token could be wrong that must not be forgiven,
// because every one of them ends with the wrong person's mailbox being opened.
func TestRefusesEveryWayATokenCanBeWrong(t *testing.T) {
	iss := newIssuer(t)
	other := newIssuer(t)

	tampered := iss.token(t, goodClaims(iss.url))
	// Flip a byte in the claims, keeping the shape: the classic "the signature
	// was checked against the wrong bytes" failure.
	parts := strings.SplitN(tampered, ".", 3)
	swapped := iss.token(t, map[string]any{
		"iss": iss.url, "aud": "privasys-platform", "sub": "somebody-else",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tampered = parts[0] + "." + strings.SplitN(swapped, ".", 3)[1] + "." + parts[2]

	expired := goodClaims(iss.url)
	expired["exp"] = time.Now().Add(-time.Minute).Unix()

	noExpiry := goodClaims(iss.url)
	delete(noExpiry, "exp")

	noSub := goodClaims(iss.url)
	delete(noSub, "sub")

	wrongAud := goodClaims(iss.url)
	wrongAud["aud"] = "some-other-service"

	wrongIss := goodClaims(iss.url)
	wrongIss["iss"] = "https://not-us.example"

	unsigned := func() string {
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		body, _ := json.Marshal(goodClaims(iss.url))
		return hdr + "." + base64.RawURLEncoding.EncodeToString(body) + "."
	}()

	for _, c := range []struct {
		what  string
		token string
	}{
		{"a token signed by somebody else's key", other.token(t, goodClaims(iss.url))},
		{"claims swapped under a valid signature", tampered},
		{"an expired token", iss.token(t, expired)},
		{"a token with no expiry at all", iss.token(t, noExpiry)},
		{"a token naming no subject", iss.token(t, noSub)},
		{"a token minted for another service", iss.token(t, wrongAud)},
		{"a token from another issuer", iss.token(t, wrongIss)},
		{"an unsigned token", unsigned},
		{"something that is not a token", "not-a-token"},
		{"an empty token", ""},
	} {
		if _, err := iss.verifier("privasys-platform").Verify(context.Background(), c.token); err == nil {
			t.Errorf("%s was accepted", c.what)
		}
	}
}

// Discovery that names a different issuer is refused: following it would be
// taking somebody else's keys as our issuer's.
func TestRefusesDiscoveryThatNamesAnotherIssuer(t *testing.T) {
	iss := newIssuer(t)
	iss.wrongIssuer = true
	if _, err := iss.verifier("privasys-platform").Verify(context.Background(), iss.token(t, goodClaims(iss.url))); err == nil {
		t.Fatal("a key set fetched under the wrong issuer was accepted")
	}
}

// The audience claim comes in both shapes and both must work, or the wallet's
// token would be refused for a reason nobody could see.
func TestAudienceAcceptsBothShapes(t *testing.T) {
	iss := newIssuer(t)
	list := goodClaims(iss.url)
	list["aud"] = []any{"something-else", "privasys-platform"}
	if _, err := iss.verifier("privasys-platform").Verify(context.Background(), iss.token(t, list)); err != nil {
		t.Fatalf("a list audience should be accepted: %v", err)
	}
}
