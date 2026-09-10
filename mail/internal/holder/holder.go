// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package holder answers one question: which PERSON is this, as opposed to
// which app.
//
// It exists because the two are asserted in completely different ways and
// conflating them is a privilege escalation rather than a tidiness problem. An
// app names the user it is acting for in a header it writes itself, which is
// fine for "read this person's mail under a capability they approved" and is
// worthless for "this person approves a capability". If the same header were
// good enough for both, the app that wants access could grant itself access,
// and the wallet would never be asked.
//
// So a holder is established one of exactly two ways:
//
//  1. The relay-asserted subject header, which the runtime's session-relay
//     middleware sets from a wallet-authenticated sealed session and STRIPS
//     from every inbound request first, so it cannot be spoofed by a caller.
//     This is the person sitting in front of the linking page.
//
//  2. A bearer token from the platform's identity provider, verified here
//     against its JWKS. This is the wallet, dialling the connector directly
//     over RA-TLS to mint a capability, with no relay in between.
//
// Verification is offline apart from the cached JWKS, so a mailbox is never
// opened by asking the platform about the person whose mail it is.
package holder

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultIssuer and DefaultAudience are the platform's own identity provider
// and the audience the wallet mints its platform token for.
const (
	DefaultIssuer   = "https://privasys.id"
	DefaultAudience = "privasys-platform"
)

// Identity is a verified person. Deliberately small: a connector needs to know
// whose mailbox this is and nothing else about them.
type Identity struct {
	Sub   string
	Email string
}

// Verifier validates a bearer token and returns who presented it.
type Verifier interface {
	Verify(ctx context.Context, token string) (*Identity, error)
}

// JWKS verifies tokens from one issuer, fetching and caching its signing keys.
type JWKS struct {
	issuer   string
	audience string
	client   *http.Client

	mu        sync.RWMutex
	keys      map[string]*jwk
	fetchedAt time.Time
}

// NewJWKS returns a verifier for one issuer. An empty audience skips the
// audience check, which is only ever right in a test.
func NewJWKS(issuer, audience string) *JWKS {
	return &JWKS{
		issuer:   strings.TrimRight(issuer, "/"),
		audience: audience,
		client:   &http.Client{Timeout: 10 * time.Second},
		keys:     map[string]*jwk{},
	}
}

// jwksTTL is how long signing keys are reused before being refetched. A key
// that has rotated is picked up by the unknown-kid path immediately; this only
// bounds how long a REVOKED key stays usable.
const jwksTTL = 15 * time.Minute

// Verify checks the signature, issuer, audience and expiry, and returns the
// subject. Every failure is an error: there is no partial success here, and a
// token this code only half understands is one it must not act on.
func (v *JWKS) Verify(ctx context.Context, token string) (*Identity, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, fmt.Errorf("token header: %w", err)
	}
	// "none" is rejected by not being in the table jwkVerify switches on, but
	// refuse it by name too: it is the one algorithm whose whole failure mode
	// is being accepted by accident.
	if strings.EqualFold(header.Alg, "none") {
		return nil, errors.New("token is unsigned")
	}

	key, err := v.signingKey(ctx, header.Kid, header.Alg)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("token signature: %w", err)
	}
	if err := jwkVerify(header.Alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, fmt.Errorf("token signature: %w", err)
	}

	var claims map[string]any
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("token claims: %w", err)
	}
	if iss, _ := claims["iss"].(string); strings.TrimRight(iss, "/") != v.issuer {
		return nil, fmt.Errorf("token was issued by %q, not %q", iss, v.issuer)
	}
	if v.audience != "" && !hasAudience(claims, v.audience) {
		return nil, fmt.Errorf("token is not for %q", v.audience)
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		// An unbounded token is not something to shrug at: it would let a
		// captured bearer link a mailbox forever.
		return nil, errors.New("token has no expiry")
	}
	if time.Now().Unix() > int64(exp) {
		return nil, errors.New("token has expired")
	}

	id := &Identity{}
	id.Sub, _ = claims["sub"].(string)
	id.Email, _ = claims["email"].(string)
	if id.Sub == "" {
		return nil, errors.New("token names no subject")
	}
	return id, nil
}

// signingKey returns the key for kid, refetching the key set when the kid is
// unknown or the cache has aged out.
func (v *JWKS) signingKey(ctx context.Context, kid, alg string) (*jwk, error) {
	v.mu.RLock()
	k, ok := v.keys[kid]
	fresh := time.Since(v.fetchedAt) < jwksTTL
	v.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}
	if err := v.refresh(ctx); err != nil {
		// An expired cache entry is better than no answer when the IdP is
		// briefly unreachable: the key was valid, and refusing every holder
		// during a blip would be its own outage. An UNKNOWN kid still fails.
		if ok {
			return k, nil
		}
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	// A token with no kid is answerable only when the issuer publishes exactly
	// one key of the right type; anything else would be guessing.
	if kid == "" {
		var only *jwk
		for _, candidate := range v.keys {
			if !strings.HasPrefix(alg, candidate.Kty[:2]) && candidate.Kty != keyTypeFor(alg) {
				continue
			}
			if only != nil {
				return nil, errors.New("token names no key and the issuer publishes several")
			}
			only = candidate
		}
		if only != nil {
			return only, nil
		}
	}
	return nil, fmt.Errorf("issuer publishes no key %q", kid)
}

func (v *JWKS) refresh(ctx context.Context) error {
	// Discovery first, so a change to the JWKS location is followed rather
	// than hard-coded here.
	uri, err := v.jwksURI(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	res, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("key set: %s", res.Status)
	}
	var set struct {
		Keys []*jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&set); err != nil {
		return err
	}
	keys := make(map[string]*jwk, len(set.Keys))
	for _, k := range set.Keys {
		if k != nil && k.Kty != "" {
			keys[k.Kid] = k
		}
	}
	if len(keys) == 0 {
		// Replacing a working key set with an empty one would turn a bad
		// response into an outage that outlives it.
		return errors.New("key set is empty")
	}
	v.mu.Lock()
	v.keys, v.fetchedAt = keys, time.Now()
	v.mu.Unlock()
	return nil
}

func (v *JWKS) jwksURI(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		v.issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}
	res, err := v.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery: %s", res.Status)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&doc); err != nil {
		return "", err
	}
	// The document must agree about who it belongs to, or a redirect could
	// hand us somebody else's keys under our issuer's name.
	if strings.TrimRight(doc.Issuer, "/") != v.issuer {
		return "", fmt.Errorf("discovery names issuer %q, not %q", doc.Issuer, v.issuer)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("discovery names no key set")
	}
	// The key set must be no less protected than the issuer it belongs to. An
	// https issuer whose keys arrive over http would let whoever sits on that
	// hop decide who the holder is. Phrased against the issuer's own scheme
	// rather than as a flat https requirement, so a test issuer on http stays
	// self-consistent; config.Validate is what forbids an http issuer in a
	// real deployment.
	if strings.HasPrefix(v.issuer, "https://") && !strings.HasPrefix(doc.JWKSURI, "https://") {
		return "", errors.New("key set is not served over https")
	}
	return doc.JWKSURI, nil
}

// ---------------------------------------------------------------- key material

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func keyTypeFor(alg string) string {
	switch {
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		return "RSA"
	case strings.HasPrefix(alg, "ES"):
		return "EC"
	}
	return ""
}

func (k *jwk) rsa() (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
}

func (k *jwk) ecdsa() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve %q", k.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}

func hashFor(alg string) (crypto.Hash, error) {
	switch alg {
	case "RS256", "ES256":
		return crypto.SHA256, nil
	case "RS384", "ES384":
		return crypto.SHA384, nil
	case "RS512", "ES512":
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported algorithm %q", alg)
}

func digest(h crypto.Hash, b []byte) []byte {
	switch h {
	case crypto.SHA384:
		s := sha512.Sum384(b)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(b)
		return s[:]
	default:
		s := sha256.Sum256(b)
		return s[:]
	}
}

func jwkVerify(alg string, k *jwk, signed, sig []byte) error {
	h, err := hashFor(alg)
	if err != nil {
		return err
	}
	sum := digest(h, signed)
	switch {
	case strings.HasPrefix(alg, "RS"):
		pub, err := k.rsa()
		if err != nil {
			return err
		}
		return rsa.VerifyPKCS1v15(pub, h, sum, sig)
	case strings.HasPrefix(alg, "ES"):
		pub, err := k.ecdsa()
		if err != nil {
			return err
		}
		// Raw r||s, fixed width per curve. A signature of the wrong length is
		// refused rather than left-padded: quietly reinterpreting it is how a
		// malleable encoding gets accepted.
		n := (pub.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return errors.New("signature has the wrong length for the curve")
		}
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(pub, sum, r, s) {
			return errors.New("signature does not verify")
		}
		return nil
	}
	return fmt.Errorf("unsupported algorithm %q", alg)
}

// ---------------------------------------------------------------- helpers

func decodeSegment(seg string, into any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

// hasAudience accepts both shapes the claim comes in, a string and a list.
func hasAudience(claims map[string]any, want string) bool {
	switch aud := claims["aud"].(type) {
	case string:
		return aud == want
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
