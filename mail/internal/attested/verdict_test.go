// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package attested

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

type scriptedRT struct {
	answers []*http.Response
	bodies  []string
}

func (s *scriptedRT) RoundTrip(req *http.Request) (*http.Response, error) {
	body := ""
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		body = string(b)
	}
	s.bodies = append(s.bodies, body)
	resp := s.answers[0]
	s.answers = s.answers[1:]
	return resp, nil
}

func answer(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

const lapsed = `{"error":"caller attestation failed: caller presented a certificate without current evidence on this connection (attest with client evidence first)"}`

func TestStaleVerdictIsRetriedOverAFreshDial(t *testing.T) {
	rt := &scriptedRT{answers: []*http.Response{answer(403, lapsed), answer(200, "ok")}}
	evictions := 0
	req, _ := http.NewRequest("PUT", "https://drive.example/v1/tenants/t/path", bytes.NewReader([]byte("sealed")))
	resp, err := roundTripStaleVerdict(rt, func() { evictions++ }, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || evictions != 1 || len(rt.bodies) != 2 || rt.bodies[1] != "sealed" {
		t.Fatalf("status=%d evictions=%d bodies=%q; want the request replayed once after one eviction", resp.StatusCode, evictions, rt.bodies)
	}
}

func TestOtherForbiddenPassesThrough(t *testing.T) {
	rt := &scriptedRT{answers: []*http.Response{answer(403, `{"error":"the capability does not cover this"}`)}}
	evictions := 0
	req, _ := http.NewRequest("GET", "https://drive.example/v1/x", nil)
	resp, _ := roundTripStaleVerdict(rt, func() { evictions++ }, req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 || !strings.Contains(string(body), "capability") || evictions != 0 || len(rt.bodies) != 1 {
		t.Fatalf("a policy refusal must pass through untouched: status=%d evictions=%d calls=%d", resp.StatusCode, evictions, len(rt.bodies))
	}
}
