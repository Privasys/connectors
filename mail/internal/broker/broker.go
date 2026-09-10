// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package broker talks to the runtime's capability broker over loopback.
//
// The app never holds the binding key. The manager generates one per app,
// seals it, serves the wallet's well-known endpoints on the app's hostname,
// keeps the outcome, and signs on request. So this package can ask three
// things and nothing else: has this holder approved us, please ask them, and
// please sign this.
//
// That split is the point. An app that held its own binding key could mint a
// capability proof after being compromised; an app that must ask the manager
// for each signature can only ever act while it is still the app the manager
// thinks it is.
package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrUnavailable means there is no runtime broker here, which is the ordinary
// state off-platform. Callers distinguish it so a workstation run can say
// "not on the platform" rather than "something failed".
var ErrUnavailable = errors.New("no runtime capability broker in this environment")

// ErrNotApproved means the holder has not approved this app for this resource.
var ErrNotApproved = errors.New("the holder has not approved this app")

// ErrDeclined means they were asked and said no. Distinct from not-yet-asked,
// because asking again after a refusal is how a consent prompt becomes spam.
var ErrDeclined = errors.New("the holder declined")

type Client struct {
	base     string
	resource string
	token    string
	http     *http.Client
}

// Status is what the broker knows about one holder's approval.
type Status struct {
	Approved     bool
	Declined     bool
	CapabilityID string
	Kind         string
	Permissions  []string
	Label        string
	ResourceApp  string

	// ServiceResult is opaque to the runtime and meaningful only to the pair
	// of services either side of it. For Drive it carries the tenant and node.
	ServiceResult map[string]string
}

func (s Status) TenantID() string { return s.ServiceResult["tenant_id"] }
func (s Status) NodeID() string   { return s.ServiceResult["node_id"] }

// New builds a client from the environment the runtime provides.
//
// Returns ErrUnavailable rather than a broken client when the variables are
// absent, so the caller can choose a development path instead of discovering
// the problem on the first real request.
func New(resource string) (*Client, error) {
	base := firstNonEmpty(
		os.Getenv("PRIVASYS_MANAGER_URL"),
		os.Getenv("PRIVASYS_RUNTIME_URL"),
	)
	token := firstNonEmpty(
		os.Getenv("PRIVASYS_CONTAINER_TOKEN"),
		os.Getenv("PRIVASYS_APP_TOKEN"),
	)
	if base == "" || token == "" {
		return nil, ErrUnavailable
	}
	return &Client{
		base:     strings.TrimRight(base, "/"),
		resource: resource,
		token:    token,
		http: &http.Client{
			Timeout: 20 * time.Second,
			// Loopback only. Explicitly NOT ProxyFromEnvironment: the app's
			// egress proxy variables must never send a control-plane call
			// through the policy it is asking about.
			Transport: &http.Transport{
				Proxy:       nil,
				DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
		},
	}, nil
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("capability broker: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("capability broker: %s answered %d", path, res.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(res.Body).Decode(out)
}

// Status asks whether this holder has approved this app for this resource.
func (c *Client) Status(ctx context.Context, subject string) (Status, error) {
	var raw struct {
		Persistent    bool              `json:"persistent"`
		Declined      bool              `json:"declined"`
		Kind          string            `json:"kind"`
		Permissions   []string          `json:"permissions"`
		Label         string            `json:"label"`
		ResourceApp   string            `json:"resource_app"`
		CapabilityID  string            `json:"capability_id"`
		ServiceResult map[string]string `json:"service_result"`
	}
	err := c.do(ctx, http.MethodGet,
		"/api/v1/resources/"+c.resource+"/status?subject="+urlQueryEscape(subject), nil, &raw)
	if err != nil {
		return Status{}, err
	}
	return Status{
		Approved: raw.Persistent, Declined: raw.Declined,
		CapabilityID: raw.CapabilityID, Kind: raw.Kind, Permissions: raw.Permissions,
		Label: raw.Label, ResourceApp: raw.ResourceApp, ServiceResult: raw.ServiceResult,
	}, nil
}

// Request asks the runtime to push the holder's wallet for approval.
//
// retry is a user gesture, never automatic: a denial that the app can retry on
// its own is a consent prompt that becomes spam, and the holder learns to
// dismiss the thing they were meant to read.
func (c *Client) Request(ctx context.Context, subject string, retry bool) error {
	return c.do(ctx, http.MethodPost, "/api/v1/resources/"+c.resource+"/request",
		map[string]any{"subject": subject, "retry": retry}, nil)
}

// Sign returns the app's holder-of-key proof over payload. The key stays in
// the manager; every proof is asked for.
func (c *Client) Sign(ctx context.Context, payload []byte) (sig []byte, pubkeyB64 string, err error) {
	var out struct {
		SignatureB64 string `json:"signature_b64"`
		PubkeyB64    string `json:"pubkey_b64"`
	}
	err = c.do(ctx, http.MethodPost, "/api/v1/resources/sign",
		map[string]string{"payload_b64": base64.StdEncoding.EncodeToString(payload)}, &out)
	if err != nil {
		return nil, "", err
	}
	sig, err = base64.StdEncoding.DecodeString(out.SignatureB64)
	if err != nil {
		return nil, "", fmt.Errorf("capability broker returned an undecodable signature: %w", err)
	}
	return sig, out.PubkeyB64, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// urlQueryEscape is url.QueryEscape without the import, kept explicit because
// a subject with a "+" in it must not arrive as a space.
func urlQueryEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9',
			ch == '-', ch == '_', ch == '.', ch == '~':
			b.WriteByte(ch)
		default:
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}
