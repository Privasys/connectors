// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package broker talks to the runtime's capability broker over loopback, for
// a connector that declares a resource of its own (a Drive folder) and needs
// the holder's approval for it.
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
	"net/url"
	"os"
	"strings"
	"time"
)

// ErrUnavailable means there is no runtime broker here, which is the ordinary
// state off the platform. Callers distinguish it so a workstation run can say
// "not on the platform" rather than "something failed".
var ErrUnavailable = errors.New("no runtime capability broker in this environment")

// ErrNotApproved means the holder has not approved this app for this resource.
var ErrNotApproved = errors.New("the holder has not approved this app's folder")

// ErrDeclined means they were asked and said no. Distinct from not-yet-asked,
// because asking again after a refusal is how a consent prompt becomes spam.
var ErrDeclined = errors.New("the holder declined this app's folder")

// Client asks the runtime about one declared resource.
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
	// of services either side of it. For Drive it carries the tenant, the
	// node and the path of the folder.
	ServiceResult map[string]string
}

// TenantID, NodeID and Path are Drive's coordinates for the folder.
func (s Status) TenantID() string { return s.ServiceResult["tenant_id"] }
func (s Status) NodeID() string   { return s.ServiceResult["node_id"] }
func (s Status) Path() string     { return s.ServiceResult["path"] }

// Ask is the runtime's answer to a request: a push on its way (`pending`
// with the nonce and this app's host, which together let another party, the
// holder's wallet mid-approval of someone else, complete THIS ask as a
// prerequisite), or an outcome already recorded.
type Ask struct {
	Status  string `json:"status"`
	Nonce   string `json:"nonce"`
	AppHost string `json:"app_host"`
}

// Pending reports a push on its way, with a nonce to complete it by.
func (a Ask) Pending() bool { return a.Nonce != "" && a.AppHost != "" }

// Prerequisite is the ask in the shape a connector's setup route lists it,
// for the wallet to complete before the connector's own capability.
func (a Ask) Prerequisite() map[string]string {
	return map[string]string{"app_host": a.AppHost, "nonce": a.Nonce}
}

// New builds a client from the environment the runtime provides, for the
// resource named in the manifest.
//
// Returns ErrUnavailable rather than a broken client when the variables are
// absent, so the caller can choose a development path instead of discovering
// the problem on the first real request.
func New(resource string) (*Client, error) {
	base := firstNonEmpty(os.Getenv("PRIVASYS_MANAGER_URL"), os.Getenv("PRIVASYS_RUNTIME_URL"))
	token := firstNonEmpty(os.Getenv("PRIVASYS_CONTAINER_TOKEN"), os.Getenv("PRIVASYS_APP_TOKEN"))
	if base == "" || token == "" {
		return nil, ErrUnavailable
	}
	return NewAt(base, token, resource), nil
}

// NewAt builds a client for a broker at a known address. A test points it at
// a fake; production goes through New.
func NewAt(base, token, resource string) *Client {
	return &Client{
		base:     strings.TrimRight(strings.TrimSpace(base), "/"),
		resource: strings.TrimSpace(resource),
		token:    strings.TrimSpace(token),
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
	}
}

// Resource is the manifest name this client asks about.
func (c *Client) Resource() string { return c.resource }

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
		"/api/v1/resources/"+url.PathEscape(c.resource)+"/status?subject="+url.QueryEscape(subject), nil, &raw)
	if err != nil {
		return Status{}, err
	}
	return Status{
		Approved: raw.Persistent, Declined: raw.Declined,
		CapabilityID: raw.CapabilityID, Kind: raw.Kind, Permissions: raw.Permissions,
		Label: raw.Label, ResourceApp: raw.ResourceApp, ServiceResult: raw.ServiceResult,
	}, nil
}

// Ask asks the runtime to push the holder's wallet for approval, and returns
// what a wallet needs to complete the ask: this app's host and the nonce.
//
// retry is a user gesture, never automatic: a denial that the app can retry
// on its own is a consent prompt that becomes spam, and the holder learns to
// dismiss the thing they were meant to read. The one case a connector passes
// it without a gesture is a folder the holder withdrew in Drive, where the
// runtime's record still says approved and only a retry makes it ask.
func (c *Client) Ask(ctx context.Context, subject string, retry bool) (Ask, error) {
	var ask Ask
	err := c.do(ctx, http.MethodPost, "/api/v1/resources/"+url.PathEscape(c.resource)+"/request",
		map[string]any{"subject": subject, "retry": retry}, &ask)
	return ask, err
}

// Sign returns the app's holder-of-key proof over payload, and the public
// key it was made with. The key stays in the manager; every proof is asked
// for.
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
