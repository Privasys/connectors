// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package drive is the attested leg to the holder's Drive, for a connector
// that writes documents into a folder of its own there.
//
// Two independent things must hold before a byte lands in the holder's
// Drive: a folder the holder approved for this app on their device, whose
// coordinates the runtime broker hands over, and a proof of holding the
// app's binding key, which the manager signs per request and this package
// never stores. The proof lives two minutes. What is written rests under the
// holder's keys, in their tenant, where they can withdraw this app's access
// at any time; the connector's own disk never sees it.
//
// The channel is mutual RA-TLS to a peer pinned by identity (Transport). A
// plain client here would talk to whatever answers the name.
package drive

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/connectors/sdk/broker"
)

// Signer mints the app's holder-of-key proof: the runtime broker, whose key
// the app never holds.
type Signer interface {
	Sign(ctx context.Context, payload []byte) (sig []byte, pubkeyB64 string, err error)
}

// Folder is the app's folder in one holder's Drive, as the broker reports
// it after the holder approved.
type Folder struct {
	TenantID     string
	NodeID       string
	CapabilityID string
	// Path is where the holder sees it, "AppData/Meeting transcripts".
	// Read from the approval, never assumed from the label: Drive renames
	// a folder whose name another app already owns.
	Path string
}

// FolderOf reads the folder out of a broker status. ErrNotApproved and
// ErrDeclined are the broker's; an approval with no coordinates is a fault.
func FolderOf(st broker.Status) (Folder, error) {
	switch {
	case st.Declined:
		return Folder{}, broker.ErrDeclined
	case !st.Approved:
		return Folder{}, broker.ErrNotApproved
	case st.TenantID() == "" || st.NodeID() == "":
		return Folder{}, errors.New("the approval carries no folder coordinates")
	}
	return Folder{TenantID: st.TenantID(), NodeID: st.NodeID(), CapabilityID: st.CapabilityID, Path: st.Path()}, nil
}

// Node is Drive's view of one file or folder.
type Node struct {
	ID        string `json:"id"`
	ParentID  string `json:"parent_id,omitempty"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	MimeHint  string `json:"mime_hint,omitempty"`
	Rev       int64  `json:"rev"`
	Size      int64  `json:"plain_size"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// IsFile reports a file node. Drive's kind is "file" or "folder".
func (n Node) IsFile() bool { return n.Kind == "" || strings.EqualFold(n.Kind, "file") }

var (
	// ErrWithdrawn is Drive refusing this app's grant on the holder's
	// folder: the holder withdrew it in Drive, or it expired. The runtime
	// cannot see a revoke made in Drive and keeps reporting the folder
	// approved, so this is the only place the truth surfaces.
	ErrWithdrawn = errors.New("the holder withdrew this service's Drive folder")
	// ErrHolderOnly is Drive answering that only the holder may do this.
	// Marking a node searchable is one such call: an app's folder is not
	// part of the holder's searchable memory unless the holder says so.
	ErrHolderOnly = errors.New("Drive lets only the holder do this, not an app")
	// ErrNotFound is a path or node the folder does not have.
	ErrNotFound = errors.New("not found in the holder's folder")
)

// appGrantEnvelope is Drive's token payload. Field names and the wire form
// are Drive's, not ours: `Authorization: AppGrant <b64url(json)>.<b64url(sig)>`.
type appGrantEnvelope struct {
	Iss   string   `json:"iss"`
	Aud   string   `json:"aud"`
	Sub   string   `json:"sub"`  // tenant id
	Node  string   `json:"node"` // node id, the granted folder
	Scope []string `json:"scope"`
	MRTD  string   `json:"mrtd"`
	JTI   string   `json:"jti"` // the capability id, which is how Drive finds the grant
	Iat   int64    `json:"iat"`
	Exp   int64    `json:"exp"`
	PK    string   `json:"pk"`
}

const (
	driveAudience = "privasys-drive"
	// proofLife is short on purpose: a proof is minted per request and
	// never stored, so nothing useful is left lying around if one leaks.
	proofLife = 2 * time.Minute
	// maxRead bounds what Read returns; a document, not a disk image.
	maxRead = 16 << 20
)

var (
	scopeRead  = []string{"read"}
	scopeWrite = []string{"read", "write"}
)

// Client writes into and reads from app folders in holders' Drives.
type Client struct {
	host   string
	http   *http.Client
	signer Signer

	// Issuer is the `iss` the proof carries: the platform's identity
	// provider, which is what Drive expects.
	Issuer string

	mu     sync.Mutex
	pubkey string
}

// New builds the client for one Drive. The transport is taken explicitly
// because on the platform it must be the attested leg (Transport); a
// default client would talk to whatever answers the name. A test passes a
// plain transport to a fake.
func New(host string, transport http.RoundTripper, signer Signer) (*Client, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, errors.New("the Drive client needs the resource service's host")
	}
	if transport == nil {
		return nil, errors.New("the Drive client needs an attested transport; a default client would not verify the peer")
	}
	if signer == nil {
		return nil, errors.New("the Drive client needs the runtime broker to sign its proofs")
	}
	return &Client{
		host: host, signer: signer, Issuer: "https://privasys.id",
		http: &http.Client{Timeout: 60 * time.Second, Transport: transport},
	}, nil
}

// Host is the Drive this client talks to.
func (c *Client) Host() string { return c.host }

// proof mints one holder-of-key proof for one request.
func (c *Client) proof(ctx context.Context, f Folder, scope []string) (string, error) {
	now := time.Now().UTC()
	env := appGrantEnvelope{
		Iss:   c.Issuer,
		Aud:   driveAudience,
		Sub:   f.TenantID,
		Node:  f.NodeID,
		Scope: scope,
		JTI:   f.CapabilityID,
		Iat:   now.Unix(),
		Exp:   now.Add(proofLife).Unix(),
	}
	// The envelope carries the public half, and the signature must cover the
	// exact bytes Drive will verify, so the key has to be known BEFORE
	// signing. It is stable per app, so it is learned once and then reused;
	// the alternative, signing a draft to discover the key and signing again,
	// costs two round trips on every single request.
	pub, err := c.bindingKey(ctx)
	if err != nil {
		return "", err
	}
	env.PK = pub
	body, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	sig, signedWith, err := c.signer.Sign(ctx, body)
	if err != nil {
		return "", err
	}
	if signedWith != pub {
		// The manager rotated the app's key between learning it and using it.
		// Presenting a proof whose stated key is not the one that signed it
		// would be rejected by Drive anyway, and confusingly.
		c.forgetBindingKey()
		return "", errors.New("the app's binding key changed while minting a proof; retry")
	}
	return "AppGrant " + base64.RawURLEncoding.EncodeToString(body) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// bindingKey returns the app's public binding key, learning it once.
//
// There is no endpoint that just returns it, so it is learned from a
// signature over a throwaway payload. That payload is deliberately not a
// valid envelope: a signature the app asks for should never be one anybody
// could present as a capability proof.
func (c *Client) bindingKey(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.pubkey != "" {
		defer c.mu.Unlock()
		return c.pubkey, nil
	}
	c.mu.Unlock()

	_, pub, err := c.signer.Sign(ctx, []byte("privasys/connector/binding-key-probe"))
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.pubkey = pub
	c.mu.Unlock()
	return pub, nil
}

func (c *Client) forgetBindingKey() {
	c.mu.Lock()
	c.pubkey = ""
	c.mu.Unlock()
}

func (c *Client) do(ctx context.Context, f Folder, method, path string, body []byte, contentType string, scope []string, headers map[string]string) (*http.Response, error) {
	tok, err := c.proof(ctx, f, scope)
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+c.host+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		// Replayable, so the verdict-window retry can send it again.
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", tok)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.http.Do(req)
}

// refused maps Drive's answer to the sentinel a caller can act on; nil for
// any status that is not a refusal of the grant itself.
func refused(res *http.Response, what string) error {
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w (drive answered %d %s)", ErrWithdrawn, res.StatusCode, what)
	}
	return nil
}

func pathQuery(f Folder, path string) string {
	return "?root=" + url.QueryEscape(f.NodeID) + "&path=" + url.QueryEscape(strings.Trim(path, "/"))
}

// Stat resolves a path under the folder: the node, or found false. The path
// route is a stat and never answers content; Read takes the node id.
func (c *Client) Stat(ctx context.Context, f Folder, path string) (Node, bool, error) {
	res, err := c.do(ctx, f, http.MethodGet, "/v1/tenants/"+url.PathEscape(f.TenantID)+"/path"+pathQuery(f, path), nil, "", scopeRead, nil)
	if err != nil {
		return Node{}, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return Node{}, false, nil
	}
	if err := refused(res, "resolving "+path); err != nil {
		return Node{}, false, err
	}
	if res.StatusCode/100 != 2 {
		return Node{}, false, fmt.Errorf("drive answered %d resolving %s", res.StatusCode, path)
	}
	var n Node
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&n); err != nil || n.ID == "" {
		return Node{}, false, fmt.Errorf("drive's answer for %s names no node", path)
	}
	return n, true, nil
}

// Write upserts a file at a path under the folder, creating the folders on
// the way, and returns the node. The same path written twice is the same
// node at a new revision, which is what makes a save idempotent.
func (c *Client) Write(ctx context.Context, f Folder, path string, content []byte, contentType string) (Node, error) {
	if content == nil {
		content = []byte{}
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	res, err := c.do(ctx, f, http.MethodPut, "/v1/tenants/"+url.PathEscape(f.TenantID)+"/path"+pathQuery(f, path),
		content, contentType, scopeWrite, map[string]string{"X-Drive-Parents": "create"})
	if err != nil {
		return Node{}, err
	}
	defer res.Body.Close()
	if err := refused(res, "writing "+path); err != nil {
		return Node{}, err
	}
	if res.StatusCode/100 != 2 {
		return Node{}, fmt.Errorf("drive answered %d writing %s", res.StatusCode, path)
	}
	// A creation answers the node view; a replacement answers {id, rev}.
	// Both carry the id, which is all a caller needs next.
	var n Node
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&n); err != nil || n.ID == "" {
		return Node{}, fmt.Errorf("drive's answer for %s names no node", path)
	}
	if n.Name == "" {
		n.Name = path[strings.LastIndex(path, "/")+1:]
	}
	return n, nil
}

// Read returns the bytes of one file by node id, or found false.
func (c *Client) Read(ctx context.Context, f Folder, nodeID string) ([]byte, bool, error) {
	res, err := c.do(ctx, f, http.MethodGet, "/v1/tenants/"+url.PathEscape(f.TenantID)+"/files/"+url.PathEscape(nodeID), nil, "", scopeRead, nil)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if err := refused(res, "reading "+nodeID); err != nil {
		return nil, false, err
	}
	if res.StatusCode/100 != 2 {
		return nil, false, fmt.Errorf("drive answered %d reading %s", res.StatusCode, nodeID)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxRead))
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// Mkdir creates a folder under a parent (the app folder itself when parentID
// is empty) and returns it. A folder that already exists is a conflict
// from Drive; use Stat first when reuse is wanted.
func (c *Client) Mkdir(ctx context.Context, f Folder, parentID, name string) (Node, error) {
	if parentID == "" {
		parentID = f.NodeID
	}
	body, _ := json.Marshal(map[string]string{"parent_id": parentID, "name": name})
	res, err := c.do(ctx, f, http.MethodPost, "/v1/tenants/"+url.PathEscape(f.TenantID)+"/folders", body, "application/json", scopeWrite, nil)
	if err != nil {
		return Node{}, err
	}
	defer res.Body.Close()
	if err := refused(res, "creating folder "+name); err != nil {
		return Node{}, err
	}
	if res.StatusCode/100 != 2 {
		return Node{}, fmt.Errorf("drive answered %d creating folder %s", res.StatusCode, name)
	}
	var n Node
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&n); err != nil || n.ID == "" {
		return Node{}, fmt.Errorf("drive's answer for folder %s names no node", name)
	}
	return n, nil
}

// SetIndexing asks Drive to include a node in the holder's searchable
// memory, or to exclude it. Drive's route is `PUT
// /v1/tenants/{t}/nodes/{id}/indexing {"enabled": true}`.
//
// Today Drive lets only the holder make this call: an app's folder is
// created excluded from indexing and an app cannot mark its own files,
// which comes back as ErrHolderOnly. The call is here so that a connector
// asks, and says truthfully what Drive answered, rather than silently
// leaving a document unsearchable.
func (c *Client) SetIndexing(ctx context.Context, f Folder, nodeID string, enabled bool) error {
	body, _ := json.Marshal(map[string]bool{"enabled": enabled})
	res, err := c.do(ctx, f, http.MethodPut, "/v1/tenants/"+url.PathEscape(f.TenantID)+"/nodes/"+url.PathEscape(nodeID)+"/indexing",
		body, "application/json", scopeWrite, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("%w (drive answered 401 marking %s)", ErrWithdrawn, nodeID)
	case res.StatusCode == http.StatusForbidden:
		return ErrHolderOnly
	case res.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case res.StatusCode/100 != 2:
		return fmt.Errorf("drive answered %d marking %s", res.StatusCode, nodeID)
	}
	return nil
}
