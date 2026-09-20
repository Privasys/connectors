// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package api is the connector's HTTP surface: the tools an attested agent
// calls, over the shell every connector shares (the sdk's package connector).
//
// What is the files connector's here is the tool list, the account each
// tool runs against, the two providers it signs in with and the driver
// opened for each, the text a file becomes, and the mapping of the drivers'
// errors to statuses. Who the holder is, who a call acts for, the capability
// check, the credential refusal, the wallet-facing routes, the catalogue,
// the configure gate and the OAuth dance are the sdk's.
//
// The tool surface is the smallest thing that does the job. There is no
// delete, no move, no rename, no share, and no write anywhere but the
// connector's own folder: every capability omitted is one a description
// cannot talk the model into using.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	manifest "github.com/Privasys/connectors/files"
	"github.com/Privasys/connectors/files/internal/cloud"
	"github.com/Privasys/connectors/files/internal/config"
	"github.com/Privasys/connectors/files/internal/gdrive"
	"github.com/Privasys/connectors/files/internal/graph"
	"github.com/Privasys/connectors/files/internal/store"
	"github.com/Privasys/connectors/sdk/configure"
	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/extract"
	"github.com/Privasys/connectors/sdk/feed"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/holder"
	"github.com/Privasys/connectors/sdk/oauth"
	"github.com/Privasys/connectors/sdk/provider"
	"github.com/Privasys/connectors/sdk/redact"
	"github.com/Privasys/connectors/sdk/web"
)

// idleTTL is how long an unused account driver is kept.
const idleTTL = 20 * time.Minute

// maxText bounds how much text is extracted from one file, whatever its
// size on the drive: the pages an agent reads are cut from this.
const maxText = 4 << 20

// The two providers this connector signs in with. The sdk knows no provider
// by name; these values are the whole of what it is told.
var (
	microsoft = oauth.Provider{
		Name: "Microsoft",
		// The common tenant, so a work account and a personal account both
		// sign in through one registration.
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		// offline_access is what makes a refresh token come back; the rest
		// is the holder, their files and libraries, and the one folder this
		// connector writes into.
		Scopes: []string{"offline_access", "User.Read", "Files.Read.All", "Sites.Read.All", "Files.ReadWrite"},
	}
	google = oauth.Provider{
		Name:     "Google",
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
		// Everything readable, and files this app creates writable; the
		// address of the account that signed in, so a mismatch is caught.
		Scopes: []string{"openid", "email", "https://www.googleapis.com/auth/drive.readonly", "https://www.googleapis.com/auth/drive.file"},
		// A refresh token is issued only with both. Without one the
		// credential would not outlive its first access token.
		AuthParams: map[string]string{"access_type": "offline", "prompt": "consent"},
	}
)

type Server struct {
	svc   *connector.Service[store.Account]
	flows *oauth.Multi

	// The seams a test replaces: who hosts an address, how a driver is
	// opened for a provider, and where the providers' APIs are.
	who               *provider.Resolver
	open              func(ctx context.Context, provider string, tok cloud.TokenFunc) (cloud.Driver, error)
	graphBase         string
	googleBase        string
	googleUpload      string
	microsoftTokenURL string
	http              *http.Client

	cfgMu sync.Mutex
	cfg   config.Config

	mu    sync.Mutex
	conns map[string]*conn
}

type conn struct {
	drv  cloud.Driver
	used time.Time
}

// New builds the connector over its stores. requireGrant is taken explicitly
// rather than defaulted, because the zero value being permissive would be
// exactly the wrong default.
func New(s store.Store, g grant.Store, requireGrant bool) *Server {
	srv := &Server{
		conns:             map[string]*conn{},
		who:               provider.Default(),
		http:              &http.Client{Timeout: 60 * time.Second},
		microsoftTokenURL: microsoft.TokenURL,
	}
	srv.open = srv.openDriver
	srv.flows = oauth.NewMulti(cloud.Kind)
	ms := srv.flows.Add(cloud.ProviderMicrosoft, microsoft)
	ms.Identify = srv.identifier(cloud.ProviderMicrosoft)
	gg := srv.flows.Add(cloud.ProviderGoogle, google)
	gg.Identify = srv.identifier(cloud.ProviderGoogle)
	srv.svc = connector.New(connector.Options[store.Account]{
		Kind:     cloud.Kind,
		Resource: "files",
		Name:     "Privasys Files Connector",
		Note: "Reads one file store (OneDrive and SharePoint, or Google Drive) for one attested agent, under a capability the holder approved on their device, " +
			"and writes only into its own folder there. It never deletes, moves, renames or shares anything. " +
			"There is no page to connect an account on: the holder's wallet asks for the address on the approval screen, " +
			"tells from it whether the files are at Microsoft or at Google, and holds the browser for the sign-in there; " +
			"and this service keeps the credential only in memory.",
		Credentials:  s,
		Grants:       g,
		RequireGrant: requireGrant,
		Setup:        &setup{s: srv},
		Label:        func(a store.Account) string { return a.User },
		Manifest:     manifest.Manifest(),
		OnForget:     srv.dropConn,
		OnForgetAll:  srv.closeAll,
	})
	go srv.reapIdle()
	return srv
}

// SetVerifier installs the holder-token verifier.
func (s *Server) SetVerifier(v holder.Verifier) { s.svc.SetVerifier(v) }

// SetConfigurable arms the configure endpoint, and takes the OAuth clients
// from the settings now and after every configure.
func (s *Server) SetConfigurable(g *configure.Gate[config.Config]) {
	g.OnApply = s.applyConfig
	if cur, set := g.Current(); set {
		s.applyConfig(cur)
	}
	s.svc.SetConfig(g)
}

func (s *Server) applyConfig(c config.Config) {
	s.cfgMu.Lock()
	s.cfg = c
	s.cfgMu.Unlock()
	s.flows.Flow(cloud.ProviderMicrosoft).SetClient(c.MicrosoftClientID, c.MicrosoftClientSecret)
	s.flows.Flow(cloud.ProviderGoogle).SetClient(c.GoogleClientID, c.GoogleClientSecret)
}

func (s *Server) config() config.Config {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return s.cfg
}

func (s *Server) credStore() store.Store { return s.svc.Credentials() }

// Close forgets every credential and closes every account driver.
func (s *Server) Close() error { return s.svc.Close() }

func (s *Server) reapIdle() {
	for range time.Tick(time.Minute) {
		s.mu.Lock()
		for sub, c := range s.conns {
			if time.Since(c.used) > idleTTL {
				_ = c.drv.Close()
				delete(s.conns, sub)
			}
		}
		s.mu.Unlock()
	}
}

func (s *Server) dropConn(sub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.conns[sub]; ok {
		_ = c.drv.Close()
		delete(s.conns, sub)
	}
}

func (s *Server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sub, c := range s.conns {
		_ = c.drv.Close()
		delete(s.conns, sub)
	}
}

// openDriver opens the provider's driver over a token source.
func (s *Server) openDriver(ctx context.Context, provider string, tok cloud.TokenFunc) (cloud.Driver, error) {
	switch provider {
	case cloud.ProviderMicrosoft:
		return graph.Open(ctx, graph.Config{Base: s.graphBase, HTTP: s.http, Token: tok})
	case cloud.ProviderGoogle:
		return gdrive.Open(ctx, gdrive.Config{Base: s.googleBase, Upload: s.googleUpload, HTTP: s.http, Token: tok})
	}
	return nil, fmt.Errorf("unknown provider %q", provider)
}

// driverFor opens or reuses the account driver for one subject. Both drivers
// are stateless HTTP, so the change feed shares it: a held feed call does not
// delay a run's other calls.
func (s *Server) driverFor(ctx context.Context, sub string) (cloud.Driver, error) {
	s.mu.Lock()
	if c, ok := s.conns[sub]; ok {
		c.used = time.Now()
		s.mu.Unlock()
		return c.drv, nil
	}
	s.mu.Unlock()

	acct, err := s.credStore().Get(ctx, sub)
	if err != nil {
		return nil, err
	}
	drv, err := s.open(ctx, acct.Provider, s.tokenSource(sub))
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.conns[sub]; ok { // lost a race; keep the winner
		_ = drv.Close()
		c.used = time.Now()
		return c.drv, nil
	}
	s.conns[sub] = &conn{drv: drv, used: time.Now()}
	return drv, nil
}

// errTokenRefused is the provider no longer honouring the kept sign-in.
var errTokenRefused = errors.New("the provider no longer accepts the saved sign-in for these files; ask the user, then call request_access for their " +
	cloud.Kind + " resource with ask_again true so they can sign in again on their device")

// tokenSource returns a bearer for the subject's account, refreshing it from
// the kept refresh token when it is about to expire. The refreshed tokens go
// back into memory; the refresh token itself stays what the wallet keeps.
func (s *Server) tokenSource(sub string) cloud.TokenFunc {
	return func(ctx context.Context) (string, error) {
		acct, err := s.credStore().Get(ctx, sub)
		if err != nil {
			return "", err
		}
		if acct.AccessToken != "" && time.Until(acct.Expiry) > time.Minute {
			return acct.AccessToken, nil
		}
		t, err := s.refresh(ctx, acct.Provider, acct.RefreshToken)
		if err != nil {
			if errors.Is(err, oauth.ErrRefused) {
				return "", errTokenRefused
			}
			return "", err
		}
		acct.AccessToken, acct.Expiry = t.AccessToken, t.Expiry
		if t.RefreshToken != "" {
			acct.RefreshToken = t.RefreshToken
		}
		_ = s.credStore().Put(ctx, sub, acct)
		return t.AccessToken, nil
	}
}

// Routes returns the mux. Tool endpoints mirror the manifest exactly.
func (s *Server) Routes() *http.ServeMux {
	m := http.NewServeMux()
	s.svc.Mount(m)
	s.flows.Routes(m)

	// The permission each tool needs. Reading and writing are different
	// sentences on the holder's approval screen, so they are different checks
	// here: a holder who approved read-only must not find the agent writing.
	s.tool(m, "/tools/list_drives", grant.Read, s.listDrives)
	s.tool(m, "/tools/list_folder", grant.Read, s.listFolder)
	s.tool(m, "/tools/search", grant.Read, s.search)
	s.tool(m, "/tools/get_file", grant.Read, s.getFile)
	s.tool(m, "/tools/changes", grant.Read, s.changes)
	s.tool(m, "/tools/save_file", grant.Write, s.saveFile)
	s.tool(m, "/tools/account", grant.Read, s.account)
	return m
}

type handler func(ctx context.Context, sub string, drv cloud.Driver, body json.RawMessage) (any, error)

// tool registers one tool through the shell, which does the acting-user
// check, the configure gate, the credential check and the capability check
// at both paths from one closure. What is added here is the account, opened
// or reused for the subject, and the drivers' own errors given their status.
func (s *Server) tool(m *http.ServeMux, path string, need grant.Permission, h handler) {
	s.svc.Tool(m, path, need, func(ctx context.Context, sub string, body json.RawMessage) (any, error) {
		drv, err := s.driverFor(ctx, sub)
		if err != nil {
			return nil, status(err, "the file store is not reachable: ")
		}
		out, err := h(ctx, sub, drv, body)
		if err != nil {
			return nil, status(err, "")
		}
		return out, nil
	})
}

// status gives the drivers' errors their HTTP status; anything else is the
// provider's fault.
func status(err error, prefix string) error {
	switch {
	case errors.Is(err, store.ErrNoAccount):
		return err
	case errors.Is(err, cloud.ErrNotFound):
		return connector.Errorf(http.StatusNotFound, "%v", err)
	case errors.Is(err, cloud.ErrStale):
		return connector.Errorf(http.StatusConflict, "%v", err)
	case errors.Is(err, cloud.ErrBadID), errors.Is(err, cloud.ErrBadFolder), errors.Is(err, cloud.ErrBadName):
		return connector.Errorf(http.StatusBadRequest, "%v", err)
	case errors.Is(err, errTokenRefused):
		return connector.Errorf(http.StatusBadGateway, "%v", err)
	case errors.Is(err, cloud.ErrLogin):
		return connector.Errorf(http.StatusBadGateway, "the provider no longer accepts the saved sign-in; ask the user, then call request_access for their "+
			cloud.Kind+" resource with ask_again true so they can sign in again on their device (%v)", err)
	}
	if prefix != "" {
		return connector.Errorf(http.StatusBadGateway, "%s%v", prefix, err)
	}
	return err
}

// Handler builds the http.Handler for this server.
func (s *Server) Handler() http.Handler { return web.Logging(s.Routes()) }

// ---------------------------------------------------------------- tools

func (s *Server) listDrives(ctx context.Context, _ string, drv cloud.Driver, _ json.RawMessage) (any, error) {
	drives, err := drv.Drives(ctx)
	if err != nil {
		return nil, err
	}
	if drives == nil {
		drives = []cloud.Drive{}
	}
	return map[string]any{"drives": drives}, nil
}

func (s *Server) listFolder(ctx context.Context, _ string, drv cloud.Driver, body json.RawMessage) (any, error) {
	var req struct {
		Drive    string `json:"drive"`
		PathOrID string `json:"path_or_id"`
		Limit    int    `json:"limit"`
		Page     string `json:"page"`
	}
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	items, next, err := drv.List(ctx, strings.TrimSpace(req.Drive), req.PathOrID, req.Limit, strings.TrimSpace(req.Page))
	if err != nil {
		return nil, err
	}
	out := map[string]any{"items": nonNil(items)}
	if next != "" {
		out["page"] = next
	}
	return out, nil
}

func nonNil(items []cloud.Item) []cloud.Item {
	if items == nil {
		return []cloud.Item{}
	}
	return items
}

func (s *Server) search(ctx context.Context, _ string, drv cloud.Driver, body json.RawMessage) (any, error) {
	var req struct {
		Query string `json:"query"`
		Drive string `json:"drive"`
		Limit int    `json:"limit"`
	}
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Query) == "" {
		return nil, connector.Errorf(http.StatusBadRequest, "query is required")
	}
	items, err := drv.Search(ctx, req.Query, strings.TrimSpace(req.Drive), req.Limit)
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": nonNil(items)}, nil
}

// getFile is the metadata and a page of the text. What the text is depends
// on the kind: as it is, stripped, extracted, or exported by the provider.
// Anything else is metadata with a sentence saying why.
func (s *Server) getFile(ctx context.Context, _ string, drv cloud.Driver, body json.RawMessage) (any, error) {
	var req struct {
		ID     string `json:"id"`
		Offset int    `json:"offset"`
	}
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.ID) == "" {
		return nil, connector.Errorf(http.StatusBadRequest, "id is required")
	}
	if req.Offset < 0 {
		return nil, connector.Errorf(http.StatusBadRequest, "offset must not be negative")
	}
	c, err := drv.Fetch(ctx, req.ID, cloud.MaxDownload)
	out := map[string]any{"file": c.Item}
	switch {
	case err == nil:
	case errors.Is(err, cloud.ErrTooLarge):
		out["note"] = "the file is larger than this service downloads (25 MB), so only its metadata is here"
		return out, nil
	case errors.Is(err, cloud.ErrIsFolder):
		out["note"] = "this is a folder, not a file; list_folder shows what is in it"
		return out, nil
	case errors.Is(err, cloud.ErrNoText):
		out["note"] = "no text can be read from this kind of file, so only its metadata is here"
		return out, nil
	default:
		return nil, err
	}

	var text extract.Result
	var kind string
	if c.Exported {
		kind = "export"
		if strings.HasPrefix(c.MIME, "text/csv") {
			kind = "export-csv"
		}
		text, _ = extract.Text(extract.KindText, c.Data, maxText)
	} else {
		kind = extract.Kind(c.Item.Name, c.MIME)
		if kind == "" {
			out["note"] = "no text can be read from this kind of file (" + firstNonEmpty(c.MIME, "unknown type") + "), so only its metadata is here"
			return out, nil
		}
		text, err = extract.Text(kind, c.Data, maxText)
		if err != nil {
			switch {
			case errors.Is(err, extract.ErrMalformed), errors.Is(err, extract.ErrTooLarge):
				out["note"] = "the file could not be read as " + kind + " (" + err.Error() + "), so only its metadata is here"
				return out, nil
			case errors.Is(err, extract.ErrUnsupported):
				out["note"] = "no text can be read from this kind of file, so only its metadata is here"
				return out, nil
			}
			return nil, err
		}
	}

	whole := text.Text
	if req.Offset > len(whole) {
		return nil, connector.Errorf(http.StatusBadRequest, "offset %d is past the end of the text (%d bytes)", req.Offset, len(whole))
	}
	end := req.Offset + cloud.Page
	if end > len(whole) {
		end = len(whole)
	}
	for end < len(whole) && end > req.Offset && !isRuneStart(whole[end]) {
		end--
	}
	page := whole[req.Offset:end]
	red := redact.Apply(page)
	out["kind"] = kind
	out["text"] = red.Text
	out["offset"] = req.Offset
	out["text_bytes"] = len(whole)
	if end < len(whole) {
		out["next_offset"] = end
	}
	if text.Truncated {
		out["note"] = "the text was cut at 4 MB; the file holds more than is returned here"
	}
	if red.Count > 0 {
		out["redactions"] = red.Count
		out["redaction_note"] = red.Summary()
	}
	return out, nil
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *Server) changes(ctx context.Context, _ string, drv cloud.Driver, body json.RawMessage) (any, error) {
	var req feed.Request
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	changes, cursor, err := drv.Changes(ctx, req.Since, req.Wait())
	if err != nil {
		return nil, err
	}
	if changes == nil {
		changes = []cloud.Change{}
	}
	return map[string]any{"changes": changes, "cursor": cursor}, nil
}

func (s *Server) saveFile(ctx context.Context, _ string, drv cloud.Driver, body json.RawMessage) (any, error) {
	var req struct {
		Name    string `json:"name"`
		Content string `json:"content"`
		Folder  string `json:"folder"`
	}
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	name, mime, err := cloud.CleanName(req.Name)
	if err != nil {
		return nil, err
	}
	if _, err := cloud.CleanFolder(req.Folder); err != nil {
		return nil, err
	}
	if req.Content == "" {
		return nil, connector.Errorf(http.StatusBadRequest, "content is required")
	}
	if len(req.Content) > cloud.MaxSave {
		return nil, connector.Errorf(http.StatusBadRequest, "content is larger than %d bytes", cloud.MaxSave)
	}
	it, err := drv.Save(ctx, req.Folder, name, []byte(req.Content), mime)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"file": it,
		"note": "written under " + cloud.Folder + "/ on the user's personal drive, under a new name; nothing was replaced",
	}, nil
}

func (s *Server) account(ctx context.Context, sub string, drv cloud.Driver, _ json.RawMessage) (any, error) {
	a, err := s.credStore().Get(ctx, sub)
	if err != nil {
		return nil, err
	}
	live, err := drv.Account(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"account": a.Redacted(), "provider": live.Provider, "personal_drive": map[string]string{"id": live.DriveID, "type": live.DriveType}}, nil
}
