// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package cloud is the connector's domain: what a file store looks like to
// an attested agent, and what a driver must implement to provide one.
//
// The surface is deliberately smaller than either provider's API. An agent
// needs to see which drives the holder has, walk a folder, search, read a
// file as text, follow what changed, and leave a note of its own. It does
// not need to delete, move, rename or share anything, and there is no
// method for any of those on the driver: a capability that is absent is one
// a description cannot talk the model into using, exactly as the mail
// driver has no Send.
//
// The provider is the system of record. This connector reads on demand and
// stores nothing; the one thing it writes is a text file, into one folder of
// its own at the root of the holder's personal drive, under a name that
// does not already exist there.
package cloud

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

// Kind is the one capability this connector issues. The vocabulary is closed
// on the wallet side too, and both ends must agree or the holder is shown a
// sentence that does not match what is enforced.
const Kind = "files.cloud"

// Folder is the one place this connector writes: a folder of this name at
// the root of the holder's personal drive, created when first needed.
// Subfolders may be made under it and nowhere else.
const Folder = "Privasys"

// MaxDownload bounds what is fetched for one read. A file past it is
// metadata only; the limit is the provider's cost and this process's
// memory, not the agent's context, which has its own bound (page).
const MaxDownload = 25 << 20

// Page is how much text one get_file call returns; the rest is reached with
// offset.
const Page = 200 << 10

// MaxSave bounds what save_file will write: a note, not an upload service.
const MaxSave = 1 << 20

// Provider names, as kept beside the credential and shown to the holder.
const (
	ProviderMicrosoft = "microsoft"
	ProviderGoogle    = "google"
)

var (
	// ErrNotFound is an item the drive does not have. Distinct from an
	// error, because a file disappearing between a listing and a read is
	// ordinary in a live drive, not a fault.
	ErrNotFound = errors.New("file not found")
	// ErrStale is an id whose file changed since it was listed. The id
	// encodes the version it was read at, so a stale one fails rather than
	// addressing what the file has become.
	ErrStale = errors.New("the file has changed since it was listed; list or search again for a fresh id")
	// ErrBadID is an id that does not decode.
	ErrBadID = errors.New("malformed file id")
	// ErrTooLarge is a file past MaxDownload; its metadata is still served.
	ErrTooLarge = errors.New("the file is larger than this service will download")
	// ErrIsFolder is a read of a folder's content.
	ErrIsFolder = errors.New("this id is a folder; use list_folder on it")
	// ErrNoText is a file whose kind has no text to extract: an image, an
	// archive, a form. Its metadata is still served.
	ErrNoText = errors.New("no text can be read from this kind of file")
	// ErrLogin is the provider refusing the credential: the token was
	// revoked, or the sign-in withdrawn.
	ErrLogin = errors.New("the provider no longer accepts the saved sign-in")
	// ErrBadFolder is a folder argument that would reach outside Folder.
	ErrBadFolder = errors.New("folder must be a relative path of plain names under the connector's own folder")
	// ErrBadName is a file name save_file will not write.
	ErrBadName = errors.New("name must be a plain file name ending in .md, .markdown, .txt, .csv or .json")
)

// Drive is one place files live: the holder's own OneDrive or My Drive, a
// SharePoint document library, a Google shared drive.
type Drive struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Kind is "personal", "sharepoint" or "shared".
	Kind string `json:"kind"`
	// Site names the SharePoint site a library belongs to.
	Site   string `json:"site,omitempty"`
	WebURL string `json:"web_url,omitempty"`
}

// Item is one file or folder as the agent sees it.
type Item struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Folder   bool      `json:"folder"`
	Size     int64     `json:"size,omitempty"`
	MIME     string    `json:"mime,omitempty"`
	Modified time.Time `json:"modified"`
	// ModifiedBy is a display name, when the provider says.
	ModifiedBy string `json:"modified_by,omitempty"`
	// Path is where the item sits, when the provider says: a folder path
	// from the drive's root, without the item's own name.
	Path   string `json:"path,omitempty"`
	WebURL string `json:"web_url,omitempty"`
	Drive  string `json:"drive"`
	// Native names a provider-native document that has no bytes of its own
	// and is read through an export: "document", "spreadsheet" or
	// "presentation". Empty for an ordinary file.
	Native string `json:"native,omitempty"`
	// Children is a folder's child count, when the provider says.
	Children int `json:"children,omitempty"`
}

// Content is a file's bytes as fetched: downloaded as they are, or exported
// as text by the provider for a native document.
type Content struct {
	Item Item
	Data []byte
	// MIME is the type of Data.
	MIME string
	// Exported says Data is already text, from the provider's export.
	Exported bool
}

// Change is one event from the drive's own feed. Kind is "changed" (created
// or updated: neither provider tells them apart in its feed), "removed", or
// "reset" when the provider dropped the cursor and the agent should list
// again from scratch.
type Change struct {
	ID     string `json:"id,omitempty"`
	Kind   string `json:"kind"`
	Name   string `json:"name,omitempty"`
	Folder bool   `json:"folder,omitempty"`
}

// Account is what a holder connected, with nothing secret in it.
type Account struct {
	Provider string `json:"provider"`
	User     string `json:"user"`
	Name     string `json:"name,omitempty"`
	// DriveID is the personal drive, where the connector's folder lives.
	DriveID   string `json:"drive_id,omitempty"`
	DriveType string `json:"drive_type,omitempty"`
}

// TokenFunc hands a driver a bearer for the holder's account, refreshed as
// needed by whoever holds the refresh token.
type TokenFunc func(ctx context.Context) (string, error)

// Driver is one file provider. There is deliberately no delete, move,
// rename or share, and no write anywhere but Save's folder.
type Driver interface {
	Account(ctx context.Context) (Account, error)
	Drives(ctx context.Context) ([]Drive, error)

	// List returns the children of a folder, newest first, at most limit,
	// with an opaque token for the next page or "" when there is none. The
	// folder is a path from the drive's root, an item id from a listing,
	// or "" for the root; drive "" is the personal drive.
	List(ctx context.Context, drive, folder string, limit int, page string) ([]Item, string, error)

	// Search runs the provider's own search over one drive, or over the
	// personal drive when drive is "".
	Search(ctx context.Context, query, drive string, limit int) ([]Item, error)

	// Fetch reads one file's metadata and its bytes, at most max of them
	// (ErrTooLarge past that, with the metadata still in Content.Item).
	// A native document is exported as text.
	Fetch(ctx context.Context, id string, max int64) (Content, error)

	// Changes reports what changed since the cursor, holding for up to wait
	// when nothing has. The cursor is opaque.
	Changes(ctx context.Context, since string, wait time.Duration) ([]Change, string, error)

	// Save writes a text file under Folder on the personal drive, in a
	// subfolder when folder is not "", under a name that does not exist
	// there yet. Never anywhere else, and never over anything.
	Save(ctx context.Context, folder, name string, content []byte, mime string) (Item, error)

	Close() error
}

// ---------------------------------------------------------------- ids

// An item id encodes the drive, the provider's item id and the version it
// was listed at, so an id addresses the version that was listed and a
// later change makes it fail (ErrStale) rather than address what the file
// has become. Opaque to the agent, and to the harness.
const idVersion = "1"

// EncodeID builds an id.
func EncodeID(drive, item, etag string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join([]string{idVersion, drive, item, etag}, "\x00")))
}

// DecodeID reads one back.
func DecodeID(id string) (drive, item, etag string, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(id))
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %v", ErrBadID, err)
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 4 || parts[0] != idVersion || parts[2] == "" {
		return "", "", "", ErrBadID
	}
	return parts[1], parts[2], parts[3], nil
}

// ---------------------------------------------------------------- names

// segmentRe is a plain folder name: no separators, no leading dot, no
// control characters, nothing a provider treats specially.
var segmentRe = regexp.MustCompile(`^[^/\\:*?"<>|\x00-\x1f]{1,100}$`)

// CleanFolder turns save_file's folder argument into segments under Folder,
// refusing anything that could reach outside it: an absolute path, "..",
// an empty segment, a name the providers will not take. The connector's
// folder itself is not one of the segments; a driver prepends it.
func CleanFolder(folder string) ([]string, error) {
	folder = strings.TrimSpace(strings.ReplaceAll(folder, "\\", "/"))
	if folder == "" {
		return nil, nil
	}
	if strings.HasPrefix(folder, "/") {
		return nil, ErrBadFolder
	}
	var out []string
	for _, seg := range strings.Split(folder, "/") {
		seg = strings.TrimSpace(seg)
		if seg == "." || seg == ".." || strings.HasPrefix(seg, ".") || !segmentRe.MatchString(seg) {
			return nil, ErrBadFolder
		}
		out = append(out, seg)
	}
	if len(out) > 8 {
		return nil, ErrBadFolder
	}
	return out, nil
}

// textTypes are the kinds save_file writes, and the media type each is
// uploaded as.
var textTypes = map[string]string{
	".md": "text/markdown", ".markdown": "text/markdown", ".txt": "text/plain",
	".csv": "text/csv", ".json": "application/json",
}

// CleanName validates a file name for Save and returns it with its media
// type. A name without an extension is a Markdown file.
func CleanName(name string) (clean, mime string, err error) {
	name = strings.TrimSpace(name)
	if name == "" || name != path.Base(name) || strings.HasPrefix(name, ".") || !segmentRe.MatchString(name) {
		return "", "", ErrBadName
	}
	ext := strings.ToLower(path.Ext(name))
	if ext == "" {
		name += ".md"
		ext = ".md"
	}
	mime, ok := textTypes[ext]
	if !ok {
		return "", "", ErrBadName
	}
	return name, mime, nil
}

// UniqueName picks the first of name, "name (2).ext", "name (3).ext" and
// so on that is not taken. Never overwrite: what the holder has is theirs.
func UniqueName(name string, taken func(string) bool) string {
	if !taken(name) {
		return name
	}
	ext := path.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for n := 2; n < 1000; n++ {
		candidate := fmt.Sprintf("%s (%d)%s", stem, n, ext)
		if !taken(candidate) {
			return candidate
		}
	}
	return fmt.Sprintf("%s (%d)%s", stem, time.Now().UnixNano(), ext)
}
