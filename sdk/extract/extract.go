// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package extract turns the documents a file store holds into plain text an
// agent can read: Word, Excel and PowerPoint files by reading the zip and
// the XML inside with the standard library alone, PDF through one
// permissively licensed parser, HTML by stripping its tags.
//
// Everything here is bounded on both sides. The input is a byte slice the
// caller already capped; the output stops at a size the caller names, and
// says so, rather than handing a model a spreadsheet the size of its
// context. A malformed file is an error and never a panic: a connector that
// could be crashed by a document someone dropped into a shared folder is a
// connector anyone can take down, so a truncated zip, a nonsense XML and a
// PDF that trips the parser all come back as ErrMalformed.
//
// The output is text for reading, not a faithful rendering. Paragraphs end
// in a newline, table cells are separated by a tab, sheets and slides are
// headed by their name or number. Formatting, images and embedded objects
// are dropped without comment.
package extract

import (
	"errors"
	"path"
	"strings"
)

var (
	// ErrUnsupported is a kind this package has no extractor for. The
	// caller returns the file's metadata alone.
	ErrUnsupported = errors.New("no text can be extracted from this kind of file")
	// ErrMalformed is a file that claims a kind and does not parse as it.
	ErrMalformed = errors.New("the file could not be read as what its name says it is")
	// ErrTooLarge is an entry inside a container that would decompress past
	// the bound: the shape of a zip bomb, and refused as one.
	ErrTooLarge = errors.New("a part of this file is larger than this service will decompress")
)

// The kinds this package knows. A caller switches on them; anything else is
// metadata only.
const (
	KindText     = "text"
	KindMarkdown = "markdown"
	KindCSV      = "csv"
	KindJSON     = "json"
	KindHTML     = "html"
	KindDocx     = "docx"
	KindXlsx     = "xlsx"
	KindPptx     = "pptx"
	KindPDF      = "pdf"
)

// Kind decides how a file is read, from its name first and its declared
// media type second. The name first, because providers are careless with
// media types (a .md served as text/plain, a .docx as octet-stream) and
// careful with extensions, and because a name is what the holder sees.
// Empty means the file is returned as metadata alone.
func Kind(name, mime string) string {
	switch strings.ToLower(strings.TrimPrefix(path.Ext(strings.TrimSpace(name)), ".")) {
	case "txt", "text", "log", "rst", "adoc", "tex", "yaml", "yml", "toml", "ini", "cfg", "conf", "properties",
		"go", "py", "js", "ts", "tsx", "jsx", "java", "kt", "rs", "c", "h", "cc", "cpp", "hpp", "cs", "rb", "php",
		"sh", "bash", "zsh", "ps1", "sql", "r", "swift", "scala", "lua", "pl", "xml", "svg", "env", "gitignore", "editorconfig":
		return KindText
	case "md", "markdown", "mdx":
		return KindMarkdown
	case "csv", "tsv":
		return KindCSV
	case "json", "jsonl", "ndjson", "geojson":
		return KindJSON
	case "html", "htm", "xhtml":
		return KindHTML
	case "docx", "docm", "dotx":
		return KindDocx
	case "xlsx", "xlsm", "xltx":
		return KindXlsx
	case "pptx", "pptm", "potx":
		return KindPptx
	case "pdf":
		return KindPDF
	}
	mime = strings.ToLower(strings.TrimSpace(strings.SplitN(mime, ";", 2)[0]))
	switch mime {
	case "text/plain":
		return KindText
	case "text/markdown":
		return KindMarkdown
	case "text/csv", "text/tab-separated-values":
		return KindCSV
	case "application/json":
		return KindJSON
	case "text/html", "application/xhtml+xml":
		return KindHTML
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return KindDocx
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return KindXlsx
	case "application/vnd.openxmlformats-officedocument.presentationml.presentation":
		return KindPptx
	case "application/pdf":
		return KindPDF
	}
	if strings.HasPrefix(mime, "text/") {
		return KindText
	}
	return ""
}

// Result is the text and whether the bound cut it short.
type Result struct {
	Text      string
	Truncated bool
}

// Text extracts from data according to kind, producing at most max bytes of
// text. Plain kinds come back as they are, HTML stripped, the Office kinds
// and PDF parsed. A kind this package does not know is ErrUnsupported.
func Text(kind string, data []byte, max int) (Result, error) {
	if max <= 0 {
		return Result{}, errors.New("the output bound must be positive")
	}
	switch kind {
	case KindText, KindMarkdown, KindCSV, KindJSON:
		return bound(string(data), max), nil
	case KindHTML:
		return bound(StripHTML(string(data)), max), nil
	case KindDocx:
		return Docx(data, max)
	case KindXlsx:
		return Xlsx(data, max)
	case KindPptx:
		return Pptx(data, max)
	case KindPDF:
		return PDF(data, max)
	}
	return Result{}, ErrUnsupported
}

// bound cuts text at max bytes, on a rune boundary, and says whether it did.
func bound(s string, max int) Result {
	if len(s) <= max {
		return Result{Text: s}
	}
	cut := max
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return Result{Text: s[:cut], Truncated: true}
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// writer accumulates output up to a bound and reports when it is full, so an
// extractor can stop reading a document it will not be returning more of.
type writer struct {
	b         strings.Builder
	max       int
	truncated bool
}

func (w *writer) write(s string) {
	if w.truncated {
		return
	}
	room := w.max - w.b.Len()
	if len(s) > room {
		s = bound(s, room).Text
		w.truncated = true
	}
	w.b.WriteString(s)
}

func (w *writer) full() bool { return w.truncated }

func (w *writer) result() Result {
	return Result{Text: strings.TrimRight(w.b.String(), "\n\t "), Truncated: w.truncated}
}
