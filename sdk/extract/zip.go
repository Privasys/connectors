// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package extract

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxPart bounds what one entry of an Office file may decompress to. The
// XML behind a large document is a few megabytes; a part that goes past
// this is a zip bomb, or a spreadsheet nobody should be reading as text.
const maxPart = 64 << 20

// container is an Office Open XML file: a zip with XML parts inside.
type container struct {
	z *zip.Reader
}

// openContainer reads the zip directory. A truncated or corrupt file fails
// here, because the directory is at the end of the file and is what the
// reader checks first.
func openContainer(data []byte) (*container, error) {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return &container{z: z}, nil
}

// part returns the bytes of one entry, bounded, or nil when it is absent.
func (c *container) part(name string) ([]byte, error) {
	for _, f := range c.z.File {
		if f.Name != name {
			continue
		}
		if f.UncompressedSize64 > maxPart {
			return nil, ErrTooLarge
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrMalformed, name, err)
		}
		defer rc.Close()
		// The declared size is not trusted: a crafted header can say 1 KB
		// and inflate to gigabytes, so the read itself is bounded too.
		b, err := io.ReadAll(io.LimitReader(rc, maxPart+1))
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: %s: %v", ErrMalformed, name, err)
		}
		if len(b) > maxPart {
			return nil, ErrTooLarge
		}
		return b, nil
	}
	return nil, nil
}

// names lists the entries with a prefix, in directory order.
func (c *container) names(prefix string) []string {
	var out []string
	for _, f := range c.z.File {
		if strings.HasPrefix(f.Name, prefix) {
			out = append(out, f.Name)
		}
	}
	return out
}

// xmlTokens walks one XML part and hands each token to fn, stopping when fn
// asks to. Namespaces are not resolved: the Office parts use fixed prefixes
// (w:, a:, and the unprefixed spreadsheet namespace), and matching on the
// local name is enough and far cheaper than resolving them.
func xmlTokens(data []byte, fn func(t xml.Token) (stop bool)) error {
	d := xml.NewDecoder(bytes.NewReader(data))
	// The parts are UTF-8 by the standard; a decoder that would fetch a
	// charset converter is one that could be pointed at anything.
	d.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		if strings.EqualFold(charset, "utf-8") || charset == "" {
			return input, nil
		}
		return nil, fmt.Errorf("unsupported charset %q", charset)
	}
	d.Strict = false
	for {
		t, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		if fn(t) {
			return nil
		}
	}
}

// local is the local name of a start or end element.
func local(n xml.Name) string { return n.Local }

// attr reads one attribute of a start element by local name.
func attr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}
