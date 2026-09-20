// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package extract

import (
	"bytes"
	"fmt"

	"github.com/ledongthuc/pdf"
)

// maxPages bounds the walk over a document's pages.
const maxPages = 5000

// PDF reads the text of every page in order, a form feed between pages.
//
// The parser is github.com/ledongthuc/pdf, BSD-3, pinned in go.mod. It is a
// text extractor and not a renderer: what comes out is the text operators of
// each page's content stream in the order they were written, which is the
// reading order for a document produced from text and an approximation for
// one produced from a layout. A scanned PDF has no text operators and comes
// back empty, which the caller reports as such rather than as a failure.
//
// The parser panics on some malformed inputs rather than returning an error,
// so every call into it runs under a recover: a document someone dropped
// into a shared folder must not be able to stop the connector.
func PDF(data []byte, max int) (res Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = Result{}, fmt.Errorf("%w: %v", ErrMalformed, r)
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	w := &writer{max: max}
	fonts := map[string]*pdf.Font{}
	// The page count is read from the file and a crafted one can claim
	// billions; the lookup of a page past the real ones is cheap but not
	// free, so the walk is capped at more pages than any document has text
	// worth reading in one call.
	pages := r.NumPage()
	if pages > maxPages {
		pages = maxPages
	}
	for i := 1; i <= pages && !w.full(); i++ {
		p := r.Page(i)
		if p.V.IsNull() {
			continue
		}
		text, err := p.GetPlainText(fonts)
		if err != nil {
			return Result{}, fmt.Errorf("%w: page %d: %v", ErrMalformed, i, err)
		}
		if i > 1 {
			w.write("\f")
		}
		w.write(text)
	}
	return w.result(), nil
}
