// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package extract

import (
	"encoding/xml"
)

// Docx reads a Word document: the paragraphs of word/document.xml in order,
// with table cells separated by tabs and rows by newlines. Headers,
// footers, footnotes and comments are other parts and are left out: they
// are rarely what a reader wants and often repeat on every page.
func Docx(data []byte, max int) (Result, error) {
	c, err := openContainer(data)
	if err != nil {
		return Result{}, err
	}
	body, err := c.part("word/document.xml")
	if err != nil {
		return Result{}, err
	}
	if body == nil {
		return Result{}, ErrMalformed
	}
	w := &writer{max: max}
	var (
		inText    bool
		cellDepth int  // inside a table cell, paragraphs are joined by spaces
		cellIndex int  // which cell of the row, for the tab before it
		pending   bool // a paragraph ended inside a cell; space before more text
	)
	err = xmlTokens(body, func(t xml.Token) bool {
		switch e := t.(type) {
		case xml.StartElement:
			switch local(e.Name) {
			case "t":
				inText = true
			case "tab":
				w.write("\t")
			case "br", "cr":
				w.write("\n")
			case "tr":
				cellIndex = 0
			case "tc":
				if cellIndex > 0 {
					w.write("\t")
				}
				cellIndex++
				cellDepth++
				pending = false
			}
		case xml.EndElement:
			switch local(e.Name) {
			case "t":
				inText = false
			case "p":
				if cellDepth > 0 {
					pending = true
				} else {
					w.write("\n")
				}
			case "tc":
				cellDepth--
				pending = false
			case "tr":
				w.write("\n")
			}
		case xml.CharData:
			if inText {
				if pending {
					w.write(" ")
					pending = false
				}
				w.write(string(e))
			}
		}
		return w.full()
	})
	if err != nil {
		return Result{}, err
	}
	return w.result(), nil
}
