// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package extract

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"path"
	"strconv"
	"strings"
)

// Xlsx reads a workbook sheet by sheet, each headed by its name and written
// as CSV rows: the shared strings resolved, inline strings and numbers as
// they are, formulas by their cached value. Empty cells between filled
// ones are kept so columns stay aligned; empty rows are dropped.
func Xlsx(data []byte, max int) (Result, error) {
	c, err := openContainer(data)
	if err != nil {
		return Result{}, err
	}
	shared, err := sharedStrings(c)
	if err != nil {
		return Result{}, err
	}
	sheets, err := workbookSheets(c)
	if err != nil {
		return Result{}, err
	}
	if len(sheets) == 0 {
		return Result{}, ErrMalformed
	}
	w := &writer{max: max}
	for i, sh := range sheets {
		part, err := c.part(sh.part)
		if err != nil {
			return Result{}, err
		}
		if part == nil {
			continue
		}
		if i > 0 {
			w.write("\n")
		}
		w.write("## " + sh.name + "\n")
		if err := sheetRows(part, shared, w); err != nil {
			return Result{}, err
		}
		if w.full() {
			break
		}
	}
	return w.result(), nil
}

// sharedStrings reads xl/sharedStrings.xml: each si is one string, made of
// one or more t runs (rich text splits a cell into several).
func sharedStrings(c *container) ([]string, error) {
	part, err := c.part("xl/sharedStrings.xml")
	if err != nil || part == nil {
		return nil, err
	}
	var out []string
	var cur strings.Builder
	inSI, inT := false, false
	err = xmlTokens(part, func(t xml.Token) bool {
		switch e := t.(type) {
		case xml.StartElement:
			switch local(e.Name) {
			case "si":
				inSI = true
				cur.Reset()
			case "t":
				inT = inSI
			}
		case xml.EndElement:
			switch local(e.Name) {
			case "si":
				out = append(out, cur.String())
				inSI = false
			case "t":
				inT = false
			}
		case xml.CharData:
			if inT {
				cur.Write(e)
			}
		}
		return false
	})
	return out, err
}

type sheet struct {
	name string
	part string
}

// workbookSheets lists the sheets in the workbook's own order, resolving
// each one's part through the relationships file, because sheetN.xml is
// numbered by creation and not by position.
func workbookSheets(c *container) ([]sheet, error) {
	wb, err := c.part("xl/workbook.xml")
	if err != nil {
		return nil, err
	}
	if wb == nil {
		return nil, ErrMalformed
	}
	rels, err := c.part("xl/_rels/workbook.xml.rels")
	if err != nil {
		return nil, err
	}
	targets := map[string]string{}
	if rels != nil {
		err = xmlTokens(rels, func(t xml.Token) bool {
			if se, ok := t.(xml.StartElement); ok && local(se.Name) == "Relationship" {
				target := attr(se, "Target")
				if strings.HasPrefix(target, "/") {
					target = strings.TrimPrefix(target, "/")
				} else {
					target = path.Join("xl", target)
				}
				targets[attr(se, "Id")] = target
			}
			return false
		})
		if err != nil {
			return nil, err
		}
	}
	var out []sheet
	n := 0
	err = xmlTokens(wb, func(t xml.Token) bool {
		if se, ok := t.(xml.StartElement); ok && local(se.Name) == "sheet" {
			n++
			name := attr(se, "name")
			if name == "" {
				name = "Sheet " + strconv.Itoa(n)
			}
			part := targets[attr(se, "id")]
			if part == "" {
				// No relationships file, or a relationship that names
				// nothing: fall back to the conventional part name.
				part = "xl/worksheets/sheet" + strconv.Itoa(n) + ".xml"
			}
			out = append(out, sheet{name: name, part: part})
		}
		return false
	})
	return out, err
}

// sheetRows writes one worksheet as CSV.
func sheetRows(part []byte, shared []string, w *writer) error {
	var (
		row     []string
		col     int    // the next column to fill, zero-based
		cellCol int    // the column of the cell being read
		cellT   string // the cell's t attribute
		inV     bool
		inIS    bool // an inline string: is/t
		inT     bool
		value   strings.Builder
		buf     bytes.Buffer
	)
	cw := csv.NewWriter(&buf)
	flush := func() {
		// Trim trailing empties so a row padded to the sheet's width does
		// not end in a run of commas.
		for len(row) > 0 && row[len(row)-1] == "" {
			row = row[:len(row)-1]
		}
		if len(row) > 0 {
			buf.Reset()
			_ = cw.Write(row)
			cw.Flush()
			w.write(buf.String())
		}
		row = row[:0]
		col = 0
	}
	place := func(v string) {
		for col < cellCol {
			row = append(row, "")
			col++
		}
		row = append(row, v)
		col++
	}
	return xmlTokens(part, func(t xml.Token) bool {
		switch e := t.(type) {
		case xml.StartElement:
			switch local(e.Name) {
			case "row":
				row = row[:0]
				col = 0
			case "c":
				cellT = attr(e, "t")
				cellCol = columnIndex(attr(e, "r"))
				if cellCol < col {
					cellCol = col
				}
				value.Reset()
			case "v":
				inV = true
			case "is":
				inIS = true
			case "t":
				inT = inIS
			}
		case xml.EndElement:
			switch local(e.Name) {
			case "v":
				inV = false
			case "t":
				inT = false
			case "is":
				inIS = false
			case "c":
				v := value.String()
				switch cellT {
				case "s":
					i, err := strconv.Atoi(strings.TrimSpace(v))
					if err == nil && i >= 0 && i < len(shared) {
						v = shared[i]
					} else {
						v = ""
					}
				case "b":
					if strings.TrimSpace(v) == "1" {
						v = "TRUE"
					} else {
						v = "FALSE"
					}
				}
				place(v)
			case "row":
				flush()
			}
		case xml.CharData:
			if inV || inT {
				value.Write(e)
			}
		}
		return w.full()
	})
}

// columnIndex turns "C7" into 2. A reference that does not parse is -1, and
// the cell then follows the previous one.
func columnIndex(ref string) int {
	n := 0
	seen := false
	for i := 0; i < len(ref); i++ {
		ch := ref[i]
		switch {
		case ch >= 'A' && ch <= 'Z':
			n = n*26 + int(ch-'A') + 1
			seen = true
		case ch >= 'a' && ch <= 'z':
			n = n*26 + int(ch-'a') + 1
			seen = true
		default:
			if !seen {
				return -1
			}
			return n - 1
		}
		if n > 20000 {
			return -1
		}
	}
	if !seen {
		return -1
	}
	return n - 1
}
