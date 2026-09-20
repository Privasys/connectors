// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package extract

import (
	"encoding/xml"
	"regexp"
	"sort"
	"strconv"
)

var slidePart = regexp.MustCompile(`^ppt/slides/slide([0-9]+)\.xml$`)

// Pptx reads a presentation slide by slide, each headed by its number, the
// text runs of every shape in the order they appear and one paragraph per
// line. Notes are a separate part and are left out.
//
// Slides are taken in the order of their part numbers. The presentation's
// own order lives in presentation.xml through a relationships file; the
// numbers match it in every deck saved by PowerPoint and Google Slides, and
// a deck whose slides were reordered by hand in the zip is not a case worth
// a second parser.
func Pptx(data []byte, max int) (Result, error) {
	c, err := openContainer(data)
	if err != nil {
		return Result{}, err
	}
	type slide struct {
		n    int
		name string
	}
	var slides []slide
	for _, name := range c.names("ppt/slides/slide") {
		m := slidePart.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		slides = append(slides, slide{n: n, name: name})
	}
	if len(slides) == 0 {
		return Result{}, ErrMalformed
	}
	sort.Slice(slides, func(i, j int) bool { return slides[i].n < slides[j].n })

	w := &writer{max: max}
	for i, s := range slides {
		part, err := c.part(s.name)
		if err != nil {
			return Result{}, err
		}
		if part == nil {
			continue
		}
		if i > 0 {
			w.write("\n")
		}
		w.write("--- slide " + strconv.Itoa(s.n) + " ---\n")
		inT := false
		err = xmlTokens(part, func(t xml.Token) bool {
			switch e := t.(type) {
			case xml.StartElement:
				switch local(e.Name) {
				case "t":
					inT = true
				case "br":
					w.write("\n")
				}
			case xml.EndElement:
				switch local(e.Name) {
				case "t":
					inT = false
				case "p":
					w.write("\n")
				}
			case xml.CharData:
				if inT {
					w.write(string(e))
				}
			}
			return w.full()
		})
		if err != nil {
			return Result{}, err
		}
		if w.full() {
			break
		}
	}
	return w.result(), nil
}
