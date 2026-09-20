// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package extract

import (
	"html"
	"regexp"
	"strings"
)

// The tag stripper is a few regular expressions rather than a parser, on
// purpose. The goal is text an agent can read, not a document model, and
// the failure mode of a regular expression on hostile HTML is some tag text
// left in, which is harmless, where the failure mode of a hand-rolled
// parser is a hang or a panic.
var (
	// Whole elements whose content is never text: scripts, styles, and the
	// head with its metadata. (?s) so a multi-line block is one match.
	htmlDrop = regexp.MustCompile(`(?is)<(script|style|head|noscript|template|svg)\b[^>]*>.*?</\s*(?:script|style|head|noscript|template|svg)\s*>`)
	// Comments, and the XML prologue an XHTML file starts with.
	htmlComment = regexp.MustCompile(`(?s)<!--.*?-->|<\?[^>]*>|<!\[CDATA\[.*?\]\]>`)
	// Tags that end a line of text when they open or close.
	htmlBlock = regexp.MustCompile(`(?i)</?\s*(?:p|div|br|hr|h[1-6]|li|ul|ol|tr|table|thead|tbody|section|article|header|footer|blockquote|pre|dt|dd|dl|figure|figcaption|nav|aside|form|fieldset|address)\b[^>]*>`)
	// The end of a cell is a tab. It is written as a placeholder until the
	// whitespace has been collapsed, so the collapse does not eat it; the
	// tab after the last cell of a row is trimmed with the line.
	htmlCell = regexp.MustCompile(`(?i)</\s*(?:td|th)\s*>`)
	// Every other tag is inline and simply removed, so "<b>two</b>," stays
	// "two," rather than gaining a space before the comma.
	htmlTag = regexp.MustCompile(`<[^>]*>`)
	// Runs of horizontal space, and of blank lines.
	htmlSpaces = regexp.MustCompile(`[ \t\r\f\v\x{00a0}]+`)
	htmlLines  = regexp.MustCompile(`\n[ \t]*(?:\n[ \t]*)+`)
)

// cellMark stands in for a cell boundary while whitespace is collapsed: a
// private-use rune no document contains as text.
const cellMark = ""

// StripHTML reduces a document to its text: no tags, entities decoded,
// block elements as line breaks, cells as tabs, whitespace collapsed.
func StripHTML(s string) string {
	s = htmlDrop.ReplaceAllString(s, " ")
	s = htmlComment.ReplaceAllString(s, " ")
	s = htmlBlock.ReplaceAllString(s, "\n")
	s = htmlCell.ReplaceAllString(s, cellMark)
	s = htmlTag.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = htmlSpaces.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, cellMark, "\t")
	// Trim each line, so indentation from the source does not survive as
	// leading spaces on every line of the text.
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	s = strings.Join(lines, "\n")
	s = htmlLines.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}
