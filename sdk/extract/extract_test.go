// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package extract

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// zipOf builds an Office-shaped zip in memory from part names to content.
func zipOf(t *testing.T, parts map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range parts {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const docxBody = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:r><w:t>Title of the </w:t></w:r><w:r><w:rPr><w:b/></w:rPr><w:t>memo</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">Second paragraph with a</w:t><w:tab/><w:t>tab and a</w:t><w:br/><w:t>break.</w:t></w:r></w:p>
<w:tbl>
<w:tr><w:tc><w:p><w:r><w:t>Name</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>Amount</w:t></w:r></w:p></w:tc></w:tr>
<w:tr><w:tc><w:p><w:r><w:t>Alice</w:t></w:r></w:p><w:p><w:r><w:t>(lead)</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>12</w:t></w:r></w:p></w:tc></w:tr>
</w:tbl>
<w:p><w:r><w:t>After the table. Caf&#233; &amp; co.</w:t></w:r></w:p>
</w:body>
</w:document>`

func TestDocx(t *testing.T) {
	data := zipOf(t, map[string]string{"[Content_Types].xml": "<Types/>", "word/document.xml": docxBody})
	res, err := Docx(data, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	want := "Title of the memo\nSecond paragraph with a\ttab and a\nbreak.\nName\tAmount\nAlice (lead)\t12\nAfter the table. Café & co."
	if res.Text != want {
		t.Fatalf("docx text:\n%q\nwant\n%q", res.Text, want)
	}
	if res.Truncated {
		t.Fatal("not truncated")
	}
	// The bound cuts the text and says so.
	res, err = Docx(data, 20)
	if err != nil || !res.Truncated || len(res.Text) > 20 || !strings.HasPrefix(res.Text, "Title of the memo") {
		t.Fatalf("bounded: %+v %v", res, err)
	}
	// Through the dispatcher, by name.
	if k := Kind("Memo.DOCX", "application/octet-stream"); k != KindDocx {
		t.Fatalf("kind by name: %q", k)
	}
	if k := Kind("memo", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"); k != KindDocx {
		t.Fatalf("kind by mime: %q", k)
	}
	if r, err := Text(KindDocx, data, 1<<20); err != nil || r.Text != want {
		t.Fatalf("Text: %v %q", err, r.Text)
	}
}

func TestDocxMalformed(t *testing.T) {
	data := zipOf(t, map[string]string{"word/document.xml": docxBody})
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"truncated zip", data[:len(data)/2]},
		{"not a zip", []byte("PK\x03\x04 this is not a zip at all")},
		{"empty", nil},
		{"no document part", zipOf(t, map[string]string{"word/other.xml": "<a/>"})},
	} {
		_, err := Docx(tc.data, 1<<20)
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: want ErrMalformed, got %v", tc.name, err)
		}
	}
	// Broken XML inside a good zip is an error, not a panic, and text
	// before the break may or may not come back; either way it is an error.
	broken := zipOf(t, map[string]string{"word/document.xml": "<w:document><w:body><w:p><w:r><w:t>hello</w:t></w:r></w:p><w:p><w:r><w:t>unterminated"})
	if _, err := Docx(broken, 1<<20); !errors.Is(err, ErrMalformed) {
		t.Fatalf("broken xml: %v", err)
	}
}

func TestXlsx(t *testing.T) {
	data := zipOf(t, map[string]string{
		"xl/workbook.xml": `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Budget" sheetId="1" r:id="rId2"/><sheet name="Notes, etc" sheetId="2" r:id="rId1"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
</Relationships>`,
		"xl/sharedStrings.xml": `<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="3" uniqueCount="3">
<si><t>Item</t></si><si><r><t>Cost, </t></r><r><rPr><b/></rPr><t>net</t></r></si><si><t>Widget</t></si></sst>`,
		// Budget: a header row, a data row with a gap, a formula with a
		// cached value, an inline string, a boolean, and an empty row.
		"xl/worksheets/sheet2.xml": `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>
<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>
<row r="2"><c r="A2" t="s"><v>2</v></c><c r="C2"><v>12.5</v></c><c r="D2"><f>C2*2</f><v>25</v></c></row>
<row r="3"/>
<row r="4"><c r="A4" t="inlineStr"><is><t>Total</t></is></c><c r="B4" t="b"><v>1</v></c></row>
</sheetData></worksheet>`,
		"xl/worksheets/sheet1.xml": `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>
<row r="1"><c r="A1" t="str"><v>a "quoted" note</v></c></row>
</sheetData></worksheet>`,
	})
	res, err := Xlsx(data, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	want := "## Budget\nItem,\"Cost, net\"\nWidget,,12.5,25\nTotal,TRUE\n\n## Notes, etc\n\"a \"\"quoted\"\" note\""
	if res.Text != want {
		t.Fatalf("xlsx text:\n%q\nwant\n%q", res.Text, want)
	}
	if _, err := Xlsx(data[:len(data)-30], 1<<20); !errors.Is(err, ErrMalformed) {
		t.Fatalf("truncated: %v", err)
	}
	if _, err := Xlsx(zipOf(t, map[string]string{"xl/sharedStrings.xml": "<sst/>"}), 1<<20); !errors.Is(err, ErrMalformed) {
		t.Fatalf("no workbook: %v", err)
	}
	for ref, want := range map[string]int{"A1": 0, "Z9": 25, "AA1": 26, "ab3": 27, "": -1, "7": -1} {
		if got := columnIndex(ref); got != want {
			t.Errorf("columnIndex(%q) = %d, want %d", ref, got, want)
		}
	}
}

func TestPptx(t *testing.T) {
	slide := func(lines ...string) string {
		var b strings.Builder
		b.WriteString(`<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree>`)
		for _, l := range lines {
			b.WriteString(`<p:sp><p:txBody><a:p><a:r><a:t>` + l + `</a:t></a:r></a:p></p:txBody></p:sp>`)
		}
		b.WriteString(`</p:spTree></p:cSld></p:sld>`)
		return b.String()
	}
	data := zipOf(t, map[string]string{
		"ppt/slides/slide10.xml":            slide("Tenth"),
		"ppt/slides/slide2.xml":             slide("Agenda", "One", "Two"),
		"ppt/slides/slide1.xml":             slide("Welcome"),
		"ppt/slides/_rels/slide1.xml.rels":  "<Relationships/>",
		"ppt/notesSlides/notesSlide1.xml":   slide("speaker notes are not read"),
		"ppt/slideLayouts/slideLayout1.xml": slide("layout text is not read"),
	})
	res, err := Pptx(data, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	want := "--- slide 1 ---\nWelcome\n\n--- slide 2 ---\nAgenda\nOne\nTwo\n\n--- slide 10 ---\nTenth"
	if res.Text != want {
		t.Fatalf("pptx text:\n%q\nwant\n%q", res.Text, want)
	}
	if strings.Contains(res.Text, "notes") {
		t.Fatal("notes leaked")
	}
	if _, err := Pptx(zipOf(t, map[string]string{"ppt/presentation.xml": "<p/>"}), 1<<20); !errors.Is(err, ErrMalformed) {
		t.Fatalf("no slides: %v", err)
	}
	if _, err := Pptx(data[:40], 1<<20); !errors.Is(err, ErrMalformed) {
		t.Fatalf("truncated: %v", err)
	}
}

// A zip whose entry claims a small size and inflates to more than the bound
// is refused as ErrTooLarge, before it is decompressed in full.
func TestZipBombIsRefused(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("word/document.xml")
	// Highly compressible: the deflate of 70 MB of spaces is a few KB.
	chunk := bytes.Repeat([]byte(" "), 1<<20)
	for i := 0; i < 70; i++ {
		_, _ = w.Write(chunk)
	}
	_ = zw.Close()
	if buf.Len() > 1<<20 {
		t.Fatalf("the fixture did not compress: %d bytes", buf.Len())
	}
	_, err := Docx(buf.Bytes(), 1<<20)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

// pdfOf builds a one-page PDF with an uncompressed content stream and a
// correct cross-reference table, which is what the parser reads first.
func pdfOf(t *testing.T, pages ...string) []byte {
	t.Helper()
	var objs []string
	kids := ""
	for i := range pages {
		kids += fmt.Sprintf("%d 0 R ", 4+2*i)
	}
	objs = append(objs,
		"<< /Type /Catalog /Pages 2 0 R >>",
		fmt.Sprintf("<< /Type /Pages /Kids [ %s] /Count %d >>", kids, len(pages)),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	)
	for i, text := range pages {
		content := fmt.Sprintf("BT /F1 12 Tf 72 700 Td (%s) Tj ET", text)
		objs = append(objs,
			fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", 5+2*i),
			fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
		)
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs)+1)
	for i, o := range objs {
		offsets[i+1] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n", len(objs)+1)
	b.WriteString("0000000000 65535 f \n")
	for i := 1; i <= len(objs); i++ {
		fmt.Fprintf(&b, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}

func TestPDF(t *testing.T) {
	data := pdfOf(t, "Hello from page one", "And page two")
	res, err := PDF(data, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Text, "Hello from page one") || !strings.Contains(res.Text, "And page two") {
		t.Fatalf("pdf text: %q", res.Text)
	}
	if !strings.Contains(res.Text, "\f") {
		t.Fatalf("pages are separated: %q", res.Text)
	}
	if res, err := PDF(data, 8); err != nil || !res.Truncated || len(res.Text) > 8 {
		t.Fatalf("bounded: %+v %v", res, err)
	}
	for name, bad := range map[string][]byte{
		"truncated": data[:len(data)-40],
		"garbage":   []byte("%PDF-1.4 nothing else"),
		"empty":     nil,
		"xref lies": bytes.Replace(data, []byte("startxref\n"), []byte("startxref\n9"), 1),
	} {
		if _, err := PDF(bad, 1<<20); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: want ErrMalformed, got %v", name, err)
		}
	}
}

func TestStripHTML(t *testing.T) {
	in := `<!DOCTYPE html><html><head><title>T</title><style>p{color:red}</style></head>
<body><script>alert('x')</script><h1>Heading</h1>
<p>One &amp; <b>two</b>, three&nbsp;four.</p>
<!-- a comment -->
<table><tr><td>a</td><td>b</td></tr><tr><td>c</td><td>d</td></tr></table>
<ul><li>first</li><li>second</li></ul>
<p>Line<br>break</p></body></html>`
	got := StripHTML(in)
	want := "Heading\n\nOne & two, three four.\n\na\tb\n\nc\td\n\nfirst\n\nsecond\n\nLine\nbreak"
	if got != want {
		t.Fatalf("strip:\n%q\nwant\n%q", got, want)
	}
	if r, err := Text(KindHTML, []byte("<p>x</p>"), 100); err != nil || r.Text != "x" {
		t.Fatalf("Text html: %v %q", err, r.Text)
	}
	// Unterminated markup does not hang or panic.
	_ = StripHTML(strings.Repeat("<div <p <<", 1000) + "<script>" + strings.Repeat("x", 1000))
}

func TestKindAndBounds(t *testing.T) {
	for _, tc := range []struct{ name, mime, want string }{
		{"a.txt", "", KindText},
		{"README.md", "text/plain", KindMarkdown},
		{"data.CSV", "", KindCSV},
		{"x.json", "", KindJSON},
		{"page.html", "", KindHTML},
		{"deck.pptx", "", KindPptx},
		{"book.xlsx", "", KindXlsx},
		{"paper.pdf", "", KindPDF},
		{"photo.jpg", "image/jpeg", ""},
		{"noext", "text/plain; charset=utf-8", KindText},
		{"noext", "application/pdf", KindPDF},
		{"noext", "text/x-something", KindText},
		{"archive.zip", "application/zip", ""},
		{"main.go", "", KindText},
	} {
		if got := Kind(tc.name, tc.mime); got != tc.want {
			t.Errorf("Kind(%q, %q) = %q, want %q", tc.name, tc.mime, got, tc.want)
		}
	}
	if _, err := Text("", []byte("x"), 10); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown kind: %v", err)
	}
	// The bound never splits a rune.
	r, _ := Text(KindText, []byte("héllo"), 2)
	if r.Text != "h" || !r.Truncated {
		t.Fatalf("rune boundary: %+v", r)
	}
	if _, err := Text(KindText, []byte("x"), 0); err == nil {
		t.Fatal("a zero bound is refused")
	}
}

// Every extractor survives arbitrary bytes: an error or a result, never a
// panic. The fuzz seeds are the fixtures cut at random points.
func FuzzExtractors(f *testing.F) {
	docx := zipOf(&testing.T{}, map[string]string{"word/document.xml": docxBody})
	f.Add(docx)
	f.Add(pdfOf(&testing.T{}, "seed"))
	f.Add([]byte("<html><body>x</body></html>"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, k := range []string{KindDocx, KindXlsx, KindPptx, KindPDF, KindHTML, KindText} {
			_, _ = Text(k, data, 4096)
		}
	})
}
