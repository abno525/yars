package export

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/image/bmp"

	"github.com/abno525/yars/internal/finding"
)

// A BMP or WebP attachment a push or an earlier version stored is shown in
// every export as a PNG, also in the PDF's report (which keeps only pictures
// that decode), and whatever the file's name says.
func TestStoredBMPAndWebPShowInExports(t *testing.T) {
	var b bytes.Buffer
	if err := bmp.Encode(&b, image.NewRGBA(image.Rect(0, 0, 3, 2))); err != nil {
		t.Fatal(err)
	}
	webp, err := base64.StdEncoding.DecodeString("UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA==")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"attachments/a.bmp": b.Bytes(), "attachments/b.webp": webp, "attachments/c.png": webp, "attachments/bad.bmp": b.Bytes()[:40]}
	in := input(t)
	in.Findings = in.Findings[:1]
	in.Findings[0].SetSection("Impact", "![one](attachments/a.bmp)\n\n![two](attachments/b.webp)\n\n![three](attachments/c.png)\n\n![four](attachments/bad.bmp)")
	in.Attachment = func(_ *finding.Finding, rel string) ([]byte, bool) {
		data, ok := files[rel]
		return data, ok
	}
	uri := regexp.MustCompile(`<img src="data:image/png;base64,([^"]+)" alt="(one|two|three)" />`)
	check := func(what, x string) {
		t.Helper()
		ms := uri.FindAllStringSubmatch(x, -1)
		if len(ms) != 3 {
			t.Fatalf("%s: %d of 3 pictures shown:\n%s", what, len(ms), x[strings.Index(x, "Impact"):])
		}
		for _, m := range ms {
			raw, err := base64.StdEncoding.DecodeString(m[1])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := png.Decode(bytes.NewReader(raw)); err != nil {
				t.Errorf("%s: picture %s is no PNG: %v", what, m[2], err)
			}
		}
		// one that cannot be read is left out, as before
		if !strings.Contains(x, "<em>[image removed: four]</em>") || strings.Contains(x, "image/bmp") || strings.Contains(x, "image/webp") {
			t.Errorf("%s: the broken picture, or a type no export reads, is in:\n%s", what, x[strings.Index(x, "Impact"):])
		}
	}
	check("XHTML", XHTML(in, false))
	in.strictImages = true
	check("Report", Report(in))

	// the HTML ZIP and a Confluence page name the converted file .png
	in.strictImages = false
	var names []string
	in.imageSrc = func(_ *finding.Finding, rel, ct string, data []byte) string {
		if _, err := png.Decode(bytes.NewReader(data)); err != nil || ct != "image/png" {
			t.Errorf("%s handed on as %s: %v", rel, ct, err)
		}
		names = append(names, rel)
		return rel
	}
	XHTML(in, false)
	if got := strings.Join(names, " "); got != "attachments/a.bmp.png attachments/b.webp.png attachments/c.png.png" {
		t.Errorf("names handed on: %s", got)
	}
}
