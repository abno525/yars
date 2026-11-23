package export

import (
	"strings"
	"testing"
)

// Pictures that don't decode are left out of a PDF (xelatex would fail on
// them); other formats keep them.
func TestPDFDropsBrokenImages(t *testing.T) {
	in := imageInput(t, "http://x/y.png")
	in.strictImages = true
	if x := XHTML(in, false); strings.Contains(x, "data:image/png") || strings.Count(x, "image removed") != 3 {
		t.Fatalf("broken image kept:\n%s", x)
	}
}
