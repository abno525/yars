package store

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/image/bmp"
)

// webpBytes is a lossless WebP picture of one pixel (the standard library
// cannot write one).
func webpBytes(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString("UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA==")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bmpBytes(t *testing.T, c color.Color) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 4, 3))
	for x := 0; x < 4; x++ {
		for y := 0; y < 3; y++ {
			img.Set(x, y, c)
		}
	}
	var b bytes.Buffer
	if err := bmp.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// hugeBMP is a BMP header that claims w x h pixels and holds none.
func hugeBMP(w, h int32) []byte {
	b := make([]byte, 54)
	copy(b, "BM")
	binary.LittleEndian.PutUint32(b[2:], 54)
	binary.LittleEndian.PutUint32(b[10:], 54)
	binary.LittleEndian.PutUint32(b[14:], 40)
	binary.LittleEndian.PutUint32(b[18:], uint32(w))
	binary.LittleEndian.PutUint32(b[22:], uint32(h))
	binary.LittleEndian.PutUint16(b[26:], 1)
	binary.LittleEndian.PutUint16(b[28:], 24)
	return b
}

// The exports read PNG, JPEG and GIF. An uploaded BMP or WebP picture is
// stored as a PNG under a .png name, whatever its own name says; a header
// that claims a huge picture is refused before anything is decoded.
func TestAttachmentBMPAndWebPBecomePNG(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding(eng, "XSS", alice)
	stored := func(name string) image.Image {
		t.Helper()
		b, err := s.ReadAttachment(eng, f.Dir, "attachments/"+name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ct := http.DetectContentType(b); ct != "image/png" {
			t.Fatalf("%s is stored as %s", name, ct)
		}
		img, err := png.Decode(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return img
	}
	for _, c := range []struct {
		upload string
		data   []byte
		want   string
		w, h   int
	}{
		{"shot.bmp", bmpBytes(t, color.White), "shot.png", 4, 3},
		{"pic.webp", webpBytes(t), "pic.png", 1, 1},
		{"x.png", webpBytes(t), "x.png", 1, 1},                     // the bytes decide, not the name
		{"shot.BMP", bmpBytes(t, color.Black), "shot-2.png", 4, 3}, // beside the first shot.png
		{"noext", bmpBytes(t, color.White), "noext.png", 4, 3},
	} {
		name, err := s.AddAttachment(eng, f.Dir, c.upload, c.data, m17Pen)
		if err != nil || name != c.want {
			t.Fatalf("%s: stored as %q, %v; want %s", c.upload, name, err, c.want)
		}
		if b := stored(name).Bounds(); b.Dx() != c.w || b.Dy() != c.h {
			t.Errorf("%s: %v", name, b)
		}
		if got := last(t, dir, "%s"); got != "F-001: attach "+c.want {
			t.Errorf("%s: commit %q", c.upload, got)
		}
	}
	// the colour survives
	if r, g, b, _ := stored("shot.png").At(1, 1).RGBA(); r != 0xffff || g != 0xffff || b != 0xffff {
		t.Errorf("the white BMP reads %x %x %x", r, g, b)
	}
	// a PNG is stored as it came
	p := pngBytes(t, color.White)
	if name, err := s.AddAttachment(eng, f.Dir, "plain.png", p, m17Pen); err != nil || name != "plain.png" {
		t.Fatalf("png: %q %v", name, err)
	} else if b, _ := s.ReadAttachment(eng, f.Dir, "attachments/"+name); !bytes.Equal(b, p) {
		t.Fatal("a PNG was rewritten")
	}

	head := last(t, dir, "%H")
	for what, data := range map[string][]byte{
		"a huge header":  hugeBMP(60000, 60000),
		"a cut-off BMP":  bmpBytes(t, color.White)[:60],
		"a cut-off WebP": webpBytes(t)[:24],
	} {
		_, err := s.AddAttachment(eng, f.Dir, "bad.bmp", data, m17Pen)
		if !errors.Is(err, ErrInvalidValue) || errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", what, err)
		}
	}
	if _, err := s.AddAttachment(eng, f.Dir, "bad.bmp", hugeBMP(60000, 60000), m17Pen); err == nil || !strings.Contains(err.Error(), "megapixels") {
		t.Errorf("the huge header's refusal: %v", err)
	}
	if last(t, dir, "%H") != head {
		t.Fatal("a refused picture made a commit")
	}

	// a redacted copy that arrives as BMP is stored as PNG under the same name
	if err := s.ReplaceAttachment(eng, f.Dir, "plain.png", bmpBytes(t, color.Black), m17Pen); err != nil {
		t.Fatal(err)
	}
	if r, _, _, _ := stored("plain.png").At(1, 1).RGBA(); r != 0 {
		t.Errorf("the redacted copy reads %x", r)
	}
}
