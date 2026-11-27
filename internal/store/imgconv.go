package store

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"io"
	"net/http"

	"golang.org/x/image/bmp"
	"golang.org/x/image/webp"
)

// maxPixels is the largest picture PNGOf decodes. A file of a few bytes can
// claim any size, and a decoded picture takes four bytes a pixel: the size
// is read from the header and checked before anything is decoded. At this
// size one conversion holds about 64 MB of pixels (a 5K screenshot is under
// it; a 10 MB BMP is about 3 megapixels).
const maxPixels = 16 << 20

// pngSlot lets one conversion run at a time: uploads sent together and the
// pictures of one export wait for each other, so the pixels of one picture
// are in memory, not of all of them.
var pngSlot = make(chan struct{}, 1)

// PNGOf turns a BMP or WebP picture into a PNG: the exports read PNG, JPEG
// and GIF only, so an upload is stored as one and an export converts what a
// push or an earlier version stored. The bytes decide, not a file name. Any
// other data comes back as it is, with converted false. A picture that
// cannot be read (an animated WebP is one), one over maxPixels and one whose
// PNG is over MaxAttachment are an ErrInvalidValue in plain words.
func PNGOf(data []byte) (out []byte, converted bool, err error) {
	var (
		kind   string
		config func(io.Reader) (image.Config, error)
		decode func(io.Reader) (image.Image, error)
	)
	switch http.DetectContentType(data) {
	case "image/bmp":
		kind, config, decode = "BMP", bmp.DecodeConfig, bmp.Decode
	case "image/webp":
		kind, config, decode = "WebP", webp.DecodeConfig, webp.Decode
	default:
		return data, false, nil
	}
	unread := fmt.Errorf("%w: this %s picture cannot be read (an animated one is not taken); save it as PNG", ErrInvalidValue, kind)
	cfg, err := config(bytes.NewReader(data))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, false, unread
	}
	if int64(cfg.Width)*int64(cfg.Height) > maxPixels {
		return nil, false, fmt.Errorf("%w: this %s picture is larger than %d megapixels; save it as PNG", ErrInvalidValue, kind, maxPixels>>20)
	}
	pngSlot <- struct{}{}
	defer func() { <-pngSlot }()
	img, err := decode(bytes.NewReader(data))
	if err != nil {
		return nil, false, unread
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, false, unread
	}
	if buf.Len() > MaxAttachment {
		return nil, false, fmt.Errorf("%w: as a PNG this %s picture is larger than 10 MB; save it as JPEG", ErrInvalidValue, kind)
	}
	return buf.Bytes(), true, nil
}
