package web

import (
	"bytes"
	"image"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/image/bmp"

	"github.com/abno525/yars/internal/auth"
)

// An uploaded BMP is stored as a PNG: the answer names the stored file, so
// the Markdown the editor inserts points at it, and a picture that cannot be
// read is refused in words.
func TestUploadBMPAnswersThePNGName(t *testing.T) {
	e := setup(t)
	post := func(name string, data []byte) *httptest.ResponseRecorder {
		t.Helper()
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		part, err := mw.CreateFormFile("file", name)
		if err != nil {
			t.Fatal(err)
		}
		part.Write(data)
		mw.Close()
		req := httptest.NewRequest("POST", fpath+"/attachments", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["alice"]})
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec
	}
	var b bytes.Buffer
	if err := bmp.Encode(&b, image.NewRGBA(image.Rect(0, 0, 3, 2))); err != nil {
		t.Fatal(err)
	}
	rec := post("shot.bmp", b.Bytes())
	if rec.Code != 200 || rec.Header().Get("X-Yars-Name") != "shot.png" || rec.Header().Get("X-Yars-Insert") != "![shot.png](attachments/shot.png)" {
		t.Fatalf("upload %d: name %q insert %q", rec.Code, rec.Header().Get("X-Yars-Name"), rec.Header().Get("X-Yars-Insert"))
	}
	if got := e.lastCommit(t); got != "alice|F-001: attach shot.png" {
		t.Fatalf("commit %q", got)
	}
	img := e.do(t, "alice", "GET", fpath+"/attachments/shot.png", nil, nil)
	if img.Code != 200 || !strings.HasPrefix(img.Header().Get("Content-Type"), "image/png") {
		t.Fatalf("stored file: %d %s", img.Code, img.Header().Get("Content-Type"))
	}
	rec = post("cut.bmp", b.Bytes()[:40])
	if rec.Code != http.StatusUnsupportedMediaType || !strings.Contains(rec.Body.String(), "cannot be read") {
		t.Fatalf("a cut-off BMP: %d %s", rec.Code, rec.Body.String())
	}
}
