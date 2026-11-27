package notify

import (
	netmail "net/mail"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A mail has a Date and a Message-ID: strict servers refuse or mark down a
// mail without them, and clients thread and drop doubles by the ID. The ID
// is random at the sender's domain and names nothing.
func TestMailHasDateAndMessageID(t *testing.T) {
	idRe := regexp.MustCompile(`^<[0-9a-f]{32}@acme\.example>$`)
	var ids []string
	for range 2 {
		m, err := netmail.ReadMessage(strings.NewReader(string(message("yars@acme.example", "pen1@client.example", "[YARS] Returned to me: F-005 SQL injection", "line"))))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.Header.Date(); err != nil {
			t.Fatalf("Date %q: %v", m.Header.Get("Date"), err)
		}
		id := m.Header.Get("Message-ID")
		if !idRe.MatchString(id) {
			t.Fatalf("Message-ID %q", id)
		}
		// not the bare digits "005": 32 random hex digits hold them now and then
		for _, no := range []string{"pen1", "client", "F-005"} {
			if strings.Contains(id, no) {
				t.Fatalf("the Message-ID holds %q: %s", no, id)
			}
		}
		ids = append(ids, id)
	}
	if ids[0] == ids[1] {
		t.Fatalf("two mails share the Message-ID %s", ids[0])
	}

	// the Date is the clock's, in the form of RFC 5322
	at := time.Date(2026, 11, 5, 14, 12, 9, 0, time.FixedZone("", 3600))
	msg := string(messageAt("yars@acme.example", "pen1@client.example", "s", "b", at, "<abc@acme.example>"))
	if !strings.Contains(msg, "Date: Thu, 05 Nov 2026 14:12:09 +0100\r\n") || !strings.Contains(msg, "Message-ID: <abc@acme.example>\r\n") {
		t.Fatalf("headers:\n%s", msg)
	}
	m, err := netmail.ReadMessage(strings.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := m.Header.Date(); err != nil || !got.Equal(at) {
		t.Fatalf("Date %v %v", got, err)
	}
	// a sender without a usable domain still gets a well-formed ID, and a
	// header cannot be added through it
	for _, from := range []string{"yars", "yars@", "yars@bad domain", "yars@x y\r\nBcc: evil@x"} {
		if id := newMessageID(from); !regexp.MustCompile(`^<[0-9a-f]{32}@yars\.invalid>$`).MatchString(id) {
			t.Errorf("from %q: Message-ID %q", from, id)
		}
	}
	if id := newMessageID("yars@acme.example\r\nBcc: evil@x"); !idRe.MatchString(id) {
		t.Errorf("a sender with a line break: Message-ID %q", id)
	}
}
