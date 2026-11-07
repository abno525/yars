package gitserve

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// testHash is a bcrypt hash at the minimum cost. A login check reads the cost
// from the stored hash, so fixtures log in fast; production hashes stay at 12.
func testHash(t testing.TB, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}
