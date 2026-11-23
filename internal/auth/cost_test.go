package auth

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// startCost is read during package initialisation, before TestMain lowers
// cost, so it is the value a production binary runs with.
var startCost = cost

func TestMain(m *testing.M) {
	// Only this package's tests hash at the minimum cost; the tests below
	// check what production uses.
	cost = bcrypt.MinCost
	os.Exit(m.Run())
}

func TestProductionCostIs12(t *testing.T) {
	if defaultCost != 12 || startCost != 12 {
		t.Fatalf("defaultCost %d, cost at start %d, want 12", defaultCost, startCost)
	}
	saved := cost
	cost = startCost
	defer func() { cost = saved }()
	h, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := bcrypt.Cost([]byte(h)); c != 12 {
		t.Fatalf("HashPassword cost %d, want 12", c)
	}
}
