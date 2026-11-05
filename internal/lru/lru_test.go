package lru

import (
	"strconv"
	"sync"
	"testing"
)

func TestGetAdd(t *testing.T) {
	c := New[string, int](2)
	if _, ok := c.Get("a"); ok {
		t.Fatal("empty cache hit")
	}
	c.Add("a", 1)
	c.Add("b", 2)
	if v, ok := c.Get("a"); !ok || v != 1 {
		t.Fatalf("a = %d %v", v, ok)
	}
	c.Add("a", 3) // update in place
	if v, _ := c.Get("a"); v != 3 || c.Len() != 2 {
		t.Fatalf("a = %d len %d", v, c.Len())
	}
}

// The least recently used entry goes first; a Get counts as a use.
func TestEvictsLeastRecentlyUsed(t *testing.T) {
	c := New[string, int](2)
	c.Add("a", 1)
	c.Add("b", 2)
	c.Get("a")
	c.Add("c", 3)
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should have been evicted")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a evicted although recently used")
	}
	if _, ok := c.Get("c"); !ok || c.Len() != 2 {
		t.Fatalf("c missing or len %d", c.Len())
	}
}

func TestBounded(t *testing.T) {
	c := New[int, int](100)
	for i := 0; i < 1000; i++ {
		c.Add(i, i)
	}
	if c.Len() != 100 {
		t.Fatalf("len %d", c.Len())
	}
	if _, ok := c.Get(899); ok {
		t.Fatal("old entry kept")
	}
	if v, ok := c.Get(999); !ok || v != 999 {
		t.Fatal("newest entry missing")
	}
}

func TestZeroMaxIsOne(t *testing.T) {
	c := New[string, int](0)
	c.Add("a", 1)
	c.Add("b", 2)
	if c.Len() != 1 {
		t.Fatalf("len %d", c.Len())
	}
}

func TestConcurrent(t *testing.T) {
	c := New[string, int](50)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				k := strconv.Itoa((g * i) % 80)
				c.Add(k, i)
				c.Get(k)
			}
		}(g)
	}
	wg.Wait()
	if c.Len() > 50 {
		t.Fatalf("len %d", c.Len())
	}
}
