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

// A sized cache also keeps the summed size of its values under a budget:
// the least recently used entries go while it is over.
func TestSizedEvictsOverBudget(t *testing.T) {
	c := NewSized[string, string](100, 10, func(v string) int64 { return int64(len(v)) })
	c.Add("a", "1234")
	c.Add("b", "1234")
	if c.Len() != 2 || c.Bytes() != 8 {
		t.Fatalf("len %d bytes %d, want 2/8", c.Len(), c.Bytes())
	}
	c.Get("a")
	c.Add("c", "1234")
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should have been evicted")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a evicted although recently used")
	}
	if c.Len() != 2 || c.Bytes() != 8 {
		t.Fatalf("len %d bytes %d, want 2/8", c.Len(), c.Bytes())
	}
	// An update in place counts the new size, not both.
	c.Add("a", "12")
	if c.Bytes() != 6 {
		t.Fatalf("bytes %d after update, want 6", c.Bytes())
	}
	// A value larger than the whole budget is not kept, and takes nothing
	// else with it.
	c.Add("big", "12345678901")
	if _, ok := c.Get("big"); ok {
		t.Fatal("a value over the budget was kept")
	}
	if c.Len() != 2 || c.Bytes() != 6 {
		t.Fatalf("len %d bytes %d, want 2/6", c.Len(), c.Bytes())
	}
	// The entry limit still holds.
	n := NewSized[int, string](3, 1000, func(v string) int64 { return int64(len(v)) })
	for i := range 10 {
		n.Add(i, "x")
	}
	if n.Len() != 3 || n.Bytes() != 3 {
		t.Fatalf("len %d bytes %d, want 3/3", n.Len(), n.Bytes())
	}
}

// A cache made with New has no budget: values of any size are kept.
func TestNewHasNoBudget(t *testing.T) {
	c := New[string, string](2)
	c.Add("a", string(make([]byte, 1<<20)))
	if c.Len() != 1 || c.Bytes() != 0 {
		t.Fatalf("len %d bytes %d, want 1/0", c.Len(), c.Bytes())
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
