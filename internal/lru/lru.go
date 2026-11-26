// Package lru is a small mutex-protected least-recently-used cache with a
// fixed number of entries and, when asked for, a byte budget.
package lru

import (
	"container/list"
	"sync"
)

type entry[K comparable, V any] struct {
	key  K
	val  V
	size int64
}

// Cache holds at most max entries; adding beyond that drops the least
// recently used one. A cache made with NewSized also keeps the summed size
// of its values under a budget. Safe for concurrent use.
type Cache[K comparable, V any] struct {
	mu     sync.Mutex
	max    int
	budget int64         // 0: no byte budget
	size   func(V) int64 // nil without a budget
	bytes  int64
	ll     *list.List // front = most recently used
	m      map[K]*list.Element
}

// New returns a cache for max entries (at least 1).
func New[K comparable, V any](max int) *Cache[K, V] {
	if max < 1 {
		max = 1
	}
	return &Cache[K, V]{max: max, ll: list.New(), m: map[K]*list.Element{}}
}

// NewSized returns a cache for max entries (at least 1) whose values, as
// measured by size, sum to at most budget. A value larger than the budget
// is not kept.
func NewSized[K comparable, V any](max int, budget int64, size func(V) int64) *Cache[K, V] {
	c := New[K, V](max)
	if budget < 1 {
		budget = 1
	}
	c.budget, c.size = budget, size
	return c
}

// Get returns the value for k and marks it as recently used.
func (c *Cache[K, V]) Get(k K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		c.ll.MoveToFront(e)
		return e.Value.(*entry[K, V]).val, true
	}
	var zero V
	return zero, false
}

// Add stores v under k, evicting the least recently used entries while the
// cache is over its entry limit or its budget.
func (c *Cache[K, V]) Add(k K, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var n int64
	if c.size != nil {
		n = c.size(v)
	}
	if e, ok := c.m[k]; ok {
		if c.budget > 0 && n > c.budget {
			c.remove(e)
			return
		}
		en := e.Value.(*entry[K, V])
		c.bytes += n - en.size
		en.val, en.size = v, n
		c.ll.MoveToFront(e)
	} else {
		if c.budget > 0 && n > c.budget {
			return
		}
		c.m[k] = c.ll.PushFront(&entry[K, V]{k, v, n})
		c.bytes += n
	}
	for c.ll.Len() > c.max || (c.budget > 0 && c.bytes > c.budget) {
		c.remove(c.ll.Back())
	}
}

// remove drops one entry; the caller holds the lock.
func (c *Cache[K, V]) remove(e *list.Element) {
	en := e.Value.(*entry[K, V])
	c.ll.Remove(e)
	delete(c.m, en.key)
	c.bytes -= en.size
}

// Len is the number of entries.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// Bytes is the summed size of the values of a sized cache; 0 for a cache
// without a budget.
func (c *Cache[K, V]) Bytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytes
}
