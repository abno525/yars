// Package lru is a small mutex-protected least-recently-used cache with a
// fixed number of entries.
package lru

import (
	"container/list"
	"sync"
)

type entry[K comparable, V any] struct {
	key K
	val V
}

// Cache holds at most max entries; adding beyond that drops the least
// recently used one. Safe for concurrent use.
type Cache[K comparable, V any] struct {
	mu  sync.Mutex
	max int
	ll  *list.List // front = most recently used
	m   map[K]*list.Element
}

// New returns a cache for max entries (at least 1).
func New[K comparable, V any](max int) *Cache[K, V] {
	if max < 1 {
		max = 1
	}
	return &Cache[K, V]{max: max, ll: list.New(), m: map[K]*list.Element{}}
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

// Add stores v under k, evicting the least recently used entry when full.
func (c *Cache[K, V]) Add(k K, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		e.Value.(*entry[K, V]).val = v
		c.ll.MoveToFront(e)
		return
	}
	c.m[k] = c.ll.PushFront(&entry[K, V]{k, v})
	for c.ll.Len() > c.max {
		old := c.ll.Back()
		c.ll.Remove(old)
		delete(c.m, old.Value.(*entry[K, V]).key)
	}
}

// Len is the number of entries.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
