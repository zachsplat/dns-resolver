package dns

import (
	"sync"
	"time"
)

type CacheEntry struct {
	Records   []Record
	ExpiresAt time.Time
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]CacheEntry
}

func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]CacheEntry),
	}
}

func (c *Cache) Get(key string) ([]Record, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.ExpiresAt) {
		return nil, false
	}
	return e.Records, true
}

func (c *Cache) Set(key string, records []Record, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = CacheEntry{
		Records:   records,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func CacheKey(name string, qtype uint16) string {
	return name + ":" + TypeString(qtype)
}
