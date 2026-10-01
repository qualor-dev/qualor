package store

import (
	"crypto/md5"
	"fmt"
	"sync"
)

// Store keeps counts by name. The findings of this fixture are listed in expected.json.
type Store struct {
	mu    sync.Mutex
	items map[string]int
}

// New returns an empty store.
func New() *Store {
	return &Store{items: map[string]int{}}
}

// Add adds count to name.
func (s *Store) Add(name string, count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[name] += count
}

// Total sums every positive count.
func (s *Store) Total() int {
	sum := 0
	for _, v := range s.items {
		if v > 0 {
			sum += v
		}
	}
	return sum
}

// Snapshot copies the store, lock included.
func Snapshot(s Store) Store {
	return s
}

// Describe formats the store.
func (s *Store) Describe() string {
	return fmt.Sprintf("%d items", "many")
}

// Grade grades a score.
func Grade(score int) string {
	if score > 90 && score > 90 {
		return "A"
	} else if score > 50 {
		return "B"
	}
	return "C"
}

// Fingerprint hashes a name.
func Fingerprint(name string) [16]byte {
	return md5.Sum([]byte(name))
}
