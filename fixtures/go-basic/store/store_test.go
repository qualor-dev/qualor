package store

import "testing"

func TestAdd(t *testing.T) {
	s := New()
	s.Add("a", 2)
	if s.Total() != 2 {
		t.Fatal("total")
	}
}
