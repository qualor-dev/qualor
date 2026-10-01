package main

import (
	"fmt"
	"os"

	"example.com/gobasic/store"
)

func main() {
	s := store.New()
	s.Add(os.Args[0], 1)
	fmt.Println(s.Total(), store.Grade(s.Total()))
}
