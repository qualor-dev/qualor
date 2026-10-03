package shop

import (
	"database/sql"
	"fmt"
	"net/http"
)

type Orders struct {
	db *sql.DB
}

func (o *Orders) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	customer := r.URL.Query().Get("customer")
	found, err := o.db.Query("SELECT * FROM orders WHERE customer = '" + customer + "'")
	if err == nil {
		found.Close()
	}
	bound, err := o.db.Query("SELECT * FROM orders WHERE customer = ?", customer)
	if err == nil {
		bound.Close()
	}
	fmt.Fprintln(w, "ok")
}
