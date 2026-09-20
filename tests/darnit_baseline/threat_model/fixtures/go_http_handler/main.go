// Minimal Go HTTP handler fixture used by discovery tests.
//
// Expected discovery:
// - One HTTP_ROUTE entry point for /api
// - One DataStore with technology=postgresql (sql.Open call)
package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

func handler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("postgres", "postgres://localhost/app")
	if err != nil {
		http.Error(w, "db error", 500)
		return
	}
	defer db.Close()
	fmt.Fprintln(w, "hello")
}

func main() {
	http.HandleFunc("/api", handler)
	http.ListenAndServe(":8080", nil)
}
