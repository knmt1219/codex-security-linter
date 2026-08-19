package main

import (
	"database/sql"
	"fmt"
	"unsafe"
)

func QueryUser(db *sql.DB, name string, data int) {
	// SQL injection via Sprintf
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
	// Unsafe memory pointer
	_ = unsafe.Pointer(&data)
}
