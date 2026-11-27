// Sendora linkage fork of github.com/mattn/go-sqlite3 v1.14.53.
// Upstream MIT license retained in LICENSE.
//go:build cgo

package sqlite3

/*
#cgo pkg-config: sqlcipher
#cgo CFLAGS: -DUSE_LIBSQLITE3 -DSQLITE_HAS_CODEC -DSQLITE_TEMP_STORE=2
*/
import "C"
