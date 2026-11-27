//go:build libsqlite3

package sqlite3

// A mixed sqlite3/sqlcipher link can silently defeat encryption. Reject it.
var _ = SQLCipherBuildMustNotUseTheLibsqlite3Tag
