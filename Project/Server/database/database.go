package database

import (
	"math/big"
)

type User struct {
	ID         int
	Username   string
	Salt       []byte
	Verifier   *big.Int
	Created_at int64
}

const CREATE_USERS_TABLE = `CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	salt BLOB NOT NULL,
	verifier BLOB NOT NULL,
	created_at INTEGER DEFAULT (unixepoch())
	)`
