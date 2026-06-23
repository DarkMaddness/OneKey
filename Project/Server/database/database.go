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

type Session struct {
	ID        int
	UserID    int
	Token     [16]byte
	ExpiresAt int64
}

const CREATE_SESSIONS_TABLE = `CREATE TABLE IF NOT EXISTS sessions (
		id INTEGER PRIMARY KEY,
		userID INTEGER NOT NULL,
		token BLOB NOT NULL,
		expires_at INTEGER NOT NULL,
		FOREIGN KEY(userID) REFERENCES users(id) ON DELETE CASCADE
	)`

type Entry struct {
	ID     int
	UserID int
	title  []byte
	data   []byte
}

const CREATE_ENTRIES_TABLE = `CREATE TABLE IF NOT EXIST entries (
		id INTEGER PRIMARY KEY,
		userID INTEGER NOT NULL,
		title BLOB NOT NULL,
		data BLOB NOT NULL,
		FOREIGN KEY(userID) REFERENCES users(id) ON DELETE CASCADE
	)`
