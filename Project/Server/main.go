package main

import (
	"database/sql"
	"log"
	"server/database"

	_ "modernc.org/sqlite"
)

type state int

const (
	STARTUP state = iota
	ERROR
	EXIT
)

const (
	PORT int = 32500
)

func main() {
	var (
		state state = STARTUP
		db    *sql.DB
		err   error
	)

main:
	for {
		switch state {
		case STARTUP:
			state, db, err = startup()
		case ERROR:
			log.Println(err)
			state = EXIT
		case EXIT:
			db.Close()
			log.Println("Server Stopping")
			break main
		}
	}
}

func startup() (state state, db *sql.DB, err error) {
	log.Printf("Server Starting on Port: %d\n", PORT)
	// Open database and check for any errors.
	db, err = sql.Open("sqlite", "Onekey")
	if err != nil {
		return ERROR, nil, err
	}

	// Set max connections to 1, enable foreign key support, and check for any errors.
	db.SetMaxOpenConns(1)
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		return ERROR, nil, err
	}

	// Run User table creation query and check for any errors.
	_, err = db.Exec(database.CREATE_USERS_TABLE)
	if err != nil {
		return ERROR, nil, err
	}

	// CHANGE THIS LATER ONCE THE NEXT STATE HAS BEEN DEFINED.
	return EXIT, db, nil
}
