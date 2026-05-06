package main

import (
	"database/sql"
	"log"
	"server/database"
	"server/session"
	"time"

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
		state   = STARTUP
		db      *sql.DB
		err     error
		quit    = make(chan bool)
		atsDone = make(chan bool)
	)

main:
	for {
		switch state {
		case STARTUP:
			state, db, err = startup(quit, atsDone)
		case ERROR:
			log.Println(err)
			state = EXIT
		case EXIT:
			quit <- true
			<-atsDone
			db.Close()
			log.Println("Server Stopping")
			break main
		}
	}
}

func startup(quit <-chan bool, atsDone chan<- bool) (state state, db *sql.DB, err error) {
	log.Printf("Server Starting on Port: %d\n", PORT)
	// Open database and check for any errors.
	db, err = sql.Open("sqlite", "Onekey")
	if err != nil {
		return ERROR, nil, err
	}
	log.Println("Database Connected")

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

	// Run Session table creation query and check for any errors.
	_, err = db.Exec(database.CREATE_SESSIONS_TABLE)
	if err != nil {
		return ERROR, nil, err
	}

	// Create admin token management structure and start token cleaner.
	ats := session.NewAdminTokenStorage()
	go tokenCleaner(ats, db, quit, atsDone)

	// CHANGE THIS LATER ONCE THE NEXT STATE HAS BEEN DEFINED.
	return EXIT, db, nil
}

// Periodically removes expired tokens.
func tokenCleaner(ats *session.AdminTokenStorage, db *sql.DB, quit <-chan bool, atsDone chan<- bool) {
	duration := 10 * time.Second
	timer := time.NewTimer(duration)
	defer timer.Stop()

loop:
	for {
		select {
		case <-quit:
			break loop
		case <-timer.C:
			log.Println("Starting token cleanup")
			ats.ClearExpired()
			_, err := db.Exec(`DELETE from sessions WHERE expires_at < ? `, time.Now().Unix())
			if err != nil {
				log.Println(err)
			}
			log.Println("Token cleanup finished")
			timer.Reset(duration)
		}
	}
	atsDone <- true
}
