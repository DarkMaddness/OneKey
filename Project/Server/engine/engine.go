package engine

import (
	"Onekey/Server/database"
	"Onekey/Server/routes"
	"Onekey/Server/session"
	"database/sql"
	"log"
	"net/http"
	"time"

	_ "modernc.org/sqlite"
)

type state int

const (
	STARTUP state = iota
	LISTEN
	ERROR
	EXIT
)

const (
	PORT    string = ":32500"
	DB_NAME string = "Onekey"
)

func Startup(dbName string, port string, quit <-chan bool, tcDone chan<- bool) (state state, db *sql.DB, err error) {
	log.Printf("Server Starting on Port%s\n", port)
	// Open database and check for any errors.
	db, err = sql.Open("sqlite", dbName)
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

	// Run Entry table creation query and check for any errors.
	_, err = db.Exec(database.CREATE_ENTRIES_TABLE)
	if err != nil {
		return ERROR, nil, err
	}

	// Create admin token management structure and start token cleaner.
	ats := session.NewAdminTokenStorage()
	go tokenCleaner(ats, db, quit, tcDone)

	// Register routes and endpoints for the server.
	for _, route := range routes.Routes(db, ats) {
		http.Handle(route.Path, route.Handler)
	}

	// CHANGE THIS LATER ONCE THE NEXT STATE HAS BEEN DEFINED.
	return LISTEN, db, nil
}

// Periodically removes expired tokens.
func tokenCleaner(ats *session.AdminTokenStorage, db *sql.DB, quit <-chan bool, tcDone chan<- bool) {
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
	tcDone <- true
}
