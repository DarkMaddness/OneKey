package main

import (
	. "Onekey/Server/engine"
	"database/sql"
	"log"
	"net/http"

	_ "modernc.org/sqlite"
)

func main() {
	var (
		state  = STARTUP
		db     *sql.DB
		err    error
		quit   = make(chan bool)
		tcDone = make(chan bool)
	)

main:
	for {
		switch state {
		case STARTUP:
			state, db, err = Startup(DB_NAME, PORT, quit, tcDone)
		case LISTEN:
			http.ListenAndServe(PORT, nil)
		case ERROR:
			log.Println(err)
			state = EXIT
		case EXIT:
			quit <- true
			<-tcDone
			db.Close()
			log.Println("Server Stopping")
			break main
		}
	}
}
