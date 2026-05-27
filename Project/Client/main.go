package main

import (
	. "Onekey/Client/engine"
	"fmt"
)

func main() {
	var (
		state        = PARSE_URL
		serverURL    string
		loggedIn     bool = false
		sessionToken [16]byte
		adminToken   [16]byte
		aesKey       []byte
		username     string
		err          error
	)

main:
	for {
		switch state {
		case PARSE_URL:
			state, serverURL, err = ParseURL()
		case VERIFY_URL:
			state, err = VerifyURL(serverURL)
		case OPTIONS:
			state = Options(loggedIn)
		case REGISTER:
			state, err = Register(serverURL)
		case AUTHENTICATE:
			state, loggedIn, sessionToken, adminToken, aesKey, username, err = Authenticate(serverURL)
		case ERROR:
			fmt.Println(err)
			state = EXIT
		case EXIT:
			println(len(sessionToken), len(adminToken), len(aesKey), username)
			break main
		}
	}
}
