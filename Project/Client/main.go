package main

import (
	. "Onekey/Client/engine"
	"fmt"
)

func main() {
	var (
		state        = PARSE_URL
		serverURL    string
		sessionToken [16]byte
		adminToken   [16]byte
		aesKey       []byte
		username     string
		entryID      int
		retryState   State
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
			state = Options(isLoggedIn(sessionToken))
		case REGISTER:
			state, err = Register(serverURL)
		case AUTHENTICATE:
			state, sessionToken, adminToken, aesKey, username, err = Authenticate(serverURL)
		case RE_AUTHENTICATE:
			state, sessionToken, adminToken, aesKey, err = ReAuthenticate(serverURL, username, retryState)
		case ENTRIES:
			state, entryID, retryState, err = Entries(serverURL, sessionToken, aesKey)
		case LOG_OUT:
			state, sessionToken, adminToken, aesKey, username = LogOut(serverURL, sessionToken)
		case ERROR:
			fmt.Println(err)
			state = EXIT
		case EXIT:
			println(len(sessionToken), len(adminToken), len(aesKey), username)
			break main
		}
	}
}

func isLoggedIn(sessionToken [16]byte) bool {
	return sessionToken != [16]byte{}
}
