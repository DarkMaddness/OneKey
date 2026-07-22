package main

import (
	. "Onekey/Client/engine"
	"fmt"
)

func main() {
	var (
		state          = PARSE_URL
		serverURL      string
		sessionToken   [16]byte
		adminToken     [16]byte
		aesKey         []byte
		username       string
		entryID        int
		encryptedTitle []byte
		encryptedData  []byte
		retryState     State
		err            error
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
		case GET_ENTRY:
			state, retryState, err = Entry(serverURL, sessionToken, aesKey, entryID)
		case NEW_ENTRY:
			state, encryptedTitle, encryptedData, err = NewEntry(aesKey)
		case CREATE_ENTRY:
			state, retryState, err = CreateEntry(serverURL, sessionToken, adminToken, encryptedTitle, encryptedData)
		case EDIT_ENTRY_DETAILS:
			state, retryState, encryptedTitle, encryptedData, err = EditEntry(serverURL, sessionToken, aesKey, entryID)
		case UPDATE_ENTRY:
			state, retryState, err = UpdateEntry(serverURL, sessionToken, adminToken, encryptedTitle, encryptedData, entryID)
		case DELETE_ENTRY:
			state, retryState, err = DeleteEntry(serverURL, sessionToken, adminToken, entryID)
		case LOG_OUT:
			state, sessionToken, adminToken, aesKey, username, entryID, encryptedTitle, encryptedData = LogOut(serverURL, sessionToken)
		case DELETE_ACCOUNT:
			state, retryState, err = DeleteAccount(serverURL, sessionToken, adminToken)
		case ERROR:
			fmt.Println(err)
			state = EXIT
		case EXIT:
			fmt.Println("Connection closed.")
			break main
		}
	}
}

func isLoggedIn(sessionToken [16]byte) bool {
	return sessionToken != [16]byte{}
}
