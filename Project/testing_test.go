package main

import (
	clientEngine "Onekey/Client/engine"
	serverEngine "Onekey/Server/engine"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestEndpoints(t *testing.T) {
	const (
		PORT           = ":33333"
		URL            = "localhost:33333"
		PASSWORD       = "password123"
		USERNAME       = "alex"
		OTHER_PASSWORD = "321password"
		OTHER_USERNAME = "sam"
	)
	var (
		quit    = make(chan bool)
		atsDone = make(chan bool)
		// sessionToken [16]byte = [16]byte{}
		// adminToken   [16]byte = [16]byte{}
		// aesKey       []byte
	)
	log.SetOutput(io.Discard)
	_, w, _ := os.Pipe()
	os.Stdout = w
	_, db, err := serverEngine.Startup(":memory:", PORT, quit, atsDone)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := http.Server{Addr: PORT}
	go func() {
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	}()
	time.Sleep(10 * time.Millisecond)

	// Tests go here.
	{
		t.Run("VerifyURL", func(t *testing.T) {
			_, err = clientEngine.VerifyURL(URL)
			if err != nil {
				t.Error(err)
			}
		})
		t.Run("RegisterAccount", func(t *testing.T) {
			err := clientEngine.RegistrationHelper(PASSWORD, USERNAME, URL)
			if err != nil {
				t.Error(err)
			}
		})
		t.Run("RegisterAccountUsernameTaken", func(t *testing.T) {
			err := clientEngine.RegistrationHelper(PASSWORD, USERNAME, URL)
			if !errors.Is(err, clientEngine.ErrUsernameTaken) {
				t.Error("Expected a username conflict: Did not receive a username conflict error.")
			}
		})
		t.Run("Authenticate", func(t *testing.T) {
			_, _, _, err := clientEngine.AuthenticationHelper(URL, USERNAME, PASSWORD)
			if err != nil {
				t.Error(err)
			}
		})
		t.Run("AuthenticateInvalidUsername", func(t *testing.T) {
			_, _, _, err := clientEngine.AuthenticationHelper(URL, OTHER_USERNAME, PASSWORD)
			if !errors.Is(err, clientEngine.ErrUsernameNotFound) {
				t.Error("Expected an error for an invalid username: Did not receive an invalid username error.")
			}
		})
		t.Run("AuthenticateBadPassword", func(t *testing.T) {
			_, _, _, err := clientEngine.AuthenticationHelper(URL, USERNAME, OTHER_PASSWORD)
			if !errors.Is(err, clientEngine.ErrBadPassword) {
				t.Error("Expected an error for a bad passsword: Did not receive an bad password error.")
			}
		})
	}
	// End Tests.

	server.Shutdown(context.Background())
	quit <- true
	<-atsDone
}
