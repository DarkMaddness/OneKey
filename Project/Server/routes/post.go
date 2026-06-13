package routes

import (
	"Onekey/Server/session"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/1Password/srp"
)

type register struct {
	DB *sql.DB
}

func (handler *register) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	body := struct {
		Username string
		Salt     []byte
		Verifier *big.Int
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_, err = handler.DB.Exec("INSERT INTO users (username, salt, verifier) VALUES (?, ?, ?)", body.Username, body.Salt, body.Verifier.Bytes())
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

type auth1 struct {
	DB         *sql.DB
	InProgAuth *sync.Map
}

func (handler *auth1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	body := struct {
		Username string
		A        *big.Int
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id := 0
	salt := make([]byte, 0)
	verifierBytes := make([]byte, 0)
	err = handler.DB.QueryRow("SELECT id, salt, verifier FROM users WHERE username = ?", body.Username).Scan(&id, &salt, &verifierBytes)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	verifier := big.NewInt(0).SetBytes(verifierBytes)
	srpServer := srp.NewSRPServer(srp.KnownGroups[srp.RFC5054Group4096], verifier, nil)
	err = srpServer.SetOthersPublic(body.A)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_, err = srpServer.Key()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	b := srpServer.EphemeralPublic()
	m2, err := srpServer.M(salt, body.Username)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	authIDBytes := make([]byte, 16)
	rand.Read(authIDBytes)
	authID := hex.EncodeToString(authIDBytes)
	res, _ := json.Marshal(struct {
		B      *big.Int
		M2     []byte
		AuthID string
	}{
		B:      b,
		M2:     m2,
		AuthID: authID,
	})
	handler.InProgAuth.Store(authID, struct {
		ID  int
		SRP *srp.SRP
	}{
		ID:  id,
		SRP: srpServer,
	})
	time.AfterFunc(30*time.Second, func() { handler.InProgAuth.Delete(authID) })
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

type auth2 struct {
	DB         *sql.DB
	InProgAuth *sync.Map
	ATS        *session.AdminTokenStorage
}

func (handler *auth2) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	body := struct {
		M1     []byte
		AuthID string
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	value, present := handler.InProgAuth.LoadAndDelete(body.AuthID)
	if !present {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	state, ok := value.(struct {
		ID  int
		SRP *srp.SRP
	})
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !state.SRP.GoodClientProof(body.M1) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := make([]byte, 16)
	rand.Read(sessionToken)
	adminToken := make([]byte, 16)
	rand.Read(adminToken)
	_, err = handler.DB.Exec("INSERT INTO sessions (userID, token, expires_at) VALUES (?, ?, ?)", state.ID, sessionToken, time.Now().Add(24*time.Hour).Unix())
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	handler.ATS.Add([16]byte(sessionToken), [16]byte(adminToken))
	res, _ := json.Marshal(struct {
		SessionToken []byte
		AdminToken   []byte
	}{
		SessionToken: sessionToken,
		AdminToken:   adminToken,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

type logOut struct {
	DB  *sql.DB
	ATS *session.AdminTokenStorage
}

func (handler *logOut) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	body := struct {
		SessionToken [16]byte
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	handler.ATS.Remove(body.SessionToken)
	_, err = handler.DB.Exec("DELETE from sessions WHERE token = ?", body.SessionToken)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
