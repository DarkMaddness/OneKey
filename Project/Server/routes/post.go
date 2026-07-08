package routes

import (
	"Onekey/Server/session"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	_, err = handler.DB.Exec("DELETE FROM sessions WHERE token = ?", body.SessionToken)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type titles struct {
	DB *sql.DB
}

func (handler *titles) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type Title struct {
		ID    int
		Title []byte
	}
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
	id := 0
	err = handler.DB.QueryRow("SELECT id FROM sessions WHERE token = ?", body.SessionToken[:]).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Println("Request made with unknown token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	rows, err := handler.DB.Query("SELECT entries.id, title FROM entries JOIN sessions ON entries.userID = sessions.userID WHERE token = ?", body.SessionToken[:])
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer rows.Close()
	var titles []Title
	for rows.Next() {
		var title Title
		err = rows.Scan(&title.ID, &title.Title)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		titles = append(titles, title)
	}
	if err = rows.Err(); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	res, _ := json.Marshal(titles)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

type entry struct {
	DB *sql.DB
}

func (handler *entry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	body := struct {
		SessionToken [16]byte
		EntryID      int
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id := 0
	err = handler.DB.QueryRow("SELECT id FROM sessions WHERE token = ?", body.SessionToken[:]).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Println("Request made with unknown token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	title := []byte{}
	data := []byte{}
	err = handler.DB.QueryRow("SELECT title, data FROM entries JOIN sessions ON entries.userID = sessions.userID WHERE token = ? AND entries.id = ?", body.SessionToken[:], body.EntryID).Scan(&title, &data)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound)
			return
		} else {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	res, _ := json.Marshal(struct {
		Title []byte
		Data  []byte
	}{
		Title: title,
		Data:  data,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

type new_entry struct {
	DB  *sql.DB
	ATS *session.AdminTokenStorage
}

func (handler *new_entry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	body := struct {
		SessionToken [16]byte
		AdminToken   [16]byte
		Title        []byte
		Data         []byte
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id := 0
	err = handler.DB.QueryRow("SELECT userID FROM sessions WHERE token = ?", body.SessionToken[:]).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Println("Request made with unknown token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	if !handler.ATS.Check(body.SessionToken, body.AdminToken) {
		log.Println("Invalid admin token used.")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	_, err = handler.DB.Exec("INSERT INTO entries (userID, title, data) VALUES (?, ?, ?)", id, body.Title, body.Data)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}
