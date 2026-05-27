package routes

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

type ping struct{}

func (handler *ping) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	res, _ := json.Marshal(struct {
		Name    string
		Version string
	}{
		Name:    "Onekey",
		Version: "Alpha",
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

type salt struct {
	DB *sql.DB
}

func (handler *salt) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	LogRequest(r)
	salt := make([]byte, 0)
	err := handler.DB.QueryRow("SELECT salt FROM users WHERE username = ?", r.PathValue("username")).Scan(&salt)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	res, _ := json.Marshal(struct {
		Salt []byte
	}{
		Salt: salt,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}
