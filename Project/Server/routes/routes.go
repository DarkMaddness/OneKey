package routes

import (
	"Onekey/Server/session"
	"database/sql"
	"log/slog"
	"net/http"
	"sync"
)

type Route struct {
	Path    string
	Handler http.Handler
}

func LogRequest(r *http.Request) {
	slog.Info("incoming request",
		"method", r.Method,
		"path", r.URL.Path,
		"client", r.RemoteAddr,
	)
}

func Routes(db *sql.DB, ats *session.AdminTokenStorage) []Route {
	var inProgAuth sync.Map
	return []Route{
		{Path: "GET /ping", Handler: &ping{}},
		{Path: "GET /salt/{username}", Handler: &salt{DB: db}},
		{Path: "POST /register", Handler: &register{DB: db}},
		{Path: "POST /auth1", Handler: &auth1{DB: db, InProgAuth: &inProgAuth}},
		{Path: "POST /auth2", Handler: &auth2{DB: db, InProgAuth: &inProgAuth, ATS: ats}},
		{Path: "POST /logout", Handler: &logOut{DB: db, ATS: ats}},
		{Path: "POST /titles", Handler: &titles{DB: db}},
		{Path: "POST /entry", Handler: &entry{DB: db}},
		{Path: "POST /new_entry", Handler: &new_entry{DB: db, ATS: ats}},
	}
}
