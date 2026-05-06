package session

import (
	"crypto/subtle"
	"sync"
	"time"
)

// Used to store an admin token, it's paired session token, and it's expiry time.
type adminUnit struct {
	sessionToken [16]byte
	adminToken   [16]byte
	expiresAt    time.Time
}

// Used to manage admin tokens and is thread safe. ClearExpired should be called on a regular interval to keep memory usage down.
type AdminTokenStorage struct {
	lock  sync.RWMutex
	data  map[[16]byte]*adminUnit
	order []*adminUnit
}

// Returns a new AdminTokenStorage.
func NewAdminTokenStorage() *AdminTokenStorage {
	return &AdminTokenStorage{
		data:  make(map[[16]byte]*adminUnit),
		order: make([]*adminUnit, 0, 10),
	}
}

// Add a pair of tokens to the storage.
func (a *AdminTokenStorage) Add(sessionToken [16]byte, adminToken [16]byte) {
	a.lock.Lock()
	defer a.lock.Unlock()
	au := adminUnit{
		sessionToken: sessionToken,
		adminToken:   adminToken,
		expiresAt:    time.Now().Add(5 * time.Minute),
	}
	a.data[sessionToken] = &au
	a.order = append(a.order, &au)
}

// Remove admin token associated with session token. Note, this makes the admin token invalid for Check, but it will continue to occupy memory until it has expired and been cleared with ClearExpired.
func (a *AdminTokenStorage) Remove(sessionToken [16]byte) {
	a.lock.Lock()
	defer a.lock.Unlock()
	delete(a.data, sessionToken)
}

// Returns true if paired tokens are valid and the admin token hasn't expired yet. Returns false otherwise.
func (a *AdminTokenStorage) Check(sessionToken [16]byte, adminToken [16]byte) bool {
	a.lock.RLock()
	defer a.lock.RUnlock()
	au := a.data[sessionToken]
	if au == nil {
		return false
	}
	adminCompare := subtle.ConstantTimeCompare(au.adminToken[:], adminToken[:]) == 1
	expiry := au.expiresAt.After(time.Now())
	return (adminCompare && expiry) == true
}

// Clears expired tokens so their memory can be freed.
func (a *AdminTokenStorage) ClearExpired() {
	a.lock.Lock()
	defer a.lock.Unlock()
	index := 0
	now := time.Now()
	for index < len(a.order) && a.order[index].expiresAt.Before(now) {
		delete(a.data, a.order[index].sessionToken)
		a.order[index] = nil
		index++
	}
	a.order = a.order[index:]
}
