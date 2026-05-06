package main

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/1Password/srp"
)

func TestSRP(t *testing.T) {
	// Set group.
	group := srp.KnownGroups[srp.RFC5054Group4096]

	// Client: Get username and password from user. Send username to server.
	username := "Smith"
	password := "Password"

	// Server: Get user by username and grab salt. Send salt to client.
	salt := []byte{0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x09, 0x98, 0x87, 0x76, 0x65, 0x54, 0x43}

	// Client: Derive secret x and setup SRP instance. Send A to server.
	h := sha256.New()
	h.Write([]byte(password))
	h.Write(salt)
	hash := h.Sum(nil)
	x := new(big.Int).SetBytes(hash)
	client := srp.NewSRPClient(group, x, nil)
	a := client.EphemeralPublic()

	// Server: Setup SRP instance, set and verify A, and derive server proof. Send B and server proof to the client.
	v, _ := client.Verifier()
	server := srp.NewSRPServer(group, v, nil)
	err := server.SetOthersPublic(a)
	if err != nil {
		t.Error(err)
	}
	_, err = server.Key()
	if err != nil {
		t.Error(err)
	}
	m2, err := server.M(salt, username)
	if err != nil {
		t.Error(err)
	}
	b := server.EphemeralPublic()

	// Client: Set and verify B, and derive client proof. Send client proof to the server.
	err = client.SetOthersPublic(b)
	if err != nil {
		t.Error(err)
	}
	_, err = client.Key()
	if err != nil {
		t.Error(err)
	}
	if !client.GoodServerProof(salt, username, m2) {
		t.Error("Server proof is bad.")
	}
	m1, err := client.ClientProof()
	if err != nil {
		t.Error(err)
	}

	// Server: Verify client proof. Send session/admin tokens to client.
	if !server.GoodClientProof(m1) {
		t.Error("Client proof is bad.")
	}

	// Client: Accept tokens.
}
