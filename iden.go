// Package iden implements secure identifiers. Idens are sent with requests,
// allowing the server to check if the request is authenticated with a
// specified key.
package iden

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
)

// Iden is a byte slice (with a length of 32 bytes).
type Iden []byte

// NewIden returns a new iden with the salt and key.
func NewIden(salt, key []byte) Iden {
	h := hmac.New(sha512.New, key)
	h.Write(salt)
	return Iden(h.Sum(nil))
}

// Equal checks if an iden is equal to the param iden.
func (i Iden) Equal(iden Iden) bool {
	return hmac.Equal(i, iden)
}

// EqualString checks if an iden is equal to the param iden (in string form).
func (i Iden) EqualString(iden string) bool {
	d, _ := hex.DecodeString(iden)
	return hmac.Equal(i, d)
}

// String returns the iden in a hex-encoded format.
func (i Iden) String() string {
	return hex.EncodeToString(i)
}
