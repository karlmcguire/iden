package iden

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
)

type Iden []byte

func NewIden(data, key []byte) Iden {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return Iden(h.Sum(nil))
}

func (i Iden) Equal(iden Iden) bool {
	return hmac.Equal(i, iden)
}

func (i Iden) EqualString(iden string) bool {
	d, _ := hex.DecodeString(iden)
	return hmac.Equal(i, d)
}

func (i Iden) String() string {
	return hex.EncodeToString(i)
}
