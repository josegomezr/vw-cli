package main

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
)

// TODO: split this into separate files & packages
type KDFType int

const (
	// Symmetric encryption types
	KDF_Type_UNKNOWN       KDFType = -1
	KDF_Type_PBKDF2_SHA256 KDFType = 0
	KDF_Type_Argon2id              = 1
)

func deriveDecryptionKeyFromEmailPassword(email, password string) ([]byte, error) {
	// TODO: prolly make it accept the master key instead of the email/pw pair
	payload, _ := deriveMasterKeyFromEmailPassword(email, password)
	enc, _ := hkdf.Expand(sha256.New, payload, "enc", 32)
	return enc, nil
}

func deriveMasterKeyFromEmailPassword(email, password string) ([]byte, error) {
	salt := []byte(email)
	payload := password
	return pbkdf2.Key(sha256.New, string(payload), salt, 600_000, 32)
}
