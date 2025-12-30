package main

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
	"github.com/josegomezr/vw-cli/internal/encryption_type"
	"github.com/josegomezr/vw-cli/internal/symmetric_key"
)

// TODO: implement support for Argon2id
//       that probably means interfacing this and isolating implementations for
//       Argon2id/PBKDF2 in separate structs

// type KDFType int
// const (
// 	KDF_Type_UNKNOWN       KDFType = -1
// 	KDF_Type_PBKDF2_SHA256 KDFType = 0
// 	KDF_Type_Argon2id              = 1
// )

// Expands the master key into it's Encryption + Auhentication key
func expandMasterKey(masterKeyBuf []byte) ([]byte, error) {
	enc, err := hkdf.Expand(sha256.New, masterKeyBuf, "enc", 32)
	if err != nil {
		return nil, err
	}
	auth, err := hkdf.Expand(sha256.New, masterKeyBuf, "mac", 32)
	if err != nil {
		return nil, err
	}
	ret := []byte{}
	ret = append(ret, enc...)
	ret = append(ret, auth...)
	return ret, nil
}

// Derives master key out of email / password combination
func deriveMasterKeyFromEmailPassword(email, password string) ([]byte, error) {
	salt := []byte(email)
	payload := password
	return pbkdf2.Key(sha256.New, payload, salt, 600_000, 32)
}

// Derives master encryption+mac symmetric key out of email / password.
func deriveDecryptionKeyFromEmailPassword(email, password string) (symmetric_key.SymmetricKey, error) {
	payload, err := deriveMasterKeyFromEmailPassword(email, password)
	if err != nil {
		return nil, err
	}

	ret, err := expandMasterKey(payload)
	if err != nil {
		return nil, err
	}

	return symmetric_key.NewSymmetricKeyCtor(ret, encryption_type.AES_CBC_256_HMAC_SHA_256_B64)
}

// Generates email/password hash for authentication
func hashEmailPassword(email, password string) ([]byte, error) {
	key, err := deriveMasterKeyFromEmailPassword(email, password)
	if err != nil {
		return nil, err
	}
	salt := []byte(password)
	payload := string(key)
	return pbkdf2.Key(sha256.New, payload, salt, 1, 32)
}
