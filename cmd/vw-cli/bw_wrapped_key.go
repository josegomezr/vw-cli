package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// TODO: split this into separate files & packages
type KDFType int

const (
	// Symmetric encryption types
	KDF_Type_UNKNOWN       KDFType = -1
	KDF_Type_PBKDF2_SHA256 KDFType = 0
	KDF_Type_Argon2id              = 1
)

// TODO: split this into separate files & packages
type EncryptionTypeStr string

const (
	// Symmetric encryption types
	ENC_TYPE_STR_UNKNOWN         EncryptionTypeStr = "-1"
	ENC_TYPE_STR_AES_CBC_256_B64 EncryptionTypeStr = "0"
	// Type 1 was the unused and removed AesCbc128_HMAC_SHA_256_B64
	ENC_TYPE_STR_AES_CBC_256_HMAC_SHA_256_B64 = "2"
	// Asymmetric encryption types. These never occur in the same places that the symmetric ones would
	// and can be split out into a separate enum.
	// ENC_TYPE_STR_RSA2048_OAEP_SHA_256_B64              = "3"
	// ENC_TYPE_STR_RSA2048_OAEP_SHA_1_B64                = "4"
	// ENC_TYPE_STR_RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64 = "5"
	// ENC_TYPE_STR_RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64   = "6"
	// // Cose is the encoding for the key used but contained can be:
	// // - XChaCha20Poly1305
	// ENC_TYPE_STR_COSE_ENCRYPT_0 = "7"
)

// TODO: split this into separate files & packages
type EncryptionType int

const (
	// Symmetric encryption types
	ENC_TYPE_UNKNOWN         EncryptionType = -1
	ENC_TYPE_AES_CBC_256_B64 EncryptionType = 0
	// Type 1 was the unused and removed AesCbc128_HMAC_SHA_256_B64
	ENC_TYPE_AES_CBC_256_HMAC_SHA_256_B64 = 2
	// Asymmetric encryption types. These never occur in the same places that the symmetric ones would
	// and can be split out into a separate enum.
	// ENC_TYPE_RSA2048_OAEP_SHA_256_B64              = 3
	// ENC_TYPE_RSA2048_OAEP_SHA_1_B64                = 4
	// ENC_TYPE_RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64 = 5
	// ENC_TYPE_RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64   = 6
	// // Cose is the encoding for the key used but contained can be:
	// // - XChaCha20Poly1305
	// ENC_TYPE_COSE_ENCRYPT_0 = 7
)

var EXPECTED_NUM_PARTS_BY_ENCRYPTION_TYPE map[EncryptionType]int = map[EncryptionType]int{
	ENC_TYPE_AES_CBC_256_B64:              2,
	ENC_TYPE_AES_CBC_256_HMAC_SHA_256_B64: 3,
	// ENC_TYPE_RSA2048_OAEP_SHA_256_B64:              1,
	// ENC_TYPE_RSA2048_OAEP_SHA_1_B64:                1,
	// ENC_TYPE_RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64: 2,
	// ENC_TYPE_RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64:   2,
	// ENC_TYPE_COSE_ENCRYPT_0:                        1,
}

type EncryptedString interface {
	Data() []byte
	IV() []byte
	Type() EncryptionType
}

type encryptedString struct {
	data    []byte
	iv      []byte
	enctype EncryptionType
}

func (es *encryptedString) Data() []byte {
	return es.data
}
func (es *encryptedString) IV() []byte {
	return es.iv
}
func (es *encryptedString) Type() EncryptionType {
	return es.enctype
}

type symmetricKey struct {
	encryption     []byte
	authentication []byte
	keytype        EncryptionType
}

type SymmetricKey interface {
	Encryption() []byte
	Authentication() []byte
	Type() EncryptionType
}

func (sk *symmetricKey) Encryption() []byte {
	return sk.encryption
}
func (sk *symmetricKey) Authentication() []byte {
	return sk.authentication
}
func (sk *symmetricKey) Type() EncryptionType {
	return sk.keytype
}

func NewSymmetricKey(buf []byte) (SymmetricKey, error) {
	switch len(buf) {
	case 64:
		return &symmetricKey{
			keytype:        ENC_TYPE_AES_CBC_256_HMAC_SHA_256_B64,
			encryption:     buf[0:32],
			authentication: buf[32:64],
		}, nil
	default:
		return nil, fmt.Errorf("Unknown symmetric key type")
	}
}

func ParseEncryptedString(rawkeycontent string) (EncryptedString, error) {
	// TODO: Handle more errors gracefully. Still not fully convinced on the
	// design of this fn but it works for now
	keyAndContentPieces := strings.SplitN(rawkeycontent, ".", 2)
	var encType EncryptionType = ENC_TYPE_UNKNOWN

	pieceCount := len(keyAndContentPieces)
	var keycontent string

	if pieceCount < 2 {
		encType = ENC_TYPE_AES_CBC_256_B64
		keycontent = keyAndContentPieces[0]
	} else {
		ktype := keyAndContentPieces[0]
		keycontent = keyAndContentPieces[1]
		switch EncryptionTypeStr(ktype) {
		// case ENC_TYPE_STR_UNKNOWN:
		// 	encType = ENC_TYPE_UNKNOWN

		case ENC_TYPE_STR_AES_CBC_256_B64:
			encType = ENC_TYPE_AES_CBC_256_B64

		case ENC_TYPE_STR_AES_CBC_256_HMAC_SHA_256_B64:
			encType = ENC_TYPE_AES_CBC_256_HMAC_SHA_256_B64

		// case ENC_TYPE_STR_RSA2048_OAEP_SHA_256_B64:
		// 	encType = ENC_TYPE_RSA2048_OAEP_SHA_256_B64

		// case ENC_TYPE_STR_RSA2048_OAEP_SHA_1_B64:
		// 	encType = ENC_TYPE_RSA2048_OAEP_SHA_1_B64

		// case ENC_TYPE_STR_RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64:
		// 	encType = ENC_TYPE_RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64

		// case ENC_TYPE_STR_RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64:
		// 	encType = ENC_TYPE_RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64

		// case ENC_TYPE_STR_COSE_ENCRYPT_0:
		// 	encType = ENC_TYPE_COSE_ENCRYPT_0
		default:
			return nil, fmt.Errorf("Unknown key type: %s", ktype)
		}
	}

	expectedKeyParts, ok := EXPECTED_NUM_PARTS_BY_ENCRYPTION_TYPE[encType]

	if !ok {
		return nil, fmt.Errorf("Unknown key fragments expectation: %s", encType)
	}

	keypieces := strings.Split(keycontent, "|")
	totalkeypieces := len(keypieces)

	if expectedKeyParts != totalkeypieces {
		return nil, fmt.Errorf("Keytype %v does not have required pieces", encType)
	}

	switch encType {
	// case ENC_TYPE_STR_AES_CBC_256_B64:
	//   iv = keypieces[0]
	//   data = keypieces[1]
	case ENC_TYPE_AES_CBC_256_HMAC_SHA_256_B64:
		iv := B64d(keypieces[0])
		data := B64d(keypieces[1])
		// mac := keypieces[2]
		return &encryptedString{
			data:    data,
			iv:      iv,
			enctype: encType,
		}, nil
		// parse_AES_CBC_256_HMAC_SHA_256_B64(iv, data, mac)
	// case ENC_TYPE_RSA2048_OAEP_SHA_256_B64:
	//   fallthrough
	// case ENC_TYPE_RSA2048_OAEP_SHA_1_B64:
	//   data := keypieces[0]
	// case ENC_TYPE_STR_RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64:
	//   fallthrough
	// case ENC_TYPE_STR_RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64:
	//   data := keypieces[0]
	//   mac := keypieces[1]
	default:
		return nil, fmt.Errorf("I don't know how to handle: %v keys", encType)
	}

	return &encryptedString{}, nil
}

func B64d(b string) []byte {
	// TODO: Handle errors gracefully
	decoded, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		panic(err)
	}
	return decoded
}

func AES_CBC_256_decrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Cipher error: %w", err)
	}
	ciphertext := data
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// TODO: find out how to detect when this doesn't really decrypt.
	clen := len(ciphertext)
	pd := aes.BlockSize - len(ciphertext)%aes.BlockSize

	// TODO: this gets weird when it's not really decrypted
	if pd > 0 {
		ciphertext = ciphertext[:clen-int(ciphertext[clen-1])]
	}
	return ciphertext, nil
}

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
