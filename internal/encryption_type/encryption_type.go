package encryption_type

type EncryptionType int

const (
	// Symmetric encryption types
	UNKNOWN         EncryptionType = -1
	AES_CBC_256_B64 EncryptionType = 0
	// Type 1 was the unused and removed AesCbc128_HMAC_SHA_256_B64
	AES_CBC_256_HMAC_SHA_256_B64 = 2
	// Asymmetric encryption types. These never occur in the same places that the symmetric ones would
	// and can be split out into a separate enum.
	RSA2048_OAEP_SHA_256_B64              = 3
	RSA2048_OAEP_SHA_1_B64                = 4
	RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64 = 5
	RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64   = 6
	// // Cose is the encoding for the key used but contained can be:
	// // - XChaCha20Poly1305
	COSE_ENCRYPT_0  = 7
	AES_GCM_256_B64 = 700
)

var knownEnctypes map[string]EncryptionType = map[string]EncryptionType{
	"0":   AES_CBC_256_B64,
	"2":   AES_CBC_256_HMAC_SHA_256_B64,
	"3":   RSA2048_OAEP_SHA_256_B64,
	"4":   RSA2048_OAEP_SHA_1_B64,
	"5":   RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64,
	"6":   RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64,
	"7":   COSE_ENCRYPT_0,
	"700": AES_GCM_256_B64,
}

var NUM_PARTS map[EncryptionType]int = map[EncryptionType]int{
	AES_CBC_256_B64:                       2, // IV|CIPHER
	AES_CBC_256_HMAC_SHA_256_B64:          3, // IV|CIPHER|HMAC
	RSA2048_OAEP_SHA_256_B64:              1, // CIPHER
	RSA2048_OAEP_SHA_1_B64:                1, // CIPHER
	RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64: 2, // CIPHER|HMAC
	RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64:   2, // CIPHER|HMAC
	COSE_ENCRYPT_0:                        1, // CIPHER
	AES_GCM_256_B64:                       2, // IV|CIPHER
}

func FromString(kind string) EncryptionType {
	value, ok := knownEnctypes[kind]
	if ok {
		return value
	}
	return UNKNOWN
}
