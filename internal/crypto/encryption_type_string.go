package crypto

type EncryptionTypeStr string

const (
	// Symmetric encryption types
	ENC_TYPE_STR_UNKNOWN         EncryptionTypeStr = "-1"
	ENC_TYPE_STR_AES_CBC_256_B64                   = "0"
	// Type 1 was the unused and removed AesCbc128_HMAC_SHA_256_B64
	ENC_TYPE_STR_AES_CBC_256_HMAC_SHA_256_B64 = "2"
	// Asymmetric encryption types. These never occur in the same places that the symmetric ones would
	// and can be split out into a separate enum.
	// ENC_TYPE_STR_RSA2048_OAEP_SHA_256_B64              = "3"
	ENC_TYPE_STR_RSA2048_OAEP_SHA_1_B64 = "4"
	// ENC_TYPE_STR_RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64 = "5"
	// ENC_TYPE_STR_RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64   = "6"
	// // Cose is the encoding for the key used but contained can be:
	// // - XChaCha20Poly1305
	// ENC_TYPE_STR_COSE_ENCRYPT_0 = "7"
)
