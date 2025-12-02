package symmetric_key

// TODO: Figure out how this actually works so organization keys can be used
import (
	// "fmt"
	"bytes"
	// "crypto/cipher"
	// "crypto/rsa"
)

func RSA_2048_OAEP_SHA_1_decrypt(key, data []byte) ([]byte, error) {
	ciphertext := bytes.Clone(data)
	// rsa.DecryptOAEP(sha256.New(), nil, key, ciphertext, label)

	return ciphertext, nil
}
