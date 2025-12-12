package symmetric_key

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func AES_GCM_256_encrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Cipher error: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, iv, data, nil)

	return ciphertext, nil
}

func RandomIV() []byte {
	iv := make([]byte, 12)
	rand.Read(iv)
	return iv
}
