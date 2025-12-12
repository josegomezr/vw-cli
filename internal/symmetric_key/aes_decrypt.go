package symmetric_key

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func AES_CBC_256_decrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Cipher error: %w", err)
	}
	ciphertext := bytes.Clone(data)

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// TODO: find out how to detect when this doesn't really decrypt.
	clen := len(ciphertext)
	pd := aes.BlockSize - len(ciphertext)%aes.BlockSize

	// TODO: this gets weird when it's not really decrypted
	// S.O. says this is impossible to detect :c
	if pd > 0 {
		offset := int(ciphertext[clen-1])
		if offset < clen {
			ciphertext = ciphertext[:clen-offset]
		}
	}
	return ciphertext, nil
}

func AES_CBC_256_HMAC_decrypt(key, hmacKey, iv, data, mac []byte) ([]byte, error) {
	if !validMAC(iv, data, mac, hmacKey) {
		return nil, fmt.Errorf("Invalid HMAC")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Cipher error: %w", err)
	}
	ciphertext := bytes.Clone(data)

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	clen := len(ciphertext)
	pd := aes.BlockSize - len(ciphertext)%aes.BlockSize

	if pd > 0 {
		offset := int(ciphertext[clen-1])
		if offset < clen {
			ciphertext = ciphertext[:clen-offset]
		}
	}
	return ciphertext, nil
}

func validMAC(iv, data, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(iv)
	mac.Write(data)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

// GCM has authenticated messages, so no need for HMACs
func AES_GCM_256_decrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Cipher error: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext, err := gcm.Open(nil, iv, data, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}
