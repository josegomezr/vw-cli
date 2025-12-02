package symmetric_key

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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
