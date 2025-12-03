package symmetric_key

// TODO: Figure out how this actually works so organization keys can be used
import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

func RSA_2048_OAEP_SHA_1_decrypt(key, data []byte) ([]byte, error) {
	priv, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	privkey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("no privkey")
	}

	ciphertext := bytes.Clone(data)
	return rsa.DecryptOAEP(sha1.New(), nil, privkey, ciphertext, nil)
}

func RSA_2048_OAEP_SHA_256_decrypt(key, data []byte) ([]byte, error) {
	priv, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	privkey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("no privkey")
	}

	ciphertext := bytes.Clone(data)
	return rsa.DecryptOAEP(sha256.New(), nil, privkey, ciphertext, nil)
}
