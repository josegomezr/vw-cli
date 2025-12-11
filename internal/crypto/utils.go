package crypto

import (
	"encoding/base64"
)

func MustB64d(b string) []byte {
	decoded, err := B64d(b)
	if err != nil {
		panic(err)
	}
	return decoded
}

func B64d(b string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func B64e(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
