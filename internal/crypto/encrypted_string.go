package crypto

import (
	"encoding/json"
	"fmt"
	"strings"
)

type EncString interface {
	Data() []byte
	IV() []byte
	MAC() []byte
	Type() EncryptionType
	String() string
}

type EncryptedString struct {
	data    []byte
	iv      []byte
	mac     []byte
	enctype EncryptionType
}

func (es *EncryptedString) Data() []byte {
	return es.data
}

func (es *EncryptedString) String() string {
	b := B64e(es.iv) + "|" + B64e(es.data)
	return b
}

func (es *EncryptedString) IV() []byte {
	return es.iv
}

func (es *EncryptedString) MAC() []byte {
	return es.mac
}

func (es *EncryptedString) Type() EncryptionType {
	return es.enctype
}

func (a *EncryptedString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	r, err := NewEncStringFrom(s)
	if err != nil {
		return err
	}
	switch r.(type) {
	case *EncryptedString:
		a.data = r.Data()
		a.iv = r.IV()
		a.enctype = r.Type()
		return nil
	default:
		return nil
	}

}

func NewEncString(data, iv, mac []byte, enctype EncryptionType) EncString {
	return &EncryptedString{
		data:    data,
		iv:      iv,
		mac:     mac,
		enctype: enctype,
	}
}

func NewEncStringFrom(rawkeycontent string) (EncString, error) {
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

		case ENC_TYPE_STR_RSA2048_OAEP_SHA_1_B64:
			encType = ENC_TYPE_RSA2048_OAEP_SHA_1_B64

		// case ENC_TYPE_STR_RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64:
		// 	encType = ENC_TYPE_RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64

		// case ENC_TYPE_STR_RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64:
		// 	encType = ENC_TYPE_RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64

		// case ENC_TYPE_STR_COSE_ENCRYPT_0:
		// 	encType = ENC_TYPE_COSE_ENCRYPT_0
		default:
			return nil, fmt.Errorf("Unknown key type: %v", ktype)
		}
	}

	expectedKeyParts, ok := EXPECTED_NUM_PARTS_BY_ENCRYPTION_TYPE[encType]

	if !ok {
		return nil, fmt.Errorf("Unknown key fragments expectation: %v", encType)
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
		iv := MustB64d(keypieces[0])
		data := MustB64d(keypieces[1])
		mac := MustB64d(keypieces[2])
		return NewEncString(data, iv, mac, encType), nil

		// mac := keypieces[2]
		// parse_AES_CBC_256_HMAC_SHA_256_B64(iv, data, mac)
	// case ENC_TYPE_RSA2048_OAEP_SHA_256_B64:
	//   fallthrough
	case ENC_TYPE_RSA2048_OAEP_SHA_1_B64:

		data := MustB64d(keypieces[0])
		return NewEncString(data, nil, nil, encType), nil
	// case ENC_TYPE_STR_RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64:
	//   fallthrough
	// case ENC_TYPE_STR_RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64:
	//   data := keypieces[0]
	//   mac := keypieces[1]
	default:
		return nil, fmt.Errorf("I don't know how to handle: %v keys", encType)
	}

	return &EncryptedString{}, nil
}
