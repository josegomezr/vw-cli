package crypto

import (
	"encoding/json"
	"fmt"
	"github.com/josegomezr/vw-cli/internal/encryption_type"
	"github.com/josegomezr/vw-cli/internal/interfaces"
	"strings"
)

type encString struct {
	data    []byte
	iv      []byte
	mac     []byte
	enctype encryption_type.EncryptionType
}

func (es *encString) Data() []byte {
	return es.data
}

func (es *encString) String() string {
	b := fmt.Sprintf("%d", es.enctype) + "." + B64e(es.iv) + "|" + B64e(es.data)
	return b
}

func (es *encString) IV() []byte {
	return es.iv
}

func (es *encString) MAC() []byte {
	return es.mac
}

func (es *encString) Type() encryption_type.EncryptionType {
	return es.enctype
}

func (a *encString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	r, err := NewEncStringFrom(s)
	if err != nil {
		return err
	}
	switch r.(type) {
	case *encString:
		a.data = r.Data()
		a.iv = r.IV()
		a.enctype = r.Type()
		return nil
	default:
		return nil
	}
}
func (a *encString) Decrypt(key interfaces.SymmetricKey) ([]byte, error) {
	if a.Type() != key.Type() {
		return nil, fmt.Errorf("unmatched key types")
	}
	return key.Decrypt(a)
}

func NewEncryptedString(data, iv, mac []byte, enctype encryption_type.EncryptionType) interfaces.EncryptedString {
	return &encString{
		data:    data,
		iv:      iv,
		mac:     mac,
		enctype: enctype,
	}
}

func NewEncStringFrom(rawkeycontent string) (interfaces.EncryptedString, error) {
	// TODO: Handle more errors gracefully. Still not fully convinced on the
	// design of this fn but it works for now
	keyAndContentPieces := strings.SplitN(rawkeycontent, ".", 2)
	var encType encryption_type.EncryptionType = encryption_type.UNKNOWN

	pieceCount := len(keyAndContentPieces)
	var keycontent string
	if pieceCount < 2 {
		encType = encryption_type.AES_CBC_256_B64
		keycontent = keyAndContentPieces[0]
	} else {
		encType = encryption_type.FromString(keyAndContentPieces[0])
		keycontent = keyAndContentPieces[1]
		switch encType {
		case encryption_type.AES_CBC_256_B64:
			fallthrough
		case encryption_type.AES_CBC_256_HMAC_SHA_256_B64:
			fallthrough
		// case encryption_type.RSA2048_OAEP_SHA_256_B64:
		// 	fallthrough
		case encryption_type.RSA2048_OAEP_SHA_1_B64:
			fallthrough
		case encryption_type.AES_GCM_256_B64:
			// no op
		// case encryption_type.RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64:
		// 	fallthrough
		// case encryption_type.RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64:
		// 	fallthrough
		// case encryption_type.COSE_ENCRYPT_0:
		//	// no op
		case encryption_type.UNKNOWN:
			fallthrough
		default:
			return nil, fmt.Errorf("Unknown key type: %v", encType)
		}
	}

	expectedKeyParts, ok := encryption_type.NUM_PARTS[encType]

	if !ok {
		return nil, fmt.Errorf("Unknown key fragments expectation: %v", encType)
	}

	keypieces := strings.Split(keycontent, "|")
	totalkeypieces := len(keypieces)

	if expectedKeyParts != totalkeypieces {
		return nil, fmt.Errorf("Keytype %v does not have required pieces", encType)
	}

	switch encType {
	// case encryption_type.AES_CBC_256_B64:
	//   iv = keypieces[0]
	//   data = keypieces[1]
	case encryption_type.AES_CBC_256_HMAC_SHA_256_B64:
		iv, err := B64d(keypieces[0])
		if err != nil {
			return nil, err
		}
		data, err := B64d(keypieces[1])
		if err != nil {
			return nil, err
		}
		mac, err := B64d(keypieces[2])
		if err != nil {
			return nil, err
		}
		return NewEncryptedString(data, iv, mac, encType), nil

		// mac := keypieces[2]
		// parse_AES_CBC_256_HMAC_SHA_256_B64(iv, data, mac)
	// case encryption_type.RSA2048_OAEP_SHA_256_B64:
	//   fallthrough
	case encryption_type.RSA2048_OAEP_SHA_1_B64:

		data, err := B64d(keypieces[0])
		if err != nil {
			return nil, err
		}
		return NewEncryptedString(data, nil, nil, encType), nil
	// case encryption_type.STR_RSA2048_OAEP_SHA_256_HMAC_SHA_256_B64:
	//   fallthrough
	// case encryption_type.STR_RSA2048_OAEP_SHA_1_HMAC_SHA_256_B64:
	//   data := keypieces[0]
	//   mac := keypieces[1]
	case encryption_type.AES_GCM_256_B64:
		iv, err := B64d(keypieces[0])
		if err != nil {
			return nil, err
		}
		data, err := B64d(keypieces[1])
		if err != nil {
			return nil, err
		}
		return NewEncryptedString(data, iv, nil, encType), nil
	default:
		return nil, fmt.Errorf("I don't know how to handle: %v keys", encType)
	}
}
