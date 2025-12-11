package symmetric_key

import (
	"fmt"
	"github.com/josegomezr/vw-cli/internal/crypto"
)

type symmetricKey struct {
	encryption     []byte
	authentication []byte
	keytype        crypto.EncryptionType
}

type SymmetricKey interface {
	Encryption() []byte
	Authentication() []byte
	Type() crypto.EncryptionType
	Encrypt([]byte, crypto.EncryptionType) (crypto.EncString, error)
	Decrypt(crypto.EncString) ([]byte, error)
	DecryptString(crypto.EncString) (string, error)
}

func (sk *symmetricKey) Encryption() []byte {
	return sk.encryption
}
func (sk *symmetricKey) Authentication() []byte {
	return sk.authentication
}
func (sk *symmetricKey) Type() crypto.EncryptionType {
	return sk.keytype
}

func (sk *symmetricKey) Encrypt(data []byte, enctype crypto.EncryptionType) (crypto.EncString, error) {
	switch enctype {
	case crypto.ENC_TYPE_AES_GCM_256_B64:
		iv := RandomIV()
		encdata, err := AES_GCM_256_encrypt(sk.Encryption(), iv, data)
		if err != nil {
			return nil, err
		}
		return crypto.NewEncString(encdata, iv, nil, enctype), nil
		// case crypto.ENC_TYPE_RSA2048_OAEP_SHA_1_B64:
		// 	return RSA_2048_OAEP_SHA_1_decrypt(sk.Encryption(), encstr.Data())
	}

	return nil, fmt.Errorf("Don't know how to handle %v text", enctype)
}

func (sk *symmetricKey) Decrypt(encstr crypto.EncString) ([]byte, error) {
	switch encstr.Type() {
	case crypto.ENC_TYPE_AES_CBC_256_HMAC_SHA_256_B64:
		return AES_CBC_256_HMAC_decrypt(sk.Encryption(), sk.Authentication(), encstr.IV(), encstr.Data(), encstr.MAC())
	case crypto.ENC_TYPE_AES_GCM_256_B64:
		return AES_GCM_256_decrypt(sk.Encryption(), encstr.IV(), encstr.Data())
		// case crypto.ENC_TYPE_RSA2048_OAEP_SHA_1_B64:
		// 	return RSA_2048_OAEP_SHA_1_decrypt(sk.Encryption(), encstr.Data())
	}

	return nil, fmt.Errorf("Don't know how to handle %v text", encstr.Type())
}

func (sk *symmetricKey) DecryptString(encstr crypto.EncString) (string, error) {
	r, err := sk.Decrypt(encstr)
	return string(r), err
}

func NewSymmetricKey(buf []byte) (SymmetricKey, error) {
	l := len(buf)
	switch l {
	case 32:
		return &symmetricKey{
			keytype:        crypto.ENC_TYPE_AES_CBC_256_B64,
			encryption:     buf[0:32],
			authentication: nil,
		}, nil
	case 64:
		return &symmetricKey{
			keytype:        crypto.ENC_TYPE_AES_CBC_256_HMAC_SHA_256_B64,
			encryption:     buf[0:32],
			authentication: buf[32:64],
		}, nil
	default:
		// TODO: make this parametrizable from consumer
		return &symmetricKey{
			keytype:    crypto.ENC_TYPE_RSA2048_OAEP_SHA_1_B64,
			encryption: buf,
		}, nil
		// return nil, fmt.Errorf("Unknown symmetric key type with length=%d", l)
	}
}

func New_AES_256_GCM_Key(buf []byte) (SymmetricKey, error) {
	l := len(buf)
	switch l {
	case 32:
		return &symmetricKey{
			keytype:        crypto.ENC_TYPE_AES_GCM_256_B64,
			encryption:     buf[0:32],
			authentication: nil,
		}, nil
	default:
		return nil, fmt.Errorf("Invalid AES-256-GCM symmetric key with length=%d", l)
	}
}
