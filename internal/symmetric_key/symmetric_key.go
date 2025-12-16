package symmetric_key

import (
	"fmt"
	"github.com/josegomezr/vw-cli/internal/crypto"
	"github.com/josegomezr/vw-cli/internal/encryption_type"
	"github.com/josegomezr/vw-cli/internal/interfaces"
)

type symmetricKey struct {
	encryption     []byte
	authentication []byte
	keytype        encryption_type.EncryptionType
}

type SymmetricKey interface {
	Buffer() []byte
	Encryption() []byte
	Authentication() []byte
	Type() encryption_type.EncryptionType
	Encrypt([]byte, encryption_type.EncryptionType) (interfaces.EncryptedString, error)
	Decrypt(interfaces.EncryptedString) ([]byte, error)
	DecryptString(interfaces.EncryptedString) (string, error)
}

func (sk *symmetricKey) Buffer() []byte {
	buf := []byte{}
	buf = append(buf, sk.Encryption()...)
	if auth := sk.Authentication(); auth != nil {
		buf = append(buf, auth...)
	}
	return buf
}
func (sk *symmetricKey) Encryption() []byte {
	return sk.encryption
}
func (sk *symmetricKey) Authentication() []byte {
	return sk.authentication
}
func (sk *symmetricKey) Type() encryption_type.EncryptionType {
	return sk.keytype
}

func (sk *symmetricKey) Encrypt(data []byte, enctype encryption_type.EncryptionType) (interfaces.EncryptedString, error) {
	switch enctype {
	case encryption_type.AES_GCM_256_B64:
		iv := RandomIV()
		encdata, err := AES_GCM_256_encrypt(sk.Encryption(), iv, data)
		if err != nil {
			return nil, err
		}
		return crypto.NewEncryptedString(encdata, iv, nil, enctype), nil
	case encryption_type.RSA2048_OAEP_SHA_1_B64:
		encdata, err := RSA_2048_OAEP_SHA_1_decrypt(sk.Encryption(), data)
		if err != nil {
			return nil, err
		}
		return crypto.NewEncryptedString(encdata, nil, nil, enctype), nil
	}

	return nil, fmt.Errorf("Don't know how to handle %v text", enctype)
}

func (sk *symmetricKey) Decrypt(encstr interfaces.EncryptedString) ([]byte, error) {
	switch encstr.Type() {
	case encryption_type.AES_CBC_256_HMAC_SHA_256_B64:
		return AES_CBC_256_HMAC_decrypt(sk.Encryption(), sk.Authentication(), encstr.IV(), encstr.Data(), encstr.MAC())
	case encryption_type.AES_GCM_256_B64:
		return AES_GCM_256_decrypt(sk.Encryption(), encstr.IV(), encstr.Data())
	case encryption_type.RSA2048_OAEP_SHA_1_B64:
		return RSA_2048_OAEP_SHA_1_decrypt(sk.Encryption(), encstr.Data())
	}

	return nil, fmt.Errorf("Don't know how to handle %v text", encstr.Type())
}

func (sk *symmetricKey) DecryptString(encstr interfaces.EncryptedString) (string, error) {
	r, err := sk.Decrypt(encstr)
	return string(r), err
}

func NewSymmetricKey(buf []byte) (SymmetricKey, error) {
	l := len(buf)
	switch l {
	case 32:
		return &symmetricKey{
			keytype:        encryption_type.AES_CBC_256_B64,
			encryption:     buf[0:32],
			authentication: nil,
		}, nil
	case 64:
		return &symmetricKey{
			keytype:        encryption_type.AES_CBC_256_HMAC_SHA_256_B64,
			encryption:     buf[0:32],
			authentication: buf[32:64],
		}, nil
	default:
		// TODO: make this parametrizable from consumer
		return &symmetricKey{
			keytype:    encryption_type.RSA2048_OAEP_SHA_1_B64,
			encryption: buf,
		}, nil
		// return nil, fmt.Errorf("Unknown symmetric key type with length=%d", l)
	}
}
func NewSymmetricKeyCtor(originalBuffer []byte, enctype encryption_type.EncryptionType) (SymmetricKey, error) {
	fixedBuff := make([]byte, 64)
	copy(fixedBuff, originalBuffer)

	switch enctype {
	case encryption_type.AES_GCM_256_B64:
		return &symmetricKey{
			keytype:        enctype,
			encryption:     fixedBuff[0:32],
			authentication: nil,
		}, nil
	case encryption_type.AES_CBC_256_HMAC_SHA_256_B64:
		return &symmetricKey{
			keytype:        enctype,
			encryption:     fixedBuff[0:32],
			authentication: fixedBuff[32:64],
		}, nil
	case encryption_type.RSA2048_OAEP_SHA_1_B64:
		return &symmetricKey{
			keytype:    enctype,
			encryption: fixedBuff,
		}, nil
	default:
		return nil, fmt.Errorf("Unknown symmetric key type=%d", enctype)
	}
}
