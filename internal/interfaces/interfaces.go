package interfaces

import (
	"github.com/josegomezr/vw-cli/internal/encryption_type"
)

type EncryptedString interface {
	Data() []byte
	IV() []byte
	MAC() []byte
	Type() encryption_type.EncryptionType
	String() string
}

type Decryptable interface {
	Decrypt(EncryptedString) ([]byte, error)
}

type SymmetricKey interface {
	Encryption() []byte
	Authentication() []byte
	Type() encryption_type.EncryptionType
	Decrypt(EncryptedString) ([]byte, error)
	Encrypt([]byte, encryption_type.EncryptionType) (EncryptedString, error)
}
