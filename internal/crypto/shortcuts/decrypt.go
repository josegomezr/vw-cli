package shortcuts

import (
	"github.com/josegomezr/vw-cli/internal/crypto"
	"github.com/josegomezr/vw-cli/internal/encryption_type"
	"github.com/josegomezr/vw-cli/internal/interfaces"
	"github.com/josegomezr/vw-cli/internal/symmetric_key"
	"reflect"
)

func Decrypt(key interfaces.Decryptable, cipher string) ([]byte, error) {
	encstring, err := crypto.NewEncStringFrom(cipher)
	if err != nil {
		return nil, err
	}

	decr, err := key.Decrypt(encstring)
	if err != nil {
		return nil, err
	}
	return decr, nil
}

func DecryptString(key symmetric_key.SymmetricKey, cipher string) (string, error) {
	encstring, err := Decrypt(key, cipher)
	if err != nil {
		return "", err
	}
	return string(encstring), nil
}

func DecryptSymmetricKey(key symmetric_key.SymmetricKey, cipher string) (symmetric_key.SymmetricKey, error) {
	encstring, err := Decrypt(key, cipher)
	if err != nil {
		return nil, err
	}

	decr, err := symmetric_key.NewSymmetricKey(encstring)
	if err != nil {
		return nil, err
	}
	return decr, nil
}

func DecryptSymmetricKeyCtor(key symmetric_key.SymmetricKey, cipher string, enctype encryption_type.EncryptionType) (symmetric_key.SymmetricKey, error) {
	encstring, err := Decrypt(key, cipher)
	if err != nil {
		return nil, err
	}

	decr, err := symmetric_key.NewSymmetricKeyCtor(encstring, enctype)
	if err != nil {
		return nil, err
	}
	return decr, nil
}

func DecryptStruct(daStruct any, sk symmetric_key.SymmetricKey) error {
	val := reflect.ValueOf(daStruct).Elem()

	for _, field := range reflect.VisibleFields(val.Type()) {
		res := field.Tag.Get("encryptedString")
		if res != "true" {
			continue
		}

		structMem := val.FieldByIndex(field.Index)
		newval := ""
		if curval := structMem.String(); curval != "" {
			dec, err := DecryptString(sk, curval)
			if err != nil {
				return err
			}
			newval = dec
		}
		structMem.Set(reflect.ValueOf(newval))
	}
	return nil
}
