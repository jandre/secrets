//
// Encryption wrappers
//
package secrets

import (
	"crypto/des"
	"crypto/sha256"
	"errors"
)

//
// KeyGen() will generate a key with a passphrase that is `keySize` bytes
// in length.
//
func KeyGen(passphrase string, keySize uint) ([]byte, error) {

	// there's too many bytes requested
	// TODO: can generate multi-hashes
	if keySize > sha256.Size {
		return nil, errors.New("key size is too large:", keySize)
	}

	// it's an n byte key, so let's generate a cryptographic hash of the passphrase and
	// use the first n bytes
	bytes, err := sha256.Sum256([]byte(passphrase))
	if err {
		return nil, err
	}
	return bytes[:keySize], nil

}

func EncryptString(passphrase string, data string) {
	key, err := KeyGen(passphrase, des.BlockSize)

}
