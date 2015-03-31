//
// Encryption wrappers
//
package secrets

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
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
		return nil, errors.New("key size is too large: " + string(keySize))
	}

	// it's an n byte key, so let's generate a cryptographic hash of the passphrase and
	// use the first n bytes
	bytes := sha256.Sum256([]byte(passphrase))
	return bytes[:keySize], nil
}

func GenRandomIv(blockSize int) ([]byte, error) {
	b := make([]byte, blockSize)
	bytesRead, err := rand.Read(b)

	if err != nil {
		return nil, err
	}

	if bytesRead != blockSize {
		return nil, errors.New("unable to generate random iv bytes")
	}

	return b, nil
}

// returns a byte block with <32 byte sha-256 hmac>< blockSize iv>< n blocks payload>
func Encrypt(passphrase string, bytes []byte) ([]byte, error) {

	key, err := KeyGen(passphrase, des.BlockSize)

	if err != nil {
		return nil, err
	}

	block, err := des.NewCipher(key)

	if err != nil {
		return nil, err
	}

	ivBytesSize := block.BlockSize()
	hmacBytesSize := sha256.Size
	totalBytes := len(bytes)
	totalBlocks := totalBytes/block.BlockSize() + 1

	result := make([]byte, hmacBytesSize+ivBytesSize+
		(totalBlocks)*block.BlockSize())

	iv, err := GenRandomIv(block.BlockSize())

	if err != nil {
		return nil, err
	}

	// copy iv
	copy(result[hmacBytesSize:hmacBytesSize+ivBytesSize], iv)

	mode := cipher.NewCBCEncrypter(block, iv)

	mode.CryptBlocks(result[ivBytesSize+hmacBytesSize:], bytes)

	hmacBytes := sha256.Sum256(result[hmacBytesSize:])

	copy(result[:hmacBytesSize], hmacBytes[0:hmacBytesSize])

	return result, nil
}

//
// Encrypts a string
//
func EncryptString(passphrase string, data string) ([]byte, error) {
	return Encrypt(passphrase, []byte(data))
}
