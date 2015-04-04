package secrets

import (
	"errors"
	"strings"

	"github.com/jandre/keyutils"
)

const SECRETS_PARENT = "__SECRETS"

func MakeContainerKeyRing() (keyutils.KeySerial, error) {
	serial, err := keyutils.NewKeyRing(SECRETS_PARENT, keyutils.KEY_SPEC_USER_KEYRING)
	return serial, err
}

func GetContainerKeyRing() (*keyutils.KeyDesc, error) {
	serial, err := keyutils.RequestKey("keyring",
		SECRETS_PARENT, keyutils.KEY_SPEC_USER_KEYRING)

	if err != nil {
		MakeContainerKeyRing()
		serial, err = keyutils.RequestKey("keyring", SECRETS_PARENT, keyutils.KEY_SPEC_USER_KEYRING)
	}

	if err != nil {
		return nil, err
	}

	if serial == 0 {
		return nil, nil
	}

	return keyutils.DescribeKey(serial)
}

//
//
func GetVaultKeys() ([]*keyutils.KeyDesc, error) {

	parentRing, err := GetContainerKeyRing()

	if err != nil {
		return nil, err
	}

	if parentRing == nil {
		return nil, errors.New("no keyring found")
	}

	keys, err := keyutils.ListKeysInKeyRing(parentRing.Serial)

	if err != nil {
		return nil, err
	}
	result := make([]*keyutils.KeyDesc, 0)

	for _, key := range keys {
		if IsVaultKey(key) {
			result = append(result, key)
		}
	}
	return result, nil
}

func IsVaultKey(desc *keyutils.KeyDesc) bool {
	return desc.Type == "keyring" && strings.HasPrefix(desc.Description, "secrets$")
}

func AddVaultToKeyRing(vault *Vault, passphrase string) (keyutils.KeySerial, error) {
	parentRing, err := GetContainerKeyRing()

	if err != nil {
		return 0, err
	}

	if parentRing == nil {
		return 0, errors.New("no keyring found")
	}

	vaultRing, err := keyutils.NewKeyRing(vault.GetKeyRingId(), parentRing.Serial)

	if err != nil {
		return 0, err
	}

	id, err := keyutils.AddKey(keyutils.USER, "passphrase", passphrase, vaultRing)

	if err != nil {
		return 0, err
	}

	return id, err
}

func FindKeyRing(name string, keys []*keyutils.KeyDesc) *keyutils.KeyDesc {
	for _, desc := range keys {
		if desc.Description == name {
			return desc
		}
	}
	return nil
}
