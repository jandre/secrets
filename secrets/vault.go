package secrets

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"

	"github.com/jandre/secrets/secrets/util"
)

type Vault struct {
	Path          string `json:"-"`
	KeyRingId     string
	Name          string
	Keys          map[string]string
	DecryptedKeys map[string]string `json:"-"`
}

func LoadVaultsFromKeyRing() ([]*Vault, error) {
	keys, err := GetVaultKeys()
	if err != nil {
		return nil, err
	}

	result := make([]*Vault, 0)
	for _, desc := range keys {
		vault := DetectVault(desc.Description)

		if vault != nil {
			result = append(result, vault)
		}
	}

	return result, nil
}

//
// Returns name, path of keyring if `keyRingId` is valid
//
func DetectVault(keyRingId string) *Vault {

	if !strings.HasPrefix(keyRingId, "secrets$") {
		return nil
	}

	substrings := strings.Split(keyRingId, "$")

	if len(substrings) != 3 {
		return nil
	}

	name := substrings[1]
	configPath := substrings[2]

	if !util.FileExists(configPath) {
		return nil
	}

	return NewVault(name, configPath)
}

//
// NewVault() creates a new vault at `configPath`.
//
// If the file exists already, attempts to load the metadata from the path.
//
func NewVault(name string, configPath string) *Vault {
	v := Vault{Path: configPath, Name: name}
	return &v
}

func (v *Vault) GenerateKeyRingId() {
	if v.KeyRingId == "" {
		v.KeyRingId = "secrets$" + v.Name + "$" + v.Path
	}
}

//
// Serialize to string
//
func (v *Vault) Serialize() ([]byte, error) {
	result, err := json.Marshal(v)
	return result, err
}

//
// Load the vault meta-data from disk.
//
func (v *Vault) Load() {

}

func (v *Vault) Unlock(passphrase string) {
}

//
// Save the vault to disk
//
func (v *Vault) Save() error {
	bytes, err := v.Serialize()
	if err != nil {
		return err
	} else {
		return ioutil.WriteFile(v.Path, bytes, 0600)
	}
}

//
// IsUnlocked() returns true if `unlocked`.
//
// A vault is unlocked if a password in the keychain is available.
//
func (v *Vault) IsUnlocked() bool {

	// XXX:
	return false
}

func (v *Vault) getPassword() (string, error) {
	// XXX: get the vault password
	return "", nil
}

//
// Add() adds a secret to the vault.
//
func (v *Vault) Add(key string, secret string) error {

	if !v.IsUnlocked() {
		return errors.New("Vault is not unlocked - please run `secrets vault unlock --path=<path_to_vault>`")
	}
	v.Keys[key] = secret
	v.Save()

	return nil
}
