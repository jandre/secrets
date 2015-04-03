package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/jandre/secrets/secrets/util"
)

type Vault struct {
	Path          string `json:"-"`
	KeyRingId     string `json:"-"`
	Name          string
	LastUpdatedAt string
	Keys          map[string]string
	DecryptedKeys map[string]string `json:"-"`
	Signature     string
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

	return ReadVault(name, configPath)
}

// TODO: read vault
func ReadVault(name string, configPath string) *Vault {
	v := Vault{Path: configPath, Name: name}
	v.GenerateKeyRingId()
	v.Load()
	return &v
}

//
// NewVault() creates a new vault at `configPath`.
//
// If the file exists already, attempts to load the metadata from the path.
//
func NewVault(name string, configPath string) *Vault {
	v := Vault{Path: configPath, Name: name}
	v.GenerateKeyRingId()
	return &v
}

func (v *Vault) VerifyPassphrase(passphrase string) bool {

	return false
}

func (v *Vault) Sign(passphrase string) error {
	// generate a vault key and encrypt it
	data, err := json.Marshal(v.Keys)

	if err != nil {
		return err
	}

	toSign := fmt.Sprintf("%s-%s-%s", v.Name, v.KeyRingId, data)
	v.Signature = SignData(passphrase, toSign)

	return nil
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

//
// Unlock the vault by putting the secrets into memory.
//
func (v *Vault) Unlock(passphrase string) error {

	if v.Signature != nil {

	} else {
		return errors.New("Could not unlock - vault is not signed!")

	}

}

//
// TODO: keyRingId should be dynamic
//
func (v *Vault) GetKeyRingId() string {
	return v.KeyRingId
}

//
// Save the vault to disk
//
func (v *Vault) Save() error {
	v.LastUpdatedAt = time.Now().String()
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
