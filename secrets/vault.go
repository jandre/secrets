package secrets

import (
	"errors"
	"encoding/json"
)

type Vault struct {
	Path      string `json:"-"`
	KeyRingId string
	Name      string
	Keys      map[string]string  `json:"-"`
	BinData     []byte
}

//
// NewVault() creates a new vault at `configPath`.
//
// If the file exists already, attempts to load the metadata from the path.
//
func NewVault(name string, configPath string) (*Vault) {
	v := Vault{Path: configPath, Name: name}
	return &v
}

//
// Serialize to string 
//
func (v *Vault) Serialize() (byte[], error){

	// TODO: populate BinData
	return json.Marshal(v)
}

func (v *Vault) EncryptKeys() (byte[], error) {

	return nil, nil
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
	}
	err := ioutil.WriteFile(v.Path, bytes, 0600)
	return err
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

	if !IsUnlocked() {
		return errors.New("Vault is not unlocked - please run `secrets vault unlock --path=<path_to_vault>`")
	}
	v.Keys[key] = secret
	v.Save()
}
