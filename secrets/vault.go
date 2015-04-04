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
		vault, err := DetectVault(desc.Description)

		if err != nil {
			debug("LoadVaultsFromKeyRing() error: unable to load vault keys:", err)
		}

		if vault != nil {
			result = append(result, vault)
		}
	}

	return result, nil
}

func LookupVaultFromKeyRing(name string) *Vault {
	var vault *Vault

	allVaults, err := LoadVaultsFromKeyRing()

	if err != nil {
		debug("error loading all vaults", err)
		return nil
	}

	for _, v := range allVaults {
		if v.Name == name {
			vault = v
			break
		}
	}

	if vault != nil {
		return vault
	}

	return nil
}

//
// Returns name, path of keyring if `keyRingId` is valid
//
func DetectVault(keyRingId string) (*Vault, error) {

	if !strings.HasPrefix(keyRingId, "secrets$") {
		return nil, nil
	}

	substrings := strings.Split(keyRingId, "$")

	if len(substrings) != 3 {
		return nil, nil
	}

	name := substrings[1]
	configPath := substrings[2]

	if !util.FileExists(configPath) {
		return nil, nil
	}

	return ReadVault(name, configPath)
}

//
// Read vault from disk
//
func ReadVault(name string, configPath string) (*Vault, error) {
	v := Vault{Path: configPath, Name: name}
	err := v.Load()

	if err != nil {
		return nil, err
	}
	return &v, nil
}

//
// NewVault() creates a new vault at `configPath`.
//
// If the file exists already, attempts to load the metadata from the path.
//
func NewVault(name string, configPath string) *Vault {
	v := Vault{Path: configPath, Name: name}
	v.DecryptedKeys = make(map[string]string, 0)
	v.Keys = make(map[string]string, 0)
	return &v
}

func (v *Vault) VerifyPassphrase(passphrase string) bool {
	data, err := v.getSigningData()

	if err != nil {
		debug("Invalid signing data:", err)
		return false
	}

	debug("signature is %s", data)

	return VerifySignature(passphrase, data, v.Signature)
}

func (v *Vault) getSigningData() (string, error) {
	data, err := json.Marshal(v.Keys)

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s-%s", v.Name, data), nil
}

func (v *Vault) Sign(passphrase string) error {
	// generate a vault key and encrypt it

	toSign, err := v.getSigningData()
	if err != nil {
		return err
	}

	v.Signature = SignData(passphrase, toSign)

	return nil
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
func (v *Vault) Load() error {
	data, err := ioutil.ReadFile(v.Path)

	if err != nil {
		return err
	}

	json.Unmarshal(data, v)

	if v.Keys == nil {
		v.Keys = make(map[string]string, 0)
	}
	v.DecryptedKeys = make(map[string]string, 0)

	return nil
}

//
// Unlock the vault by putting the secrets into memory.
//
func (v *Vault) Unlock(passphrase string) error {

	if v.Signature != "" {
		if v.VerifyPassphrase(passphrase) {
			_, err := AddVaultToKeyRing(v, passphrase)
			return err
		} else {
			return errors.New("Invalid passphrase.")
		}

	} else {
		return errors.New("Could not unlock - vault is not signed!")
	}

}

//
// TODO: keyRingId should be dynamic
//
func (v *Vault) GetKeyRingId() string {
	return "secrets$" + v.Name + "$" + v.Path
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
	return true
}

func (v *Vault) getPassphrase() (string, error) {

	keys, err := GetVaultKeys()

	if err != nil {
		return "", err
	}

	vaultKeyDesc := FindKeyRing(v.GetKeyRingId(), keys)

	if vaultKeyDesc == nil {
		return "", errors.New("Vault not found.  Please try `vault unlock <name>`")
	}

	keyDesc, err := FetchKeyInKeyRing("passphrase", vaultKeyDesc.Serial)

	if err != nil {
		return "", err
	}

	if keyDesc == nil {
		return "", errors.New("No vault passphrase found.")
	}

	passphrase, err := GetKeyValue(keyDesc.Serial)

	if err != nil {
		return "", err
	}

	if passphrase == "" {
		return "", errors.New("No passphrase vault set.")
	}

	return passphrase, nil
}

//
// Add() adds a secret to the vault.
//
func (v *Vault) Add(key string, secret string) error {

	if !v.IsUnlocked() {
		return errors.New("Vault is not unlocked - please run `secrets vault unlock --path=<path_to_vault>`")
	}

	passphrase, err := v.getPassphrase()

	if err != nil {
		return err
	}

	encryptedSecret, err := EncryptAndBase64String(passphrase, secret)

	if err != nil {
		return err
	}

	v.Keys[key] = encryptedSecret
	v.Sign(passphrase)

	return v.Save()
}
