package cli

import (
	"fmt"
	"log"
	"path"
	"path/filepath"

	"github.com/jandre/secrets/secrets"
	"github.com/jandre/secrets/secrets/util"
	"github.com/mgutz/ansi"
)

var (
	lime  = ansi.ColorCode("green+h:black")
	red   = ansi.ColorCode("red")
	reset = ansi.ColorCode("reset")
)

func PrettyPrintLoadedVaults(vaults []*secrets.Vault) {

	if vaults == nil || len(vaults) == 0 {
		fmt.Println("No vaults loaded into the user keyring.")
		fmt.Println("Load an existing vault by using `vault unlock`, or " +
			"create a new one using `vault new`")
		return
	}

	fmt.Printf("Found %s%d%s vault(s):\n\n", lime, len(vaults), reset)
	for id, vault := range vaults {
		fmt.Printf("%d. %s (%d keys)\n", id+1, vault.Name, len(vault.Keys))
		fmt.Printf("\t%s\n", vault.Path)
	}
}

//
// List vaults loaded in keyring.
//
func ListVaults() {
	vaults, err := secrets.LoadVaultsFromKeyRing()
	if err != nil {
		log.Fatal(err)
	}
	PrettyPrintLoadedVaults(vaults)
}

//
// Create a new vault
//
func CreateVault(name string, folder string) {

	folder, err := filepath.Abs(folder)

	if err != nil {
		log.Fatal("No vault created!  Not a valid folder: ", folder, err)
	}

	if !util.DirectoryExists(folder) {
		log.Fatal("No vault created!  Not a valid folder: ", folder)
	}

	file := path.Join(folder, ".vault")

	if util.FileExists(file) {
		log.Fatal("No vault created!  A vault file already exists at: ", file)
	}

	passphrase := secrets.TryGetPassphrase()

	vault := secrets.NewVault(name, file)
	vault.Sign(passphrase)
	err = vault.Save()

	if err != nil {
		log.Fatal("Failure to create vault:", err)
	} else {
		vault.Unlock(passphrase)
		log.Println("Vault created: ", name)
		log.Println("The vault has been unlocked. Add new secrets using:")
		log.Print("`secrets vault add-secret \"" + name + "\" <key> <value>`")
	}
}

func ShowVault(name string) {
	vault := secrets.LookupVaultFromKeyRing(name)

	if vault != nil {

	} else {
		log.Fatal("No vault found: ", name)
	}
}

func AddSecretToVault(name string, key string, val string) {
	if val == "" {
		// XXX: read from line
	}

}
