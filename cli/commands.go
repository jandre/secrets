package cli

import (
	"fmt"
	"log"
	"path"

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

	fmt.Printf("Found %s%d%s vaults:\n", lime, len(vaults), reset)
	for id, vault := range vaults {
		fmt.Printf("-- [%d]: %s (%d keys)\n", id, vault.Name, len(vault.Keys))
	}
}

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

	file := path.Join(folder, ".vault")

	if util.FileExists(file) {
		log.Fatal("No vault created!  A vault file already exists at: ", file)
	}

	vault := secrets.NewVault(name, file)
	vault.GenerateKeyRingId()
	err := vault.Save()

	if err != nil {
		log.Println("Vault created: ", file)
	} else {
		log.Fatal("Failure to create vault:", err)
	}
}
