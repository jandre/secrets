package cli

import (
	"os"

	kingpin "gopkg.in/alecthomas/kingpin.v1"
)

const VERSION = "0.1.0"
const NAME = "secrets"

var (
	app   = kingpin.New("secrets", "Store and fetch application secrets.")
	debug = app.Flag("debug", "Enable debug mode.").Bool()

	// vault new
	vault        = app.Command("vault", "Create and manage vaults.")
	vaultNew     = vault.Command("new", "Create a new vault.")
	vaultNewName = vaultNew.Arg("name", "Name of the vault to create").Required().String()
	vaultNewPath = vaultNew.Flag("path", "Path to create the .vault file (default is current working dir)").Default(".").String()

	vaultList = vault.Command("list", "List all loaded vaults.")

	vaultUnlock     = vault.Command("unlock", "Unlock a given vault.")
	vaultUnlockPath = vaultUnlock.Flag("path", "Path to the .vault file (default is current working dir)").Default(".").String()

	vaultAddSecret      = vault.Command("add-secret", "Add a secret")
	vaultAddSecretName  = vaultAddSecret.Arg("name", "Name of the vault").Required().String()
	vaultAddSecretKey   = vaultAddSecret.Arg("key", "Secret key").Required().String()
	vaultAddSecretValue = vaultAddSecret.Arg("value", "Secret value").String()

	vaultShow     = vault.Command("show", "Show the contents of a vault.")
	vaultShowName = vaultShow.Arg("name", "Name of the vault to show").Required().String()

	vaultDelete     = vault.Command("delete", "Delete a vault.")
	vaultDeleteName = vaultDelete.Arg("name", "Name of the vault to delete.").Required().String()

	run        = app.Command("run", "Execution wrapper for commands.")
	runVault   = run.Flag("vault", "Name of vault to use.").String()
	runEnviron = run.Flag("environ", "Load secrets into environment variables.").Bool()
)

func Run() {
	app.Version(VERSION)

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {

	case vault.FullCommand():
		println("Subcommand for `vault` is required.")
		app.CommandUsage(os.Stderr, vault.FullCommand())

	case vaultNew.FullCommand():
		CreateVault(*vaultNewName, *vaultNewPath)

	case vaultList.FullCommand():
		ListVaults()

	case vaultAddSecret.FullCommand():
		AddSecretToVault(*vaultAddSecretName, *vaultAddSecretKey, *vaultAddSecretValue)

	case vaultShow.FullCommand():
		println("got vault show")

	default:
		app.Usage(os.Stderr)
	}
}
