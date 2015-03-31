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

	vaultList     = vault.Command("list", "List all vaults.")
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
		println("got vault with no args")
	case vaultNew.FullCommand():
		println("got vault")

	case vaultShow.FullCommand():
		println("got vault show")
	}
}
