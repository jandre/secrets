package secrets

import (
	"bufio"
	"fmt"
	"os"

	"github.com/howeyc/gopass"
)

const ENV_SECRETS_PASSPHRASE = "SECRETS_PASSPHRASE"

func ReadPassword() string {
	fmt.Printf("Enter passphrase: ")
	return string(gopass.GetPasswdMasked())
}

func ConfirmPassword(orig string) bool {
	fmt.Printf("Confirm passphrase: ")
	pass := string(gopass.GetPasswdMasked())
	return pass == orig
}

func ReadEnvPassword() string {
	return os.Getenv(ENV_SECRETS_PASSPHRASE)
}

func TryGetPassphrase() string {
	envPass := ReadEnvPassword()
	if envPass != "" {
		return envPass
	}
	return ReadPassword()
}

func ReadLine() (string, error) {
	bio := bufio.NewReader(os.Stdin)

	tmp, hasMoreInLine, err := bio.ReadLine()
	line := string(tmp)

	for hasMoreInLine && err != nil {
		var tmp []byte
		tmp, hasMoreInLine, err = bio.ReadLine()
		line += string(tmp)
	}

	if err != nil {
		return "", err
	}

	return line, nil
}
