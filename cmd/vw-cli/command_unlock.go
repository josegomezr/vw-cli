package main

import (
	"fmt"
	"github.com/josegomezr/vw-cli/internal/command"
	"github.com/josegomezr/vw-cli/internal/crypto"
	"os"
)

func init() {
	UnlockCommand.Flags().BoolVar(&CLIOPTS.UnlockOpts.Check, "check", false, "reveal password")
}

var UnlockCommand = &command.Command{
	Name:    "unlock",
	Summary: "Unlock your local vault",
	Run:     doUnlock,
	PreRun:  loadConfigState,
}

func doUnlock(c *command.Command, args []string) error {
	opts := CLIOPTS

	if opts.UnlockOpts.Check {
		if !GlobalVW.hasDecryptedSessionKey {
			fmt.Println("Locked!")
			os.Exit(1)
			return nil
		}
		fmt.Println("Unlocked!")
		return nil
	}

	if !GlobalVW.hasDecryptedSessionKey {
		askpass := func() string {
			if opts.MasterPassword != "" {
				return opts.MasterPassword
			}
			return askPass("Master password: ")
		}

		if err := GlobalVW.LoadKeys(CLIOPTS.SessionToken, askpass); err != nil {
			return err
		}

		if err := GlobalVW.SaveSession(); err != nil {
			os.Exit(1)
		}
	}

	switch opts.OutputFormat {
	case "text":
		encodedKey := crypto.B64e(GlobalVW.sessionKey.Encryption())
		fmt.Println("Make sure to export the following variable:")
		fmt.Printf("export VW_SESSION=%q\n", encodedKey)
		fmt.Printf("Or pass --session-token %q to the next vw-cli invocations\n", encodedKey)
	case "plain":
		fmt.Println(crypto.B64e(GlobalVW.sessionKey.Encryption()))
	}
	return nil
}
