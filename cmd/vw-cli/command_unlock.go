package main

import (
	"fmt"
	"github.com/josegomezr/vw-cli/internal/command"
	"github.com/josegomezr/vw-cli/internal/crypto"
	"os"
	"path/filepath"
)

func init() {
	masterPasswordFile := ""
	UnlockCommand.Flags().BoolVar(&CLIOPTS.UnlockOpts.Check, "check", false, "reveal password")
	UnlockCommand.Flags().StringVar(&masterPasswordFile, "master-password-file", "", "master-password-file")
}

var UnlockCommand = &command.Command{
	Name:    "unlock",
	Summary: "Unlock your local vault",
	Run:     doUnlock,
}

func doUnlock(c *command.Command, args []string) error {
	opts := CLIOPTS

	vw := &VW{}
	vw.cfgdir = filepath.Join(homedir(), ".config/vw-cli")
	vw.LoadConfig()
	vw.LoadState()
	if env_sess := os.Getenv("VW_SESSION"); env_sess != "" {
		opts.SessionToken = env_sess
	}

	if opts.UnlockOpts.Check {
		if !vw.hasDecryptedSessionKey {
			fmt.Println("Locked!")
			os.Exit(1)
			return nil
		}
		fmt.Println("Unlocked!")
		return nil
	}
	if vw.hasDecryptedSessionKey {
		switch opts.OutputFormat {
		case "plain":
			encodedKey := crypto.B64e(vw.sessionKey.Encryption())
			fmt.Println("Make sure to export the following variable:")
			fmt.Printf("export VW_SESSION=%q\n", encodedKey)
			fmt.Printf("Or pass --session-token %q to the next vw-cli invocations\n", encodedKey)
		case "text":
			fmt.Println(crypto.B64e(vw.sessionKey.Encryption()))
		}
		return nil
	}

	loadkeys(vw, opts.SessionToken)
	if err := vw.SaveSession(); err != nil {
		os.Exit(1)
	}
	switch opts.OutputFormat {
	case "plain":
		encodedKey := crypto.B64e(vw.sessionKey.Encryption())
		fmt.Println("Make sure to export the following variable:")
		fmt.Printf("export VW_SESSION=%q\n", encodedKey)
		fmt.Printf("Or pass --session-token %q to the next vw-cli invocations\n", encodedKey)
	case "text":
		fmt.Println(crypto.B64e(vw.sessionKey.Encryption()))
	}
	return nil
}
