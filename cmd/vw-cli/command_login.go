package main

import (
	"fmt"
	"github.com/josegomezr/vw-cli/internal/command"
	"os"
)

func init() {
	masterPasswordFile := ""
	LoginCommand.Flags().BoolVar(&CLIOPTS.UnlockOpts.Check, "check", false, "reveal password")
	LoginCommand.Flags().StringVar(&masterPasswordFile, "master-password-file", "", "master-password-file")
}

var LoginCommand = &command.Command{
	Name:    "login",
	Summary: "Log-in to your Bitwarden vault",
	Run:     doLogin,
}

func doLogin(c *command.Command, args []string) error {
	opts := CLIOPTS

	vw := NewVW().WithConfigDir(opts.ConfigDir)
	vw.LoadConfigAndState()

	if vw.state.Email == "" {
		if opts.LoginOpts.ApiClientId != "" || opts.LoginOpts.ApiClientSecret != "" {
			fmt.Println("Log-in with API Credentials")
			if opts.LoginOpts.ApiClientSecret == "" {
				opts.LoginOpts.ApiClientSecret = askPass("API Secret: ")
			}

			err := vw.LoginWithAPIKeys(opts.LoginOpts.ApiClientId, opts.LoginOpts.ApiClientSecret)
			if err != nil {
				fmt.Println("error:", err)
				os.Exit(1)
				return nil
			}

			fmt.Println("Logged in!")
		} else if opts.LoginOpts.Email != "" {
			fmt.Println("Log-in Email+Master password")
			if opts.LoginOpts.MasterPassword == "" {
				opts.LoginOpts.MasterPassword = askPass("User password: ")
			}
			err := vw.LoginWithEmailPassword(opts.LoginOpts.Email, opts.LoginOpts.MasterPassword)
			if err != nil {
				fmt.Println("error:", err)
				os.Exit(1)
				return nil
			}
			fmt.Println("Logged in!")
		}
	} else {
		fmt.Println("Logged in as:", vw.state.Email)
	}
	return nil
}
