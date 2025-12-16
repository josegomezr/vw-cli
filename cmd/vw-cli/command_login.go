package main

import (
	"fmt"
	"github.com/josegomezr/vw-cli/internal/command"
	"os"
)

func init() {
	LoginCommand.Flags().BoolVar(&CLIOPTS.LoginOpts.Force, "force", false, "Force/Overwrite login")
	LoginCommand.Flags().StringVar(&CLIOPTS.LoginOpts.ApiClientId, "api-client-id", "", "OAuth2 `client-id` for API authentication")
	LoginCommand.Flags().StringVar(&CLIOPTS.LoginOpts.ApiClientSecret, "api-client-secret", "", "OAuth2 `client-secret` for API authentication")
	LoginCommand.Flags().StringVar(&CLIOPTS.LoginOpts.Email, "email", "", "Vault `email`")
}

var LoginCommand = &command.Command{
	Name:    "login",
	Summary: "Log-in to your Bitwarden vault",
	Run:     doLogin,
	PreRun:  loadConfigState,
}

func doLogin(c *command.Command, args []string) error {
	opts := CLIOPTS

	if GlobalVW.state.Email != "" && !opts.LoginOpts.Force {
		fmt.Println("Logged in as:", GlobalVW.state.Email)
		return nil
	}

	if opts.LoginOpts.ApiClientId != "" || opts.LoginOpts.ApiClientSecret != "" {
		return doApiLogin()
	} else {
		return doEmailPwLogin()
	}
}

func doApiLogin() error {
	opts := CLIOPTS
	fmt.Println("Log-in with API Credentials")
	if opts.LoginOpts.ApiClientSecret == "" {
		opts.LoginOpts.ApiClientSecret = askPass("API Secret: ")
	}

	err := GlobalVW.LoginWithAPIKeys(opts.LoginOpts.ApiClientId, opts.LoginOpts.ApiClientSecret)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}

	fmt.Println("Logged in!")
	return nil
}

func doEmailPwLogin() error {
	opts := CLIOPTS
	fmt.Println("Log-in Email+Master password")
	email := GlobalVW.state.Email
	if email == "" {
		email = opts.LoginOpts.Email
	}
	if email == "" {
		email = askString("Email: ")
	}

	fmt.Println("Logging in as:", email)

	pw := opts.MasterPassword
	if pw == "" {
		pw = askPass("User password: ")
	}

	err := GlobalVW.LoginWithEmailPassword(email, pw)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println("Logged in!")
	return nil
}
