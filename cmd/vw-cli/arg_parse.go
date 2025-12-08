package main

import (
	"flag"
	"fmt"
	"os"
)

type CLIShowOpts struct {
	Folder       string
	Organization string
	Cipher       string
}

type CLIListOpts struct {
	Folder       string
	Organization string
}

type CLILoginOpts struct {
	APIKey         string
	Email          string
	MasterPassword string
}

type CLIOpts struct {
	ConfigDir string
	Password  string
	Command   string

	LoginOpts CLILoginOpts
	ShowOpts  CLIShowOpts
	ListOpts  CLIListOpts
}

var FlagMode = flag.ExitOnError

func parseLoginArgs(cliopts *CLIOpts, args []string) (err error) {
	masterPasswordFile := ""

	loginFlagset := flag.NewFlagSet("vw-cli login", FlagMode)
	loginFlagset.StringVar(&cliopts.LoginOpts.APIKey, "api-key", "", "api key")
	loginFlagset.StringVar(&cliopts.LoginOpts.Email, "email", "", "email")
	loginFlagset.StringVar(&masterPasswordFile, "master-password-file", "", "master-password-file")

	err = loginFlagset.Parse(args)

	if err != nil {
		if err == flag.ErrHelp {
			err = nil
			return
		}
	}

	if masterPasswordFile != "" {
		content, readError := os.ReadFile(masterPasswordFile)
		if readError != nil {
			err = readError
			return
		}
		cliopts.LoginOpts.MasterPassword = string(content)
	}

	return
}

func parseShowArgs(showopts *CLIShowOpts, args []string) (err error) {
	loginFlagset := flag.NewFlagSet("vw-cli show", FlagMode)
	loginFlagset.StringVar(&showopts.Folder, "folder", "", "folder id or name")
	loginFlagset.StringVar(&showopts.Organization, "organization", "", "organization id or name")

	err = loginFlagset.Parse(args)

	if err != nil {
		if err == flag.ErrHelp {
			err = nil
			return
		}
	}

	secretName := loginFlagset.Arg(0)
	if secretName == "" {
		err = fmt.Errorf("Missing first argument: secret id or name")
	}

	showopts.Cipher = secretName

	return
}

func parseListArgs(listopts *CLIListOpts, args []string) (err error) {
	loginFlagset := flag.NewFlagSet("vw-cli list", FlagMode)
	loginFlagset.StringVar(&listopts.Folder, "folder", "", "folder id or name")
	loginFlagset.StringVar(&listopts.Organization, "organization", "", "organization id or name")

	err = loginFlagset.Parse(args)

	if err != nil {
		if err == flag.ErrHelp {
			err = nil
			return
		}
	}
	return
}

func ParseArgs(args []string) (cliopts *CLIOpts, err error) {
	cliopts = &CLIOpts{}

	globalflagset := flag.NewFlagSet("vw-cli", FlagMode)
	globalflagset.StringVar(&cliopts.ConfigDir, "config-dir", "", "config dir (defaults to ~/.config/vw-cli/)")

	err = globalflagset.Parse(args)

	if err != nil {
		if err == flag.ErrHelp {
			err = nil
			cliopts.Command = "help"
			return
		}
		cliopts = nil
		return
	}

	cmd := globalflagset.Arg(0)

	switch cmd {
	case "":
		fallthrough
	case "help":
		cliopts.Command = "help"
		return
	case "login":
		err = parseLoginArgs(cliopts, args[1:])
		if err != nil {
			cliopts = nil
			return
		}
		cliopts.Command = "login"
		return
	case "logout":
		cliopts.Command = "logout"
		return
	case "show":
		err = parseShowArgs(&cliopts.ShowOpts, args[1:])
		if err != nil {
			cliopts = nil
			return
		}
		cliopts.Command = "show"
		return
	case "ls":
		fallthrough
	case "list":
		err = parseListArgs(&cliopts.ListOpts, args[1:])
		if err != nil {
			cliopts = nil
			return
		}
		cliopts.Command = "list"
		return
	default:
		cliopts = nil
		err = fmt.Errorf("Unknown command: %s", cmd)
		return
	}
}
