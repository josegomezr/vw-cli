package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
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
	ApiClientId     string
	ApiClientSecret string
	Email           string
	BitwardenURL    string
	MasterPassword  string
}

type CLIUnlockOpts struct {
	Check          bool
	MasterPassword string
}

type CLIOpts struct {
	ConfigDir string
	Command   string

	LoginOpts  CLILoginOpts
	ShowOpts   CLIShowOpts
	ListOpts   CLIListOpts
	UnlockOpts CLIUnlockOpts
}

var FlagMode = flag.ExitOnError

var loginFlagset *flag.FlagSet
var globalflagset *flag.FlagSet
var listFlagSet *flag.FlagSet
var showFlagSet *flag.FlagSet
var unlockFlagSet *flag.FlagSet

func init() {
	globalflagset = flag.NewFlagSet("vw-cli", FlagMode)
	loginFlagset = flag.NewFlagSet("vw-cli login", FlagMode)
	listFlagSet = flag.NewFlagSet("vw-cli list", FlagMode)
	showFlagSet = flag.NewFlagSet("vw-cli show", FlagMode)
	unlockFlagSet = flag.NewFlagSet("vw-cli unlock", FlagMode)
}

func parseUnlockArgs(cliopts *CLIOpts, args []string) (err error) {
	masterPasswordFile := ""
	loginFlagset.BoolVar(&cliopts.UnlockOpts.Check, "check", false, "check unlock status")
	loginFlagset.StringVar(&masterPasswordFile, "master-password-file", "", "master-password-file")

	err = loginFlagset.Parse(args)

	if err != nil {
		if err == flag.ErrHelp {
			loginFlagset.Usage()
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
		cliopts.UnlockOpts.MasterPassword = string(content)
	}

	return
}
func parseLoginArgs(cliopts *CLIOpts, args []string) (err error) {
	masterPasswordFile := ""
	loginFlagset.StringVar(&cliopts.LoginOpts.ApiClientId, "api-client-id", "", "api key")
	loginFlagset.StringVar(&cliopts.LoginOpts.ApiClientSecret, "api-client-secret", "", "api key")
	loginFlagset.StringVar(&cliopts.LoginOpts.Email, "email", "", "email")
	loginFlagset.StringVar(&cliopts.LoginOpts.BitwardenURL, "bitwarden-url", "", "bitwarden-url")
	loginFlagset.StringVar(&masterPasswordFile, "master-password-file", "", "master-password-file")

	err = loginFlagset.Parse(args)

	if err != nil {
		if err == flag.ErrHelp {
			loginFlagset.Usage()
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
	showFlagSet.StringVar(&showopts.Folder, "folder", "", "folder id or name")
	showFlagSet.StringVar(&showopts.Organization, "organization", "", "organization id or name")

	err = showFlagSet.Parse(args)

	if err != nil {
		if err == flag.ErrHelp {
			err = nil
			return
		}
	}

	secretName := showFlagSet.Arg(0)
	if secretName == "" {
		err = fmt.Errorf("Missing first argument: secret id or name")
	}

	showopts.Cipher = secretName

	return
}

func parseListArgs(listopts *CLIListOpts, args []string) (err error) {
	listFlagSet.StringVar(&listopts.Folder, "folder", "", "folder id or name")
	listFlagSet.StringVar(&listopts.Organization, "organization", "", "organization id or name")

	err = listFlagSet.Parse(args)

	if err != nil {
		if err == flag.ErrHelp {
			listFlagSet.Usage()
			err = nil
			return
		}
	}
	return
}

func homedir() string {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}
	return user.HomeDir
}

func ParseArgs(args []string) (cliopts *CLIOpts, err error) {
	cliopts = &CLIOpts{}

	globalflagset.StringVar(&cliopts.ConfigDir, "config-dir", "", "config dir (defaults to ~/.config/vw-cli/)")

	err = globalflagset.Parse(args)

	if cliopts.ConfigDir == "" {
		cliopts.ConfigDir = filepath.Join(homedir(), ".config/vw-cli")
	}

	if err != nil {
		if err == flag.ErrHelp {
			err = nil
			globalflagset.Usage()
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
		globalflagset.Usage()
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
	case "unlock":
		err = parseUnlockArgs(cliopts, args[1:])
		if err != nil {
			cliopts = nil
			return
		}
		cliopts.Command = "unlock"
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
