package main

import (
	"bufio"
	"fmt"
	"github.com/josegomezr/vw-cli/internal/command"
	"os"
	"path/filepath"
	"strings"
)

const DefaultEmptyStringValue = "\x00"

var RootCommand = &command.Command{
	Name: "vw-cli",
	PreRun: func(c *command.Command) (err error) {
		if env_sess := os.Getenv("VW_SESSION"); env_sess != "" {
			CLIOPTS.SessionToken = env_sess
		}
		if CLIOPTS.ConfigDir == "" {
			CLIOPTS.ConfigDir = filepath.Join(homedir(), ".config/vw-cli")
		}

		return nil
	},
}

var CLIOPTS = &CLIOpts{}
var GlobalVW *VW

func loadConfigState(c *command.Command) (err error) {
	GlobalVW = NewVW().WithConfigDir(CLIOPTS.ConfigDir)
	GlobalVW.LoadConfigAndState()
	if CLIOPTS.MasterPasswordFile != "" {
		f, err := os.Open(CLIOPTS.MasterPasswordFile)
		if err != nil {
			return fmt.Errorf("Could not open master password-file: %w", err)
		}
		str, err := bufio.NewReader(f).ReadString(byte('\n'))
		if err != nil {
			return fmt.Errorf("Could not read master password-file: %w", err)
		}
		str = strings.TrimSpace(str)
		CLIOPTS.MasterPassword = str
	}
	return nil
}

func loadConfigStateAndKeys(c *command.Command) (err error) {
	loadConfigState(c)
	askpass := func() string {
		if CLIOPTS.MasterPassword != "" {
			return CLIOPTS.MasterPassword
		}
		return askPass("Master password: ")
	}

	if err := GlobalVW.LoadKeys(CLIOPTS.SessionToken, askpass); err != nil {
		return err
	}
	return
}

func init() {
	RootCommand.PersistentFlags().StringVar(&CLIOPTS.ConfigDir, "config-dir", "", "path to config `dir`")
	RootCommand.PersistentFlags().StringVar(&CLIOPTS.SessionToken, "session-token", "", "Session `token` from "+`"vw-cli unlock"`)
	RootCommand.PersistentFlags().StringVar(&CLIOPTS.OutputFormat, "output-format", "text", "Output `format`. "+`Allowed values are: "text" (default), "plain"`)
	RootCommand.PersistentFlags().StringVar(&CLIOPTS.MasterPasswordFile, "master-password-file", "", "path to master password `file`")

	RootCommand.AddChild(ListCommand)
	RootCommand.AddChild(ShowCommand)
	RootCommand.AddChild(UnlockCommand)
	RootCommand.AddChild(LoginCommand)
}

func main() {
	if err := RootCommand.Execute(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
		os.Exit(1)
	}
}
