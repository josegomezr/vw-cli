package main

import (
	"fmt"
	"github.com/josegomezr/vw-cli/internal/command"
	"os"
	"path/filepath"
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
		return
	},
}

var CLIOPTS = &CLIOpts{}

func init() {
	RootCommand.PersistentFlags().StringVar(&CLIOPTS.ConfigDir, "config-dir", "", "`dir` config dir")
	RootCommand.PersistentFlags().StringVar(&CLIOPTS.SessionToken, "session-token", "", "`token` sess tok")
	RootCommand.PersistentFlags().StringVar(&CLIOPTS.OutputFormat, "output-format", "plain", "`format`")

	RootCommand.AddChild(ListCommand)
	RootCommand.AddChild(ShowCommand)
	RootCommand.AddChild(UnlockCommand)
	RootCommand.AddChild(LoginCommand)
}

func main() {
	if err := RootCommand.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error: %s", err)
		os.Exit(1)
	}
}
