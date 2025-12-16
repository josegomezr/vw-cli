package main

type CLIShowOpts struct {
	Folder         string
	Organization   string
	Cipher         string
	Attribute      string
	WithPassword   bool
	WithTotp       bool
	WithTotpSource bool
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
	Force           bool
}

type CLIUnlockOpts struct {
	Check bool
}

type CLIOpts struct {
	ConfigDir          string
	Command            string
	MasterPasswordFile string
	MasterPassword     string

	LoginOpts    CLILoginOpts
	ShowOpts     CLIShowOpts
	ListOpts     CLIListOpts
	UnlockOpts   CLIUnlockOpts
	OutputFormat string
	SessionToken string
}
