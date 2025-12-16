package main

import (
	"fmt"
	"github.com/josegomezr/vw-cli/internal/api"
	"github.com/josegomezr/vw-cli/internal/command"
	"github.com/josegomezr/vw-cli/internal/crypto/shortcuts"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	ShowCommand.Flags().BoolVar(&CLIOPTS.ShowOpts.WithPassword, "with-password", false, "reveal password")
	ShowCommand.Flags().BoolVar(&CLIOPTS.ShowOpts.WithTotpSource, "with-totp-source", false, "reveal TOTP raw value")
	ShowCommand.Flags().BoolVar(&CLIOPTS.ShowOpts.WithTotp, "with-totp", false, "reveal TOTP code")

	ShowCommand.Flags().StringVar(&CLIOPTS.ShowOpts.Folder, "folder", DefaultEmptyStringValue, "`folder` id or name")
	ShowCommand.Flags().StringVar(&CLIOPTS.ShowOpts.Organization, "organization", DefaultEmptyStringValue, "`organization` id or name")
}

var ShowCommand = &command.Command{
	Name:    "show [id-or-name]",
	Summary: "Shows a specific secret from the vault",
	Run:     doShowCommand,
}

func doShowCommand(c *command.Command, args []string) error {
	opts := CLIOPTS
	println("HERE")
	vw := &VW{}
	vw.cfgdir = filepath.Join(homedir(), ".config/vw-cli")
	vw.LoadConfig()
	vw.LoadState()
	if env_sess := os.Getenv("VW_SESSION"); env_sess != "" {
		opts.SessionToken = env_sess
	}
	loadkeys(vw, opts.SessionToken)
	allOrgs, err := vw.AllOrganizations()
	if err != nil {
		fmt.Println("TODO: handle this error, folder could not be decrypted")
	}
	allFolders, err := vw.AllFolders()
	if err != nil {
		fmt.Println("TODO: handle this error, folder could not be decrypted")
	}
	if c.IsFlagPresent("folder") && !allFolders.Has(opts.ListOpts.Folder) {
		fmt.Println("Unknown folder: ", opts.ListOpts.Folder)
		os.Exit(1)
	}
	if c.IsFlagPresent("organization") && !allOrgs.Has(opts.ListOpts.Organization) {
		fmt.Println("Unknown org: ", opts.ListOpts.Organization)
		os.Exit(1)
	}

	matchesOrganization := func(givenOrg string, cipherObj *api.CipherObject, orgs *ChainedMap) (found bool) {
		if orgs.HasChained(cipherObj.OrganizationId, givenOrg) {
			found = true
		}
		return
	}
	matchesFolder := func(givenFolder string, cipherObj *api.CipherObject, folders *ChainedMap) (found bool) {
		if folders.HasChained(cipherObj.FolderId, givenFolder) {
			found = true
		}
		return
	}

	machesCriteria := func(criteria string, cipherObj *api.CipherObject) (found bool) {
		fpieces := []string{cipherObj.Name}
		if folderName, ok := allFolders[cipherObj.FolderId]; ok {
			fpieces = []string{folderName, cipherObj.Name}
		}
		if len(criteria) <= 0 || strings.Contains(strings.Join(fpieces, "/"), criteria) {
			found = true
		}
		return
	}

	revealTotp := CLIOPTS.ShowOpts.WithTotp
	revealPw := CLIOPTS.ShowOpts.WithPassword

	for _, cipherObj := range vw.state.LatestSync.Ciphers {
		key, ok := vw.allkeys[cipherObj.OrganizationId]
		if !ok {
			log.Printf("Unknown organization key for cipher %s, skipping", cipherObj.Id)
			continue
		}
		if err := shortcuts.DecryptStruct(&cipherObj, key); err != nil {
			fmt.Println("TODO: handle this error, cipher could not be decrypted")
			continue
		}

		if c.IsFlagPresent("organization") && !matchesOrganization(opts.ListOpts.Organization, &cipherObj, &allOrgs) {
			continue
		}
		if c.IsFlagPresent("folder") && !matchesFolder(opts.ListOpts.Folder, &cipherObj, &allFolders) {
			continue
		}
		if len(args) > 0 && !machesCriteria(args[0], &cipherObj) {
			continue
		}

		if err := shortcuts.DecryptStruct(&cipherObj.Login, key); err != nil {
			log.Fatalf("error decrypting cipher login data: %s", err)
		}

		attr := "all"
		if len(args) > 1 {
			attr = args[1]
		}
		switch attr {
		case "name":
			fmt.Println(cipherObj.Name)
		case "notes":
			fmt.Println(cipherObj.Notes)
		case "login.password":
			fmt.Println(cipherObj.Login.Password)
		case "login.username":
			fmt.Println(cipherObj.Login.Username)
		case "all":
			fmt.Println("Id:", cipherObj.Id)
			if cipherObj.Name != "" {
				fmt.Println("Name:", cipherObj.Name)
			}
			if cipherObj.Login.Username != "" {
				fmt.Println("Login-Username:", cipherObj.Login.Username)
			}

			if cipherObj.Login.Uri != "" {
				fmt.Println("Login-Uri:", cipherObj.Login.Uri)
			}

			if revealTotp && cipherObj.Login.Totp != "" {
				url, err := url.Parse(cipherObj.Login.Totp)
				if err == nil {
					totp, err := totpgen(NewTOTPSettingsFromURL(url.Query()))
					if err == nil {
						fmt.Println("Login-Totp:", totp)
					}
				} else {
					log.Fatalf("cannot generate totp")
				}
			}

			if revealPw && cipherObj.Login.Password != "" {
				fmt.Println("Login-Password:", cipherObj.Login.Password)
			}

			if cipherObj.Notes != "" {
				fmt.Println("Notes:", cipherObj.Notes)
			}
		case "login.totp":
			if cipherObj.Login.Totp == "" {
				fmt.Println("no totp for this entry")
				return nil
			}

			url, err := url.Parse(cipherObj.Login.Totp)
			if err != nil {
				log.Fatalf("invalid totp uri: %s", cipherObj.Login.Totp)
			}
			totp, err := totpgen(NewTOTPSettingsFromURL(url.Query()))
			if err != nil {
				log.Fatalf("invalid totp uri: %s", err)
			}

			fmt.Println(totp)
		default:
			log.Fatalf("unknown field: %s", attr)
		}
	}
	return nil
}
