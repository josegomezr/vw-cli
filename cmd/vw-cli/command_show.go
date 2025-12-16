package main

import (
	"fmt"
	"github.com/josegomezr/vw-cli/internal/api"
	"github.com/josegomezr/vw-cli/internal/command"
	"github.com/josegomezr/vw-cli/internal/crypto/shortcuts"
	"log"
	"net/url"
	"os"
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
	Name:    "show {secret-id-or-name} [attribute = all]",
	Summary: "Displays a secret identified by `secret-id-or-name`. A specific attribute can be provided as the second argument.",
	PreRun: func(c *command.Command) error {
		if len(c.Args()) < 1 {
			c.Usage()
			return fmt.Errorf("Missing `secret-id-or-name`")
		}
		return loadConfigStateAndKeys(c)
	},
	Run: doShowCommand,
}

func doShowCommand(c *command.Command, args []string) error {
	opts := CLIOPTS

	allOrgs, err := GlobalVW.AllOrganizations()
	if err != nil {
		fmt.Println("TODO: handle this error, folder could not be decrypted")
	}
	allFolders, err := GlobalVW.AllFolders()
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
		if len(criteria) > 0 && (cipherObj.Id == criteria || strings.Contains(strings.Join(fpieces, "/"), criteria)) {
			found = true
		}
		return
	}

	// it is guaranteed that we have at least one arg.
	searchCriteria := args[0]

	attr := "all"
	if len(args) > 1 {
		attr = args[1]
	}

	for _, cipherObj := range GlobalVW.AllCiphers() {
		key, ok := GlobalVW.KeyForOrg(cipherObj.OrganizationId)
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
		if !machesCriteria(searchCriteria, &cipherObj) {
			continue
		}
		if err := shortcuts.DecryptStruct(&cipherObj.Login, key); err != nil {
			log.Fatalf("error decrypting cipher login data: %s", err)
		}

		return showOutputText(&cipherObj, attr)
	}

	return fmt.Errorf("Secret `%s` not found", searchCriteria)
}

const protectedNeedle = "[PROTECTED]"

func showOutputTextAllAttrs(cipherObj *api.CipherObject) (err error) {
	revealTotp := CLIOPTS.ShowOpts.WithTotp
	revealTotpSource := CLIOPTS.ShowOpts.WithTotpSource
	revealPw := CLIOPTS.ShowOpts.WithPassword

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

	if cipherObj.Login.Totp != "" {
		if revealTotpSource {
			fmt.Println("Login-Totp-Source:", cipherObj.Login.Totp)
		}

		totp := protectedNeedle
		if revealTotp {
			url, daErr := url.Parse(cipherObj.Login.Totp)
			if daErr != nil {
				err = fmt.Errorf("Cannot generate OTP: %w", daErr)
				return
			}
			generatedTotp, daErr2 := totpgen(NewTOTPSettingsFromURL(url.Query()))
			if daErr2 != nil {
				err = fmt.Errorf("Cannot generate OTP: %w", daErr2)
				return
			}
			totp = generatedTotp
		}
		fmt.Println("Login-Totp:", totp)
	}

	if cipherObj.Login.Password != "" {
		pw := protectedNeedle
		if revealPw {
			pw = cipherObj.Login.Password
		}
		fmt.Println("Login-Password:", pw)
	}

	if cipherObj.Notes != "" {
		fmt.Println("Notes:", cipherObj.Notes)
	}
	return
}
func showOutputText(cipherObj *api.CipherObject, attr string) (err error) {
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
		showOutputTextAllAttrs(cipherObj)
	case "login.totp-source":
		fmt.Println(cipherObj.Login.Totp)
	case "login.totp":
		if cipherObj.Login.Totp == "" {
			return fmt.Errorf("No totp for this entry")
		}

		qs, daErr := shortcuts.QSFromURL(cipherObj.Login.Totp)
		if daErr != nil {
			err = daErr
			return
		}
		totp, daErr := totpgen(NewTOTPSettingsFromURL(qs))
		if daErr != nil {
			err = daErr
			return
		}

		fmt.Println(totp)
	default:
		err = fmt.Errorf("unknown field: %s", attr)
	}
	return
}
