package main

import (
	"fmt"
	"github.com/josegomezr/vw-cli/internal/api"
	"github.com/josegomezr/vw-cli/internal/command"
	"github.com/josegomezr/vw-cli/internal/crypto/shortcuts"
	"log"
	"os"
	"strings"
)

func init() {
	ListCommand.Flags().StringVar(&CLIOPTS.ListOpts.Folder, "folder", DefaultEmptyStringValue, "`folder` id or name")
	ListCommand.Flags().StringVar(&CLIOPTS.ListOpts.Organization, "organization", DefaultEmptyStringValue, "`organization` id or name")
}

var ListCommand = &command.Command{
	Name:    "list [search-criteria]",
	Summary: "List all secrets in the vault",
	PreRun:  loadConfigStateAndKeys,
	Run:     doList,
}

var headerPrinted = false

func doList(c *command.Command, args []string) error {
	opts := CLIOPTS

	allOrgs, err := GlobalVW.AllOrganizations()
	if err != nil {
		fmt.Println("TODO: could not load orgs")
	}
	allFolders, err := GlobalVW.AllFolders()
	if err != nil {
		fmt.Println("TODO: could not load folders")
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
		if len(args) > 0 && !machesCriteria(args[0], &cipherObj) {
			continue
		}

		if cipherObj.FolderId != "" {
			if folderName, ok := allFolders[cipherObj.FolderId]; ok {
				cipherObj.FolderName = folderName
			}
		}

		if cipherObj.OrganizationId != "" {
			if orgName, ok := allOrgs[cipherObj.OrganizationId]; ok {
				cipherObj.OrganizationName = orgName
			}
		}

		switch CLIOPTS.OutputFormat {
		case "csv":
			listOutputCsv(&cipherObj)
		case "text":
			listOutputText(&cipherObj)
		case "plain":
			fallthrough
		default:
			listOutputPlain(&cipherObj)
		}
	}
	return nil
}

func listOutputText(decryptedCipher *api.CipherObject) {
	fmt.Println("---")
	fmt.Println("Id:", decryptedCipher.Id)
	fmt.Println("Name:", decryptedCipher.Name)
	if decryptedCipher.FolderId != "" {
		fmt.Printf("Folder: %s (%s)\n", decryptedCipher.FolderName, decryptedCipher.FolderId)
	}
	if decryptedCipher.OrganizationId != "" {
		fmt.Printf("Organization: %s (%s)\n", decryptedCipher.OrganizationName, decryptedCipher.OrganizationId)
	}
	fmt.Println("...")
}

func listOutputPlain(decryptedCipher *api.CipherObject) {
	name := decryptedCipher.Name
	if decryptedCipher.FolderName != "" {
		name = fmt.Sprintf("%s/%s", decryptedCipher.FolderName, decryptedCipher.Name)
	}
	fmt.Printf("%s %s", decryptedCipher.Id, name)
	if decryptedCipher.OrganizationId != "" {
		fmt.Printf(" (%s: %s)", decryptedCipher.OrganizationName, decryptedCipher.OrganizationId)
	}
	fmt.Println()
}

func listOutputCsv(decryptedCipher *api.CipherObject) {
	if !headerPrinted {
		headerPrinted = true
		fmt.Println("id,name,folder-id,folder,organziation-id,organization")
	}
	fmt.Printf("%s,%s,%s,%s,%s,%s\n", decryptedCipher.Id, decryptedCipher.Name, decryptedCipher.FolderId, decryptedCipher.FolderName, decryptedCipher.OrganizationId, decryptedCipher.OrganizationName)
}
