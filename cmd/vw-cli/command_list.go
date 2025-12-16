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
	Run:     doList,
}

func doList(c *command.Command, args []string) error {
	opts := CLIOPTS

	vw := NewVW().WithConfigDir(opts.ConfigDir)
	vw.LoadConfigAndState()

	loadkeys(vw, opts.SessionToken)
	allOrgs, err := vw.AllOrganizations()
	if err != nil {
		fmt.Println("TODO: could not load orgs")
	}
	allFolders, err := vw.AllFolders()
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

		fmt.Printf("%s|%s|%s\n", cipherObj.Id, cipherObj.Name, allOrgs[cipherObj.OrganizationId])
	}
	return nil
}
