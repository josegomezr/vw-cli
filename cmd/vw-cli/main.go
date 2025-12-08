package main

import (
	"flag"
	"fmt"
	"github.com/josegomezr/vw-cli/internal/crypto"
	"github.com/josegomezr/vw-cli/internal/symmetric_key"
	"github.com/josegomezr/vw-cli/internal/utils"
	"log"
	"net/url"
	"os"
	"reflect"
)

var GLOBAL_VW *VW

func init() {
	GLOBAL_VW = &VW{}
}

func main() {
	cfgdir := "./state-files/"

	GLOBAL_VW.cfgdir = cfgdir

	if err := GLOBAL_VW.LoadConfig(); err != nil {
		log.Fatalf("error-load-config: %s", err)
	}

	if err := GLOBAL_VW.LoadState(); err != nil {
		log.Fatalf("error-load-state: %s", err)
	}

	globalflagset := flag.NewFlagSet("vw-cli", flag.ExitOnError)
	globalflagset.Parse(os.Args[1:])
	cmd := globalflagset.Arg(0)

	switch cmd {
	case "":
		fallthrough
	case "help":
		globalflagset.Usage()
		return
	case "show":
		doShow(os.Args[2:])
		return
	case "ls":
		doList(os.Args[2:])
		return
	default:
		log.Printf("Unknown command: %s", cmd)
		os.Exit(1)
		return
	}
}

func doList(args []string) {
	defaultFolder := "-no-folder-set-really-im-too-lazy-to-make-this-right-"

	orgIdorName := ""
	help := false
	showFlagSet := flag.NewFlagSet("list", flag.ExitOnError)
	folderPtr := showFlagSet.String("folder", defaultFolder, "folder id or name")
	showFlagSet.StringVar(folderPtr, "f", defaultFolder, "folder id or name")

	showFlagSet.BoolVar(&help, "h", false, "help")
	showFlagSet.BoolVar(&help, "help", false, "help")
	showFlagSet.StringVar(&orgIdorName, "org", "", "folder id or name")
	showFlagSet.Parse(args)

	if help {
		showFlagSet.Usage()
	}

	if err := GLOBAL_VW.DecryptUserKey(); err != nil {
		log.Fatalf("error-decrypt: %s", err)
	}

	if err := GLOBAL_VW.DecryptOrganizationKeys(); err != nil {
		log.Fatalf("error-org-decrypt: %s", err)
	}

	orgs := make(map[string]string)
	folders := make(map[string]string)
	folders[""] = ""

	for _, folderObj := range GLOBAL_VW.state.LatestSync.Folders {
		folderName := utils.Must2(GLOBAL_VW.userKey.DecryptString(utils.Must2(crypto.NewEncStringFrom(folderObj.Name))))
		folders[folderName] = folderName
		folders[folderObj.Id] = folderName
	}

	for _, orgObj := range GLOBAL_VW.state.LatestSync.Profile.Organizations {
		orgName := orgObj.Name
		orgs[orgName] = orgName
		orgs[orgObj.Id] = orgName
	}

	for _, cipherObj := range GLOBAL_VW.state.LatestSync.Ciphers {
		key, ok := GLOBAL_VW.allkeys[cipherObj.OrganizationId]
		if !ok {
			log.Printf("Cannot decrypt ciphjer %s, skipping", cipherObj.Id)
			continue
		}

		encryptedAttr := cipherObj.Name
		decryptedAttr, err := key.DecryptString(utils.Must2(crypto.NewEncStringFrom(encryptedAttr)))
		if err != nil {
			fmt.Printf("%s,%s,%s\n", cipherObj.Id, "TODO:cannot decrypt this yet", "~")
			break
		}

		if orgIdorName != "" {
			cipherOrg, ok := orgs[cipherObj.OrganizationId]
			if !ok {
				continue
			}
			if orgIdorName == cipherObj.OrganizationId || orgIdorName == cipherOrg {
				fmt.Printf("%s %s/%s\n", cipherObj.Id, folders[cipherObj.FolderId], decryptedAttr)
				continue
			}
		}

		if *folderPtr == defaultFolder {
			fmt.Printf("%s %s/%s\n", cipherObj.Id, folders[cipherObj.FolderId], decryptedAttr)
		} else {
			cipherFolder, ok := folders[cipherObj.FolderId]
			if !ok {
				continue
			}

			if *folderPtr == cipherObj.FolderId || *folderPtr == cipherFolder {
				fmt.Printf("%s %s/%s\n", cipherObj.Id, folders[cipherObj.FolderId], decryptedAttr)
			}
		}
	}
}

func doShow(args []string) {
	showFlagSet := flag.NewFlagSet("list", flag.ExitOnError)
	revealPw := false
	revealTotp := false
	showFlagSet.BoolVar(&revealPw, "with-password", false, "reveal password")
	showFlagSet.BoolVar(&revealTotp, "with-totp", false, "reveal password")
	showFlagSet.Parse(args)

	id := showFlagSet.Arg(0)
	attr := showFlagSet.Arg(1)

	if id == "" {
		log.Fatalf("Missing ID")
	}

	if attr == "" {
		attr = "all"
	}

	if err := GLOBAL_VW.DecryptUserKey(); err != nil {
		log.Fatalf("error-decrypt: %s", err)
	}

	if err := GLOBAL_VW.DecryptOrganizationKeys(); err != nil {
		log.Fatalf("error-org-decrypt: %s", err)
	}

	for _, cipherObj := range GLOBAL_VW.state.LatestSync.Ciphers {
		key, ok := GLOBAL_VW.allkeys[cipherObj.OrganizationId]
		if !ok {
			log.Printf("Cannot decrypt ciphjer %s, skipping", cipherObj.Id)
			continue
		}

		decryptedName, err := key.DecryptString(utils.Must2(crypto.NewEncStringFrom(cipherObj.Name)))
		if err != nil {
			log.Fatalf("err: %s", err)
		}
		if !(id == cipherObj.Id || decryptedName == id) {
			continue
		}

		if err := decryptStruct(&cipherObj, key); err != nil {
			log.Fatalf("error decrypting cipher: %s", err)
		}
		if err := decryptStruct(&cipherObj.Login, key); err != nil {
			log.Fatalf("error decrypting cipher: %s", err)
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
				fmt.Println(cipherObj.Login.Totp)
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
}

func decryptStruct(daStruct any, sk symmetric_key.SymmetricKey) error {
	val := reflect.ValueOf(daStruct).Elem()

	for _, field := range reflect.VisibleFields(val.Type()) {
		res := field.Tag.Get("encryptedString")
		if res != "true" {
			continue
		}

		structMem := val.FieldByIndex(field.Index)
		newval := ""
		if curval := structMem.String(); curval != "" {
			encstr, err := crypto.NewEncStringFrom(curval)
			if err != nil {
				return err
			}
			dec, err := sk.DecryptString(encstr)
			if err != nil {
				return err
			}
			newval = dec
		}
		structMem.Set(reflect.ValueOf(newval))
	}
	return nil
}

func main2() {
	cfgdir := "./state-files/"

	vw := &VW{
		cfgdir: cfgdir,
	}

	if err := vw.LoadConfig(); err != nil {
		log.Fatalf("error-load-config: %s", err)
	}

	if err := vw.LoadState(); err != nil {
		log.Fatalf("error-load-state: %s", err)
	}

	if err := vw.Login(); err != nil {
		log.Fatalf("error-login: %s", err)
	}

	if err := vw.DecryptUserKey(); err != nil {
		log.Fatalf("error-decrypt: %s", err)
	}

	if err := vw.DecryptOrganizationKeys(); err != nil {
		log.Fatalf("error-org-decrypt: %s", err)
	}

	folders := make(map[string]string)
	{
		// Folder cache
		folders[""] = "-"
		for _, folderObj := range vw.state.LatestSync.Folders {
			folder := utils.Must2(vw.userKey.DecryptString(utils.Must2(crypto.NewEncStringFrom(folderObj.Name))))
			folders[folderObj.Id] = folder
		}
	}

	// List all secrets
	{
		fmt.Printf("%s,%s,%s,%s\n", "ID", "Folder", "Name", "Password")
		for _, cipherObj := range vw.state.LatestSync.Ciphers {
			key, ok := vw.allkeys[cipherObj.OrganizationId]
			if !ok {
				fmt.Printf("%s,%s,%s,%s\n", cipherObj.Id, folders[cipherObj.FolderId], "TODO:no key known ", "~")
				continue
			}
			cipher, err := key.DecryptString(utils.Must2(crypto.NewEncStringFrom(cipherObj.Name)))
			if err != nil {
				fmt.Printf("%s,%s,%s,%s\n", cipherObj.Id, folders[cipherObj.FolderId], "TODO:cannot decrypt this yet", "~")
				continue
			}

			pw := "-not-yet-"

			if pwR := cipherObj.Login.Password; pwR != "" {
				pw = utils.Must2(key.DecryptString(utils.Must2(crypto.NewEncStringFrom(cipherObj.Login.Password))))
			}

			fmt.Printf("%s,%s,%s,%s\n", cipherObj.Id, folders[cipherObj.FolderId], cipher, pw)
		}
	}
}
