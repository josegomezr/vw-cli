package main

import (
	"fmt"
	"log"
	"strings"
	"os"
	"flag"
	"github.com/josegomezr/vw-cli/internal/crypto"
	"github.com/josegomezr/vw-cli/internal/utils"
)


type CLIOpts struct {
	ConfigDir string
	Password string
	MasterPassword string
}

func argParse() *CLIOpts {
	return nil
}

var flagvar int
var GLOBAL_VW *VW
func init() {
	flag.IntVar(&flagvar, "n", 1234, "help message for flag n")
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

	flag.Parse()
	cmd := flag.Arg(0)

	switch cmd {
	case "":
		fallthrough
	case "help":
		flag.Usage()
		return
	case "show":
		doShow(flag.Arg(1), flag.Arg(2))
		return
	default:
		log.Printf("Unknown command: %s", cmd)
		os.Exit(1)
		return
	}
}

func doShow(attr, id string){
	// log.Printf("Showing %s of secret %s", attr, id)

	if err := GLOBAL_VW.DecryptUserKey(); err != nil {
		log.Fatalf("error-decrypt: %s", err)
	}

	if err := GLOBAL_VW.DecryptOrganizationKeys(); err != nil {
		log.Fatalf("error-org-decrypt: %s", err)
	}

	for _, cipherObj := range GLOBAL_VW.state.LatestSync.Ciphers {
		if id != cipherObj.Id {
			continue
		}
		key, ok := GLOBAL_VW.allkeys[cipherObj.OrganizationId]
		if !ok {
			fmt.Printf("%s,%s,%s\n", cipherObj.Id, "TODO:no key known ", "~")
			break
		}

		encryptedAttr := ""
		switch attr {
		case "password":
			encryptedAttr = cipherObj.Login.Password
		case "username":
			encryptedAttr = cipherObj.Login.Username
		default:
			log.Fatalf("Unknown attribute %s", attr)
			return
		}

		decryptedName, err := key.DecryptString(utils.Must2(crypto.NewEncStringFrom(encryptedAttr)))
		if err != nil {
			fmt.Printf("%s,%s,%s\n", cipherObj.Id, "TODO:cannot decrypt this yet", "~")
			break
		}
		fmt.Printf(decryptedName)
		return
		_ = strings.Contains
		// if strings.Contains(decryptedName, strings.ToLower(id))
	}

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
