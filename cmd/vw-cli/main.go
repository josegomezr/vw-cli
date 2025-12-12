package main

import (
	"fmt"
	"github.com/josegomezr/vw-cli/internal/api"
	"github.com/josegomezr/vw-cli/internal/crypto"
	"github.com/josegomezr/vw-cli/internal/crypto/shortcuts"
	"github.com/josegomezr/vw-cli/internal/symmetric_key"
	"log"
	"net/url"
	"os"
)

var GLOBAL_VW *VW

const DefaultEmptyStringValue = "\x00"

func init() {
	GLOBAL_VW = &VW{}
}

func main() {
	opts, err := ParseArgs(os.Args[1:])
	if err != nil {
		log.Fatalf("Error parsing args: %s", err)
	}
	GLOBAL_VW.cfgdir = opts.ConfigDir
	GLOBAL_VW.LoadConfig()
	GLOBAL_VW.LoadState()

	session := opts.SessionToken
	if env_sess := os.Getenv("VW_SESSION"); env_sess != "" {
		session = env_sess
	}

	hasDecryptedSessionKey := false
	if err := GLOBAL_VW.LoadSessionKey(session); err == nil {
		hasDecryptedSessionKey = true
	}

	switch opts.Command {
	case "help":
		return
	case "unlock":
		doUnlockCommand(opts, hasDecryptedSessionKey)
		return
	case "login":
		doLoginCommand(opts, hasDecryptedSessionKey)
		return
	case "list":
		doListCommand(opts, hasDecryptedSessionKey)
		return
	case "show":
		doShowCommand(opts, hasDecryptedSessionKey)
		return
	default:
		fmt.Printf("Unhandled command: %s\n", opts.Command)
		os.Exit(1)
	}
}

func loadkeys(hasDecryptedSessionKey bool) {
	if !hasDecryptedSessionKey {
		masterPassword := askPass("Master password: ")
		if err := GLOBAL_VW.DecryptUserKeynew(masterPassword); err != nil {
			fmt.Println("Could not decrypt master key")
			os.Exit(1)
			return
		}
	}
	if err := GLOBAL_VW.DecryptUserAsymmetricKey(); err != nil {
		fmt.Println("Could not unlock the store (asymmetric key borkd)...")
		os.Exit(1)
		return
	}
	if err := GLOBAL_VW.DecryptOrganizationKeys(); err != nil {
		fmt.Println("Could not unlock the store (organization keys key borkd)...")
		os.Exit(1)
		return
	}
}

func doLoginCommand(opts *CLIOpts, hasDecryptedSessionKey bool) {
	if GLOBAL_VW.state.Email == "" {
		if opts.LoginOpts.ApiClientId != "" || opts.LoginOpts.ApiClientSecret != "" {
			fmt.Println("Log-in with API Credentials")
			if opts.LoginOpts.ApiClientSecret == "" {
				opts.LoginOpts.ApiClientSecret = askPass("API Secret: ")
			}

			err := GLOBAL_VW.LoginWithAPIKeys(opts.LoginOpts.ApiClientId, opts.LoginOpts.ApiClientSecret)
			if err != nil {
				fmt.Println("error:", err)
				os.Exit(1)
				return
			}

			fmt.Println("Logged in!")
		} else if opts.LoginOpts.Email != "" {
			fmt.Println("Log-in Email+Master password")
			if opts.LoginOpts.MasterPassword == "" {
				opts.LoginOpts.MasterPassword = askPass("User password: ")
			}
			err := GLOBAL_VW.LoginWithEmailPassword(opts.LoginOpts.Email, opts.LoginOpts.MasterPassword)
			if err != nil {
				fmt.Println("error:", err)
				os.Exit(1)
				return
			}
			fmt.Println("Logged in!")
		}
	} else {
		fmt.Println("Logged in as:", GLOBAL_VW.state.Email)
	}
}
func doListCommand(opts *CLIOpts, hasDecryptedSessionKey bool) {
	loadkeys(hasDecryptedSessionKey)
	orgs := make(map[string]string)
	folders := make(map[string]string)
	folders[""] = ""

	for _, folderObj := range GLOBAL_VW.state.LatestSync.Folders {
		if err := shortcuts.DecryptStruct(&folderObj, GLOBAL_VW.userKey); err != nil {
			fmt.Println("TODO: handle this error, folder could not be decrypted")
		}
		folders[folderObj.Name] = folderObj.Name
		folders[folderObj.Id] = folderObj.Name
	}

	for _, orgObj := range GLOBAL_VW.state.LatestSync.Profile.Organizations {
		orgName := orgObj.Name
		orgs[orgName] = orgName
		orgs[orgObj.Id] = orgName
	}

	for _, cipherObj := range GLOBAL_VW.state.LatestSync.Ciphers {
		key, ok := GLOBAL_VW.allkeys[cipherObj.OrganizationId]
		if !ok {
			log.Printf("Unknown organization key for cipher %s, skipping", cipherObj.Id)
			continue
		}
		if err := shortcuts.DecryptStruct(&cipherObj, key); err != nil {
			fmt.Println("TODO: handle this error, cipher could not be decrypted")
			continue
		}

		if opts.ListOpts.Organization != DefaultEmptyStringValue {
			cipherOrg, ok := orgs[cipherObj.OrganizationId]
			if !ok {
				continue
			}
			if opts.ListOpts.Organization == cipherObj.OrganizationId || opts.ListOpts.Organization == cipherOrg {
				fmt.Printf("%s|%s/%s|%s\n", cipherObj.Id, folders[cipherObj.FolderId], cipherObj.Name, orgs[cipherObj.OrganizationId])
				continue
			}
		}

		if opts.ListOpts.Folder == DefaultEmptyStringValue {
			fmt.Printf("%s|%s/%s|%s\n", cipherObj.Id, folders[cipherObj.FolderId], cipherObj.Name, orgs[cipherObj.OrganizationId])
		} else {
			cipherFolder, ok := folders[cipherObj.FolderId]
			if !ok {
				continue
			}

			if opts.ListOpts.Folder == cipherObj.FolderId || opts.ListOpts.Folder == cipherFolder {
				fmt.Printf("%s|%s/%s|%s\n", cipherObj.Id, folders[cipherObj.FolderId], cipherObj.Name, orgs[cipherObj.OrganizationId])
			}
		}
	}
}
func doShowCommand(opts *CLIOpts, hasDecryptedSessionKey bool) {
	loadkeys(hasDecryptedSessionKey)

	id := opts.ShowOpts.Cipher
	attr := opts.ShowOpts.Attribute
	revealTotp := opts.ShowOpts.WithTotp
	revealPw := opts.ShowOpts.WithPassword

	var foundCipher *api.CipherObject
	var key symmetric_key.SymmetricKey

	folders := make(map[string]string)
	for _, folderObj := range GLOBAL_VW.state.LatestSync.Folders {
		if err := shortcuts.DecryptStruct(&folderObj, GLOBAL_VW.userKey); err != nil {
			fmt.Println("TODO: handle this error, folder could not be decrypted")
		}
		folders[folderObj.Name] = folderObj.Name
		folders[folderObj.Id] = folderObj.Name
	}

	for _, cipherObj := range GLOBAL_VW.state.LatestSync.Ciphers {
		if wantedOrg := opts.ShowOpts.Organization; wantedOrg != DefaultEmptyStringValue {
			if wantedOrg != cipherObj.OrganizationId {
				continue
			}
		}

		if wantedFolder := opts.ShowOpts.Folder; wantedFolder != DefaultEmptyStringValue {
			_, ok := folders[cipherObj.FolderId]

			if !ok {
				continue
			}
		}

		ckey, ok := GLOBAL_VW.allkeys[cipherObj.OrganizationId]
		if !ok {
			log.Printf("Cannot decrypt cipher %s, skipping", cipherObj.Id)
			continue
		}

		if err := shortcuts.DecryptStruct(&cipherObj, ckey); err != nil {
			fmt.Println("TODO: handle this error, cipher could not be decrypted")
			fmt.Printf("%+v\n\n", cipherObj)
			continue
		}

		decryptedName := cipherObj.Name
		if !(id == cipherObj.Id || decryptedName == id) {
			continue
		}

		foundCipher = &cipherObj
		key = ckey
		break
	}

	if foundCipher == nil {
		log.Fatalf("Could not find cipher %q", id)
		os.Exit(1)
	}

	if err := shortcuts.DecryptStruct(&foundCipher.Login, key); err != nil {
		log.Fatalf("error decrypting cipher login data: %s", err)
	}

	switch attr {
	case "name":
		fmt.Println(foundCipher.Name)
	case "notes":
		fmt.Println(foundCipher.Notes)
	case "login.password":
		fmt.Println(foundCipher.Login.Password)
	case "login.username":
		fmt.Println(foundCipher.Login.Username)
	case "all":
		fmt.Println("Id:", foundCipher.Id)
		if foundCipher.Name != "" {
			fmt.Println("Name:", foundCipher.Name)
		}
		if foundCipher.Login.Username != "" {
			fmt.Println("Login-Username:", foundCipher.Login.Username)
		}

		if foundCipher.Login.Uri != "" {
			fmt.Println("Login-Uri:", foundCipher.Login.Uri)
		}

		if revealTotp && foundCipher.Login.Totp != "" {
			url, err := url.Parse(foundCipher.Login.Totp)
			if err == nil {
				totp, err := totpgen(NewTOTPSettingsFromURL(url.Query()))
				if err == nil {
					fmt.Println("Login-Totp:", totp)
				}
			} else {
				log.Fatalf("cannot generate totp")
			}
		}

		if revealPw && foundCipher.Login.Password != "" {
			fmt.Println("Login-Password:", foundCipher.Login.Password)
		}

		if foundCipher.Notes != "" {
			fmt.Println("Notes:", foundCipher.Notes)
		}
	case "login.totp":
		if foundCipher.Login.Totp == "" {
			fmt.Println("no totp for this entry")
			return
		}

		url, err := url.Parse(foundCipher.Login.Totp)
		if err != nil {
			log.Fatalf("invalid totp uri: %s", foundCipher.Login.Totp)
		}
		totp, err := totpgen(NewTOTPSettingsFromURL(url.Query()))
		if err != nil {
			log.Fatalf("invalid totp uri: %s", err)
		}

		fmt.Println(totp)
	default:
		log.Fatalf("unknown field: %s", attr)
	}
	return
}
func doUnlockCommand(opts *CLIOpts, hasDecryptedSessionKey bool) {
	if opts.UnlockOpts.Check {
		if !hasDecryptedSessionKey {
			fmt.Println("Locked!")
			os.Exit(1)
			return
		}
		fmt.Println("Unlocked!")
		return
	}
	if hasDecryptedSessionKey {
		switch opts.OutputFormat {
		case "plain":
			encodedKey := crypto.B64e(GLOBAL_VW.sessionKey.Encryption())
			fmt.Println("Make sure to export the following variable:")
			fmt.Printf("export VW_SESSION=%q\n", encodedKey)
			fmt.Printf("Or pass --session-token %q to the next vw-cli invocations\n", encodedKey)
		case "text":
			fmt.Println(crypto.B64e(GLOBAL_VW.sessionKey.Encryption()))
		}
		return
	}

	loadkeys(hasDecryptedSessionKey)
	if err := GLOBAL_VW.SaveSession(); err != nil {
		os.Exit(1)
	}
	switch opts.OutputFormat {
	case "plain":
		encodedKey := crypto.B64e(GLOBAL_VW.sessionKey.Encryption())
		fmt.Println("Make sure to export the following variable:")
		fmt.Printf("export VW_SESSION=%q\n", encodedKey)
		fmt.Printf("Or pass --session-token %q to the next vw-cli invocations\n", encodedKey)
	case "text":
		fmt.Println(crypto.B64e(GLOBAL_VW.sessionKey.Encryption()))
	}
}
