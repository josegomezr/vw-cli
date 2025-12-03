package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/josegomezr/vw-cli/internal/api"
	"github.com/josegomezr/vw-cli/internal/crypto"
	"github.com/josegomezr/vw-cli/internal/symmetric_key"
	"github.com/josegomezr/vw-cli/internal/utils"
)

// TODO: split this into separate files & packages
type VWConfig struct {
	BitwardenURL string `json:"bitwarden-url"`
	ClientId     string `json:"client-id"`
	ClientSecret string `json:"client-secret"`
	Email        string `json:"email"`
	Password     string `json:"password"`
}

type VWState struct {
	AccessToken         string           `json:"access_token"`
	ExpiresAtEpoch      int64            `json:"expires_at_epoch"`
	ExpiresIn           int64            `json:"expires_in"`
	Kdf                 int64            `json:"Kdf"`
	KdfIterations       int64            `json:"KdfIterations"`
	KdfMemory           string           `json:"KdfMemory"`
	KdfParallelism      string           `json:"KdfParallelism"`
	Key                 string           `json:"Key"`
	PrivateKey          string           `json:"PrivateKey"`
	ResetMasterPassword bool             `json:"ResetMasterPassword"`
	LatestSync          api.SyncResponse `json:"latest_sync"`
}

type VW struct {
	cfgdir        string
	cfg           *VWConfig
	state         *VWState
	userKey       symmetric_key.SymmetricKey
	asymmetricKey symmetric_key.SymmetricKey
	allkeys       map[string]symmetric_key.SymmetricKey
}

// TODO: bring here a proper http client that takes care of the auth using the
// transport interface.

func (vw *VW) Login() (err error) {
	if vw == nil {
		return fmt.Errorf("not initialized")
	}

	if vw.cfg == nil {
		return fmt.Errorf("not configured")
	}

	if vw.state != nil {
		exp := time.Unix(vw.state.ExpiresAtEpoch, 0)

		if time.Now().Before(exp) {
			return nil
		}
	} else {
		vw.state = &VWState{}
	}

	uri := "/identity/connect/token"
	bwUrl := vw.cfg.BitwardenURL + uri

	qs := url.Values{}
	qs.Set("grant_type", "client_credentials")
	qs.Set("scope", "api")
	qs.Set("device_identifier", "vw-cli")
	qs.Set("device_name", "vw-cli name")
	qs.Set("device_type", "CLI")
	qs.Set("client_id", vw.cfg.ClientId)
	qs.Set("client_secret", vw.cfg.ClientSecret)

	resp, err := http.PostForm(bwUrl, qs)

	if err != nil {
		return fmt.Errorf("http-error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		io.Copy(os.Stdout, resp.Body)
		return fmt.Errorf("http-error-not-200")
	}

	if err := json.NewDecoder(resp.Body).Decode(vw.state); err != nil {
		io.Copy(os.Stdout, resp.Body)
		return fmt.Errorf("error-decode-state: %w", err)
	}

	// TODO: Extract this into SaveState()
	file, err := os.Create(vw.cfgdir + "state.file")
	if err != nil {
		return fmt.Errorf("error-state-file: %w", err)
	}
	defer file.Close()
	vw.state.ExpiresAtEpoch = time.Now().Add(time.Duration(vw.state.ExpiresIn) * time.Second).Unix()
	if err := json.NewEncoder(file).Encode(vw.state); err != nil {
		return fmt.Errorf("error-flush-state: %w", err)
	}

	syncObj, err := vw.Sync()
	if err != nil {
		return fmt.Errorf("sync-state: %w", err)
	}

	vw.state.LatestSync = *syncObj

	file.Seek(0, 0)
	if err := json.NewEncoder(file).Encode(vw.state); err != nil {
		return fmt.Errorf("error-flush-state: %w", err)
	}

	return nil
}

func (vw *VW) LoadConfig() error {
	if vw == nil {
		return fmt.Errorf("not initialized")
	}

	file, err := os.Open(vw.cfgdir + "config.config")
	if err != nil {
		return fmt.Errorf("error-open-config-file: %w", err)
	}
	defer file.Close()

	cfg := VWConfig{}

	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return fmt.Errorf("error-decode-config-file: %w", err)
	}

	vw.cfg = &cfg
	return nil
}

func (vw *VW) LoadState() error {
	state := &VWState{}
	vw.state = state

	file, err := os.Open(vw.cfgdir + "state.file")
	if err != nil {
		if err == io.EOF || os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("error-open: %w", err)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(state); err != nil {
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("error-decode: %w", err)
	}

	return nil
}

func (vw *VW) DecryptUserKey() error {
	masterkey, err := deriveDecryptionKeyFromEmailPassword(
		vw.state.LatestSync.Profile.Email,
		vw.cfg.Password,
	)
	if err != nil {
		return err
	}
	{
		encsymkey, err := crypto.NewEncStringFrom(vw.state.Key)
		if err != nil {
			return err
		}

		key, err := symmetric_key.AES_CBC_256_HMAC_decrypt(masterkey.Encryption(), masterkey.Authentication(), encsymkey.IV(), encsymkey.Data(), encsymkey.MAC())
		if err != nil {
			return err
		}

		symkey, err := symmetric_key.NewSymmetricKey(key)
		if err != nil {
			return err
		}
		vw.userKey = symkey
	}
	{
		encsymkey, err := crypto.NewEncStringFrom(vw.state.PrivateKey)
		if err != nil {
			return err
		}

		key, err := symmetric_key.AES_CBC_256_HMAC_decrypt(vw.userKey.Encryption(), vw.userKey.Authentication(), encsymkey.IV(), encsymkey.Data(), encsymkey.MAC())
		if err != nil {
			return err
		}

		symkey, err := symmetric_key.NewSymmetricKey(key)
		if err != nil {
			return err
		}
		vw.asymmetricKey = symkey
	}

	return nil
}

func (vw *VW) DecryptOrganizationKeys() error {
	if vw.allkeys == nil {
		vw.allkeys = make(map[string]symmetric_key.SymmetricKey)
	}
	vw.allkeys[""] = vw.userKey

	for _, orgObj := range vw.state.LatestSync.Profile.Organizations {
		encsymkey, err := crypto.NewEncStringFrom(orgObj.Key)
		if err != nil {
			return err
		}

		key, err := symmetric_key.RSA_2048_OAEP_SHA_1_decrypt(vw.asymmetricKey.Encryption(), encsymkey.Data())
		if err != nil {
			return err
		}

		symkey, err := symmetric_key.NewSymmetricKey(key)
		if err != nil {
			return err
		}

		vw.allkeys[orgObj.Id] = symkey

	}
	return nil
}

func main() {
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

// TODO: separate this into file/packages.

func (vw *VW) ListFolders() ([]api.FolderObject, error) {
	bwUrl := vw.cfg.BitwardenURL + "/api/folders"

	req, err := http.NewRequest("GET", bwUrl, nil)
	req.Header.Add("Authorization", "Bearer "+vw.state.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http-error: %w", err)
	}
	defer resp.Body.Close()

	r := &api.FoldersResponse{}
	if err := json.NewDecoder(resp.Body).Decode(r); err != nil {
		return nil, fmt.Errorf("error-decode-state: %w", err)
	}
	return r.Data, nil
}

func (vw *VW) Sync() (*api.SyncResponse, error) {
	bwUrl := vw.cfg.BitwardenURL + "/api/sync"

	req, err := http.NewRequest("GET", bwUrl, nil)
	req.Header.Add("Authorization", "Bearer "+vw.state.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		io.Copy(os.Stdout, resp.Body)
		return nil, fmt.Errorf("http-error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(os.Stdout, resp.Body)
		return nil, fmt.Errorf("bad status code for sync")
	}
	return api.NewSyncResponseFromReader(resp.Body)
}
