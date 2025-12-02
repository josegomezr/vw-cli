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
	AccessToken    string `json:"access_token"`
	ExpiresAtEpoch int64  `json:"expires_at_epoch"`
	ExpiresIn      int64  `json:"expires_in"`
	TokenType      string `json:"token_type"`
	Kdf            int64  `json:"Kdf"`
	KdfIterations  int64  `json:"KdfIterations"`
	// KdfMemory string `json:"KdfMemory"`
	// KdfParallelism string `json:"KdfParallelism"`
	Key                 string `json:"Key"`
	PrivateKey          string `json:"PrivateKey"`
	ResetMasterPassword bool   `json:"ResetMasterPassword"`
	Scope               string `json:"scope"`
	SessionKey          []byte `json:"session-key"`
}

type VW struct {
	cfgdir string
	cfg    *VWConfig
	state  *VWState
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
		return fmt.Errorf("http-error-not-200")
	}

	if err := json.NewDecoder(resp.Body).Decode(vw.state); err != nil {
		io.Copy(os.Stdout, resp.Body)
		return fmt.Errorf("error-decode-state: %w", err)
	}

	// TODO: Extract this into SaveState()

	// TODO: Pull the email out of the /api/accounts/profile endpoint to avoid
	// saving it on configs.

	file, err := os.Create(vw.cfgdir + "state.file")
	if err != nil {
		return fmt.Errorf("error-state-file: %w", err)
	}
	defer file.Close()
	vw.state.ExpiresAtEpoch = time.Now().Add(time.Duration(vw.state.ExpiresIn) * time.Second).Unix()

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
	file, err := os.Open(vw.cfgdir + "state.file")
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("error-open: %w", err)
	}

	state := VWState{}

	if err := json.NewDecoder(file).Decode(&state); err != nil {
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("error-decode: %w", err)
	}

	vw.state = &state
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

	masterkey, _ := deriveDecryptionKeyFromEmailPassword(
		vw.cfg.Email, // TODO: pull email out of /api/accounts/profile
		vw.cfg.Password,
	)

	privkey, err := ParseEncryptedString(vw.state.Key)
	if err != nil {
		panic(err)
	}

	// TODO: encapsulate all of this into a single fn to get all the way to the
	// symkey in a single call
	key, err := AES_CBC_256_decrypt(masterkey, privkey.IV(), privkey.Data())
	if err != nil {
		panic(err)
	}

	symkey, err := NewSymmetricKey(key)
	if err != nil {
		panic(err)
	}

	// TODO: Save folders & ciphers locally encrypted
	// TODO: Search after saved.

	folderIt, err := vw.ListFolders()
	if err != nil {
		panic(err)
	}

	for _, folderObj := range folderIt {
		encFolderName, err := ParseEncryptedString(folderObj.Name)
		if err != nil {
			panic(err)
		}
		folder, err := AES_CBC_256_decrypt(symkey.Encryption(), encFolderName.IV(), encFolderName.Data())
		if err != nil {
			panic(err)
		}
		fmt.Printf("---\nid: %s\nenc: %s\ndecr:%s\n...\n", folderObj.Id, folderObj.Name, string(folder))
	}
}

// TODO: separate this into file/packages.

type folderItem struct {
	Id     string `json:"id"`
	Name   string `json:"name"`
	Object string `json:"object"`
}

type foldersResp struct {
	Data []folderItem `json:"data"`
}

func (vw *VW) ListFolders() ([]folderItem, error) {
	bwUrl := vw.cfg.BitwardenURL + "/api/folders"

	req, err := http.NewRequest("GET", bwUrl, nil)
	req.Header.Add("Authorization", "Bearer "+vw.state.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http-error: %w", err)
	}
	defer resp.Body.Close()

	r := &foldersResp{}
	if err := json.NewDecoder(resp.Body).Decode(r); err != nil {
		return nil, fmt.Errorf("error-decode-state: %w", err)
	}
	return r.Data, nil
}
