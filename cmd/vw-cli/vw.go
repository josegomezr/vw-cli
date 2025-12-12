package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/josegomezr/vw-cli/internal/api"
	"github.com/josegomezr/vw-cli/internal/crypto"
	"github.com/josegomezr/vw-cli/internal/crypto/shortcuts"
	"github.com/josegomezr/vw-cli/internal/encryption_type"
	"github.com/josegomezr/vw-cli/internal/symmetric_key"
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
	Email               string           `json:"email"`
	SessionMasterPw     string           `json:"session_master_password"`
}

type VW struct {
	cfgdir        string
	cfg           *VWConfig
	state         *VWState
	sessionKey    symmetric_key.SymmetricKey
	userKey       symmetric_key.SymmetricKey
	asymmetricKey symmetric_key.SymmetricKey
	allkeys       map[string]symmetric_key.SymmetricKey
}

// TODO: bring here a proper http client that takes care of the auth using the
// transport interface.

func (vw *VW) LoginWithEmailPassword(email string, password string) (err error) {
	uri := "/identity/connect/token"
	bwUrl := vw.cfg.BitwardenURL + uri

	qs := url.Values{}
	qs.Set("grant_type", "password")
	qs.Set("scope", "api offline_access")
	qs.Set("username", email)
	qs.Set("password", password)
	qs.Set("device_identifier", "vw-cli") // TODO: make this a UUID and keep it in the state file
	qs.Set("device_name", "vw-cli")
	qs.Set("device_type", "CLI")
	qs.Set("client_id", "25") // 25 => DeviceType::LinuxCLI. TODO: use a custom id here

	fmt.Println(qs)
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

	vw.state.ExpiresAtEpoch = time.Now().Add(time.Duration(vw.state.ExpiresIn) * time.Second).Unix()
	if err := vw.SaveState(); err != nil {
		return fmt.Errorf("error-state-file: %w", err)
	}
	syncObj, err := vw.Sync()
	if err != nil {
		return fmt.Errorf("sync-state: %w", err)
	}

	vw.state.LatestSync = *syncObj

	if err := vw.SaveState(); err != nil {
		return fmt.Errorf("error-state-file: %w", err)
	}
	return nil
}

func (vw *VW) SaveState() (err error) {
	file, err := os.Create(filepath.Join(vw.cfgdir, "state.file"))
	if err != nil {
		return fmt.Errorf("error-state-file: %w", err)
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(vw.state); err != nil {
		return fmt.Errorf("error-flush-state: %w", err)
	}
	return
}

func (vw *VW) LoginWithAPIKeys(clientId, clientSecret string) (err error) {
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
	qs.Set("client_id", clientId)
	qs.Set("client_secret", clientSecret)

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

	vw.state.ExpiresAtEpoch = time.Now().Add(time.Duration(vw.state.ExpiresIn) * time.Second).Unix()
	if err := vw.SaveState(); err != nil {
		return fmt.Errorf("error-state-file: %w", err)
	}

	syncObj, err := vw.Sync()
	if err != nil {
		return fmt.Errorf("sync-state: %w", err)
	}

	vw.state.LatestSync = *syncObj
	vw.state.Email = vw.state.LatestSync.Profile.Email

	if err := vw.SaveState(); err != nil {
		return fmt.Errorf("error-state-file: %w", err)
	}

	return nil
}

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
	vw.state.ExpiresAtEpoch = time.Now().Add(time.Duration(vw.state.ExpiresIn) * time.Second).Unix()

	if err := vw.SaveState(); err != nil {
		return fmt.Errorf("error-state-file: %w", err)
	}

	syncObj, err := vw.Sync()
	if err != nil {
		return fmt.Errorf("sync-state: %w", err)
	}

	vw.state.LatestSync = *syncObj

	if err := vw.SaveState(); err != nil {
		return fmt.Errorf("error-state-file: %w", err)
	}
	return nil
}

func (vw *VW) LoadConfig() error {
	if vw == nil {
		return fmt.Errorf("not initialized")
	}

	file, err := os.Open(filepath.Join(vw.cfgdir, "config.config"))
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

	file, err := os.Open(filepath.Join(vw.cfgdir, "state.file"))
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

func (vw *VW) DecryptUserKeynew(masterpassword string) error {
	if vw == nil {
		return fmt.Errorf("not initialized")
	}

	masterkey, err := deriveDecryptionKeyFromEmailPassword(
		vw.state.Email,
		masterpassword,
	)
	if err != nil {
		return err
	}

	symkey, err := shortcuts.DecryptSymmetricKey(masterkey, vw.state.Key)
	if err != nil {
		return err
	}
	vw.userKey = symkey

	return nil
}

func (vw *VW) DecryptUserAsymmetricKey() error {
	if vw.userKey == nil {
		return fmt.Errorf("no user key available")
	}

	symkey, err := shortcuts.DecryptSymmetricKey(vw.userKey, vw.state.PrivateKey)
	if err != nil {
		return err
	}
	vw.asymmetricKey = symkey
	return nil
}

func (vw *VW) DecryptUserKey() error {
	if vw == nil {
		return fmt.Errorf("not initialized")
	}
	if vw.userKey != nil {
		return nil
	}

	masterkey, err := deriveDecryptionKeyFromEmailPassword(
		vw.state.Email,
		vw.cfg.Password,
	)
	if err != nil {
		return err
	}

	symkey, err := shortcuts.DecryptSymmetricKey(masterkey, vw.state.Key)
	if err != nil {
		return err
	}
	vw.userKey = symkey

	privKey, err := shortcuts.DecryptSymmetricKey(vw.userKey, vw.state.PrivateKey)
	if err != nil {
		return err
	}
	vw.asymmetricKey = privKey

	return nil
}

func (vw *VW) GenerateSessionKey() symmetric_key.SymmetricKey {
	buf := make([]byte, 32)
	rand.Read(buf)
	k, err := symmetric_key.NewSymmetricKeyCtor(buf, encryption_type.AES_GCM_256_B64)
	if err != nil {
		fmt.Println("this should really never fail")
		panic(err)
	}
	return k
}

func (vw *VW) LoadSessionKey(sessionkey string) error {
	if sessionkey == "" {
		simkey := vw.GenerateSessionKey()
		vw.sessionKey = simkey
	} else {
		buf, err := crypto.B64d(sessionkey)
		if err != nil {
			return err
		}
		simkey, err := symmetric_key.NewSymmetricKeyCtor(buf, encryption_type.AES_GCM_256_B64)
		if err != nil {
			simkey = vw.GenerateSessionKey()
		}
		vw.sessionKey = simkey
	}

	userKey, err := shortcuts.DecryptSymmetricKey(vw.sessionKey, vw.state.SessionMasterPw)
	if err != nil {
		return err
	}
	vw.userKey = userKey
	return nil
}

func (vw *VW) DecryptOrganizationKeys() error {
	if vw == nil || vw.userKey == nil {
		return fmt.Errorf("not initialized")
	}

	if vw.allkeys == nil {
		vw.allkeys = make(map[string]symmetric_key.SymmetricKey)
	}
	vw.allkeys[""] = vw.userKey

	for _, orgObj := range vw.state.LatestSync.Profile.Organizations {
		symkey, err := shortcuts.DecryptSymmetricKeyCtor(vw.asymmetricKey, orgObj.Key, encryption_type.AES_CBC_256_HMAC_SHA_256_B64)
		if err != nil {
			return err
		}
		vw.allkeys[orgObj.Id] = symkey

	}
	return nil
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
