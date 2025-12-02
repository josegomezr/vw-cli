package api

import (
	"encoding/json"
	"fmt"
	"io"
)

type SyncResponse struct {
	Ciphers     []CipherObject     `json:"ciphers"`
	Collections []CollectionObject `json:"collections"`
	Folders     []FolderObject     `json:"folders"`
	Object      string             `json:"object"`
	Profile     ProfileObject      `json:"profile"`
}

func NewSyncResponseFromReader(rdr io.Reader) (*SyncResponse, error) {
	r := &SyncResponse{}
	if err := json.NewDecoder(rdr).Decode(r); err != nil {
		return nil, fmt.Errorf("error-decode-state: %w", err)
	}
	return r, nil
}
