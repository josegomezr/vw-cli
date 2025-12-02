package api

import (
	"encoding/json"
	"fmt"
	"io"
)

type FoldersResponse struct {
	Data []FolderObject `json:"data"`
}

func NewFoldersResponseFromReader(rdr io.Reader) (*FoldersResponse, error) {
	r := &FoldersResponse{}
	if err := json.NewDecoder(rdr).Decode(r); err != nil {
		return nil, fmt.Errorf("error-decode-state: %w", err)
	}
	return r, nil
}
