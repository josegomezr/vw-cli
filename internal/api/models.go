package api

import (
// "github.com/josegomezr/vw-cli/internal/crypto"
)

type LoginObject struct {
	Password             string `json:"password" encryptedString:"true"`
	PasswordRevisionDate string `json:"passwordRevisionDate"`
	Totp                 string `json:"totp" encryptedString:"true"`
	Uri                  string `json:"uri" encryptedString:"true"`
	Username             string `json:"username" encryptedString:"true"`
}

type CipherObject struct {
	Id             string      `json:"id"`
	FolderId       string      `json:"folderId"`
	Name           string      `json:"name" encryptedString:"true"`
	Object         string      `json:"object"`
	OrganizationId string      `json:"organizationId"`
	Notes          string      `json:"notes" encryptedString:"true"`
	Login          LoginObject `json:"login"`
}

type CollectionObject struct {
	Id             string `json:"id"`
	Name           string `json:"name"`
	Object         string `json:"object"`
	OrganizationId string `json:"organizationId"`
}

type OrganizationObject struct {
	Id     string `json:"id"`
	Name   string `json:"name"`
	Object string `json:"object"`
	Key    string `json:"key"`
}

type FolderObject struct {
	Id     string `json:"id"`
	Name   string `json:"name"`
	Object string `json:"object"`
}

type ProfileObject struct {
	Id            string               `json:"id"`
	Name          string               `json:"name"`
	Object        string               `json:"object"`
	Key           string               `json:"key"`
	Email         string               `json:"email"`
	Organizations []OrganizationObject `json:"organizations"`
}
