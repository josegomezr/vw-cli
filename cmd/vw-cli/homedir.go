package main

import (
	"os/user"
)

func homedir() string {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}
	return user.HomeDir
}
