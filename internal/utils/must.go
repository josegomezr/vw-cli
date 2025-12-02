package utils

import ()

func Must2[T any](a T, b error) T {
	if b != nil {
		panic(b)
	}
	return a
}
