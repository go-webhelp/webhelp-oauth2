// Copyright (C) 2014 JT Olds
// See LICENSE for copying information

package oauth2

import (
	"crypto/rand"
	"encoding/hex"
)

// RedirectURLs contains a collection of URLs to redirect to in a variety
// of cases
type RedirectURLs struct {
	// If a login URL isn't provided to redirect to after successful login, use
	// this one.
	DefaultLoginURL string

	// If a logout URL isn't provided to redirect to after successful logout, use
	// this one.
	DefaultLogoutURL string
}

func newState() string {
	var p [16]byte
	_, err := rand.Read(p[:])
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(p[:])
}
