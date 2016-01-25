// Copyright (C) 2014 JT Olds
// See LICENSE for copying information

package oauth2

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/linkedin"
)

type Config oauth2.Config

// Provider is a named *oauth2.Config
type Provider struct {
	Name string
	oauth2.Config
}

func Github(conf Config) *Provider {
	if conf.Endpoint.AuthURL == "" {
		conf.Endpoint = github.Endpoint
	}
	return &Provider{
		Name:   "github",
		Config: oauth2.Config(conf)}
}

func Google(conf Config) *Provider {
	if conf.Endpoint.AuthURL == "" {
		conf.Endpoint = google.Endpoint
	}
	return &Provider{
		Name:   "google",
		Config: oauth2.Config(conf)}
}

func Facebook(conf Config) *Provider {
	if conf.Endpoint.AuthURL == "" {
		conf.Endpoint = facebook.Endpoint
	}
	return &Provider{
		Name:   "facebook",
		Config: oauth2.Config(conf)}
}

func LinkedIn(conf Config) *Provider {
	if conf.Endpoint.AuthURL == "" {
		conf.Endpoint = linkedin.Endpoint
	}
	return &Provider{
		Name:   "linkedin",
		Config: oauth2.Config(conf)}
}
