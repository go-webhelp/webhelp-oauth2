// Copyright (C) 2016 JT Olds
// See LICENSE for copying information

// This example shows how to set up a web service that allows users to log in
// via one single OAuth2 Provider
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"

	"github.com/jtolds/webhelp"
	"github.com/jtolds/webhelp-oauth2"
	"github.com/jtolds/webhelp/sessions"
	"golang.org/x/net/context"
)

var (
	listenAddr   = flag.String("addr", ":8080", "address to listen on")
	cookieSecret = flag.String("cookie_secret", "abcdef0123456789",
		"the secret for securing cookie information")

	githubClientId     = flag.String("github_client_id", "", "")
	githubClientSecret = flag.String("github_client_secret", "", "")
)

type SampleHandler struct {
	Prov       *oauth2.ProviderHandler
	Restricted bool
}

func (s *SampleHandler) HandleHTTP(ctx context.Context,
	w webhelp.ResponseWriter, r *http.Request) error {
	t, err := s.Prov.Token(ctx)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html")
	if s.Restricted {
		fmt.Fprintf(w, `<h3>Restricted</h3>`)
	}
	if t != nil {
		fmt.Fprintf(w, `
		  <p>Logged in | <a href="%s">Log out</a></p>
	  `, s.Prov.LogoutURL("/"))
	} else {
		fmt.Fprintf(w, `
		  <p><a href="%s">Log in</a> | Logged out</p>
	  `, s.Prov.LoginURL(r.RequestURI, false))
	}
	if !s.Restricted {
		fmt.Fprintf(w, `
	    <p><a href="/restricted">Restricted</a></p>
    `)
	}
	return nil
}

func main() {
	flag.Parse()

	secret, err := hex.DecodeString(*cookieSecret)
	if err != nil {
		panic(err)
	}
	store := sessions.NewCookieStore(secret)

	oauth := oauth2.NewProviderHandler(
		oauth2.Github(oauth2.Config{
			ClientID:     *githubClientId,
			ClientSecret: *githubClientSecret}),
		"oauth-github", "/auth",
		oauth2.RedirectURLs{})

	webhelp.ListenAndServe(*listenAddr,
		webhelp.LoggingHandler(
			sessions.HandlerWithStore(store,
				webhelp.DirMux{
					"": &SampleHandler{Prov: oauth, Restricted: false},
					"restricted": oauth.LoginRequired(
						&SampleHandler{Prov: oauth, Restricted: true}),
					"auth": oauth})))
}
