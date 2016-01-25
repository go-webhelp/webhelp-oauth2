// Copyright (C) 2014 JT Olds
// See LICENSE for copying information

// This example shows how to set up a web service that allows users to log in
// via multiple OAuth2 providers
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"net/url"

	"github.com/jtolds/webhelp"
	"github.com/jtolds/webhelp-oauth2"
	"github.com/jtolds/webhelp/sessions"
	"golang.org/x/net/context"
)

var (
	listenAddr   = flag.String("addr", ":8080", "address to listen on")
	cookieSecret = flag.String("cookie_secret", "abcdef0123456789",
		"the secret for securing cookie information")

	githubClientId       = flag.String("github_client_id", "", "")
	githubClientSecret   = flag.String("github_client_secret", "", "")
	facebookClientId     = flag.String("facebook_client_id", "", "")
	facebookClientSecret = flag.String("facebook_client_secret", "", "")
)

type SampleHandler struct {
	Group      *oauth2.ProviderGroup
	Restricted bool
}

func (s *SampleHandler) HandleHTTP(ctx context.Context,
	w webhelp.ResponseWriter, r *http.Request) error {
	tokens, err := s.Group.Tokens(ctx)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html")
	if s.Restricted {
		fmt.Fprintf(w, `<h3>Restricted</h3>`)
	}
	if len(tokens) > 0 {
		fmt.Fprintf(w, `
	    <p>Logged in with:
      	<ul>
  	`)
		for name := range tokens {
			fmt.Fprintf(w, `
		    <li>%s (<a href="%s">logout</a>)</li>
	    `, name, s.Group.LogoutURL(name, "/"))
		}
		fmt.Fprintf(w, `
		    <li><a href="%s">logout all</a></li>
	    `, s.Group.LogoutAllURL("/"))
		fmt.Fprintf(w, `
		  </ul></p>`)
	} else {
		fmt.Fprintf(w, `
	    <p>Not logged in</p>
    `)
	}

	login_possible := false
	for name := range s.Group.Providers() {
		_, logged_in := tokens[name]
		if !logged_in {
			login_possible = true
			break
		}
	}

	if login_possible {
		fmt.Fprintf(w, "<p>Log in with:<ul>")
	}
	for name, provider := range s.Group.Providers() {
		_, logged_in := tokens[name]
		if logged_in {
			continue
		}
		fmt.Fprintf(w, `<li><a href="%s">%s</a></li>`,
			provider.LoginURL(r.RequestURI, false), name)
	}
	fmt.Fprintf(w, "</ul></p>")

	if !s.Restricted {
		fmt.Fprintf(w, `
	    <p><a href="/restricted">Restricted</a></p>
    `)
	}
	return nil
}

type LoginHandler struct {
	Group *oauth2.ProviderGroup
}

func (l *LoginHandler) HandleHTTP(ctx context.Context,
	w webhelp.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<h3>Login required</h3>`)
	fmt.Fprintf(w, "<p>Log in with:<ul>")
	for name, provider := range l.Group.Providers() {
		fmt.Fprintf(w, `<li><a href="%s">%s</a></li>`,
			provider.LoginURL(r.FormValue("redirect_to"), false), name)
	}
	fmt.Fprintf(w, "</ul></p>")
	return nil
}

func loginurl(redirect_to string) string {
	return "/login?" + url.Values{"redirect_to": {redirect_to}}.Encode()
}

func main() {
	flag.Parse()

	secret, err := hex.DecodeString(*cookieSecret)
	if err != nil {
		panic(err)
	}
	store := sessions.NewCookieStore(secret)

	group, err := oauth2.NewProviderGroup(
		"oauth", "/auth", oauth2.RedirectURLs{},
		oauth2.Github(oauth2.Config{
			ClientID:     *githubClientId,
			ClientSecret: *githubClientSecret}),
		oauth2.Facebook(oauth2.Config{
			ClientID:     *facebookClientId,
			ClientSecret: *facebookClientSecret,
			RedirectURL:  "http://localhost:8080/auth/facebook/_cb"}))
	if err != nil {
		panic(err)
	}

	webhelp.ListenAndServe(*listenAddr,
		webhelp.LoggingHandler(
			sessions.HandlerWithStore(store,
				webhelp.DirMux{
					"":      &SampleHandler{Group: group, Restricted: false},
					"login": &LoginHandler{Group: group},
					"logout": webhelp.HandlerFunc(func(ctx context.Context,
						w webhelp.ResponseWriter, r *http.Request) error {
						return webhelp.Redirect(w, r, "/auth/all/logout")
					}),
					"restricted": group.LoginRequired(
						&SampleHandler{Group: group, Restricted: true}, loginurl),
					"auth": group})))
}
