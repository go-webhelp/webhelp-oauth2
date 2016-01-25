// Copyright (C) 2014 JT Olds
// See LICENSE for copying information

package oauth2

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jtolds/webhelp"
	"github.com/jtolds/webhelp/sessions"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

func init() {
	gob.Register(&oauth2.Token{})
}

// ProviderHandler is a webhelp.Handler that keeps track of authentication for
// a single OAuth2 provider
//
// ProviderHandler handles requests to the following paths:
//  * /login
//  * /logout
//  * /_cb
//
// ProviderHandler will also return associated state to you about its state,
// in addition to a LoginRequired middleware and a Login URL generator.
type ProviderHandler struct {
	provider          *Provider
	session_namespace string
	handler_base_url  string
	urls              RedirectURLs
	webhelp.Handler
}

// NewProviderHandler makes a provider handler. Requires a provider
// configuration, a session namespace, a base URL for the handler, and a
// collection of URLs for redirecting.
func NewProviderHandler(provider *Provider, session_namespace string,
	handler_base_url string, urls RedirectURLs) *ProviderHandler {
	if urls.DefaultLoginURL == "" {
		urls.DefaultLoginURL = "/"
	}
	if urls.DefaultLogoutURL == "" {
		urls.DefaultLogoutURL = "/"
	}
	h := &ProviderHandler{
		provider:          provider,
		session_namespace: session_namespace,
		handler_base_url:  strings.TrimRight(handler_base_url, "/"),
		urls:              urls}
	h.Handler = webhelp.DirMux{
		"login":  webhelp.Exact(webhelp.HandlerFunc(h.login)),
		"logout": webhelp.Exact(webhelp.HandlerFunc(h.logout)),
		"_cb":    webhelp.Exact(webhelp.HandlerFunc(h.cb))}
	return h
}

// Token returns a token if the provider is currently logged in, or nil if not.
func (o *ProviderHandler) Token(ctx context.Context) (*oauth2.Token, error) {
	session, err := o.Session(ctx)
	if err != nil {
		return nil, err
	}
	return o.token(session), nil
}

// Session returns a provider-specific authenticated session for the current
// user. This session is cleared whenever a user logs out.
func (o *ProviderHandler) Session(ctx context.Context) (*sessions.Session,
	error) {
	return sessions.Load(ctx, o.session_namespace)
}

// LoggedIn returns true if the user is logged in with this provider
func (o *ProviderHandler) LoggedIn(ctx context.Context) (bool, error) {
	t, err := o.Token(ctx)
	return t != nil, err
}

func (o *ProviderHandler) token(session *sessions.Session) *oauth2.Token {
	val, exists := session.Values["_token"]
	token, correct := val.(*oauth2.Token)
	if exists && correct && token.Valid() {
		return token
	}
	return nil
}

// Logout prepares the request to log the user out of just this OAuth2
// provider. If you're using a ProviderGroup you may be interested in
// LogoutAll.
func (o *ProviderHandler) Logout(ctx context.Context,
	w webhelp.ResponseWriter) error {
	session, err := o.Session(ctx)
	if err != nil {
		return err
	}
	for name := range session.Values {
		delete(session.Values, name)
	}
	return session.Save(w)
}

// LoginURL returns the login URL for this provider
// redirect_to is the URL to navigate to after logging in, and force_prompt
// tells OAuth2 whether or not the login prompt should always be shown
// regardless of if the user is already logged in.
func (o *ProviderHandler) LoginURL(redirect_to string,
	force_prompt bool) string {
	return o.handler_base_url + "/login?" + url.Values{
		"redirect_to":  {redirect_to},
		"force_prompt": {fmt.Sprint(force_prompt)}}.Encode()
}

// LogoutURL returns the logout URL for this provider
// redirect_to is the URL to navigate to after logging out.
func (o *ProviderHandler) LogoutURL(redirect_to string) string {
	return o.handler_base_url + "/logout?" + url.Values{
		"redirect_to": {redirect_to}}.Encode()
}

func (o *ProviderHandler) login(ctx context.Context, w webhelp.ResponseWriter,
	r *http.Request) error {
	session, err := o.Session(ctx)
	if err != nil {
		return err
	}

	redirect_to := r.FormValue("redirect_to")
	if redirect_to == "" {
		redirect_to = o.urls.DefaultLoginURL
	}

	force_prompt, err := strconv.ParseBool(r.FormValue("force_prompt"))
	if err != nil {
		force_prompt = false
	}

	if !force_prompt && o.token(session) != nil {
		return webhelp.Redirect(w, r, redirect_to)
	}

	state := newState()
	session.Values["_state"] = state
	session.Values["_redirect_to"] = redirect_to
	err = session.Save(w)
	if err != nil {
		return err
	}

	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOnline}
	if force_prompt {
		opts = append(opts, oauth2.ApprovalForce)
	}

	return webhelp.Redirect(w, r, o.provider.AuthCodeURL(state, opts...))
}

func (o *ProviderHandler) cb(ctx context.Context, w webhelp.ResponseWriter,
	r *http.Request) error {
	session, err := o.Session(ctx)
	if err != nil {
		return err
	}

	val, exists := session.Values["_state"]
	existing_state, correct := val.(string)
	if !exists || !correct {
		return webhelp.ErrBadRequest.New("invalid session storage state")
	}

	val, exists = session.Values["_redirect_to"]
	redirect_to, correct := val.(string)
	if !exists || !correct {
		return webhelp.ErrBadRequest.New("invalid redirect_to")
	}

	if existing_state != r.FormValue("state") {
		return webhelp.ErrBadRequest.New("csrf detected")
	}

	token, err := o.provider.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		return err
	}

	session.Values["_token"] = token
	err = session.Save(w)
	if err != nil {
		return err
	}

	return webhelp.Redirect(w, r, redirect_to)
}

func (o *ProviderHandler) logout(ctx context.Context, w webhelp.ResponseWriter,
	r *http.Request) error {
	err := o.Logout(ctx, w)
	if err != nil {
		return err
	}
	redirect_to := r.FormValue("redirect_to")
	if redirect_to == "" {
		redirect_to = o.urls.DefaultLogoutURL
	}
	return webhelp.Redirect(w, r, redirect_to)
}

// LoginRequired is a middleware for redirecting users to a login page if
// they aren't logged in yet. If you are using a ProviderGroup and don't know
// which provider a user should use, consider using
// (*ProviderGroup).LoginRequired instead
func (o *ProviderHandler) LoginRequired(h webhelp.Handler) webhelp.Handler {
	return webhelp.HandlerFunc(func(ctx context.Context,
		w webhelp.ResponseWriter, r *http.Request) error {
		token, err := o.Token(ctx)
		if err != nil {
			return err
		}
		if token != nil {
			return h.HandleHTTP(ctx, w, r)
		} else {
			return webhelp.Redirect(w, r, o.LoginURL(r.RequestURI, false))
		}
	})
}
