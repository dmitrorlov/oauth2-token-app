package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	stateFmt = "%s_%s_%s" // "name_platform_random"
)

type PlatformBase struct {
	Name     string
	Platform string
}

type TokenData struct {
	PlatformBase
	*oauth2.Token
}

type Factory struct {
	settings map[PlatformBase]*oauth2.Config
}

func NewHandlersFactory(settings map[PlatformBase]*oauth2.Config) *Factory {
	return &Factory{
		settings: settings,
	}
}

func (f *Factory) GetHomeHandler(homeTemplate string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var localErr error
		defer func() {
			f.handleLocalError(localErr)
		}()

		tmpl, err := template.ParseFiles(homeTemplate)
		if err != nil {
			_, localErr = fmt.Fprintf(w, "failed to parse template file: %s\n", err)
			return
		}

		localErr = tmpl.Execute(w, f.settings)
	}
}

func (f *Factory) GetLoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var localErr error
		defer func() {
			f.handleLocalError(localErr)
		}()

		name := r.FormValue("name")
		platform := r.FormValue("platform")
		cfg, ok := f.settings[PlatformBase{
			Name:     name,
			Platform: platform,
		}]
		if !ok {
			_, localErr = fmt.Fprintf(w, "Missing config for %s, platform %s\n", name, platform)
			return
		}

		/*
			AuthCodeURL receive state that is a token to protect the user from CSRF attacks. You must always provide a non-empty string and
			validate that it matches the state query parameter on your redirect callback.
		*/

		opts := []oauth2.AuthCodeOption{
			oauth2.ApprovalForce,
			oauth2.AccessTypeOffline,
		}

		oauthState, err := f.generateStateAndAddCookie(w, name, platform)
		if err != nil {
			_, localErr = fmt.Fprintf(w, "failed to generate state and add cookie: %v\n", err)
			return
		}

		u := cfg.AuthCodeURL(oauthState, opts...)

		log.Printf("Auth code url: %s\n", u)
		http.Redirect(w, r, u, http.StatusTemporaryRedirect)
	}
}

func (f *Factory) GetCallbackHandler(tokenTemplate string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var localErr error
		defer func() {
			f.handleLocalError(localErr)
		}()

		cookieState, _ := r.Cookie("state")
		oauth2State := r.FormValue("state")

		if oauth2State != cookieState.Value {
			_, localErr = fmt.Fprintf(w, "states are different")
			return
		}

		code := r.FormValue("code")
		stateSplitted := strings.Split(oauth2State, "_")
		if len(stateSplitted) < 3 {
			_, localErr = fmt.Fprintf(w, "invalid oauth2State")
			return
		}

		name := stateSplitted[0]
		platform := stateSplitted[1]
		cfg, ok := f.settings[PlatformBase{
			Name:     name,
			Platform: platform,
		}]
		if !ok {
			_, localErr = fmt.Fprintf(w, "Missing config for %s, platform %s\n", name, platform)
			return
		}

		token, err := cfg.Exchange(context.Background(), code)
		if err != nil {
			_, localErr = fmt.Fprintf(w, "failed to exchange token for %s\n", platform)
			return
		}

		data := TokenData{
			PlatformBase: PlatformBase{
				Name:     name,
				Platform: platform,
			},
			Token: token,
		}

		tmpl, err := template.ParseFiles(tokenTemplate)
		if err != nil {
			_, localErr = fmt.Fprintf(w, "failed to parse template file: %s\n", err)
			return
		}

		localErr = tmpl.Execute(w, data)
	}
}

func (f *Factory) handleLocalError(err error) {
	if err == nil {
		return
	}

	log.Printf("local error: %v", err)
}

func (f *Factory) generateStateAndAddCookie(w http.ResponseWriter, name, platform string) (string, error) {
	expiration := time.Now().Add(20 * time.Minute)

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := fmt.Sprintf(stateFmt, name, platform, base64.URLEncoding.EncodeToString(b))
	cookie := http.Cookie{Name: "state", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state, nil
}
