package main

import (
	"context"
	"encoding/json"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/davecgh/go-spew/spew"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"os"
)

func main() {
	e := echo.New()

	provider, err := oidc.NewProvider(context.Background(), "https://athena.skymavis.com/")

	if err != nil {
		log.Fatalf("failed to create provider: %v", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "offline"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

	// create a simple route
	e.GET("/login", func(c echo.Context) error {
		return c.Redirect(http.StatusTemporaryRedirect, oauth2Config.AuthCodeURL("this-is-ma-state"))
	})

	e.GET("/", func(c echo.Context) error {

		code := c.QueryParam("code")

		if code == "" {
			return c.HTML(http.StatusOK, "Please login at <a href='/login'>/login</a> first.")
		}

		oauth2Token, err := oauth2Config.Exchange(context.Background(), code)
		if err != nil {
			spew.Dump(err)
			return c.JSON(http.StatusInternalServerError, err)
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)

		if !ok {
			return c.JSON(http.StatusInternalServerError, "no id_token field in oauth2 token")
		}

		idtoken, err := verifier.Verify(context.Background(), rawIDToken)

		if err != nil {
			return c.JSON(http.StatusInternalServerError, err.Error())
		}

		playload, _ := json.Marshal(map[string]interface{}{
			"access_token":  oauth2Token.AccessToken,
			"refresh_token": oauth2Token.RefreshToken,
			"id_token":      rawIDToken,
			"user_id":       idtoken.Subject,
		})

		myapplink := os.Getenv("PROTOCOL") + "://login?" + string(playload)

		return c.HTML(http.StatusOK, "Click here to login to your app: <a href='"+myapplink+"'>Login</a>")

	})

	// start the server
	e.Start(":1805")
}
