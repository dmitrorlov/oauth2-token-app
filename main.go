package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/dmitrorlov/oauth2-token-app/handlers"

	"golang.org/x/oauth2"
)

const (
	homeTemplate  = "./templates/index.html"
	tokenTemplate = "./templates/result.html"
)

func main() {
	settings := map[handlers.PlatformBase]*oauth2.Config{}

	handlersFactory := handlers.NewHandlersFactory(settings)

	mux := http.NewServeMux()
	mux.Handle("/", handlersFactory.GetHomeHandler(homeTemplate))
	mux.HandleFunc("/auth/login", handlersFactory.GetLoginHandler())
	mux.HandleFunc("/auth/callback", handlersFactory.GetCallbackHandler(tokenTemplate))

	server := &http.Server{
		Addr:    fmt.Sprintf(":8000"),
		Handler: mux,
	}

	log.Printf("Listening at http://localhost%s", server.Addr)
	err := http.ListenAndServe(server.Addr, server.Handler)
	if err != http.ErrServerClosed {
		log.Printf("%v", err)
	}
}
