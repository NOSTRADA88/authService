package http

import (
	"net/http"
	"github.com/NOSTRADA88/authService/internal/authService/config"
	"github.com/NOSTRADA88/authService/internal/authService/logger"
	"github.com/NOSTRADA88/authService/internal/authService/http/handlers"
)

func StartServer() error {
	config := config.AppConfig
	
	logger := logger.Logger
	logger.Println("Starting the server...")

	http.HandleFunc("/token", handlers.NewTokenPair)
	http.HandleFunc("/refresh", handlers.RefreshTokenPair)

	logger.Printf("Server started on http://%v", config.Host)
	errListen := http.ListenAndServe(config.Host, nil)
	if errListen != nil {
		return errListen
	}
	return nil 
}

