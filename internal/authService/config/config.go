package config

import (
	"os"
	"encoding/json"
	"github.com/NOSTRADA88/authService/internal/authService/logger"
)

type config struct {
	Host string `json:"host"`
	Dbname string `json:"db-name"`
	SecretKey string `json:"secret-key"`
	MongoDBURL string `json:"mongodb-url"`
}


func loadConfig() *config {
	logger := logger.Logger
	logger.Println("Loading the configuration...")

	file, err := os.Open("../../config.json")
	if err != nil {
		logger.Fatal(err)
	}
	defer file.Close()

	config := new(config)
	decoder := json.NewDecoder(file)
	errDecode := decoder.Decode(config)
	if errDecode != nil {
		logger.Fatal(errDecode)
	}

	return config
}

var AppConfig *config = loadConfig()
