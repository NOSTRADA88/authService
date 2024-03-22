package handlers

import (
	"time"
	"strconv"
	"net/http"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/NOSTRADA88/authService/internal/authService/config"
	"github.com/NOSTRADA88/authService/internal/authService/logger"
	"github.com/NOSTRADA88/authService/internal/authService/mongodb"
)

func NewTokenPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		logger.Logger.Println("Method not allowed")
		return
	}

	guid, err := strconv.Atoi(r.FormValue("GUID"))
	if err != nil {
		logger.Logger.Println("Invalid GUID")
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid GUID", "error": err.Error()})
		return
	}
	expirationTime := time.Now().Add(2 * time.Minute)
	accessTokenString, err := mongodb.GenerateTokensPair(guid, expirationTime)
	if err != nil {
		logger.Logger.Println("Error generating tokens pair")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "Error generating tokens pair", "error": err.Error()})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "access_token",
		Value: accessTokenString,
		HttpOnly: true,
		Expires: expirationTime,
	})
	logger.Logger.Println("Token pair generated")
	json.NewEncoder(w).Encode(map[string]string{"message": "Token pair generated. Access token is in the cookie"})
}

func RefreshTokenPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	accessTokenCookie, err := r.Cookie("access_token")
	if err != nil {
		logger.Logger.Println("No access token found")
		w.WriteHeader(http.StatusUnauthorized)
		http.Redirect(w, r, "/refresh", http.StatusSeeOther)
		return
	}

	claims := new(jwt.MapClaims)
	_, err = jwt.ParseWithClaims(accessTokenCookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
        return []byte(config.AppConfig.SecretKey), nil
    })
	if err != nil {
		logger.Logger.Println("Error parsing access token")
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "Error parsing access token", "error": err.Error()})
		return
	}
	guid := int((*claims)["GUID"].(float64))
	mongodb.UpdateTokenPair(mongodb.MongoClient, w, guid)
	logger.Logger.Println("Token pair updated")
}

